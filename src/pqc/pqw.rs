//! `.pqw` v2 — контейнер нейровесов POLER Quantum Weights (Part E.3).
//!
//! Формат заменяет `.onnx`: наш заголовок, наши секции, наша Sha256
//! верификация, наш mmap. Данные тензоров лежат **выравненными на
//! страницу 4096** — `QuantizedWeightsView` отдаёт zero-copy срезы прямо
//! из страниц файла (ядро подгружает их по касанию: 70B-модель читается
//! с NVMe лениво, только затронутые страницы живут в RAM).
//!
//! ```text
//! СМЕЩЕНИЕ  РАЗМЕР  ПОЛЕ
//! 0x00      8       magic "PQW2NN\0\0"
//! 0x08      4       version u32 = 2
//! 0x0C      4       header_size u32 = 128
//! 0x10      1       model_type: 0=encoder, 1=decoder, 2=span-ner
//! 0x11      1       quant: 0=fp32, 1=int8, 2=int4 (основной режим весов)
//! 0x12      2       flags: bit0=bias, bit1=xlmr-позиции, bit2=MoE
//! 0x14      4       num_layers u32
//! 0x18      4       hidden u32
//! 0x1C      4       intermediate u32
//! 0x20      4       heads u32
//! 0x24      4       head_dim u32
//! 0x28      4       vocab u32
//! 0x2C      4       max_pos u32
//! 0x30      4       num_experts u32 (0 = плотный FFN)
//! 0x34      4       top_k u32 (MoE-маршрутизация)
//! 0x38      4       kv_heads u32 (1 = MQA)
//! 0x3C      4       reserved = 0
//! 0x40      8       table_offset u64 (абс., выравнен на 4096)
//! 0x48      8       table_len u64 (байты)
//! 0x50      8       payload_len u64 (байты данных тензоров)
//! 0x58      8       file_len u64
//! 0x60      32      sha256([4096 .. table_offset+table_len))  ← payload+таблица
//! 0x80      —       (конец заголовка, 128 байт)
//!
//! 0x1000    ·       секции данных тензоров, каждая выравнена на 4096
//! …         ·       таблица тензоров (записи переменной длины):
//!                     u16 name_len | name utf8 | u8 dtype | u8 ndims
//!                     u16 reserved | u32 scale_count | u64 dims[ndims]
//!                     u64 data_offset | u64 data_len | f32 scales[·]
//! ```
//!
//! dtype: 0 = f32 (LayerNorm-гаммы, bias'ы), 1 = int8 (веса Linear),
//! 2 = int4 (GLM-эксперты), 3 = raw (метаданные: список меток GLiNER).
//!
//! Формат little-endian (x86_64/aarch64). Масштабы квантования копируются
//! при разборе таблицы (единицы КБ на модель) — данные весов остаются
//! zero-copy. Заголовок в 128 байт описывает архитектуру целиком.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use memmap2::{Advice, Mmap};

use super::sha256::{hex, sha256};

/// Магия формата (v2 — нейровеса; v1 «POLER_QW» занята фазовыми
/// состояниями в крейте pqw репозитория POLER-Quantum-RS).
pub const MAGIC: [u8; 8] = *b"PQW2NN\0\0";
/// Альтернативная магия POLER Quantum Weights v2.
pub const MAGIC_ALT: [u8; 8] = *b"POLERQW\0";
/// Версия формата нейровесов.
pub const VERSION: u32 = 2;
/// Размер заголовка.
pub const HEADER: usize = 128;
/// Выравнивание секций данных (страница памяти → zero-copy mmap).
pub const PAGE: usize = 4096;

// ---------------------------------------------------------------------------
// Перечисления формата
// ---------------------------------------------------------------------------

/// Класс модели в контейнере.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    /// BERT/XLM-R-энкодер (BGE-M3, SPLADE-класс).
    Encoder = 0,
    /// GLM-декодер (ChatGLM-класс: RoPE + MQA + RMSNorm + SwiGLU).
    Decoder = 1,
    /// Энкодер + span-голова (GLiNER).
    SpanNer = 2,
    /// GLiNER реальных чекпойнтов: mdeberta/deberta-спина + BiLSTM +
    /// SpanMarker + prompt-проекция, пословленная токенизация (v2).
    Gliner = 3,
}

impl ModelType {
    fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(Self::Encoder),
            1 => Ok(Self::Decoder),
            2 => Ok(Self::SpanNer),
            3 => Ok(Self::Gliner),
            _ => Err(format!("неизвестный model_type={v}")),
        }
    }
}

/// Основной режим квантования весов Linear-слоёв.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quant {
    F32 = 0,
    Int8 = 1,
    Int4 = 2,
    Trit5 = 3,
}

impl Quant {
    fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(Self::F32),
            1 => Ok(Self::Int8),
            2 => Ok(Self::Int4),
            3 => Ok(Self::Trit5),
            _ => Err(format!("неизвестный quant={v}")),
        }
    }
}

/// Тип тензора (dtype в таблице).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtype {
    F32 = 0,
    I8 = 1,
    I4 = 2,
    /// Сырые байты (метаданные: имена меток, конфиг).
    Raw = 3,
    /// Упакованные 5 тритов на байт (3^5 = 243 <= 256).
    Trit5 = 4,
}

impl Dtype {
    fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(Self::F32),
            1 => Ok(Self::I8),
            2 => Ok(Self::I4),
            3 => Ok(Self::Raw),
            4 => Ok(Self::Trit5),
            _ => Err(format!("неизвестный dtype={v}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Заголовок
// ---------------------------------------------------------------------------

/// Разобранный заголовок `.pqw`.
#[derive(Debug, Clone)]
pub struct PqwHeader {
    pub model_type: ModelType,
    pub quant: Quant,
    pub flags: u16,
    pub layers: usize,
    pub hidden: usize,
    pub intermediate: usize,
    pub heads: usize,
    pub head_dim: usize,
    pub vocab: usize,
    pub max_pos: usize,
    pub experts: usize,
    pub top_k: usize,
    pub kv_heads: usize,
    /// eps RMSNorm (заголовок, смещение 60; 0 → 1e-6).
    pub rms_eps: f32,
    pub table_offset: u64,
    pub table_len: u64,
    pub payload_len: u64,
    pub file_len: u64,
    pub sha256: [u8; 32],
}

impl PqwHeader {
    /// Флаг: слои содержат bias-тензоры.
    pub fn has_bias(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Флаг: XLM-R-позиции (сдвиг на padding_idx + 1 = 2).
    pub fn xlmr_positions(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Флаг: FFN — MoE (экспертные тензоры в слоях).
    pub fn is_moe(&self) -> bool {
        self.flags & 4 != 0
    }
    /// Флаг: спина — DeBERTa-v2/v3 (disentangled attention, rel-buckets,
    /// без абсолютных позиций, eps 1e-7). Для model_type Gliner.
    pub fn is_deberta(&self) -> bool {
        self.flags & 8 != 0
    }
    /// Флаг: послойное масштабирование внимания (ChatGLM-класс:
    /// scores/(layer_number·√hd), нумерация слоёв с 1).
    pub fn qk_layer_scaling(&self) -> bool {
        self.flags & 16 != 0
    }
}

// ---------------------------------------------------------------------------
// Билдер (запись .pqw; для тестов и конвертера)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BuilderTensor {
    name: String,
    dtype: Dtype,
    dims: Vec<usize>,
    scales: Vec<f32>,
    data: Vec<u8>,
}

/// Сборщик `.pqw`-файла. Держит тензоры в RAM — рассчитан на
/// синтетические модели и юнит-тесты; конвертер реальных весов
/// (600 МБ+) будет стримить секции напрямую в файл (следующий кирпич).
pub struct PqwBuilder {
    pub model_type: ModelType,
    pub quant: Quant,
    pub xlmr_positions: bool,
    pub layers: usize,
    pub hidden: usize,
    pub intermediate: usize,
    pub heads: usize,
    pub vocab: usize,
    pub max_pos: usize,
    pub experts: usize,
    pub top_k: usize,
    pub kv_heads: usize,
    /// Послойное масштабирование внимания (ChatGLM-класс: деление
    /// скоров на layer_number·√head_dim, нумерация слоёв с 1).
    pub qk_layer_scaling: bool,
    /// eps RMSNorm (ChatGLM3 = 1e-5; 0/устаревшие файлы → 1e-6).
    pub rms_eps: f32,
    tensors: Vec<BuilderTensor>,
}

impl PqwBuilder {
    /// Новый сборщик с архитектурой модели.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        model_type: ModelType,
        quant: Quant,
        layers: usize,
        hidden: usize,
        heads: usize,
        intermediate: usize,
        vocab: usize,
        max_pos: usize,
    ) -> Self {
        Self {
            model_type,
            quant,
            xlmr_positions: matches!(model_type, ModelType::Encoder | ModelType::SpanNer),
            layers,
            hidden,
            intermediate,
            heads,
            vocab,
            max_pos,
            experts: 0,
            top_k: 0,
            kv_heads: 1,
            qk_layer_scaling: false,
            rms_eps: 1e-6,
            tensors: Vec::new(),
        }
    }

    /// Включает MoE-FFN (декодеры GLM MoE): `experts` экспертов, топ-k.
    pub fn with_moe(mut self, experts: usize, top_k: usize) -> Self {
        self.experts = experts;
        self.top_k = top_k;
        self
    }

    /// Число KV-голов внимания (1 = MQA; heads = MHA; 2..heads = GQA).
    pub fn with_kv_heads(mut self, kv_heads: usize) -> Self {
        self.kv_heads = kv_heads;
        self
    }

    /// Послойное масштабирование внимания (ChatGLM-класс,
    /// apply_query_key_layer_scaling=true).
    pub fn with_qk_layer_scaling(mut self) -> Self {
        self.qk_layer_scaling = true;
        self
    }

    /// eps RMSNorm (ChatGLM3: layernorm_epsilon = 1e-5).
    pub fn with_rms_eps(mut self, eps: f32) -> Self {
        self.rms_eps = eps;
        self
    }

    /// Добавляет fp32-тензор (LayerNorm-гаммы/беты, bias'ы).
    pub fn add_f32(&mut self, name: &str, dims: Vec<usize>, data: &[f32]) {
        debug_assert_eq!(data.len(), dims.iter().product::<usize>());
        let bytes = data.iter().flat_map(|v| v.to_le_bytes()).collect();
        self.tensors.push(BuilderTensor {
            name: name.into(),
            dtype: Dtype::F32,
            dims,
            scales: Vec::new(),
            data: bytes,
        });
    }

    /// Добавляет уже квантованный int8-тензор (коды + масштабы на строку).
    pub fn add_i8(&mut self, name: &str, dims: Vec<usize>, codes: &[i8], scales: &[f32]) {
        debug_assert_eq!(codes.len(), dims.iter().product::<usize>());
        debug_assert_eq!(scales.len(), dims[0]);
        self.tensors.push(BuilderTensor {
            name: name.into(),
            dtype: Dtype::I8,
            dims,
            scales: scales.to_vec(),
            data: codes.iter().map(|&c| c as u8).collect(),
        });
    }

    /// Добавляет уже квантованный int4-тензор (упакованные nibble).
    pub fn add_i4(&mut self, name: &str, dims: Vec<usize>, packed: &[u8], scales: &[f32]) {
        debug_assert_eq!(packed.len(), dims[0] * ((dims[1] + 1) / 2));
        debug_assert_eq!(scales.len(), dims[0]);
        self.tensors.push(BuilderTensor {
            name: name.into(),
            dtype: Dtype::I4,
            dims,
            scales: scales.to_vec(),
            data: packed.to_vec(),
        });
    }

    /// Добавляет троичный тензор Trit5 (5 тритов на байт, 3^5 = 243 <= 256).
    pub fn add_trit5(&mut self, name: &str, dims: Vec<usize>, packed: &[u8], scales: &[f32]) {
        let cols = if dims.len() > 1 { dims[1] } else { dims[0] };
        let rows = if dims.len() > 1 { dims[0] } else { 1 };
        debug_assert_eq!(packed.len(), rows * ((cols + 4) / 5));
        self.tensors.push(BuilderTensor {
            name: name.into(),
            dtype: Dtype::Trit5,
            dims,
            scales: scales.to_vec(),
            data: packed.to_vec(),
        });
    }

    /// Добавляет сырые байты (метаданные).
    pub fn add_raw(&mut self, name: &str, data: &[u8]) {
        self.tensors.push(BuilderTensor {
            name: name.into(),
            dtype: Dtype::Raw,
            dims: vec![data.len()],
            scales: Vec::new(),
            data: data.to_vec(),
        });
    }

    /// Записывает файл: секции выравниваются на 4096, затем таблица,
    /// затем Sha256 по payload+таблице укладывается в заголовок.
    pub fn write_to(&self, path: &Path) -> Result<(), String> {
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(HEADER, 0);
        // Секции данных с выравниванием на страницу.
        let mut offsets: Vec<u64> = Vec::with_capacity(self.tensors.len());
        for t in &self.tensors {
            let here = buf.len();
            let aligned = (here + PAGE - 1) / PAGE * PAGE;
            buf.resize(aligned, 0);
            offsets.push(aligned as u64);
            buf.extend_from_slice(&t.data);
        }
        // Таблица (тоже на границе страницы).
        let table_offset = (buf.len() + PAGE - 1) / PAGE * PAGE;
        buf.resize(table_offset, 0);
        let table_start = buf.len();
        for (t, &off) in self.tensors.iter().zip(&offsets) {
            let name = t.name.as_bytes();
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name);
            buf.push(t.dtype as u8);
            buf.push(t.dims.len() as u8);
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&(t.scales.len() as u32).to_le_bytes());
            for &d in &t.dims {
                buf.extend_from_slice(&(d as u64).to_le_bytes());
            }
            buf.extend_from_slice(&off.to_le_bytes());
            buf.extend_from_slice(&(t.data.len() as u64).to_le_bytes());
            for &s in &t.scales {
                buf.extend_from_slice(&s.to_le_bytes());
            }
        }
        let table_len = buf.len() - table_start;

        // Sha256 payload+таблицы (всё после заголовка).
        let digest = sha256(&buf[PAGE..]);

        // Заголовок.
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..12].copy_from_slice(&VERSION.to_le_bytes());
        buf[12..16].copy_from_slice(&(HEADER as u32).to_le_bytes());
        buf[16] = self.model_type as u8;
        buf[17] = self.quant as u8;
        let mut flags = 0u16;
        if self.tensors.iter().any(|t| t.name.ends_with("_b")) {
            flags |= 1;
        }
        if self.xlmr_positions {
            flags |= 2;
        }
        if self.experts > 0 {
            flags |= 4;
        }
        if self.qk_layer_scaling {
            flags |= 16;
        }
        buf[18..20].copy_from_slice(&flags.to_le_bytes());
        buf[20..24].copy_from_slice(&(self.layers as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&(self.hidden as u32).to_le_bytes());
        buf[28..32].copy_from_slice(&(self.intermediate as u32).to_le_bytes());
        buf[32..36].copy_from_slice(&(self.heads as u32).to_le_bytes());
        let head_dim = if self.heads > 0 { self.hidden / self.heads } else { 0 };
        buf[36..40].copy_from_slice(&(head_dim as u32).to_le_bytes());
        buf[40..44].copy_from_slice(&(self.vocab as u32).to_le_bytes());
        buf[44..48].copy_from_slice(&(self.max_pos as u32).to_le_bytes());
        buf[48..52].copy_from_slice(&(self.experts as u32).to_le_bytes());
        buf[52..56].copy_from_slice(&(self.top_k as u32).to_le_bytes());
        buf[56..60].copy_from_slice(&(self.kv_heads as u32).to_le_bytes());
        // Ранее зарезервированное поле: eps RMSNorm (0.0 → старые файлы,
        // интерпретируется как 1e-6 в QuantizedWeightsView::open).
        buf[60..64].copy_from_slice(&self.rms_eps.to_le_bytes());
        buf[64..72].copy_from_slice(&(table_offset as u64).to_le_bytes());
        buf[72..80].copy_from_slice(&(table_len as u64).to_le_bytes());
        buf[80..88].copy_from_slice(&(table_offset as u64 - PAGE as u64).to_le_bytes());
        let total_len = buf.len() as u64;
        buf[88..96].copy_from_slice(&total_len.to_le_bytes());
        buf[96..128].copy_from_slice(&digest);

        let mut f = File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
        f.write_all(&buf).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mmap-представление (zero-copy)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Entry {
    name: String,
    dtype: Dtype,
    dims: Vec<usize>,
    /// Масштабы квантования (копия из таблицы — единицы КБ на модель).
    scales: Vec<f32>,
    data_off: usize,
    data_len: usize,
}

/// Zero-copy взгляд на веса: тензоры читаются прямо из mmap-страниц.
///
/// Открытие проверяет магию, границы, выравнивание и **Sha256** payload —
/// битый/подменённый файл не доедет до инференса.
pub struct QuantizedWeightsView {
    mmap: Mmap,
    header: PqwHeader,
    entries: Vec<Entry>,
}

impl QuantizedWeightsView {
    /// Открывает и верифицирует `.pqw`-файл.
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| format!("mmap: {e}"))?;
        let _ = mmap.advise(Advice::Random);
        if mmap.len() < HEADER {
            return Err(format!("файл обрезан: {} Б < заголовка", mmap.len()));
        }
        if mmap[0..8] != MAGIC && mmap[0..8] != MAGIC_ALT {
            return Err("чужая магия: не .pqw v2 (нейровеса)".into());
        }
        let u32_at = |off: usize| u32::from_le_bytes(mmap[off..off + 4].try_into().unwrap());
        let u64_at = |off: usize| u64::from_le_bytes(mmap[off..off + 8].try_into().unwrap());
        if u32_at(8) != VERSION {
            return Err(format!("версия формата {} != {VERSION}", u32_at(8)));
        }
        let table_offset = u64_at(64) as usize;
        let table_len = u64_at(72) as usize;
        let file_len = u64_at(88) as usize;
        if table_offset < PAGE || table_offset % PAGE != 0 || table_len == 0 {
            return Err(format!(
                "таблица невалидна: offset={table_offset}, len={table_len}"
            ));
        }
        if file_len != mmap.len() {
            return Err(format!(
                "размер файла {file_len} != фактического {}",
                mmap.len()
            ));
        }
        if table_offset + table_len > mmap.len() {
            return Err("таблица выходит за пределы файла".into());
        }

        // Заголовок.
        let model_type = ModelType::from_u8(mmap[16])?;
        let quant = Quant::from_u8(mmap[17])?;
        let mut sha_expect = [0u8; 32];
        sha_expect.copy_from_slice(&mmap[96..128]);

        // Разбор таблицы (курсор с проверкой границ на каждом шаге).
        let mut entries = Vec::new();
        let mut cur = table_offset;
        let end = table_offset + table_len;
        while cur < end {
            if cur + 2 > end {
                return Err("таблица обрезана на имени тензора".into());
            }
            let name_len = u16::from_le_bytes(mmap[cur..cur + 2].try_into().unwrap()) as usize;
            cur += 2;
            if cur + name_len > end {
                return Err("имя тензора выходит за таблицу".into());
            }
            let name = String::from_utf8(mmap[cur..cur + name_len].to_vec())
                .map_err(|_| "имя тензора не utf-8".to_string())?;
            cur += name_len;
            if cur + 8 > end {
                return Err(format!("тензор {name}: запись обрезана"));
            }
            let dtype = Dtype::from_u8(mmap[cur])?;
            let ndims = mmap[cur + 1] as usize;
            let scale_count =
                u32::from_le_bytes(mmap[cur + 4..cur + 8].try_into().unwrap()) as usize;
            cur += 8;
            if ndims > 8 || cur + ndims * 8 + 16 > end {
                return Err(format!("тензор {name}: dims выходят за таблицу"));
            }
            let mut dims = Vec::with_capacity(ndims);
            for d in 0..ndims {
                dims.push(u64_at(cur + d * 8) as usize);
            }
            cur += ndims * 8;
            let data_off = u64_at(cur) as usize;
            let data_len = u64_at(cur + 8) as usize;
            cur += 16;
            if cur + scale_count * 4 > end {
                return Err(format!("тензор {name}: масштабы выходят за таблицу"));
            }
            let mut scales = Vec::with_capacity(scale_count);
            for i in 0..scale_count {
                scales.push(f32::from_le_bytes(
                    mmap[cur + i * 4..cur + i * 4 + 4].try_into().unwrap(),
                ));
            }
            cur += scale_count * 4;
            if data_off % PAGE != 0 || data_off + data_len > table_offset {
                return Err(format!(
                    "тензор {name}: данные не выравнены или вне payload (off={data_off}, len={data_len})"
                ));
            }
            let elems: usize = dims.iter().product();
            let expect_len = match dtype {
                Dtype::F32 => elems * 4,
                Dtype::I8 => elems,
                Dtype::I4 => {
                    dims.first().copied().unwrap_or(0)
                        * ((dims.get(1).copied().unwrap_or(1) + 1) / 2)
                }
                Dtype::Trit5 => {
                    dims.first().copied().unwrap_or(0)
                        * ((dims.get(1).copied().unwrap_or(1) + 4) / 5)
                }
                Dtype::Raw => elems,
            };
            if dtype != Dtype::Raw && data_len != expect_len {
                return Err(format!(
                    "тензор {name}: data_len={data_len}, ожидалось {expect_len}"
                ));
            }
            entries.push(Entry {
                name,
                dtype,
                dims,
                scales,
                data_off,
                data_len,
            });
        }

        let flags = u16::from_le_bytes(mmap[18..20].try_into().unwrap());
        // Sha256 payload+таблицы — до разбора весов.
        let digest = sha256(&mmap[PAGE..table_offset + table_len]);
        if digest != sha_expect {
            return Err(format!(
                "Sha256 не совпал: файл бит или подменён (ожидали {}, получили {})",
                hex(&sha_expect),
                hex(&digest)
            ));
        }

        let header = PqwHeader {
            model_type,
            quant,
            flags,
            layers: u32_at(20) as usize,
            hidden: u32_at(24) as usize,
            intermediate: u32_at(28) as usize,
            heads: u32_at(32) as usize,
            head_dim: u32_at(36) as usize,
            vocab: u32_at(40) as usize,
            max_pos: u32_at(44) as usize,
            experts: u32_at(48) as usize,
            top_k: u32_at(52) as usize,
            kv_heads: u32_at(56) as usize,
            // eps RMSNorm из ранее зарезервированного поля;
            // нулевые биты старых файлов → стандартные 1e-6.
            rms_eps: {
                let e = f32::from_bits(u32_at(60));
                if e > 0.0 {
                    e
                } else {
                    1e-6
                }
            },
            table_offset: table_offset as u64,
            table_len: table_len as u64,
            payload_len: u64_at(80),
            file_len: file_len as u64,
            sha256: digest,
        };
        Ok(Self {
            mmap,
            header,
            entries,
        })
    }

    /// Заголовок контейнера.
    pub fn header(&self) -> &PqwHeader {
        &self.header
    }

    /// Имена всех тензоров (для диагностики и конвертера).
    pub fn tensor_names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Требует тензор по имени (инференс-слой зовёт без Option).
    pub fn require<'a>(&'a self, name: &str) -> Result<TensorView<'a>, String> {
        self.tensor(name)
            .ok_or_else(|| format!("тензор «{name}» отсутствует в .pqw"))
    }

    /// Тензор по имени (zero-copy срезы в mmap).
    pub fn tensor<'a>(&'a self, name: &str) -> Option<TensorView<'a>> {
        let e = self.entry(name)?;
        Some(TensorView {
            name: &e.name,
            dtype: e.dtype,
            dims: &e.dims,
            scales: &e.scales,
            data: &self.mmap[e.data_off..e.data_off + e.data_len],
        })
    }
}

// ---------------------------------------------------------------------------
// TensorView — операции над одним тензором
// ---------------------------------------------------------------------------

/// Взгляд на тензор из mmap: dtype, форма, масштабы, данные.
///
/// Ключевые операции инференса собраны здесь: матвектор квантованных
/// весов, строка эмбеддинга (gather), fp32-срез.
pub struct TensorView<'a> {
    pub name: &'a str,
    pub dtype: Dtype,
    pub dims: &'a [usize],
    pub scales: &'a [f32],
    pub data: &'a [u8],
}

impl TensorView<'_> {
    /// Число строк (dim[0]; для 1D — длина).
    pub fn rows(&self) -> usize {
        if self.dims.len() >= 2 {
            self.dims[0]
        } else {
            self.dims.first().copied().unwrap_or(0)
        }
    }

    /// Длина строки (dim[1]; для 1D — 1).
    pub fn cols(&self) -> usize {
        if self.dims.len() >= 2 {
            self.dims[1]
        } else {
            1
        }
    }

    /// Масштаб строки квантованного тензора.
    pub fn scale(&self, r: usize) -> f32 {
        self.scales.get(r).copied().unwrap_or(1.0)
    }

    /// int8-строка (только Dtype::I8).
    pub fn i8_row(&self, r: usize) -> Result<&[i8], String> {
        if self.dtype != Dtype::I8 {
            return Err(format!("тензор {} не int8", self.name));
        }
        let cols = self.cols();
        let s = r * cols;
        // i8 и u8 — одно представление байтов; reinterpret безопасен.
        let bytes = &self.data[s..s + cols];
        Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const i8, cols) })
    }

    /// int4-строка в упаковке nibble (только Dtype::I4).
    pub fn i4_row(&self, r: usize) -> Result<&[u8], String> {
        if self.dtype != Dtype::I4 {
            return Err(format!("тензор {} не int4", self.name));
        }
        let cols = self.cols();
        let packed = (cols + 1) / 2;
        let s = r * packed;
        Ok(&self.data[s..s + packed])
    }

    /// Trit5-строка (только Dtype::Trit5).
    pub fn trit5_row(&self, r: usize) -> Result<&[u8], String> {
        if self.dtype != Dtype::Trit5 {
            return Err(format!("тензор {} не trit5", self.name));
        }
        let cols = self.cols();
        let packed = (cols + 4) / 5;
        let s = r * packed;
        Ok(&self.data[s..s + packed])
    }

    /// fp32-срез целиком (только Dtype::F32; выравнивание 4 проверено).
    pub fn f32s(&self) -> Result<&[f32], String> {
        if self.dtype != Dtype::F32 {
            return Err(format!("тензор {} не f32", self.name));
        }
        if self.data.len() % 4 != 0 || self.data.as_ptr() as usize % 4 != 0 {
            return Err(format!("тензор {}: нарушено выравнивание f32", self.name));
        }
        Ok(unsafe {
            std::slice::from_raw_parts(self.data.as_ptr() as *const f32, self.data.len() / 4)
        })
    }

    /// fp32-строка 2D-тензора (bias, гаммы приходят 1D — там f32s()).
    pub fn f32_row(&self, r: usize) -> Result<&[f32], String> {
        let all = self.f32s()?;
        let cols = if self.dims.len() >= 2 {
            self.cols()
        } else {
            all.len()
        };
        Ok(&all[r * cols..(r + 1) * cols])
    }

    /// Сырые байты метаданных как utf-8.
    pub fn raw_str(&self) -> Result<&str, String> {
        if self.dtype != Dtype::Raw {
            return Err(format!("тензор {} не raw", self.name));
        }
        std::str::from_utf8(self.data).map_err(|_| "метаданные не utf-8".to_string())
    }

    /// Сырые байты RAW-секции целиком (бинарные секции: `__tokenizer__`).
    pub fn raw_bytes(&self) -> Result<&[u8], String> {
        if self.dtype != Dtype::Raw {
            return Err(format!("тензор {} не raw", self.name));
        }
        Ok(self.data)
    }

    /// Строка эмбеддинга (gather): деквантует строку `r` в `out` —
    /// единообразно для int8/int4/f32 (embeddings-таблицы).
    pub fn gather_row(&self, r: usize, out: &mut [f32]) -> Result<(), String> {
        let cols = self.cols();
        if out.len() != cols {
            return Err(format!(
                "тензор {}: gather в буфер длины {} вместо {cols}",
                self.name,
                out.len()
            ));
        }
        match self.dtype {
            Dtype::I8 => {
                let sc = self.scale(r);
                let row = self.i8_row(r)?;
                for (o, &q) in out.iter_mut().zip(row) {
                    *o = sc * q as f32;
                }
            }
            Dtype::I4 => {
                let sc = self.scale(r);
                let packed = self.i4_row(r)?;
                for i in 0..cols {
                    let nib = (packed[i / 2] >> (4 * (i % 2))) & 0xF;
                    out[i] = sc * (nib as i32 - 8) as f32;
                }
            }
            Dtype::Trit5 => {
                let sc = self.scale(r);
                let packed = self.trit5_row(r)?;
                let mut col = 0;
                for &b in packed {
                    let trits = super::tensor::Trit5Codec::unpack_5(b);
                    for i in 0..5 {
                        if col >= cols {
                            break;
                        }
                        out[col] = sc * trits[i] as f32;
                        col += 1;
                    }
                }
            }
            Dtype::F32 => {
                let row = self.f32_row(r)?;
                out.copy_from_slice(row);
            }
            Dtype::Raw => return Err(format!("тензор {}: raw не gather-ится", self.name)),
        }
        Ok(())
    }

    /// Матвектор `out = W·x` с диспетчеризацией по dtype
    /// (int8 → AVX2-кернел weight-only; f32 → dot_f32).
    pub fn matvec(&self, x: &[f32], out: &mut [f32]) -> Result<(), String> {
        let rows = self.rows();
        let cols = self.cols();
        if x.len() != cols {
            return Err(format!(
                "тензор {}: вход длины {} вместо {cols}",
                self.name,
                x.len()
            ));
        }
        if out.len() != rows {
            return Err(format!(
                "тензор {}: выход длины {} вместо {rows}",
                self.name,
                out.len()
            ));
        }
        match self.dtype {
            Dtype::I8 => {
                if rows >= 32 {
                    use rayon::prelude::*;
                    out.par_iter_mut().enumerate().for_each(|(r, out_val)| {
                        if let Ok(row) = self.i8_row(r) {
                            *out_val = self.scale(r) * super::tensor::dot_i8_f32(row, x);
                        }
                    });
                } else {
                    for r in 0..rows {
                        out[r] = self.scale(r) * super::tensor::dot_i8_f32(self.i8_row(r)?, x);
                    }
                }
            }
            Dtype::I4 => {
                if rows >= 32 {
                    use rayon::prelude::*;
                    out.par_iter_mut().enumerate().for_each(|(r, out_val)| {
                        if let Ok(packed) = self.i4_row(r) {
                            *out_val = self.scale(r) * super::tensor::dot_i4_f32(packed, x, cols);
                        }
                    });
                } else {
                    for r in 0..rows {
                        let packed = self.i4_row(r)?;
                        out[r] = self.scale(r) * super::tensor::dot_i4_f32(packed, x, cols);
                    }
                }
            }
            Dtype::Trit5 => {
                if rows >= 32 {
                    use rayon::prelude::*;
                    out.par_iter_mut().enumerate().for_each(|(r, out_val)| {
                        if let Ok(packed) = self.trit5_row(r) {
                            *out_val = self.scale(r) * super::tensor::dot_trit5_f32(packed, x, cols);
                        }
                    });
                } else {
                    for r in 0..rows {
                        let packed = self.trit5_row(r)?;
                        out[r] = self.scale(r) * super::tensor::dot_trit5_f32(packed, x, cols);
                    }
                }
            }
            Dtype::F32 => {
                if rows >= 32 {
                    use rayon::prelude::*;
                    out.par_iter_mut().enumerate().for_each(|(r, out_val)| {
                        if let Ok(row) = self.f32_row(r) {
                            *out_val = super::tensor::dot_f32(row, x);
                        }
                    });
                } else {
                    for r in 0..rows {
                        out[r] = super::tensor::dot_f32(self.f32_row(r)?, x);
                    }
                }
            }
            Dtype::Raw => return Err(format!("тензор {}: raw не матвекторится", self.name)),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc::tensor::quant_i8_per_row;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("poler-pqw-test-{name}-{}.pqw", std::process::id()));
        p
    }

    fn sample_model() -> (PqwBuilder, Vec<f32>, Vec<i8>, Vec<f32>) {
        let w: Vec<f32> = (0..12u32).map(|i| (i as f32) / 12.0 - 0.5).collect();
        let (q, s) = quant_i8_per_row(&w, 3, 4);
        let g = vec![1.0f32, 2.0, 3.0, 4.0];
        let mut b = PqwBuilder::new(ModelType::Encoder, Quant::Int8, 1, 4, 1, 8, 10, 16);
        b.add_i8("dense.w", vec![3, 4], &q, &s);
        b.add_f32("dense.g", vec![4], &g);
        (b, w, q, s)
    }

    #[test]
    fn roundtrip_tensors_bit_exact() {
        let path = tmp("roundtrip");
        let (b, _w, q, s) = sample_model();
        b.write_to(&path).unwrap();
        let view = QuantizedWeightsView::open(&path).unwrap();

        let w = view.require("dense.w").unwrap();
        assert_eq!(w.dtype, Dtype::I8);
        assert_eq!(w.dims, &[3usize, 4]);
        assert_eq!(w.scales, &s[..]);
        for r in 0..3 {
            assert_eq!(w.i8_row(r).unwrap(), &q[r * 4..(r + 1) * 4]);
        }
        let g = view.require("dense.g").unwrap();
        assert_eq!(g.f32s().unwrap(), &[1.0f32, 2.0, 3.0, 4.0]);

        let h = view.header();
        assert_eq!(h.model_type, ModelType::Encoder);
        assert_eq!(h.quant, Quant::Int8);
        assert_eq!(h.layers, 1);
        assert_eq!(h.hidden, 4);
        assert_eq!(h.vocab, 10);
        assert!(h.xlmr_positions());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn page_alignment_of_sections() {
        let path = tmp("align");
        let (b, _, _, _) = sample_model();
        b.write_to(&path).unwrap();
        let view = QuantizedWeightsView::open(&path).unwrap();
        assert_eq!(view.header().table_offset as usize % PAGE, 0);
        // Все тензорные данные лежат в [PAGE, table_offset), выравнено.
        assert!(view.header().payload_len > 0);
        for name in view.tensor_names() {
            assert!(view.require(name).is_ok(), "тензор {name} недоступен");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sha256_tamper_detected() {
        let path = tmp("tamper");
        let (b, _, _, _) = sample_model();
        b.write_to(&path).unwrap();
        // Порча одного байта payload (первая секция данных — за заголовком).
        let bytes = std::fs::read(&path).unwrap();
        let mut bad = bytes.clone();
        bad[PAGE + 3] ^= 0xFF;
        std::fs::write(&path, &bad).unwrap();
        let err = match QuantizedWeightsView::open(&path) {
            Err(e) => e,
            Ok(_) => String::from("порча не распознана"),
        };
        assert!(err.contains("Sha256"), "ошибка должна быть про Sha256: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bad_magic_rejected() {
        let path = tmp("magic");
        let (b, _, _, _) = sample_model();
        b.write_to(&path).unwrap();
        let mut bad = std::fs::read(&path).unwrap();
        bad[0] = b'X';
        std::fs::write(&path, &bad).unwrap();
        let err = match QuantizedWeightsView::open(&path) {
            Err(e) => e,
            Ok(_) => String::from("плохая магия не распознана"),
        };
        assert!(err.contains("магия"), "ошибка должна быть про магию: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_file_rejected() {
        let path = tmp("trunc");
        let (b, _, _, _) = sample_model();
        b.write_to(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 10]).unwrap();
        assert!(QuantizedWeightsView::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn matvec_matches_naive() {
        let path = tmp("matvec");
        let (b, w, _, _) = sample_model();
        b.write_to(&path).unwrap();
        let view = QuantizedWeightsView::open(&path).unwrap();
        let tv = view.require("dense.w").unwrap();
        let x = [0.5f32, -1.0, 0.25, 2.0];
        let mut out = [0f32; 3];
        tv.matvec(&x, &mut out).unwrap();
        for r in 0..3 {
            let naive: f32 = w[r * 4..(r + 1) * 4]
                .iter()
                .zip(&x)
                .map(|(a, b)| a * b)
                .sum();
            // Квантование int8: погрешность ≤ scale/2 на вес.
            let tol = tv.scale(r) * 0.5 * 4.0 + 1e-4;
            assert!(
                (out[r] - naive).abs() <= tol,
                "r={r}: {} vs {naive} (tol {tol})",
                out[r]
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gather_row_works_for_f32() {
        let path = tmp("gather");
        let g = vec![0.25f32, 0.5, 0.75, 1.0, 1.25, 1.5];
        let mut b = PqwBuilder::new(ModelType::Encoder, Quant::Int8, 1, 6, 1, 12, 8, 16);
        b.add_f32("emb", vec![2, 3], &g);
        b.write_to(&path).unwrap();
        let view = QuantizedWeightsView::open(&path).unwrap();
        let tv = view.require("emb").unwrap();
        let mut out = [0f32; 3];
        tv.gather_row(1, &mut out).unwrap();
        assert_eq!(out, [1.0f32, 1.25, 1.5]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn raw_metadata_roundtrip() {
        let path = tmp("raw");
        let mut b = PqwBuilder::new(ModelType::SpanNer, Quant::Int8, 1, 4, 1, 8, 10, 16);
        b.add_raw("__labels__", b"PERSON\nLOCATION\nOBJECT");
        b.write_to(&path).unwrap();
        let view = QuantizedWeightsView::open(&path).unwrap();
        let labels_tensor = view.require("__labels__").unwrap();
        let labels = labels_tensor.raw_str().unwrap();
        assert_eq!(labels, "PERSON\nLOCATION\nOBJECT");
        assert_eq!(view.header().model_type, ModelType::SpanNer);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn int4_tensor_roundtrip() {
        use crate::pqc::tensor::quant_i4_per_row;
        let path = tmp("int4");
        let w: Vec<f32> = (0..8u32).map(|i| (i as f32) / 8.0 - 0.5).collect();
        let (packed, s) = quant_i4_per_row(&w, 2, 4);
        let mut b = PqwBuilder::new(ModelType::Decoder, Quant::Int4, 1, 4, 2, 8, 8, 16);
        b.add_i4("w", vec![2, 4], &packed, &s);
        b.write_to(&path).unwrap();
        let view = QuantizedWeightsView::open(&path).unwrap();
        let tv = view.require("w").unwrap();
        assert_eq!(tv.dtype, Dtype::I4);
        assert_eq!(tv.i4_row(1).unwrap().len(), 2);
        let mut out = [0f32; 4];
        tv.gather_row(0, &mut out).unwrap();
        // Погрешность int4 ≤ scale/2.
        for i in 0..4 {
            assert!(
                (out[i] - w[i]).abs() <= s[0] / 2.0 + 1e-6,
                "i={i}: {} vs {}",
                out[i],
                w[i]
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trit5_tensor_roundtrip_and_matvec() {
        use crate::pqc::tensor::Trit5Codec;
        let path = tmp("trit5");
        // Создаем матрицу 2x5 из тритов:
        // row 0: [+1, -1,  0, +1, -1] -> packed byte b1
        // row 1: [-1, -1, +1,  0, +1] -> packed byte b2
        let t1: [i8; 5] = [1, -1, 0, 1, -1];
        let t2: [i8; 5] = [-1, -1, 1, 0, 1];
        let b1 = Trit5Codec::pack_5(&t1).unwrap();
        let b2 = Trit5Codec::pack_5(&t2).unwrap();
        let packed = vec![b1, b2];
        let scales = vec![1.0f32, 2.0f32];

        let mut b = PqwBuilder::new(ModelType::Decoder, Quant::Trit5, 1, 5, 1, 5, 8, 16);
        b.add_trit5("archetype_proj", vec![2, 5], &packed, &scales);
        b.write_to(&path).unwrap();

        let view = QuantizedWeightsView::open(&path).unwrap();
        let tv = view.require("archetype_proj").unwrap();
        assert_eq!(tv.dtype, Dtype::Trit5);
        assert_eq!(tv.rows(), 2);
        assert_eq!(tv.cols(), 5);

        // Gather test
        let mut row0 = [0f32; 5];
        tv.gather_row(0, &mut row0).unwrap();
        assert_eq!(row0, [1.0, -1.0, 0.0, 1.0, -1.0]);

        let mut row1 = [0f32; 5];
        tv.gather_row(1, &mut row1).unwrap();
        assert_eq!(row1, [-2.0, -2.0, 2.0, 0.0, 2.0]);

        // Matvec test: out = W * x
        let x = vec![0.5f32, 1.2, 3.4, -2.0, 0.8];
        let mut out = [0f32; 2];
        tv.matvec(&x, &mut out).unwrap();

        // row 0: 1.0 * (+0.5 - 1.2 + 0.0 - 2.0 - 0.8) = -3.5
        // row 1: 2.0 * (-0.5 - 1.2 + 3.4 + 0.0 + 0.8) = 2.0 * (2.5) = 5.0
        assert!((out[0] - (-3.5f32)).abs() < 1e-5, "out[0]={}", out[0]);
        assert!((out[1] - (5.0f32)).abs() < 1e-5, "out[1]={}", out[1]);

        let _ = std::fs::remove_file(&path);
    }
}
