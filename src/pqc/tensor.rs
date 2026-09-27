//! Тензорное ядро `pqc` — нативные SIMD-кернелы инференса (Part E/F).
//!
//! Здесь живёт ВСЯ математика прямого прохода: скалярные произведения
//! (fp32, int8, int4), нормы (LayerNorm для энкодера BERT-класса,
//! RMSNorm для GLM-декодера), активации (GELU-erf, SiLU/Swish),
//! softmax, RoPE-таблицы. Ни одной внешней ML-библиотеки: только
//! `core::arch` из std и runtime-детект CPU (тот же канон, что у
//! Teddy в retrieval-слое).
//!
//! ## Канон детерминизма
//!
//! Рантайм выбирает РОВНО ОДИН путь исполнения на процесс (детект
//! кэшируется `OnceLock`), порядок аккумуляции внутри пути фиксирован —
//! инференс побитово воспроизводим на данной машине (инвариант кирпича
//! RaBitQ/HNSW распространён на нейрослой).
//!
//! ## Квантование весов (симметричное, на строку)
//!
//! * **int8**: `scale = max|w_row| / 127`, код ∈ [-127, 127];
//!   матвектор: `out[r] = scale_r · Σ q[r,i]·x[i]` — int8-строка
//!   конвертируется в f32 регистрами AVX2 (`cvtepi8_epi32 → cvtepi32_ps
//!   → fmadd`), активации остаются fp32 (weight-only quantization).
//! * **int4**: `scale = max|w_row| / 7`, код ∈ [-7, 7], упаковка два
//!   nibble на байт (`lo = байт & 0xF`, `hi = байт >> 4`, значение =
//!   `nibble − 8`). Распаковка в горячем цикле.

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
/// Доступен ли AVX (AVX1, 256-бит float) на этой машине.
pub fn avx() -> bool {
    static CELL: OnceLock<bool> = OnceLock::new();
    *CELL.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::is_x86_feature_detected!("avx")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    })
}

/// Доступен ли AVX2+FMA на этой машине (кэш на процесс).
pub fn avx2() -> bool {
    static CELL: OnceLock<bool> = OnceLock::new();
    *CELL.get_or_init(|| {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("fma")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    })
}

// ---------------------------------------------------------------------------
// Скалярные произведения
// ---------------------------------------------------------------------------

/// Скалярное произведение fp32 (AVX2/AVX1 при наличии, иначе скаляр).
pub fn dot_f32(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len(), "dot_f32: длины не совпадают");
    #[cfg(target_arch = "x86_64")]
    {
        if avx2() {
            return unsafe { dot_f32_avx2(a, b) };
        }
        if avx() {
            return unsafe { dot_f32_avx(a, b) };
        }
    }
    dot_f32_scalar(a, b)
}

/// Скалярное произведение int8-строки весов с fp32-вектором активаций.
///
/// Кернел weight-only int8: веса живут байтом, активации — float;
/// конвертация int8→f32 делается SIMD-инструкциями прямо в регистрах.
pub fn dot_i8_f32(q: &[i8], x: &[f32]) -> f32 {
    debug_assert_eq!(q.len(), x.len(), "dot_i8_f32: длины не совпадают");
    #[cfg(target_arch = "x86_64")]
    {
        if avx2() {
            return unsafe { dot_i8_f32_avx2(q, x) };
        }
        if avx() {
            return unsafe { dot_i8_f32_avx(q, x) };
        }
    }
    dot_i8_f32_scalar(q, x)
}

/// Скалярное произведение int4-строки (упакованные nibble) с fp32-вектором.
///
/// Распаковка в горячем цикле: `v = nibble − 8 ∈ [-8, 7]`.
/// При наличии AVX1/AVX2 выполняется векторная распаковка и параллельное FMA/MUL+ADD.
pub fn dot_i4_f32(packed: &[u8], x: &[f32], n: usize) -> f32 {
    debug_assert_eq!(packed.len(), (n + 1) / 2, "dot_i4_f32: размер упаковки");
    #[cfg(target_arch = "x86_64")]
    {
        if avx() {
            return unsafe { dot_i4_f32_avx(packed, x, n) };
        }
    }
    dot_i4_f32_scalar(packed, x, n)
}

#[inline]
fn dot_i4_f32_scalar(packed: &[u8], x: &[f32], n: usize) -> f32 {
    let mut s = 0f32;
    for (i, &b) in packed.iter().enumerate() {
        let lo = (b & 0xF) as i32 - 8;
        let hi = (b >> 4) as i32 - 8;
        let x0 = if i * 2 < n { x[i * 2] } else { 0.0 };
        let x1 = if i * 2 + 1 < n { x[i * 2 + 1] } else { 0.0 };
        s += lo as f32 * x0 + hi as f32 * x1;
    }
    s
}

// ---------------------------------------------------------------------------
// Trit5 Codec (3^5 = 243 <= 256) & SIMD No-Mul Dot Product
// ---------------------------------------------------------------------------

/// Статическая таблица декодирования Trit5 -> f32 [243 x 8]
/// 5 значений — это декодированные триты t_i in {-1.0, 0.0, +1.0},
/// последние 3 элемента выровнены нулями для 256-битного AVX2 загрузчика.
pub static TRIT5_LUT_F32: [[f32; 8]; 243] = generate_trit5_lut();

/// Константный генератор таблицы декодирования во время компиляции
const fn generate_trit5_lut() -> [[f32; 8]; 243] {
    let mut lut = [[0.0f32; 8]; 243];
    let mut b = 0;
    while b < 243 {
        let mut curr = b;
        let mut i = 0;
        while i < 5 {
            let u = curr % 3;
            let t = (u as i8) - 1; // 0 -> -1.0, 1 -> 0.0, 2 -> +1.0
            lut[b][i] = t as f32;
            curr /= 3;
            i += 1;
        }
        b += 1;
    }
    lut
}

/// Кодек Trit5: упаковка и распаковка 5 тритов в 1 байт
pub struct Trit5Codec;

impl Trit5Codec {
    /// Упаковывает 5 тритов t_i in {-1, 0, +1} в 1 байт.
    /// Возвращает None, если хотя бы один трит выходит за пределы {-1, 0, +1}.
    #[inline(always)]
    pub fn pack_5(trits: &[i8; 5]) -> Option<u8> {
        let mut byte_val: u16 = 0;
        let mut mul: u16 = 1;

        for &t in trits.iter() {
            if t < -1 || t > 1 {
                return None;
            }
            let u = (t + 1) as u16; // Map {-1, 0, +1} -> {0, 1, 2}
            byte_val += u * mul;
            mul *= 3;
        }

        Some(byte_val as u8)
    }

    /// Распаковывает байт B in [0, 242] в 5 тритов t_i in {-1, 0, +1}.
    #[inline(always)]
    pub fn unpack_5(byte: u8) -> [i8; 5] {
        if byte >= 243 {
            return [0; 5];
        }
        let entry = &TRIT5_LUT_F32[byte as usize];
        [
            entry[0] as i8,
            entry[1] as i8,
            entry[2] as i8,
            entry[3] as i8,
            entry[4] as i8,
        ]
    }
}

/// Скалярное произведение Trit5-строки весов с fp32-вектором активаций.
///
/// No-Mul исполнение: веса в {-1, 0, +1}, умножение заменяется на условное
/// знаковое сложение / вычитание через маски знаков AVX2 или скалярную ветку.
pub fn dot_trit5_f32(packed: &[u8], x: &[f32], n: usize) -> f32 {
    debug_assert_eq!(packed.len(), (n + 4) / 5, "dot_trit5_f32: размер упаковки");
    #[cfg(target_arch = "x86_64")]
    {
        if avx() {
            return unsafe { dot_trit5_f32_avx(packed, x, n) };
        }
    }
    dot_trit5_f32_scalar(packed, x, n)
}

#[inline]
fn dot_trit5_f32_scalar(packed: &[u8], x: &[f32], n: usize) -> f32 {
    let mut s = 0f32;
    let mut x_idx = 0;
    for &b in packed {
        let entry = if b < 243 { &TRIT5_LUT_F32[b as usize] } else { &[0.0; 8] };
        for i in 0..5 {
            if x_idx >= n {
                break;
            }
            let t = entry[i];
            let xi = x[x_idx];
            if t == 1.0 {
                s += xi;
            } else if t == -1.0 {
                s -= xi;
            }
            x_idx += 1;
        }
    }
    s
}

#[inline]
fn dot_f32_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[inline]
fn dot_i8_f32_scalar(q: &[i8], x: &[f32]) -> f32 {
    let mut s = 0f32;
    for (w, v) in q.iter().zip(x) {
        s += *w as f32 * *v;
    }
    s
}

// ---------------------------------------------------------------------------
// AVX2-кернелы
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn dot_f32_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    let n = a.len();
    let mut acc = _mm256_setzero_ps();
    let mut i = 0;
    while i + 8 <= n {
        let va = _mm256_loadu_ps(a.as_ptr().add(i));
        let vb = _mm256_loadu_ps(b.as_ptr().add(i));
        acc = _mm256_fmadd_ps(va, vb, acc);
        i += 8;
    }
    let mut sum = hsum256(acc);
    while i < n {
        sum += a[i] * b[i];
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn dot_i8_f32_avx2(q: &[i8], x: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    let n = q.len();
    let mut acc = _mm256_setzero_ps();
    let mut i = 0;
    while i + 8 <= n {
        // 8 int8-весов → 8 int32 → 8 float, FMA с активациями.
        let w8 = _mm_loadl_epi64(q.as_ptr().add(i) as *const __m128i);
        let w32 = _mm256_cvtepi8_epi32(w8);
        let wf = _mm256_cvtepi32_ps(w32);
        let xf = _mm256_loadu_ps(x.as_ptr().add(i));
        acc = _mm256_fmadd_ps(wf, xf, acc);
        i += 8;
    }
    let mut sum = hsum256(acc);
    while i < n {
        sum += q[i] as f32 * x[i];
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn dot_f32_avx(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    let n = a.len();
    let mut acc0 = _mm256_setzero_ps();
    let mut acc1 = _mm256_setzero_ps();
    let mut acc2 = _mm256_setzero_ps();
    let mut acc3 = _mm256_setzero_ps();
    let mut i = 0;
    while i + 32 <= n {
        let va0 = _mm256_loadu_ps(a.as_ptr().add(i));
        let vb0 = _mm256_loadu_ps(b.as_ptr().add(i));
        acc0 = _mm256_add_ps(acc0, _mm256_mul_ps(va0, vb0));

        let va1 = _mm256_loadu_ps(a.as_ptr().add(i + 8));
        let vb1 = _mm256_loadu_ps(b.as_ptr().add(i + 8));
        acc1 = _mm256_add_ps(acc1, _mm256_mul_ps(va1, vb1));

        let va2 = _mm256_loadu_ps(a.as_ptr().add(i + 16));
        let vb2 = _mm256_loadu_ps(b.as_ptr().add(i + 16));
        acc2 = _mm256_add_ps(acc2, _mm256_mul_ps(va2, vb2));

        let va3 = _mm256_loadu_ps(a.as_ptr().add(i + 24));
        let vb3 = _mm256_loadu_ps(b.as_ptr().add(i + 24));
        acc3 = _mm256_add_ps(acc3, _mm256_mul_ps(va3, vb3));

        i += 32;
    }
    let acc = _mm256_add_ps(_mm256_add_ps(acc0, acc1), _mm256_add_ps(acc2, acc3));
    let mut sum = hsum256(acc);
    while i < n {
        sum += *a.get_unchecked(i) * *b.get_unchecked(i);
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx", enable = "sse4.1")]
unsafe fn dot_i8_f32_avx(q: &[i8], x: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    let n = q.len();
    let mut acc0 = _mm256_setzero_ps();
    let mut acc1 = _mm256_setzero_ps();
    let mut i = 0;
    while i + 16 <= n {
        let w8_0 = _mm_loadl_epi64(q.as_ptr().add(i) as *const __m128i);
        let w8_0_lo = _mm_cvtepi8_epi32(w8_0);
        let w8_0_hi = _mm_cvtepi8_epi32(_mm_srli_si128(w8_0, 4));
        let wf0 = _mm256_set_m128(_mm_cvtepi32_ps(w8_0_hi), _mm_cvtepi32_ps(w8_0_lo));
        let xf0 = _mm256_loadu_ps(x.as_ptr().add(i));
        acc0 = _mm256_add_ps(acc0, _mm256_mul_ps(wf0, xf0));

        let w8_1 = _mm_loadl_epi64(q.as_ptr().add(i + 8) as *const __m128i);
        let w8_1_lo = _mm_cvtepi8_epi32(w8_1);
        let w8_1_hi = _mm_cvtepi8_epi32(_mm_srli_si128(w8_1, 4));
        let wf1 = _mm256_set_m128(_mm_cvtepi32_ps(w8_1_hi), _mm_cvtepi32_ps(w8_1_lo));
        let xf1 = _mm256_loadu_ps(x.as_ptr().add(i + 8));
        acc1 = _mm256_add_ps(acc1, _mm256_mul_ps(wf1, xf1));

        i += 16;
    }
    let mut sum = hsum256(_mm256_add_ps(acc0, acc1));
    while i < n {
        sum += *q.get_unchecked(i) as f32 * *x.get_unchecked(i);
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx", enable = "sse4.1")]
unsafe fn dot_i4_f32_avx(packed: &[u8], x: &[f32], n: usize) -> f32 {
    use std::arch::x86_64::*;
    let mut acc0 = _mm256_setzero_ps();
    let mut acc1 = _mm256_setzero_ps();
    let mask = _mm_set1_epi8(0x0F);
    let offset = _mm_set1_epi8(8);

    let mut byte_idx = 0;
    let mut x_idx = 0;
    let total_bytes = packed.len();

    // 8 packed bytes = 16 int4 weights = 16 floats (two 256-bit AVX vectors)
    while byte_idx + 8 <= total_bytes && x_idx + 16 <= n {
        let raw = _mm_loadl_epi64(packed.as_ptr().add(byte_idx) as *const __m128i);
        let lo = _mm_sub_epi8(_mm_and_si128(raw, mask), offset);
        let hi = _mm_sub_epi8(_mm_and_si128(_mm_srli_epi16(raw, 4), mask), offset);
        let unpacked = _mm_unpacklo_epi8(lo, hi); // 16 signed i8s: lo0, hi0, lo1, hi1, ...

        let w_lo = _mm_cvtepi8_epi32(unpacked);
        let w_hi = _mm_cvtepi8_epi32(_mm_srli_si128(unpacked, 4));
        let wf0 = _mm256_set_m128(_mm_cvtepi32_ps(w_hi), _mm_cvtepi32_ps(w_lo));
        let xf0 = _mm256_loadu_ps(x.as_ptr().add(x_idx));
        acc0 = _mm256_add_ps(acc0, _mm256_mul_ps(wf0, xf0));

        let w_lo2 = _mm_cvtepi8_epi32(_mm_srli_si128(unpacked, 8));
        let w_hi2 = _mm_cvtepi8_epi32(_mm_srli_si128(unpacked, 12));
        let wf1 = _mm256_set_m128(_mm_cvtepi32_ps(w_hi2), _mm_cvtepi32_ps(w_lo2));
        let xf1 = _mm256_loadu_ps(x.as_ptr().add(x_idx + 8));
        acc1 = _mm256_add_ps(acc1, _mm256_mul_ps(wf1, xf1));

        byte_idx += 8;
        x_idx += 16;
    }

    let mut sum = hsum256(_mm256_add_ps(acc0, acc1));
    while byte_idx < total_bytes && x_idx < n {
        let b = *packed.get_unchecked(byte_idx);
        let lo = (b & 0xF) as i32 - 8;
        let hi = (b >> 4) as i32 - 8;
        sum += lo as f32 * *x.get_unchecked(x_idx);
        if x_idx + 1 < n {
            sum += hi as f32 * *x.get_unchecked(x_idx + 1);
        }
        byte_idx += 1;
        x_idx += 2;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn dot_trit5_f32_avx(packed: &[u8], x: &[f32], n: usize) -> f32 {
    use std::arch::x86_64::*;
    let mut acc0 = _mm256_setzero_ps();
    let mut acc1 = _mm256_setzero_ps();
    let mut acc2 = _mm256_setzero_ps();
    let mut acc3 = _mm256_setzero_ps();

    let one_v = _mm256_set1_ps(1.0);
    let neg_one_v = _mm256_set1_ps(-1.0);

    let mut byte_idx = 0;
    let total_bytes = packed.len();
    let mut x_idx = 0;

    // 4x unrolled No-Mul цикл (20 тритов за такт) — идеально ложится в 16 YMM регистров
    while byte_idx + 4 <= total_bytes && x_idx + 23 <= n {
        let b0 = *packed.get_unchecked(byte_idx);
        let b1 = *packed.get_unchecked(byte_idx + 1);
        let b2 = *packed.get_unchecked(byte_idx + 2);
        let b3 = *packed.get_unchecked(byte_idx + 3);

        if b0 < 243 && b1 < 243 && b2 < 243 && b3 < 243 {
            let t0 = _mm256_loadu_ps(TRIT5_LUT_F32.get_unchecked(b0 as usize).as_ptr());
            let xv0 = _mm256_loadu_ps(x.as_ptr().add(x_idx));
            let p0 = _mm256_and_ps(xv0, _mm256_cmp_ps::<_CMP_EQ_OQ>(t0, one_v));
            let n0 = _mm256_and_ps(xv0, _mm256_cmp_ps::<_CMP_EQ_OQ>(t0, neg_one_v));
            acc0 = _mm256_add_ps(acc0, _mm256_sub_ps(p0, n0));

            let t1 = _mm256_loadu_ps(TRIT5_LUT_F32.get_unchecked(b1 as usize).as_ptr());
            let xv1 = _mm256_loadu_ps(x.as_ptr().add(x_idx + 5));
            let p1 = _mm256_and_ps(xv1, _mm256_cmp_ps::<_CMP_EQ_OQ>(t1, one_v));
            let n1 = _mm256_and_ps(xv1, _mm256_cmp_ps::<_CMP_EQ_OQ>(t1, neg_one_v));
            acc1 = _mm256_add_ps(acc1, _mm256_sub_ps(p1, n1));

            let t2 = _mm256_loadu_ps(TRIT5_LUT_F32.get_unchecked(b2 as usize).as_ptr());
            let xv2 = _mm256_loadu_ps(x.as_ptr().add(x_idx + 10));
            let p2 = _mm256_and_ps(xv2, _mm256_cmp_ps::<_CMP_EQ_OQ>(t2, one_v));
            let n2 = _mm256_and_ps(xv2, _mm256_cmp_ps::<_CMP_EQ_OQ>(t2, neg_one_v));
            acc2 = _mm256_add_ps(acc2, _mm256_sub_ps(p2, n2));

            let t3 = _mm256_loadu_ps(TRIT5_LUT_F32.get_unchecked(b3 as usize).as_ptr());
            let xv3 = _mm256_loadu_ps(x.as_ptr().add(x_idx + 15));
            let p3 = _mm256_and_ps(xv3, _mm256_cmp_ps::<_CMP_EQ_OQ>(t3, one_v));
            let n3 = _mm256_and_ps(xv3, _mm256_cmp_ps::<_CMP_EQ_OQ>(t3, neg_one_v));
            acc3 = _mm256_add_ps(acc3, _mm256_sub_ps(p3, n3));
        }

        byte_idx += 4;
        x_idx += 20;
    }

    // 1x vector loop
    while byte_idx < total_bytes && x_idx + 8 <= n {
        let b = *packed.get_unchecked(byte_idx);
        if b < 243 {
            let trits_ptr = TRIT5_LUT_F32.get_unchecked(b as usize).as_ptr();
            let trits_v = _mm256_loadu_ps(trits_ptr);
            let x_v = _mm256_loadu_ps(x.as_ptr().add(x_idx));

            let pos_mask = _mm256_cmp_ps::<_CMP_EQ_OQ>(trits_v, one_v);
            let neg_mask = _mm256_cmp_ps::<_CMP_EQ_OQ>(trits_v, neg_one_v);

            let pos_vals = _mm256_and_ps(x_v, pos_mask);
            let neg_vals = _mm256_and_ps(x_v, neg_mask);

            let diff = _mm256_sub_ps(pos_vals, neg_vals);
            acc0 = _mm256_add_ps(acc0, diff);
        }
        x_idx += 5;
        byte_idx += 1;
    }

    let combined = _mm256_add_ps(_mm256_add_ps(acc0, acc1), _mm256_add_ps(acc2, acc3));
    let mut sum = hsum256(combined);

    // Хвост (безопасный скалярный No-Mul)
    while byte_idx < total_bytes {
        let b = *packed.get_unchecked(byte_idx);
        if b < 243 {
            let entry = TRIT5_LUT_F32.get_unchecked(b as usize);
            for i in 0..5 {
                if x_idx >= n {
                    break;
                }
                let t = entry[i];
                let xi = *x.get_unchecked(x_idx);
                if t == 1.0 {
                    sum += xi;
                } else if t == -1.0 {
                    sum -= xi;
                }
                x_idx += 1;
            }
        }
        byte_idx += 1;
    }

    sum
}

/// Горизонтальная сумма `__m256` с фиксированным порядком (детерминизм).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn hsum256(v: std::arch::x86_64::__m256) -> f32 {
    use std::arch::x86_64::*;
    let lo = _mm256_castps256_ps128(v);
    let hi = _mm256_extractf128_ps(v, 1);
    let s = _mm_add_ps(lo, hi);
    let mut arr = [0f32; 4];
    _mm_storeu_ps(arr.as_mut_ptr(), s);
    ((arr[0] + arr[1]) + (arr[2] + arr[3])) as f32
}

// ---------------------------------------------------------------------------
// Нормы
// ---------------------------------------------------------------------------

/// LayerNorm (BERT-класс, post-norm): `(x − μ)/σ · γ + β`, in-place.
///
/// σ — популяционная (ddof = 0), как в исходном BERT/XLM-R.
pub fn layer_norm(x: &mut [f32], gamma: &[f32], beta: &[f32], eps: f32) {
    debug_assert_eq!(x.len(), gamma.len());
    debug_assert_eq!(x.len(), beta.len());
    let n = x.len();
    if n == 0 {
        return;
    }
    let mean = x.iter().sum::<f32>() / n as f32;
    let mut var = 0f32;
    for v in x.iter() {
        let d = v - mean;
        var += d * d;
    }
    var /= n as f32;
    let inv = 1.0 / (var + eps).sqrt();
    for i in 0..n {
        x[i] = (x[i] - mean) * inv * gamma[i] + beta[i];
    }
}

/// RMSNorm (GLM-класс, pre-norm): `x / √(mean(x²)+ε) · γ`.
///
/// Работает в отдельный выход (residual-ветка декодера требует исходный x).
pub fn rms_norm(x: &[f32], gamma: &[f32], eps: f32, out: &mut [f32]) {
    debug_assert_eq!(x.len(), gamma.len());
    debug_assert_eq!(x.len(), out.len());
    let n = x.len();
    if n == 0 {
        return;
    }
    let mut ms = 0f32;
    for v in x.iter() {
        ms += v * v;
    }
    let inv = 1.0 / (ms / n as f32 + eps).sqrt();
    for i in 0..n {
        out[i] = x[i] * inv * gamma[i];
    }
}

/// L2-нормализация in-place (CLS-пулинг BGE-M3: косинус == IP).
pub fn l2_normalize(x: &mut [f32]) {
    let mut s = 0f32;
    for v in x.iter() {
        s += v * v;
    }
    let n = s.sqrt();
    if n > 0.0 {
        for v in x.iter_mut() {
            *v /= n;
        }
    }
}

// ---------------------------------------------------------------------------
// Активации
// ---------------------------------------------------------------------------

/// erf(x) — аппроксимация Абрамовица–Стегуна 7.1.26 (|err| < 1.5e-7),
/// достаточно точно против fp32-округления GELU-эталона.
pub fn erf(x: f32) -> f32 {
    let sign = if x < 0.0 { -1.0f32 } else { 1.0 };
    let ax = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * ax);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t
            - 0.284_496_736)
            * t
            + 0.254_829_592)
            * t
            * (-ax * ax).exp();
    sign * y
}

/// Точный GELU (erf-форма, как в BERT/XLM-R/BGE-M3): `x·Φ(x)`.
pub fn gelu(v: f32) -> f32 {
    0.5 * v * (1.0 + erf(v * std::f32::consts::FRAC_1_SQRT_2))
}

/// GELU по всему срезу in-place.
pub fn gelu_inplace(x: &mut [f32]) {
    for v in x.iter_mut() {
        *v = gelu(*v);
    }
}

/// SiLU/Swish: `x·sigmoid(x)` (ветка gate в SwiGLU-FFN декодера).
pub fn silu(v: f32) -> f32 {
    v / (1.0 + (-v).exp())
}

/// SiLU по всему срезу in-place.
pub fn silu_inplace(x: &mut [f32]) {
    for v in x.iter_mut() {
        *v = silu(*v);
    }
}

// ---------------------------------------------------------------------------
// Softmax / выбор
// ---------------------------------------------------------------------------

/// Численно стабильный softmax in-place (сдвиг максимума).
pub fn softmax_inplace(x: &mut [f32]) {
    if x.is_empty() {
        return;
    }
    let m = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut z = 0f32;
    for v in x.iter_mut() {
        *v = (*v - m).exp();
        z += *v;
    }
    if z > 0.0 {
        for v in x.iter_mut() {
            *v /= z;
        }
    }
}

/// Индекс максимума (ties → младший индекс, детерминизм).
pub fn argmax(x: &[f32]) -> usize {
    debug_assert!(!x.is_empty(), "argmax: пустой срез");
    let mut best = 0usize;
    let mut bv = x[0];
    for (i, &v) in x.iter().enumerate().skip(1) {
        if v > bv {
            bv = v;
            best = i;
        }
    }
    best
}

// ---------------------------------------------------------------------------
// RoPE (Rotary Position Embedding)
// ---------------------------------------------------------------------------

/// Таблицы RoPE: предвычисленные cos/sin на каждую позицию и пару
/// координат. Никаких тяжёлых тригонометрических вызовов в рантайме —
/// только табличные lookups (быстрее CORDIC, требование Part F).
///
/// Поддерживает частичный (partial/half) rotary: `rot_dim ≤ head_dim` —
/// поворачиваются только первые `rot_dim` измерений головы, хвост
/// проходит напрямую (семантика ChatGLM2/3: `rot_dim = kv_channels/2`).
pub struct RopeTable {
    head_dim: usize,
    /// Сколько первых измерений головы вращается (≤ head_dim, чётное).
    rot_dim: usize,
    max_pos: usize,
    cos: Vec<f32>,
    sin: Vec<f32>,
}

impl RopeTable {
    /// Полный rotary: частоты `inv_freq[i] = 10000^(−2i/d)`, угол = pos · inv_freq[i].
    pub fn new(head_dim: usize, max_pos: usize) -> Self {
        Self::new_partial(head_dim, head_dim, max_pos)
    }

    /// Частичный (half) rotary — семантика ChatGLM2/3:
    /// поворачиваются только первые `rot_dim` измерений из `head_dim`,
    /// частоты считаются по `rot_dim` (как будто rotary-пространство
    /// у́же головы): `inv_freq[i] = 10000^(−2i/rot_dim)`.
    ///
    /// В reference `modeling_chatglm.py`: `rotary_dim = kv_channels`,
    /// `RotaryEmbedding(rotary_dim // 2)` → применяемый rot_dim =
    /// `kv_channels/2`, а `x[..., rot_dim:]` проходит без поворота.
    pub fn new_partial(head_dim: usize, rot_dim: usize, max_pos: usize) -> Self {
        debug_assert!(head_dim % 2 == 0, "RoPE: head_dim должен быть чётным");
        debug_assert!(rot_dim % 2 == 0, "RoPE: rot_dim должен быть чётным");
        debug_assert!(
            rot_dim <= head_dim,
            "RoPE: rot_dim {rot_dim} > head_dim {head_dim}"
        );
        let pairs = rot_dim / 2;
        let mut cos = vec![0f32; max_pos * pairs];
        let mut sin = vec![0f32; max_pos * pairs];
        for pos in 0..max_pos {
            for i in 0..pairs {
                let freq = (10000f64).powf(-(2.0 * i as f64) / rot_dim as f64);
                let angle = pos as f64 * freq;
                cos[pos * pairs + i] = angle.cos() as f32;
                sin[pos * pairs + i] = angle.sin() as f32;
            }
        }
        Self {
            head_dim,
            rot_dim,
            max_pos,
            cos,
            sin,
        }
    }

    pub fn head_dim(&self) -> usize {
        self.head_dim
    }

    /// Вращаемая часть головы (первые rot_dim измерений).
    pub fn rot_dim(&self) -> usize {
        self.rot_dim
    }

    pub fn max_pos(&self) -> usize {
        self.max_pos
    }

    /// Поворот головы на +pos in-place: пары (2i, 2i+1) вращаются как
    /// комплексные числа `x + iy → (x+iy)·e^{iθ}`.
    pub fn rotate(&self, x: &mut [f32], pos: usize) {
        self.rotate_signed(x, pos, 1.0)
    }

    /// Обратный поворот (−pos): conjugate `e^{−iθ}`. Инвариант
    /// roundtrip: rotate(rotate(x, p), p, −1) == x.
    pub fn rotate_inv(&self, x: &mut [f32], pos: usize) {
        self.rotate_signed(x, pos, -1.0)
    }

    fn rotate_signed(&self, x: &mut [f32], pos: usize, sign: f32) {
        debug_assert_eq!(x.len(), self.head_dim, "RoPE: длина не равна head_dim");
        let pairs = self.rot_dim / 2;
        for i in 0..pairs {
            let c = self.cos[pos * pairs + i];
            let s = sign * self.sin[pos * pairs + i];
            let a = x[2 * i];
            let b = x[2 * i + 1];
            x[2 * i] = a * c - b * s;
            x[2 * i + 1] = a * s + b * c;
        }
        // Хвост [rot_dim..head_dim] — pass-through (ChatGLM half-rotary).
    }
}

// ---------------------------------------------------------------------------
// Квантование (для .pqw-билдера и конвертера)
// ---------------------------------------------------------------------------

/// Симметричное int8-квантование по строкам: `(коды, масштабы)`.
pub fn quant_i8_per_row(w: &[f32], rows: usize, cols: usize) -> (Vec<i8>, Vec<f32>) {
    debug_assert_eq!(w.len(), rows * cols);
    let mut q = vec![0i8; rows * cols];
    let mut scales = vec![1f32; rows];
    for r in 0..rows {
        let row = &w[r * cols..(r + 1) * cols];
        let m = row.iter().fold(0f32, |a, v| a.max(v.abs()));
        let sc = if m > 0.0 { m / 127.0 } else { 1.0 };
        scales[r] = sc;
        for (i, &v) in row.iter().enumerate() {
            q[r * cols + i] = (v / sc).round().clamp(-127.0, 127.0) as i8;
        }
    }
    (q, scales)
}

/// Симметричное int4-квантование по строкам: `(упакованные байты, масштабы)`.
///
/// Код ∈ [-7, 7], nibble = код + 8 ∈ [1, 15]; чётный элемент — младший
/// nibble, нечётный — старший.
pub fn quant_i4_per_row(w: &[f32], rows: usize, cols: usize) -> (Vec<u8>, Vec<f32>) {
    debug_assert_eq!(w.len(), rows * cols);
    let packed_cols = (cols + 1) / 2;
    let mut q = vec![0u8; rows * packed_cols];
    let mut scales = vec![1f32; rows];
    for r in 0..rows {
        let row = &w[r * cols..(r + 1) * cols];
        let m = row.iter().fold(0f32, |a, v| a.max(v.abs()));
        let sc = if m > 0.0 { m / 7.0 } else { 1.0 };
        scales[r] = sc;
        for (i, &v) in row.iter().enumerate() {
            let code = (v / sc).round().clamp(-7.0, 7.0) as i32 + 8;
            let byte = &mut q[r * packed_cols + i / 2];
            if i % 2 == 0 {
                *byte = (*byte & 0xF0) | (code as u8 & 0x0F);
            } else {
                *byte = (*byte & 0x0F) | ((code as u8) << 4);
            }
        }
    }
    (q, scales)
}

/// Троичное квантование по строкам (Trit5): `(упакованные байты, масштабы)`.
///
/// Код ∈ {-1, 0, +1}, упаковывается по 5 тритов в байт через `Trit5Codec`.
pub fn quant_trit5_per_row(w: &[f32], rows: usize, cols: usize) -> (Vec<u8>, Vec<f32>) {
    debug_assert_eq!(w.len(), rows * cols);
    let packed_cols = (cols + 4) / 5;
    let mut packed = vec![0u8; rows * packed_cols];
    let mut scales = vec![1f32; rows];
    for r in 0..rows {
        let row = &w[r * cols..(r + 1) * cols];
        let m = row.iter().fold(0f32, |a, v| a.max(v.abs()));
        let sc = if m > 0.0 { m } else { 1.0 };
        scales[r] = sc;
        let mut trits_buf = [0i8; 5];
        let mut buf_idx = 0;
        let mut byte_idx = 0;
        for &v in row {
            let normalized = v / sc;
            let trit = if normalized > 0.33 {
                1i8
            } else if normalized < -0.33 {
                -1i8
            } else {
                0i8
            };
            trits_buf[buf_idx] = trit;
            buf_idx += 1;
            if buf_idx == 5 {
                packed[r * packed_cols + byte_idx] = Trit5Codec::pack_5(&trits_buf).unwrap_or(0);
                trits_buf = [0i8; 5];
                buf_idx = 0;
                byte_idx += 1;
            }
        }
        if buf_idx > 0 {
            packed[r * packed_cols + byte_idx] = Trit5Codec::pack_5(&trits_buf).unwrap_or(0);
        }
    }
    (packed, scales)
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rel_close(a: f32, b: f32, eps: f32) -> bool {
        (a - b).abs() <= eps * b.abs().max(1.0)
    }

    #[test]
    fn dot_f32_matches_scalar() {
        let a: Vec<f32> = (0..257u32).map(|i| (i % 13) as f32 * 0.25 - 1.5).collect();
        let b: Vec<f32> = (0..257u32).map(|i| (i % 7) as f32 * 0.5 - 1.0).collect();
        let scalar = dot_f32_scalar(&a, &b);
        let dispatched = dot_f32(&a, &b);
        assert!(
            rel_close(dispatched, scalar, 1e-5),
            "dispatched={dispatched} scalar={scalar}"
        );
    }

    #[test]
    fn dot_i8_matches_scalar() {
        let q: Vec<i8> = (0..301i32).map(|i| (i % 51 - 25) as i8).collect();
        let x: Vec<f32> = (0..301u32).map(|i| (i % 11) as f32 * 0.3 - 1.2).collect();
        let scalar = dot_i8_f32_scalar(&q, &x);
        let dispatched = dot_i8_f32(&q, &x);
        assert!(
            rel_close(dispatched, scalar, 1e-5),
            "dispatched={dispatched} scalar={scalar}"
        );
    }

    #[test]
    fn dot_i4_roundtrip_and_value() {
        // Квантование → распаковка: ошибка ≤ scale/2 на элемент.
        let w: Vec<f32> = (0..64u32).map(|i| ((i * 37 % 19) as f32) / 19.0 - 0.5).collect();
        let (packed, scales) = quant_i4_per_row(&w, 1, 64);
        assert_eq!(packed.len(), 32);
        // Восстановим строку через dot с базисными векторами e_i.
        for i in 0..64 {
            let mut e = vec![0f32; 64];
            e[i] = 1.0;
            let restored = scales[0] * dot_i4_f32(&packed, &e, 64);
            assert!(
                (restored - w[i]).abs() <= scales[0] / 2.0 + 1e-6,
                "i={i}: {restored} vs {}",
                w[i]
            );
        }
        // Пустой хвост упаковки (нечётная длина).
        let (p2, _) = quant_i4_per_row(&[0.5, -0.5, 0.25], 1, 3);
        assert_eq!(p2.len(), 2);
    }

    #[test]
    fn quant_i8_roundtrip_error() {
        let w: Vec<f32> = (0..1000u32).map(|i| ((i * 73 % 41) as f32 / 41.0) - 0.5).collect();
        let (q, s) = quant_i8_per_row(&w, 10, 100);
        for r in 0..10 {
            for i in 0..100 {
                let restored = s[r] * q[r * 100 + i] as f32;
                assert!(
                    (restored - w[r * 100 + i]).abs() <= s[r] / 2.0 + 1e-6,
                    "r={r} i={i}"
                );
            }
        }
    }

    #[test]
    fn layer_norm_zero_mean_unit_var() {
        let gamma = vec![1.0f32; 16];
        let beta = vec![0.0f32; 16];
        let mut x: Vec<f32> = (0..16u32).map(|i| (i as f32) * 3.0 - 20.0).collect();
        layer_norm(&mut x, &gamma, &beta, 1e-5);
        let mean = x.iter().sum::<f32>() / 16.0;
        let var = x.iter().map(|v| (v - mean) * (v - mean)).sum::<f32>() / 16.0;
        assert!(mean.abs() < 1e-4, "mean={mean}");
        assert!((var - 1.0).abs() < 1e-3, "var={var}");
    }

    #[test]
    fn rms_norm_matches_reference() {
        let x: Vec<f32> = (0..32u32).map(|i| (i as f32) * 0.1 - 1.5).collect();
        let gamma: Vec<f32> = (0..32u32).map(|i| 1.0 + (i % 3) as f32 * 0.1).collect();
        let mut out = vec![0f32; 32];
        rms_norm(&x, &gamma, 1e-6, &mut out);
        let ms = x.iter().map(|v| v * v).sum::<f32>() / 32.0;
        let inv = 1.0 / (ms + 1e-6).sqrt();
        for i in 0..32 {
            let expect = x[i] * inv * gamma[i];
            assert!((out[i] - expect).abs() < 1e-5, "i={i}");
        }
    }

    #[test]
    fn gelu_known_values() {
        assert!(gelu(0.0).abs() < 1e-6);
        assert!((gelu(1.0) - 0.841_344_7).abs() < 1e-4, "gelu(1)={}", gelu(1.0));
        assert!((gelu(-1.0) + 0.158_655_3).abs() < 1e-4);
        // GELU ≈ ReLU сверху, мягкий хвост снизу.
        assert!(gelu(5.0) > 4.99);
        assert!(gelu(-5.0) > -1e-5 && gelu(-5.0) < 0.0);
    }

    #[test]
    fn softmax_properties() {
        let mut x = vec![1.0f32, 2.0, 3.0, -1.0, 0.5];
        softmax_inplace(&mut x);
        let s = x.iter().sum::<f32>();
        assert!((s - 1.0).abs() < 1e-5);
        assert!(x[2] > x[1] && x[1] > x[0] && x[0] > x[4] && x[4] > x[3]);
        // Сдвиго-инвариантность.
        let mut y = vec![101.0f32, 102.0, 103.0, 99.0, 100.5];
        softmax_inplace(&mut y);
        for i in 0..5 {
            assert!((x[i] - y[i]).abs() < 1e-5);
        }
    }

    #[test]
    fn argmax_tie_breaks_to_lowest() {
        assert_eq!(argmax(&[1.0, 3.0, 3.0, 2.0]), 1);
        assert_eq!(argmax(&[5.0, 5.0]), 0);
    }

    #[test]
    fn rope_identity_and_roundtrip() {
        let rope = RopeTable::new(16, 64);
        let x: Vec<f32> = (0..16u32).map(|i| (i as f32) * 0.25 - 2.0).collect();
        // Позиция 0 — тождество (cos=1, sin=0).
        let mut y = x.clone();
        rope.rotate(&mut y, 0);
        assert_eq!(y, x);
        // Прямой + обратный поворот = тождество (комплексное сопряжение).
        for pos in [1usize, 7, 31, 63] {
            let mut z = x.clone();
            rope.rotate(&mut z, pos);
            rope.rotate_inv(&mut z, pos);
            for i in 0..16 {
                assert!((z[i] - x[i]).abs() < 1e-5, "pos={pos} i={i}: {} vs {}", z[i], x[i]);
            }
        }
    }

    #[test]
    fn rope_preserves_norm() {
        // Вращение — унитарная операция: норма вектора не меняется.
        let rope = RopeTable::new(8, 32);
        let x: Vec<f32> = vec![0.3, -1.2, 0.7, 2.0, -0.5, 0.1, 1.4, -0.9];
        let norm = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        let mut y = x.clone();
        rope.rotate(&mut y, 17);
        let norm2 = y.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - norm2).abs() < 1e-5);
    }

    #[test]
    fn rope_half_rotary_chatglm_semantics() {
        // Семантика ChatGLM3: rot_dim = 64 из head_dim = 128.
        // 1) хвост [64..128] — pass-through (не меняется);
        // 2) первые 64 dims: interleaved-пары (x[2i], x[2i+1]) вращаются
        //    комплексным умножением на e^{i·pos·θ_i}, θ_i = 10000^(-2i/64);
        // 3) roundtrip rotate+rotate_inv = тождество;
        // 4) new_partial(d, d, m) == new(d, m) — полная обратная совместимость.
        let rope = RopeTable::new_partial(128, 64, 48);
        assert_eq!(rope.head_dim(), 128);
        assert_eq!(rope.rot_dim(), 64);

        let x: Vec<f32> = (0..128u32).map(|i| ((i as f32) * 0.137 - 8.7).sin()).collect();
        let pos = 17usize;
        let mut y = x.clone();
        rope.rotate(&mut y, pos);

        // 1) Хвост не тронут — бит-в-бит.
        for i in 64..128 {
            assert_eq!(y[i].to_bits(), x[i].to_bits(), "pass-through нарушен: i={i}");
        }
        // 2) Формула reference по парам.
        for i in 0..32usize {
            let theta = (10000f64).powf(-(2.0 * i as f64) / 64.0) * pos as f64;
            let (c, s) = (theta.cos() as f32, theta.sin() as f32);
            let (a, b) = (x[2 * i], x[2 * i + 1]);
            let expect0 = a * c - b * s;
            let expect1 = a * s + b * c;
            assert!(
                (y[2 * i] - expect0).abs() < 1e-5,
                "пара {i}: {} vs {expect0}",
                y[2 * i]
            );
            assert!(
                (y[2 * i + 1] - expect1).abs() < 1e-5,
                "пара {i}: {} vs {expect1}",
                y[2 * i + 1]
            );
        }
        // 3) Roundtrip.
        let mut z = y.clone();
        rope.rotate_inv(&mut z, pos);
        for i in 0..128 {
            assert!((z[i] - x[i]).abs() < 1e-5, "roundtrip: i={i}");
        }
        // 4) Полный поворот через new_partial == new (частоты и геометрия).
        let full_a = RopeTable::new(16, 24);
        let full_b = RopeTable::new_partial(16, 16, 24);
        let v: Vec<f32> = (0..16u32).map(|i| (i as f32) * 0.11 - 0.8).collect();
        let (mut a, mut b) = (v.clone(), v.clone());
        full_a.rotate(&mut a, 13);
        full_b.rotate(&mut b, 13);
        for i in 0..16 {
            assert_eq!(a[i].to_bits(), b[i].to_bits(), "new != new_partial(d,d)");
        }
    }

    #[test]
    fn rope_relative_property() {
        // Ключевое свойство RoPE: ⟨q_rot(p), k_rot(m)⟩ зависит только от p−m.
        let rope = RopeTable::new(8, 128);
        let q = vec![0.5f32, -0.3, 1.0, 0.7, -0.2, 0.9, 0.1, -0.6];
        let k = vec![0.4f32, 0.2, -0.8, 0.5, 0.3, -1.0, 0.6, 0.2];
        let mut qp = q.clone();
        rope.rotate(&mut qp, 10);
        let mut km = k.clone();
        rope.rotate(&mut km, 25);
        let a = dot_f32(&qp, &km);
        let mut qp2 = q.clone();
        rope.rotate(&mut qp2, 50);
        let mut km2 = k.clone();
        rope.rotate(&mut km2, 65);
        let b = dot_f32(&qp2, &km2);
        assert!((a - b).abs() < 1e-4, "RoPE относительность нарушена: {a} vs {b}");
    }

    #[test]
    fn l2_normalize_unit() {
        let mut x = vec![3.0f32, 4.0];
        l2_normalize(&mut x);
        let n = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((n - 1.0).abs() < 1e-6);
        let mut z = vec![0.0f32, 0.0];
        l2_normalize(&mut z); // не паникует на нуле
        assert_eq!(z, vec![0.0, 0.0]);
    }

    #[test]
    fn silu_known_values() {
        assert!(silu(0.0).abs() < 1e-7);
        assert!((silu(1.0) - 0.731_058_6).abs() < 1e-5);
        assert!((silu(-1.0) + 0.268_941_4).abs() < 1e-5);
        assert!(silu(10.0) > 9.999);
    }

    #[test]
    fn trit5_bijection_all_243_states() {
        for b in 0..243u8 {
            let trits = Trit5Codec::unpack_5(b);
            let packed = Trit5Codec::pack_5(&trits).expect("Ошибка упаковки Trit5");
            assert_eq!(
                packed, b,
                "Сбой биекции на байте {}: trits = {:?}",
                b, trits
            );
        }
    }

    #[test]
    fn trit5_out_of_bounds() {
        let invalid_trits = [1, 0, 2, -1, 0]; // 2 — невалидный трит (допустимы только -1, 0, 1)
        assert!(Trit5Codec::pack_5(&invalid_trits).is_none());
    }

    #[test]
    fn trit5_no_mul_dot_product_parity() {
        let t1: [i8; 5] = [1, -1, 0, 1, -1];
        let t2: [i8; 5] = [-1, -1, 1, 0, 1];

        let b1 = Trit5Codec::pack_5(&t1).unwrap();
        let b2 = Trit5Codec::pack_5(&t2).unwrap();

        let packed_weights = vec![b1, b2];
        let x = vec![0.5f32, 1.2, 3.4, -2.0, 0.8, 1.0, -1.5, 2.0, 4.0, -0.5];

        // Ручной расчет:
        // t1: +0.5 - 1.2 + 0.0 - 2.0 - 0.8 = -3.5
        // t2: -1.0 + 1.5 + 2.0 + 0.0 - 0.5 = +2.0
        // Сумма: -3.5 + 2.0 = -1.5
        let expected = -1.5f32;

        let scalar_result = dot_trit5_f32_scalar(&packed_weights, &x, 10);
        assert!(
            (scalar_result - expected).abs() < 1e-6,
            "Scalar: {} != {}",
            scalar_result,
            expected
        );

        let final_result = dot_trit5_f32(&packed_weights, &x, 10);
        assert!(
            (final_result - expected).abs() < 1e-6,
            "SIMD: {} != {}",
            final_result,
            expected
        );
    }
}
