//! Нативный XLM-R-токенизатор (Unigram + Metaspace) — Part E, задача 12.5.
//!
//! Полный конвейер без внешних библиотек, ровно как `tokenizers` (HF) для
//! BGE-M3 (портировано по исходникам `models/unigram/model.rs` v0.23.2 и
//! сверенo прототипом на 61 тексте — 0 расхождений):
//!
//! ```text
//! raw split по спец-токенам (normalized=false)
//!   → нормализация: per-codepoint таблица (точная семантика
//!     Precompiled charsmap) + NFC (порядок + композиция, таблицы
//!     nfc_tables.rs) + коллапс пробелов (' {2,}' → ' ')
//!   → метаспейс: ' ' → '▁', префикс '▁' если не начинается с '▁'
//!   → Unigram-Viterbi (DP по байтам, старты на границах чаров,
//!     unk = min_score − 10 за один чар, вставляется если нет
//!     одно-чарового куска; fuse_unk — слияние подряд идущих unk)
//!   → обёртка [bos, …, eos]
//! ```
//!
//! Данные живут в RAW-секции `__tokenizer__` контейнера `.pqw` (бинарный
//! формат ниже) — модель самодостаточна, никаких sidecar-файлов.
//!
//! ## Формат секции `__tokenizer__` (v1 / v2)
//!
//! ```text
//! "TOKR" u16 version={1,2} u8 algo(0=unigram) u8 flags(bit0=add_prefix_space)
//! u32 unk_id bos_id eos_id pad_id mask_id (0xFFFFFFFF = нет)
//! u32 vocab_size;  ×N { u16 len, bytes, f32 score }
//! u32 specials_count; ×N { u16 len, bytes, u32 id }
//! [v2] u8 norm_profile: 0 = per-cp таблица (ниже), 1 = NFC + strip_right
//!                        (mdeberta: Replace(\s{2,}|[\n\r\t]→' ')+NFC+Strip —
//!                         для пословленного кодирования редуктируется к NFC)
//! [profile 0 / v1] u32 norm_count; ×N { u32 codepoint, u16 len, bytes }
//! ```
//!
//! v2/profile 1 нужен mdeberta-v3 (спина GLiNER): у него нет charsmap-
//! таблицы XLM-R — нормализация это только NFC (+ правый trim), а 
//! коллапса пробелов и lower-case нет вовсе.

use std::collections::HashMap;

use super::nfc_tables::{CCC, COMPOSITIONS};

const MAGIC: &[u8; 4] = b"TOKR";
const NO_ID: u32 = u32::MAX;

/// Разбор бинарной секции с курсором и честными ошибками.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<(), String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "токенизатор: обрезан ({}) на смещении {}",
                self.buf.len(),
                self.pos
            ));
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8, String> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, String> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, String> {
        self.need(4)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    fn f32(&mut self) -> Result<f32, String> {
        let raw = self.u32()?;
        Ok(f32::from_bits(raw))
    }
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        self.need(len)?;
        let s = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }
}

/// Unigram-токенизатор XLM-R-класса, собранный из секции `.pqw`.
pub struct UnigramTokenizer {
    /// id → байты куска (детокенизация/отладка).
    pieces: Vec<Box<[u8]>>,
    /// счёт куска (f32 из файла; аккумулируем в f64 — как эталон).
    scores: Vec<f64>,
    /// кусок → id (первое вхождение; дубликаты словаря игнорируются).
    map: HashMap<Box<[u8]>, u32>,
    /// codepoint → замена (нормализация; только profile 0).
    norm: HashMap<u32, Box<[u8]>>,
    /// Профиль нормализации: 0 = таблица+NFC+коллапс, 1 = NFC+strip_right, 2 = Identity (ChatGLM3).
    norm_profile: u8,
    /// Спец-токены для raw-split: (bytes, id), длинные первыми.
    specials: Vec<(Box<[u8]>, u32)>,
    unk_id: u32,
    bos_id: u32,
    eos_id: u32,
    mask_id: u32,
    unk_score: f64,
    add_prefix_space: bool,
    max_piece_len: usize,
    /// Таблица 256 байтовых токенов <0x00>..<0xFF> для byte-fallback (ChatGLM3).
    byte_tokens: [Option<u32>; 256],
    has_byte_fallback: bool,
}

impl UnigramTokenizer {
    /// Разбор секции `__tokenizer__` (RAW-байты).
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let mut c = Cursor::new(raw);
        if c.bytes(4)? != MAGIC {
            return Err("токенизатор: магия TOKR не найдена".into());
        }
        let version = c.u16()?;
        if version != 1 && version != 2 {
            return Err(format!("токенизатор: версия {version} не поддерживается"));
        }
        let algo = c.u8()?;
        if algo != 0 {
            return Err(format!("токенизатор: algo {algo} (unigram = 0) не поддерживается"));
        }
        let flags = c.u8()?;
        let unk_id = c.u32()?;
        let bos_id = c.u32()?;
        let eos_id = c.u32()?;
        let _pad_id = c.u32()?;
        let mask_id = c.u32()?;

        let n_vocab = c.u32()? as usize;
        let mut pieces = Vec::with_capacity(n_vocab);
        let mut scores = Vec::with_capacity(n_vocab);
        let mut map = HashMap::with_capacity(n_vocab);
        let mut byte_tokens = [None; 256];
        let mut has_byte_fallback = false;
        let mut min_score = f64::INFINITY;
        let mut max_piece_len = 0usize;
        for i in 0..n_vocab {
            let len = c.u16()? as usize;
            let piece = c.bytes(len)?;
            let score = c.f32()? as f64;
            let boxed: Box<[u8]> = piece.into();
            if map.insert(boxed.clone(), i as u32).is_none() {
                max_piece_len = max_piece_len.max(len);
            }
            if piece.len() == 6 && piece.starts_with(b"<0x") && piece.ends_with(b">") {
                if let Ok(hstr) = std::str::from_utf8(&piece[3..5]) {
                    if let Ok(bval) = u8::from_str_radix(hstr, 16) {
                        byte_tokens[bval as usize] = Some(i as u32);
                        has_byte_fallback = true;
                    }
                }
            }
            if score < min_score {
                min_score = score;
            }
            pieces.push(boxed);
            scores.push(score);
        }
        if min_score == f64::INFINITY {
            min_score = 0.0;
        }

        let n_specials = c.u32()? as usize;
        let mut specials = Vec::with_capacity(n_specials);
        for _ in 0..n_specials {
            let len = c.u16()? as usize;
            let piece = c.bytes(len)?;
            let id = c.u32()?;
            specials.push((piece.into(), id));
        }
        // длинные первыми (raw-скан матчит жадно слева)
        specials.sort_by(|a: &(Box<[u8]>, u32), b: &(Box<[u8]>, u32)| b.0.len().cmp(&a.0.len()));

        let norm_profile = if version >= 2 { c.u8()? } else { 0 };
        if norm_profile > 2 {
            return Err(format!("токенизатор: norm_profile {norm_profile} не поддерживается"));
        }

        let n_norm = if norm_profile == 0 { c.u32()? as usize } else { 0 };
        let mut norm = HashMap::with_capacity(n_norm);
        for _ in 0..n_norm {
            let cp = c.u32()?;
            let len = c.u16()? as usize;
            let bytes = c.bytes(len)?;
            norm.insert(cp, bytes.into());
        }

        if c.pos != raw.len() {
            return Err(format!(
                "токенизатор: {} лишних байт в конце секции",
                raw.len() - c.pos
            ));
        }

        Ok(Self {
            pieces,
            scores,
            map,
            norm,
            norm_profile,
            specials,
            unk_id,
            bos_id,
            eos_id,
            mask_id,
            unk_score: min_score - 10.0,
            add_prefix_space: flags & 1 != 0,
            max_piece_len: max_piece_len.min(64),
            byte_tokens,
            has_byte_fallback,
        })
    }

    /// Размер словаря.
    pub fn vocab_size(&self) -> usize {
        self.pieces.len()
    }

    /// Кусок по id (байты; для детокенизации и отладки).
    pub fn piece(&self, id: u32) -> Option<&[u8]> {
        self.pieces.get(id as usize).map(|b| b.as_ref())
    }

    /// Спец-ids (bos/eos/unk/mask; pad скрыт — не нужен энкодеру).
    pub fn special_ids(&self) -> (u32, u32, u32, u32) {
        (self.bos_id, self.eos_id, self.unk_id, self.mask_id)
    }

    /// Полное кодирование текста → ids (с bos/eos).
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut ids = Vec::with_capacity(text.len() / 4 + 4);
        ids.push(self.bos_id);
        for seg in self.split_specials(text) {
            match seg {
                Segment::Special(id) => ids.push(id),
                Segment::Text(t) => {
                    let norm = self.normalize(t);
                    if norm.is_empty() {
                        continue;
                    }
                    let ms = self.metaspace(&norm);
                    ids.extend(self.viterbi(ms.as_bytes()));
                }
            }
        }
        ids.push(self.eos_id);
        ids
    }

    /// Детокенизация: последовательность ids → исходный текст.
    /// Обрабатывает метаспейсы (\u{2581} → пробел) и байтовые fallback-токены (<0xXX> → сырой байт).
    pub fn detokenize(&self, ids: &[u32]) -> String {
        let mut raw_bytes = Vec::new();
        for &id in ids {
            if let Some(piece) = self.piece(id) {
                if piece.len() == 6 && piece.starts_with(b"<0x") && piece.ends_with(b">") {
                    if let Ok(hstr) = std::str::from_utf8(&piece[3..5]) {
                        if let Ok(bval) = u8::from_str_radix(hstr, 16) {
                            raw_bytes.push(bval);
                            continue;
                        }
                    }
                }
                raw_bytes.extend_from_slice(piece);
            }
        }
        let s = String::from_utf8_lossy(&raw_bytes);
        let s = s.replace('\u{2581}', " ");
        if self.add_prefix_space && s.starts_with(' ') {
            s[1..].to_string()
        } else {
            s
        }
    }

    /// Пословленное кодирование (семантика HF `is_split_into_words`):
    /// каждое слово — независимый сегмент, БЕЗ обёртки bos/eos.
    ///
    /// `first_piece[w]` — индекс в `ids` первого куска слова `w`
    /// (None — спец-токен без кусков или пустое слово). GLiNER берёт
    /// скрытое состояние именно первого субтокена (subtoken_pooling=first).
    pub fn encode_words(&self, words: &[&str]) -> EncodedWords {
        let mut ids = Vec::new();
        let mut first_piece = Vec::with_capacity(words.len());
        for &w in words {
            let before = ids.len();
            for seg in self.split_specials(w) {
                match seg {
                    Segment::Special(id) => ids.push(id),
                    Segment::Text(t) => {
                        let norm = self.normalize(t);
                        if norm.is_empty() {
                            continue;
                        }
                        let ms = self.metaspace(&norm);
                        ids.extend(self.viterbi(ms.as_bytes()));
                    }
                }
            }
            first_piece.push(if ids.len() > before { Some(before as u32) } else { None });
        }
        EncodedWords { ids, first_piece }
    }

    /// id куска по строке (спец-токены + словарь; unk если нет).
    pub fn id_of(&self, piece: &str) -> u32 {
        let b = piece.as_bytes();
        for (sp, id) in &self.specials {
            if sp.as_ref() == b {
                return *id;
            }
        }
        self.map.get(b).copied().unwrap_or(self.unk_id)
    }

    /// Кодирование одного обычного сегмента: норм → метаспейс → Viterbi.
    #[cfg(test)]
    fn encode_segment(&self, text: &str) -> Vec<u32> {
        let norm = self.normalize(text);
        if norm.is_empty() {
            return Vec::new();
        }
        let ms = self.metaspace(&norm);
        self.viterbi(ms.as_bytes())
    }

    /// Разбивает сырой текст на спец-токены и обычные сегменты.
    fn split_specials<'t>(&self, text: &'t str) -> Vec<Segment<'t>> {
        if self.specials.is_empty() {
            return vec![Segment::Text(text)];
        }
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut seg_start = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            let mut hit: Option<(u32, usize)> = None;
            for (sp, id) in &self.specials {
                if bytes[i..].starts_with(sp.as_ref()) {
                    hit = Some((*id, sp.len()));
                    break;
                }
            }
            if let Some((id, sp_len)) = hit {
                if i > seg_start {
                    out.push(Segment::Text(&text[seg_start..i]));
                }
                out.push(Segment::Special(id));
                i += sp_len;
                seg_start = i;
            } else {
                i += 1;
            }
        }
        if seg_start < bytes.len() {
            out.push(Segment::Text(&text[seg_start..]));
        }
        out
    }

    /// Нормализация.
    ///
    /// profile 0 (XLM-R): per-cp таблица → NFC → коллапс пробелов.
    /// profile 1 (mdeberta): NFC → правый trim.
    /// profile 2 (ChatGLM3/raw SPM): Identity (без изменений).
    fn normalize(&self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }
        if self.norm_profile == 2 {
            return s.to_string();
        }
        if self.norm_profile == 1 {
            let chars: Vec<char> = s.chars().collect();
            let ordered = canonical_order(&chars);
            let composed = compose(&ordered);
            let mut out = String::with_capacity(composed.len());
            for ch in composed {
                out.push(ch);
            }
            return out.trim_end().to_string();
        }
        // 1. per-codepoint таблица (полная NFKC-замена одиночных символов)
        let mut chars: Vec<char> = Vec::with_capacity(s.len());
        for ch in s.chars() {
            match self.norm.get(&(ch as u32)) {
                Some(rep) => match std::str::from_utf8(rep) {
                    Ok(st) => chars.extend(st.chars()),
                    Err(_) => chars.push(ch),
                },
                None => chars.push(ch),
            }
        }
        // 2. канонический порядок + композиция (NFC)
        let ordered = canonical_order(&chars);
        let composed = compose(&ordered);
        // 3. коллапс ' {2,}' → ' '
        let mut out = String::with_capacity(composed.len());
        for ch in composed {
            if ch == ' ' && out.ends_with(' ') {
                continue;
            }
            out.push(ch);
        }
        out
    }

    /// Метаспейс: ' ' → '▁' + префикс.
    fn metaspace(&self, s: &str) -> String {
        let mut t = s.replace(' ', "\u{2581}");
        if self.add_prefix_space && !t.is_empty() && !t.starts_with('\u{2581}') {
            t.insert(0, '\u{2581}');
        }
        t
    }

    /// Unigram-Viterbi: DP по байтам.
    fn viterbi(&self, bytes: &[u8]) -> Vec<u32> {
        let size = bytes.len();
        if size == 0 {
            return Vec::new();
        }
        let neg = f64::NEG_INFINITY;

        if self.has_byte_fallback {
            let mut dp_score = vec![neg; size + 1];
            let mut dp_start = vec![usize::MAX; size + 1];
            let mut dp_tok = vec![0u32; size + 1];
            dp_score[0] = 0.0;
            dp_start[0] = 0;

            let max_l = self.max_piece_len.min(64);
            for i in 0..size {
                if dp_start[i] == usize::MAX && i != 0 {
                    continue;
                }
                let base = dp_score[i];
                let limit = (size - i).min(max_l);
                for l in 1..=limit {
                    let sub = &bytes[i..i + l];
                    if let Some(&tid) = self.map.get(sub) {
                        let cand = base + self.scores[tid as usize];
                        if cand > dp_score[i + l] {
                            dp_score[i + l] = cand;
                            dp_start[i + l] = i;
                            dp_tok[i + l] = tid;
                        }
                    }
                }
                let b = bytes[i];
                if let Some(btid) = self.byte_tokens[b as usize] {
                    let cand = base + self.scores[btid as usize];
                    if cand > dp_score[i + 1] {
                        dp_score[i + 1] = cand;
                        dp_start[i + 1] = i;
                        dp_tok[i + 1] = btid;
                    }
                }
            }

            let mut ids = Vec::new();
            let mut curr = size;
            while curr > 0 {
                let prev = dp_start[curr];
                if prev == usize::MAX || prev == curr {
                    break;
                }
                ids.push(dp_tok[curr]);
                curr = prev;
            }
            ids.reverse();
            return ids;
        }

        let mut score = vec![neg; size + 1];
        let mut start = vec![usize::MAX; size + 1];
        let mut tid = vec![0u32; size + 1];
        score[0] = 0.0;
        start[0] = 0; // старт достижим сразу (ссылка на себя)

        let mut pos = 0usize;
        while pos < size {
            // длина символа UTF-8 от границы pos
            let lead = bytes[pos];
            let mblen = if lead < 0x80 {
                1
            } else if lead >> 5 == 0b110 {
                2
            } else if lead >> 4 == 0b1110 {
                3
            } else if lead >> 3 == 0b11110 {
                4
            } else {
                1 // мусорный байт: деградируем до 1 (без паники)
            };
            let mut has_single = false;
            if start[pos] != usize::MAX {
                let base = score[pos];
                let max_l = self.max_piece_len.min(size - pos);
                for l in 1..=max_l {
                    let piece = &bytes[pos..pos + l];
                    let Some(&id) = self.map.get(piece) else {
                        continue;
                    };
                    let j = pos + l;
                    let cand = base + self.scores[id as usize];
                    if start[j] == usize::MAX || cand > score[j] {
                        score[j] = cand;
                        start[j] = pos;
                        tid[j] = id;
                    }
                    if !has_single && l == mblen {
                        has_single = true;
                    }
                }
            }
            if !has_single {
                let j = pos + mblen;
                if start[pos] != usize::MAX {
                    let cand = score[pos] + self.unk_score;
                    if start[j] == usize::MAX || cand > score[j] {
                        score[j] = cand;
                        start[j] = pos;
                        tid[j] = self.unk_id;
                    }
                }
            }
            pos += mblen;
        }

        // бэктрек + fuse_unk (подряд идущие unk сливаются в один)
        let mut ids: Vec<u32> = Vec::new();
        let mut ends = size;
        let mut unk_run = 0u32;
        while ends > 0 {
            let st = start[ends];
            if st == usize::MAX || ends == st {
                break; // недостижимый хвост — не должно случаться
            }
            let id = tid[ends];
            if id == self.unk_id {
                unk_run += 1;
            } else {
                if unk_run > 0 {
                    ids.push(self.unk_id);
                    unk_run = 0;
                }
                ids.push(id);
            }
            ends = st;
        }
        if unk_run > 0 {
            ids.push(self.unk_id);
        }
        ids.reverse();
        ids
    }
}

/// Сегмент raw-split: обычный текст или спец-токен.
enum Segment<'t> {
    Text(&'t str),
    Special(u32),
}

/// Результат пословленного кодирования (`UnigramTokenizer::encode_words`).
pub struct EncodedWords {
    /// Все куски подряд (без обёртки bos/eos).
    pub ids: Vec<u32>,
    /// Индекс первого куска каждого слова в `ids` (None — спец-слово
    /// без кусков или пустое нормализованное слово).
    pub first_piece: Vec<Option<u32>>,
}

// ---------------------------------------------------------------------------
// NFC: канонический порядок + композиция (UAX#15, Hangul алгоритмически)
// ---------------------------------------------------------------------------

/// Канонический комбинирующий класс (0 — не комбинирующий).
fn ccc_of(ch: char) -> u8 {
    let cp = ch as u32;
    let mut lo = 0usize;
    let mut hi = CCC.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (mcp, mccc) = CCC[mid];
        if mcp == cp {
            return mccc;
        }
        if mcp < cp {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    0
}

/// Попарная каноническая композиция (таблица + Hangul).
fn compose_pair(a: char, b: char) -> Option<char> {
    let (a, b) = (a as u32, b as u32);
    // Hangul: L + V → LV
    if (0x1100..=0x1112).contains(&a) && (0x1161..=0x1175).contains(&b) {
        let lv = 0xAC00 + ((a - 0x1100) * 21 + (b - 0x1161)) * 28;
        return char::from_u32(lv);
    }
    // Hangul: LV + T → LVT
    if (0xAC00..=0xD7A3).contains(&a) && (a - 0xAC00) % 28 == 0 && (0x11A8..=0x11C2).contains(&b)
    {
        return char::from_u32(a + (b - 0x11A8) + 1);
    }
    let mut lo = 0usize;
    let mut hi = COMPOSITIONS.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (sa, sb, sc) = COMPOSITIONS[mid];
        if (sa, sb) == (a, b) {
            return char::from_u32(sc);
        }
        if (sa, sb) < (a, b) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    None
}

/// Стабильная сортировка комбинирующих последовательностей по ccc.
fn canonical_order(chars: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut i = 0usize;
    while i < chars.len() {
        if ccc_of(chars[i]) == 0 {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        // [i..j) — серия комбинирующих
        let mut j = i;
        while j < chars.len() && ccc_of(chars[j]) != 0 {
            j += 1;
        }
        let mut run: Vec<(usize, char, u8)> = (i..j).map(|k| (k, chars[k], ccc_of(chars[k]))).collect();
        run.sort_by_key(|&(k, _, c)| (c, k)); // стабильно: (ccc, индекс)
        out.extend(run.iter().map(|&(_, ch, _)| ch));
        i = j;
    }
    out
}

/// Каноническая композиция (после canonical_order).
fn compose(chars: &[char]) -> Vec<char> {
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut starter: Option<usize> = None;
    let mut last_ccc: u8 = 0;
    for &ch in chars {
        let cc = ccc_of(ch);
        if let Some(si) = starter {
            // блокировки нет ⟺ предыдущая комбинирующая «легче» или её нет
            if last_ccc < cc || last_ccc == 0 {
                if let Some(c) = compose_pair(out[si], ch) {
                    out[si] = c;
                    continue;
                }
            }
        }
        out.push(ch);
        if cc == 0 {
            starter = Some(out.len() - 1);
            last_ccc = 0;
        } else {
            last_ccc = cc;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Сборка секции (для тестов и билдера синтетики)
// ---------------------------------------------------------------------------

/// Собирает бинарную секцию `__tokenizer__` (unigram v1/v2).
pub struct TokenizerSectionBuilder {
    vocab: Vec<(Box<[u8]>, f32)>,
    specials: Vec<(Box<[u8]>, u32)>,
    norm: Vec<(u32, Box<[u8]>)>,
    ids: [u32; 5],
    add_prefix_space: bool,
    /// 0 = таблица+NFC+коллапс (XLM-R), 1 = NFC+strip_right (mdeberta).
    norm_profile: u8,
}

impl Default for TokenizerSectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenizerSectionBuilder {
    pub fn new() -> Self {
        Self {
            vocab: Vec::new(),
            specials: Vec::new(),
            norm: Vec::new(),
            ids: [3, 0, 2, 1, NO_ID], // unk bos eos pad mask
            add_prefix_space: true,
            norm_profile: 0,
        }
    }

    pub fn ids(mut self, unk: u32, bos: u32, eos: u32, pad: u32, mask: u32) -> Self {
        self.ids = [unk, bos, eos, pad, mask];
        self
    }

    pub fn add_prefix_space(mut self, yes: bool) -> Self {
        self.add_prefix_space = yes;
        self
    }

    pub fn piece(mut self, p: &str, score: f32) -> Self {
        self.vocab.push((p.as_bytes().into(), score));
        self
    }

    pub fn special(mut self, p: &str, id: u32) -> Self {
        self.specials.push((p.as_bytes().into(), id));
        self
    }

    pub fn norm_rule(mut self, cp: u32, rep: &str) -> Self {
        self.norm.push((cp, rep.as_bytes().into()));
        self
    }

    /// Профиль нормализации v2: 1 = NFC+strip_right (mdeberta), без таблицы.
    pub fn norm_profile(mut self, profile: u8) -> Self {
        self.norm_profile = profile;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let v2 = self.norm_profile > 0;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&if v2 { 2u16 } else { 1u16 }.to_le_bytes());
        out.push(0); // unigram
        out.push(u8::from(self.add_prefix_space));
        for id in self.ids {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out.extend_from_slice(&(self.vocab.len() as u32).to_le_bytes());
        for (p, s) in &self.vocab {
            out.extend_from_slice(&(p.len() as u16).to_le_bytes());
            out.extend_from_slice(p);
            out.extend_from_slice(&s.to_bits().to_le_bytes());
        }
        out.extend_from_slice(&(self.specials.len() as u32).to_le_bytes());
        for (p, id) in &self.specials {
            out.extend_from_slice(&(p.len() as u16).to_le_bytes());
            out.extend_from_slice(p);
            out.extend_from_slice(&id.to_le_bytes());
        }
        if v2 {
            out.push(self.norm_profile);
        }
        if self.norm_profile == 0 {
            out.extend_from_slice(&(self.norm.len() as u32).to_le_bytes());
            for (cp, rep) in &self.norm {
                out.extend_from_slice(&cp.to_le_bytes());
                out.extend_from_slice(&(rep.len() as u16).to_le_bytes());
                out.extend_from_slice(rep);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy() -> UnigramTokenizer {
        // словарь: unk=3, 'a', 'b', 'ab', '▁', '▁ab', 'x'
        let section = TokenizerSectionBuilder::new()
            .piece("<unk>", 0.0)
            .piece("<s>", 0.0)
            .piece("</s>", 0.0)
            .piece("a", -1.0)
            .piece("b", -2.0)
            .piece("ab", -0.5)
            .piece("\u{2581}", -0.3)
            .piece("\u{2581}ab", -0.4)
            .piece("x", -1.2)
            .special("<s>", 0)
            .special("</s>", 2)
            .special("<unk>", 3)
            .build();
        UnigramTokenizer::parse(&section).unwrap()
    }

    #[test]
    fn viterbi_prefers_best_pieces() {
        let t = toy();
        // "ab a" → метаспейс "▁ab▁a" → '▁ab'(-0.4) + '▁'(-0.3) + 'a'(-1.0)
        let ids = t.encode_segment("ab a");
        assert_eq!(ids, vec![t.id_of("\u{2581}ab"), t.id_of("\u{2581}"), t.id_of("a")]);
    }

    #[test]
    fn viterbi_unknown_fuses() {
        // словарь без 'q': "qq a" → '▁' + unk(сляпан из 'qq') + '▁a'...
        let t = toy();
        let ids = t.encode_segment("qq a");
        // ▁ q q ▁ a → '▁' + unk(2 шт сляпаны в 1) + '▁' + 'a'
        assert_eq!(ids, vec![t.id_of("\u{2581}"), 3, t.id_of("\u{2581}"), t.id_of("a")]);
    }

    #[test]
    fn special_raw_split_and_wrap() {
        let t = toy();
        // "x<s>ab" → [bos=0, '▁','x', <s>=0, '▁ab', eos=2]
        let ids = t.encode("x<s>ab");
        assert_eq!(
            ids,
            vec![0, t.id_of("\u{2581}"), t.id_of("x"), 0, t.id_of("\u{2581}ab"), 2]
        );
    }

    #[test]
    fn empty_text_is_bos_eos_only() {
        let t = toy();
        assert_eq!(t.encode(""), vec![0, 2]);
    }

    #[test]
    fn metaspace_prefix_and_replacement() {
        let t = toy();
        assert_eq!(t.metaspace("ab"), "\u{2581}ab");
        assert_eq!(t.metaspace(" ab"), "\u{2581}ab");
        assert_eq!(t.metaspace("a b"), "\u{2581}a\u{2581}b");
        assert_eq!(t.metaspace(""), "");
    }

    #[test]
    fn norm_table_applied_and_space_collapse() {
        let section = TokenizerSectionBuilder::new()
            .piece("<unk>", 0.0)
            .piece("a", -1.0)
            .piece("\u{2581}", -0.3)
            .norm_rule(0x42 /* 'B' */, "b")
            .norm_rule(0x09, " ")
            .build();
        let t = UnigramTokenizer::parse(&section).unwrap();
        assert_eq!(t.normalize("B\tB  a "), "b b a ");
        assert_eq!(t.normalize("a  b"), "a b");
    }

    #[test]
    fn nfc_composes_decomposed_accents() {
        // e + U+0301 → é (каноническая пара 0x65,0x301 → 0xE9)
        let composed = compose(&['e', '\u{0301}']);
        assert_eq!(composed, vec!['é']);
        // порядок: ccc(0x0328)=202 идёт после ccc(0x0301)=230 → меняем местами
        let ordered = canonical_order(&['a', '\u{0301}', '\u{0328}']);
        assert_eq!(ordered, vec!['a', '\u{0328}', '\u{0301}']);
        // Hangul L+V
        assert_eq!(compose(&['\u{1100}', '\u{1161}']), vec!['\u{AC00}']);
        // Hangul LV+T
        assert_eq!(
            compose(&['\u{AC00}', '\u{11A8}']),
            vec!['\u{AC01}']
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(UnigramTokenizer::parse(b"NOPE").is_err());
        let mut good = TokenizerSectionBuilder::new().piece("a", -1.0).build();
        good.push(0xFF); // лишний байт
        assert!(UnigramTokenizer::parse(&good).is_err());
    }

    #[test]
    fn nfc_tables_sorted_and_idempotent() {
        assert!(CCC.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(COMPOSITIONS.windows(2).all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1)));
        for s in ["é", "\u{1100}\u{1161}\u{11A8}", "a\u{0328}\u{0301}"] {
            let once: Vec<char> = {
                let o = canonical_order(&s.chars().collect::<Vec<_>>());
                compose(&o)
            };
            let twice: Vec<char> = {
                let o = canonical_order(&once);
                compose(&o)
            };
            assert_eq!(once, twice, "NFC обязан быть идемпотентным для {s:?}");
        }
    }

    #[test]
    fn byte_fallback_and_detokenize_roundtrip() {
        let mut b = TokenizerSectionBuilder::new()
            .ids(0, 1, 2, 3, 4)
            .piece("<unk>", 0.0) // 0
            .piece("<s>", 0.0)   // 1
            .piece("</s>", 0.0)  // 2
            .piece("<pad>", 0.0) // 3
            .piece("<mask>", 0.0); // 4

        // Add 256 byte tokens <0x00>..<0xFF>
        for i in 0..256 {
            b = b.piece(&format!("<0x{i:02X}>"), -10.0);
        }
        // Add vocabulary words
        b = b.piece("\u{2581}", -1.0)
            .piece("\u{2581}hello", -0.5)
            .piece("\u{2581}world", -0.5)
            .norm_profile(2);

        let sec = b.build();
        let tok = UnigramTokenizer::parse(&sec).expect("parse byte-fallback tokenizer");
        assert!(tok.has_byte_fallback);

        let input = "hello world!";
        let ids = tok.encode(input);
        // Exclude bos and eos
        let text_ids = &ids[1..ids.len() - 1];
        let decoded = tok.detokenize(text_ids);
        assert_eq!(decoded, input);
    }
}

