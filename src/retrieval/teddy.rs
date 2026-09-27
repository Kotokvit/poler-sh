//! Teddy — SIMD-решёто мультитокен-литерального поиска (задача 2.5,
//! Foundation / v2.0). Заменяет автомат Ахо-Корасик на горячих путях
//! «встречается ли какой-либо из N литералов в сыром потоке»:
//! предфильтр streaming-прохода 1 и сканер маркеров ε-плотности.
//!
//! Класс алгоритма — «Teddy» (Hyperscan → ripgrep): SIMD-решёто по
//! редким байтам + дешёвая верификация. Реализация clean-room
//! (принцип «100% переписать»): решёто членства байта во множестве
//! построено на двух `pshufb`-таблицах (старший/младший ниббл байта),
//! таблицы и бакеты не заимствуются из ripgrep.
//!
//! # Алгоритм
//!
//! 1. **Якоря**: каждому паттерну назначается якорный байт — самый
//!    редкий байт паттерна по априорной таблице частот ru/en/code
//!    ([`byte_rarity`]; при равенстве — ближе к концу). Якорь фиксирует
//!    смещение `k` от последнего байта: кандидатная позиция `a` ⟹ конец
//!    матча в `a + k + 1`. Адаптивный выбор обходит вырождение на
//!    кириллице: якорем становится редкий trail-байт (например «ц»),
//!    а не lead-байт D0/D1, который в ru-тексте — каждый второй байт.
//! 2. **Решёто** `S` — множество якорных байтов: SIMD-скан окна
//!    (32B AVX2 / 16B SSSE3 / скаляр) даёт маску позиций-кандидатов.
//!    Членство — схема «строка×столбец»: `rows[hi]` — 16-битная строка
//!    бит для старшего ниббла, бит `lo` — младшего; обе половины
//!    достаются двумя `pshufb`.
//! 3. **Верификация** кандидата `a`: паттерны с якорем `h[a]` (таблица
//!    `by_anchor`, внутри — по возрастанию старта, при равном старте —
//!    длиннее вперёд); memcmp от `start = a + k + 1 − len(p)`.
//!
//! **Полнота** (нет ложных пропусков): совпадение паттерна `p` на
//! `[s, s+len)` ⟹ его якорный байт стоит на позиции `end − 1 − k` ∈ S
//! ⟹ позиция гарантированно даст кандидата. Ложные срабатывания
//! кандидатов отсекаются memcmp — детерминированный ценой O(хиты).
//!
//! # Семантика
//!
//! [`Teddy::find`] / [`Teddy::find_iter`] — точная семантика
//! LeftmostLongest (как `aho_corasick::MatchKind::LeftmostLongest`):
//! самый левый старт, при равном старте — самый длинный паттерн,
//! совпадения не перекрываются. Кандидат `a` не фиксирует матч
//! немедленно: будущий кандидат может дать более левый (или тот же
//! старт, но более длинный) матч — удерживается `pending`-лучший,
//! пока правило останова `a + 1 ≥ pending.start + maxlen` не
//! гарантирует, что улучшений больше не будет. Проверяется
//! дифференциальными тестами против crates.io `aho-corasick` на
//! случайных множествах (включая префиксные пары).
//!
//! # Ограничения
//!
//! * ≤ [`MAX_PATTERNS`] паттернов (дальше верификация вырождается —
//!   вызывающий код падает на Aho-Corasick);
//! * пустые паттерны запрещены;
//! * CI-фолд — только ASCII: кириллица регистрочувствительна,
//!   вызывающий код понижает регистр обеих сторон
//!   (см. `streaming::literal_present`);
//! * дубликаты паттернов схлопываются в первое вхождение.
//!
//! Ноль новых зависимостей: только `core::arch` из std.

use std::sync::OnceLock;

/// Потолок числа паттернов (якорная группировка по 256 байтам).
pub const MAX_PATTERNS: usize = 256;

/// Совпадение Teddy: индекс паттерна (для дубликатов — первого
/// вхождения) и полуинтервал `[start, end)` по байтам стога.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeddyMatch {
    pub pattern: usize,
    pub start: usize,
    pub end: usize,
}

/// Ошибки построения решёта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeddyError {
    /// Пустой паттерн (len 0): нет байтов для решёта.
    EmptyPattern,
    /// Больше [`MAX_PATTERNS`] паттернов.
    TooMany(usize),
}

impl std::fmt::Display for TeddyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeddyError::EmptyPattern => write!(f, "пустой паттерн запрещён"),
            TeddyError::TooMany(n) => {
                write!(f, "паттернов {n} > максимума {MAX_PATTERNS}")
            }
        }
    }
}

impl std::error::Error for TeddyError {}

/// ASCII-фолд байта: 'A'..='Z' → 'a'..='z', остальное без изменений.
/// Только ASCII — кириллица (двухбайтовый UTF-8 с сменой lead-байта)
/// не фолдится: это semантика `aho-corasick::ascii_case_insensitive`.
#[inline]
fn ascii_fold(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// Априорная частота байта в естественном тексте (ru/en/code):
/// меньше — реже — лучше для якоря. Таблица грубая, но ловит главное
/// вырождение: lead-байты кириллицы (D0-D3) — самые частые байты
/// ru-текста, а редкие trail-байты (ц/ф/ю/ь) — хороший якорь.
fn byte_rarity(b: u8) -> u8 {
    match b {
        0xD0..=0xD3 => 100,
        0x20 | 0x0A | 0x0D => 95,
        b'e' | b'a' | b'o' | b'i' | b'n' | b't' | b's' | b'r' | b'h' | b'l' => 85,
        // trail-байты частых кириллических букв (о е а и н т с р в)
        0xB5 | 0xB0 | 0xB8 | 0xBD | 0x82 | 0x81 | 0x80 | 0xB2 => 75,
        b'A' | b'I' | b'O' | b'E' | b'N' | b'T' | b'S' | b'R' | b'H' | b'L' | b'D' | b'C'
        | b'U' | b'M' | b'P' => 60,
        // trail-байты среднечастотных (к л м д п у я ы з б г ч й х)
        0xBA | 0xBB | 0xBC | 0xB4 | 0xBF | 0x83 | 0x8F | 0x8B | 0xB7 | 0xB1 | 0xB3 | 0x87
        | 0xB9 | 0x85 => 45,
        _ => 15,
    }
}

/// Быстрый фолд ASCII + современной кириллицы (диапазоны D0/D1):
/// побайтовая трансформация без Unicode-таблиц, ~1 ГБ/с. Для этого
/// подмножества результат байт-в-байт равен `str::to_lowercase`.
/// Историческая кириллица (U+0460+), украинско-белорусские дополнения
/// (U+0490+) и прочие письменности → `None`: вызывающий код падает на
/// полный Unicode-fold (прежний путь, семантика не сужается).
///
/// Карта (2-байтовые пары UTF-8):
/// * `D0 80-8F` (Ѐ-Џ) → `D1 90-9F` (ѐ-џ): lead+1, trail+0x10;
/// * `D0 90-9F` (А-П) → `D0 B0-BF` (а-п): trail+0x20;
/// * `D0 A0-AF` (Р-Я) → `D1 80-8F` (р-я): lead+1, trail−0x20;
/// * `D0 B0-BF`, `D1 80-9F` — уже нижний регистр, проход;
/// * ASCII — [`ascii_fold`].
pub fn fold_ascii_cyrillic(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b.is_ascii() {
            out.push(ascii_fold(b));
            i += 1;
        } else if b == 0xD0 && i + 1 < raw.len() {
            let t = raw[i + 1];
            match t {
                0x80..=0x8F => out.extend_from_slice(&[0xD1, t + 0x10]),
                0x90..=0x9F => out.extend_from_slice(&[0xD0, t + 0x20]),
                0xA0..=0xAF => out.extend_from_slice(&[0xD1, t - 0x20]),
                0xB0..=0xBF => out.extend_from_slice(&[0xD0, t]),
                _ => return None,
            }
            i += 2;
        } else if b == 0xD1 && i + 1 < raw.len() {
            let t = raw[i + 1];
            match t {
                0x80..=0x9F => out.extend_from_slice(&[0xD1, t]),
                _ => return None,
            }
            i += 2;
        } else {
            // Прочие письменности / историческая кириллица / обрыв пары.
            return None;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// SIMD-бэкенды (x86_64): AVX2 → SSSE3 → скаляр
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::x86_64::*;

    /// Таблицы решёта для SSE-окон (16B): строки `rows` в двух
    /// половинах — младший/старший байт 16-битной строки бит.
    pub(super) struct SseTables {
        rowlo: __m128i,
        rowhi: __m128i,
    }

    /// Таблицы решёта для AVX2-окон (32B): те же 16 строк,
    /// продублированные в обе 128-битные полосы.
    pub(super) struct Avx2Tables {
        rowlo: __m256i,
        rowhi: __m256i,
    }

    /// `1 << (0..8)` — бит в младшем байте строки.
    const P2LO: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 0, 0, 0, 0, 0, 0, 0, 0];
    /// `1 << (8..16)` — бит в старшем байте строки.
    const P2HI: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128];

    pub(super) unsafe fn sse_tables(rows: &[u16; 16]) -> SseTables {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        for (i, r) in rows.iter().enumerate() {
            lo[i] = *r as u8;
            hi[i] = (*r >> 8) as u8;
        }
        SseTables {
            rowlo: _mm_loadu_si128(lo.as_ptr() as *const __m128i),
            rowhi: _mm_loadu_si128(hi.as_ptr() as *const __m128i),
        }
    }

    pub(super) unsafe fn avx2_tables(rows: &[u16; 16]) -> Avx2Tables {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        for (i, r) in rows.iter().enumerate() {
            lo[i] = *r as u8;
            hi[i] = (*r >> 8) as u8;
        }
        let l = _mm_loadu_si128(lo.as_ptr() as *const __m128i);
        let h = _mm_loadu_si128(hi.as_ptr() as *const __m128i);
        Avx2Tables {
            rowlo: _mm256_broadcastsi128_si256(l),
            rowhi: _mm256_broadcastsi128_si256(h),
        }
    }

    /// ASCII-фолд 16 байтов: `t = x|0x20`, `d = t − 'a'`;
    /// буква ⟺ `0 ≤ d ≤ 25` (знаковое) — тогда `x |= 0x20`.
    /// Небуквенные байты не меняются (насыщение исключено схемой
    /// И-маски: фолдится только подтверждённая буква).
    #[target_feature(enable = "ssse3")]
    unsafe fn fold_sse(x: __m128i) -> __m128i {
        let t = _mm_or_si128(x, _mm_set1_epi8(0x20));
        let d = _mm_sub_epi8(t, _mm_set1_epi8(b'a' as i8));
        let ge0 = _mm_cmpgt_epi8(d, _mm_set1_epi8(-1));
        let lt26 = _mm_cmplt_epi8(d, _mm_set1_epi8(26));
        let is_letter = _mm_and_si128(ge0, lt26);
        _mm_or_si128(x, _mm_and_si128(is_letter, _mm_set1_epi8(0x20)))
    }

    /// Маска 16 бит: бит k взведён ⟺ байт `w[k]` (после фолда, если
    /// `ci`) НЕ входит в решёто. Вызывающий код инвертирует.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn sse_bits(t: &SseTables, w: &[u8], ci: bool) -> u16 {
        debug_assert_eq!(w.len(), 16);
        let mut x = _mm_loadu_si128(w.as_ptr() as *const __m128i);
        if ci {
            x = fold_sse(x);
        }
        // Старший ниббл: srli_epi16 на 4 + маска 0x0F (классический
        // трюк: перенос между байтами 16-битного lane остаётся в
        // старших битах и срезается маской).
        let hi = _mm_and_si128(_mm_srli_epi16(x, 4), _mm_set1_epi8(0x0F));
        let lo = _mm_and_si128(x, _mm_set1_epi8(0x0F));
        let r_lo = _mm_shuffle_epi8(t.rowlo, hi);
        let r_hi = _mm_shuffle_epi8(t.rowhi, hi);
        let p_lo = _mm_shuffle_epi8(_mm_loadu_si128(P2LO.as_ptr() as *const __m128i), lo);
        let p_hi = _mm_shuffle_epi8(_mm_loadu_si128(P2HI.as_ptr() as *const __m128i), lo);
        let m = _mm_or_si128(_mm_and_si128(r_lo, p_lo), _mm_and_si128(r_hi, p_hi));
        _mm_movemask_epi8(_mm_cmpeq_epi8(m, _mm_setzero_si128())) as u16
    }

    #[target_feature(enable = "avx2")]
    unsafe fn fold_avx2(x: __m256i) -> __m256i {
        let t = _mm256_or_si256(x, _mm256_set1_epi8(0x20));
        let d = _mm256_sub_epi8(t, _mm256_set1_epi8(b'a' as i8));
        let ge0 = _mm256_cmpgt_epi8(d, _mm256_set1_epi8(-1));
        let lt26 = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), d);
        let is_letter = _mm256_and_si256(ge0, lt26);
        _mm256_or_si256(x, _mm256_and_si256(is_letter, _mm256_set1_epi8(0x20)))
    }

    /// 32-битная маска 32-байтового окна (семантика как у `sse_bits`).
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn avx2_bits(t: &Avx2Tables, w: &[u8], ci: bool) -> u32 {
        debug_assert_eq!(w.len(), 32);
        let mut x = _mm256_loadu_si256(w.as_ptr() as *const __m256i);
        if ci {
            x = fold_avx2(x);
        }
        let hi = _mm256_and_si256(_mm256_srli_epi16(x, 4), _mm256_set1_epi8(0x0F));
        let lo = _mm256_and_si256(x, _mm256_set1_epi8(0x0F));
        let r_lo = _mm256_shuffle_epi8(t.rowlo, hi);
        let r_hi = _mm256_shuffle_epi8(t.rowhi, hi);
        let p_lo = _mm256_shuffle_epi8(
            _mm256_broadcastsi128_si256(_mm_loadu_si128(P2LO.as_ptr() as *const __m128i)),
            lo,
        );
        let p_hi = _mm256_shuffle_epi8(
            _mm256_broadcastsi128_si256(_mm_loadu_si128(P2HI.as_ptr() as *const __m128i)),
            lo,
        );
        let m = _mm256_or_si256(_mm256_and_si256(r_lo, p_lo), _mm256_and_si256(r_hi, p_hi));
        _mm256_movemask_epi8(_mm256_cmpeq_epi8(m, _mm256_setzero_si256())) as u32
    }
}

/// AVX2 доступен на этой машине (детект при первом обращении).
#[cfg(target_arch = "x86_64")]
fn have_avx2() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| is_x86_feature_detected!("avx2"))
}

/// SSSE3 доступен (pshufb — минимум для SIMD-пути).
#[cfg(target_arch = "x86_64")]
fn have_ssse3() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| is_x86_feature_detected!("ssse3"))
}

// ---------------------------------------------------------------------------
// Teddy
// ---------------------------------------------------------------------------

/// SIMD-решёто мультитокен-литерального поиска.
///
/// Построение — O(число паттернов × длина); скан — O(N/ширина окна)
/// SIMD-инструкций + O(кандидаты) верификаций. Потокобезопасен после
/// построения (иммутабелен).
pub struct Teddy {
    /// Паттерны (фолднутые в CI-режиме), дубликаты схлопнуты.
    patterns: Vec<Box<[u8]>>,
    /// ASCII-CI режим.
    ascii_ci: bool,
    /// Решёто: `rows[байт >> 4]` бит `(байт & 0xF)` ⟺ байт ∈ S.
    rows: [u16; 16],
    /// Якорная группировка: фолднутый якорный байт → паттерны,
    /// упорядоченные по возрастанию старта (при равном — длиннее).
    by_anchor: Box<[Vec<u16>; 256]>,
    /// Смещение якоря от последнего байта паттерна (k ≤ len−1).
    anchor_off: Vec<u8>,
    /// Длина самого длинного паттерна (правило останова pending).
    maxlen: usize,
    /// SSE-таблицы (если SSSE3 доступен; AVX2 предпочтительнее).
    #[cfg(target_arch = "x86_64")]
    sse: Option<x86::SseTables>,
    /// AVX2-таблицы (если доступен).
    #[cfg(target_arch = "x86_64")]
    avx2: Option<x86::Avx2Tables>,
}

impl Teddy {
    /// Точное (регистрочувствительное) решёто по байтовым паттернам.
    pub fn build(patterns: &[&[u8]]) -> Result<Teddy, TeddyError> {
        Self::build_inner(patterns, false)
    }

    /// Решёто с ASCII-регистронезависимостью: 'A'=='a' при поиске,
    /// не-ASCII байты сравниваются точно (кириллица — регистрочувствительна).
    pub fn build_ascii_ci(patterns: &[&[u8]]) -> Result<Teddy, TeddyError> {
        Self::build_inner(patterns, true)
    }

    fn build_inner(patterns: &[&[u8]], ascii_ci: bool) -> Result<Teddy, TeddyError> {
        if patterns.len() > MAX_PATTERNS {
            return Err(TeddyError::TooMany(patterns.len()));
        }
        if patterns.iter().any(|p| p.is_empty()) {
            return Err(TeddyError::EmptyPattern);
        }
        // Фолд + дедупликация (первое вхождение побеждает).
        let mut folded: Vec<Box<[u8]>> = Vec::with_capacity(patterns.len());
        'outer: for p in patterns.iter().copied() {
            let f: Box<[u8]> = if ascii_ci {
                p.iter().map(|&b| ascii_fold(b)).collect()
            } else {
                p.into()
            };
            for seen in &folded {
                if *seen == f {
                    continue 'outer;
                }
            }
            folded.push(f);
        }

        let mut rows = [0u16; 16];
        let mut by_anchor: Box<[Vec<u16>; 256]> = Box::new(std::array::from_fn(|_| Vec::new()));
        let mut anchor_off: Vec<u8> = Vec::with_capacity(folded.len());
        for (pid, p) in folded.iter().enumerate() {
            // Адаптивный якорь: самый редкий байт паттерна по априорной
            // частоте; при равенстве — ближе к концу (меньше k).
            let mut best_k = 0usize;
            let mut best_rarity = u8::MAX;
            for k in 0..p.len() {
                let r = byte_rarity(p[p.len() - 1 - k]);
                if r < best_rarity {
                    best_rarity = r;
                    best_k = k;
                }
            }
            let anchor = p[p.len() - 1 - best_k];
            anchor_off.push(best_k as u8);
            by_anchor[anchor as usize].push(pid as u16);
            rows[anchor as usize >> 4] |= 1 << (anchor & 0x0F);
        }
        // Внутри якоря — по возрастанию старта (len − k по убыванию),
        // при равном старте — длиннее вперёд: первый совпавший в списке
        // и есть LL-лучший для этого кандидата.
        for v in by_anchor.iter_mut() {
            v.sort_by_key(|&pid| {
                let p = &folded[pid as usize];
                std::cmp::Reverse((p.len() - anchor_off[pid as usize] as usize, p.len()))
            });
        }
        let maxlen = folded.iter().map(|p| p.len()).max().unwrap_or(0);

        #[cfg(target_arch = "x86_64")]
        let avx2 = if have_avx2() {
            Some(unsafe { x86::avx2_tables(&rows) })
        } else {
            None
        };
        #[cfg(target_arch = "x86_64")]
        let sse = if avx2.is_none() && have_ssse3() {
            Some(unsafe { x86::sse_tables(&rows) })
        } else {
            None
        };

        Ok(Teddy {
            patterns: folded,
            ascii_ci,
            rows,
            by_anchor,
            anchor_off,
            maxlen,
            #[cfg(target_arch = "x86_64")]
            sse,
            #[cfg(target_arch = "x86_64")]
            avx2,
        })
    }

    /// ASCII-CI режим?
    pub fn is_ascii_ci(&self) -> bool {
        self.ascii_ci
    }

    /// Паттерны (фолднутые) — для диагностики и тестов.
    pub fn patterns(&self) -> &[Box<[u8]>] {
        &self.patterns
    }

    /// Первое совпадение в потоке (или None).
    pub fn find(&self, haystack: &[u8]) -> Option<TeddyMatch> {
        self.find_from(haystack, 0, 0)
    }

    /// Встречается ли хоть один паттерн (ранний выход).
    pub fn is_present(&self, haystack: &[u8]) -> bool {
        self.find(haystack).is_some()
    }

    /// Все неперекрывающиеся совпадения (семантика — доку модуля).
    pub fn find_iter<'a>(&'a self, haystack: &'a [u8]) -> TeddyIter<'a> {
        TeddyIter {
            teddy: self,
            haystack,
            from: 0,
            last_end: 0,
        }
    }

    /// Фолд байта под режим решёта.
    #[inline]
    fn fold_byte(&self, b: u8) -> u8 {
        if self.ascii_ci {
            ascii_fold(b)
        } else {
            b
        }
    }

    /// Поиск LeftmostLongest-матча с кандидатами ≥ `from`; матч не
    /// может начинаться раньше `last_end` (неперекрывающаяся итерация).
    ///
    /// Матч кандидата `a` не возвращается немедленно: будущий кандидат
    /// может дать более левый старт (длинный паттерн, чей
    /// предпоследний байт правее). Лучший матч удерживается в
    /// `pending`; [`Self::candidate_step`] даёт правило останова.
    fn find_from(&self, h: &[u8], from: usize, last_end: usize) -> Option<TeddyMatch> {
        let n = h.len();
        if n == 0 || from >= n {
            return None;
        }
        // Неперекрывающийся следующий матч имеет кандидата a ≥ last_end:
        // len-2 → a = start ≥ last_end; len-1 → a = start; len ≥ 3 →
        // a = start + len − 2 > last_end. Поэтому from = last_end корректен.
        let mut pending: Option<TeddyMatch> = None;
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(t) = &self.avx2 {
                const CH: usize = 32;
                let full = n / CH;
                let first = from / CH;
                for ci in first..full {
                    let i = ci * CH;
                    let mut bits = !unsafe { x86::avx2_bits(t, &h[i..i + CH], self.ascii_ci) };
                    if ci == first {
                        bits &= !((1u32 << (from - i)) - 1);
                    }
                    while bits != 0 {
                        let lane = bits.trailing_zeros() as usize;
                        bits &= bits - 1;
                        if self.candidate_step(h, i + lane, last_end, &mut pending) {
                            return pending;
                        }
                    }
                }
                self.scan_scalar(h, full * CH, n, from, last_end, &mut pending);
                return pending;
            }
            if let Some(t) = &self.sse {
                const CH: usize = 16;
                let full = n / CH;
                let first = from / CH;
                for ci in first..full {
                    let i = ci * CH;
                    let mut bits =
                        !unsafe { x86::sse_bits(t, &h[i..i + CH], self.ascii_ci) } as u32;
                    if ci == first {
                        bits &= !((1u32 << (from - i)) - 1);
                    }
                    while bits != 0 {
                        let lane = bits.trailing_zeros() as usize;
                        bits &= bits - 1;
                        if self.candidate_step(h, i + lane, last_end, &mut pending) {
                            return pending;
                        }
                    }
                }
                self.scan_scalar(h, full * CH, n, from, last_end, &mut pending);
                return pending;
            }
        }
        self.scan_scalar(h, 0, n, from, last_end, &mut pending);
        pending
    }

    /// Обработка одного кандидата `a`. Обновляет `pending` (более левый
    /// старт; при равном старте — более длинный). Возвращает true, когда
    /// скан можно завершить: после кандидата `a` старты будущих
    /// кандидатов ≥ `a + 3 − maxlen > pending.start − 1`, а удлиннение
    /// того же старта невозможно (кандидаты длиннее уже пройдены).
    #[inline]
    fn candidate_step(
        &self,
        h: &[u8],
        a: usize,
        last_end: usize,
        pending: &mut Option<TeddyMatch>,
    ) -> bool {
        if let Some(m) = self.verify_at(h, a, last_end) {
            let better = match pending {
                None => true,
                Some(p) => m.start < p.start || (m.start == p.start && m.end > p.end),
            };
            if better {
                *pending = Some(m);
            }
        }
        match pending {
            Some(p) => a + 1 >= p.start + self.maxlen,
            None => false,
        }
    }

    /// Скалярный скан диапазона `[lo, hi)` (хвост окна / без SIMD).
    fn scan_scalar(
        &self,
        h: &[u8],
        lo: usize,
        hi: usize,
        from: usize,
        last_end: usize,
        pending: &mut Option<TeddyMatch>,
    ) {
        for a in lo.max(from)..hi {
            let b = self.fold_byte(h[a]);
            if self.rows[b as usize >> 4] & (1 << (b & 0x0F)) == 0 {
                continue;
            }
            if self.candidate_step(h, a, last_end, pending) {
                return;
            }
        }
    }

    /// Верификация кандидата `a` (байт на `a` — чей-то якорь): паттерны
    /// той же якорной группы, по возрастанию старта; `last_end` —
    /// запрет перекрытия. Первый совпавший — LL-лучший кандидата.
    fn verify_at(&self, h: &[u8], a: usize, last_end: usize) -> Option<TeddyMatch> {
        let anchor = self.fold_byte(h[a]);
        for &pid in &self.by_anchor[anchor as usize] {
            let p = &self.patterns[pid as usize];
            let end = a + self.anchor_off[pid as usize] as usize + 1;
            if end > h.len() {
                continue;
            }
            match end.checked_sub(p.len()) {
                Some(start) if start >= last_end => {
                    if self.eq_at(h, start, p) {
                        return Some(TeddyMatch {
                            pattern: pid as usize,
                            start,
                            end,
                        });
                    }
                }
                _ => continue,
            }
        }
        None
    }

    /// Побайтовое сравнение сегмента `h[start..start+p.len()]` с паттерном
    /// (в CI — с фолдом байтов потока).
    #[inline]
    fn eq_at(&self, h: &[u8], start: usize, p: &[u8]) -> bool {
        let seg = &h[start..start + p.len()];
        if !self.ascii_ci {
            return seg == p;
        }
        seg.iter()
            .zip(p.iter())
            .all(|(&x, &y)| ascii_fold(x) == y)
    }
}

/// Итератор неперекрывающихся совпадений (ленивый: каждое `next`
/// продолжает скан от конца предыдущего матча).
pub struct TeddyIter<'a> {
    teddy: &'a Teddy,
    haystack: &'a [u8],
    from: usize,
    last_end: usize,
}

impl Iterator for TeddyIter<'_> {
    type Item = TeddyMatch;

    fn next(&mut self) -> Option<TeddyMatch> {
        let m = self.teddy.find_from(self.haystack, self.from, self.last_end)?;
        self.from = m.end;
        self.last_end = m.end;
        Some(m)
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64 — детерминированный ГПСЧ (как в bench-модуле).
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed | 1)
        }
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    /// Классический эталон LeftmostLongest: на каждой стартовой позиции
    /// (по возрастанию) — самый длинной совпавший паттерн; итерация
    /// неперекрывающаяся. Реализация намеренно не использует ни бакеты,
    /// ни SIMD, ни решёто — прямой перебор всех позиций × паттернов.
    /// В CI-режиме фолдит обе стороны (как production-путь).
    fn naive_ll(h: &[u8], pats: &[&[u8]], ci: bool) -> Vec<(usize, usize, usize)> {
        let eq = |a: &[u8], b: &[u8]| -> bool {
            if ci {
                a.iter().zip(b).all(|(&x, &y)| ascii_fold(x) == ascii_fold(y))
            } else {
                a == b
            }
        };
        let mut out = Vec::new();
        let mut pos = 0usize;
        'outer: while pos < h.len() {
            for start in pos..h.len() {
                let mut best: Option<(usize, usize)> = None;
                for (i, p) in pats.iter().enumerate() {
                    if start + p.len() <= h.len() && eq(&h[start..start + p.len()], p) {
                        let end = start + p.len();
                        let better = match best {
                            None => true,
                            Some((_, e)) => end > e,
                        };
                        if better {
                            best = Some((i, end));
                        }
                    }
                }
                if let Some((i, end)) = best {
                    out.push((i, start, end));
                    pos = end;
                    continue 'outer;
                }
            }
            break;
        }
        out
    }

    fn naive_present(h: &[u8], pats: &[&[u8]], ci: bool) -> bool {
        pats.iter().any(|p| {
            h.windows(p.len()).any(|w| {
                if ci {
                    w.iter().zip(p.iter()).all(|(&x, &y)| ascii_fold(x) == ascii_fold(y))
                } else {
                    w == *p
                }
            })
        })
    }

    /// Полное множество совпадений Teddy в наивном формате.
    fn teddy_list(t: &Teddy, h: &[u8]) -> Vec<(usize, usize, usize)> {
        t.find_iter(h).map(|m| (m.pattern, m.start, m.end)).collect()
    }

    #[test]
    fn build_rejects_empty_and_too_many() {
        assert!(matches!(Teddy::build(&[b""]), Err(TeddyError::EmptyPattern)));
        let many: Vec<Vec<u8>> = (0..MAX_PATTERNS + 1)
            .map(|i| format!("p{i}").into_bytes())
            .collect();
        let refs: Vec<&[u8]> = many.iter().map(|v| v.as_slice()).collect();
        assert!(matches!(
            Teddy::build(&refs),
            Err(TeddyError::TooMany(n)) if n == MAX_PATTERNS + 1
        ));
        // Пустое множество паттернов допустимо: решёто пусто.
        assert!(!Teddy::build(&[]).unwrap().is_present(b"anything"));
    }

    #[test]
    fn find_basics_cs() {
        let pats: Vec<&[u8]> = vec![&b"nyx"[..], "кот".as_bytes(), &b"z"[..]];
        let t = Teddy::build(&pats).unwrap();
        let h = "::::nyx::::кот::::::".as_bytes();
        assert!(t.is_present(h));
        let m = t.find(h).unwrap();
        assert_eq!((&h[m.start..m.end], m.pattern), (b"nyx".as_slice(), 0));
        // Паттерн в самом конце потока.
        assert!(t.is_present("..кот".as_bytes()));
        // Поток короче паттерна.
        assert!(!t.is_present(b"ny"));
        assert!(!t.is_present(b""));
        // len-1 паттерн.
        assert!(t.is_present(b"zz!"));
        let m = t.find(b"az").unwrap();
        assert_eq!((m.pattern, m.start, m.end), (2, 1, 2));
    }

    #[test]
    fn find_basics_ci_ascii() {
        let t = Teddy::build_ascii_ci(&[b"process", b"Runtime"]).unwrap();
        assert!(t.is_present(b"call PROCESS now"));
        assert!(t.is_present(b"runTIME error"));
        assert!(t.is_present(b"runtime"));
        assert!(!t.is_present(b"run time"));
        let m = t.find(b"..RUNTIME..").unwrap();
        assert_eq!((m.pattern, m.start, m.end), (1, 2, 9));
    }

    #[test]
    fn ci_leaves_non_ascii_exact() {
        // Документированное ограничение: CI фолдит только ASCII.
        let t = Teddy::build_ascii_ci(&["Алексей".as_bytes()]).unwrap();
        assert!(t.is_present("Алексей here".as_bytes()));
        assert!(!t.is_present("АЛЕКСЕЙ here".as_bytes()));
    }

    #[test]
    fn boundary_all_window_sizes() {
        // Вставка паттерна в каждую позицию потоков всех граничных
        // длин вокруг SIMD-окон (16/32) и хвоста.
        for n in 0..=70usize {
            for at in 0..n {
                let mut h = vec![b'.'; n];
                h[at] = b'x';
                if at + 1 < n {
                    h[at + 1] = b'y';
                }
                let h: Vec<u8> = h;
                let t = Teddy::build(&[b"xy", b"x"]).unwrap();
                assert!(t.is_present(&h), "n={n} at={at}");
            }
        }
        // Двухбайтовый паттерн через границу чанка (байт на 15/31).
        for cut in [15usize, 16, 31, 32, 33] {
            let mut h = vec![b'.'; cut];
            h.push(b'x');
            h.push(b'y');
            h.push(b'.');
            let t = Teddy::build(&[b"xy"]).unwrap();
            let m = t.find(&h).unwrap();
            assert_eq!((m.start, m.end), (cut, cut + 2), "cut={cut}");
        }
    }

    #[test]
    fn prefix_pair_leftmost_longest() {
        // Префиксная пара {cd, cde}: LeftmostLongest — «cde» [2,5),
        // совпадает с AC и наивным эталоном.
        let pats: Vec<&[u8]> = vec![b"cd", b"cde"];
        let t = Teddy::build(&pats).unwrap();
        assert_eq!(teddy_list(&t, b"abcde"), vec![(1, 2, 5)]);
        assert_eq!(naive_ll(b"abcde", &pats, false), vec![(1, 2, 5)]);
        // Более левый, но более короткий матч не должен ослеплять
        // длинный левый: {abcdef, cd} на «abcdef».
        let pats2: Vec<&[u8]> = vec![b"abcdef", b"cd"];
        let t2 = Teddy::build(&pats2).unwrap();
        assert_eq!(teddy_list(&t2, b"zabcdef"), vec![(0, 1, 7)]);
        assert_eq!(naive_ll(b"zabcdef", &pats2, false), vec![(0, 1, 7)]);
    }

    #[test]
    fn duplicates_collapse_to_first() {
        let t = Teddy::build(&[b"ab", b"ab", b"cd"]).unwrap();
        assert_eq!(t.patterns().len(), 2);
        assert_eq!(teddy_list(&t, b"abab--cd"), vec![(0, 0, 2), (0, 2, 4), (1, 6, 8)]);
    }

    /// Генерация случайного множества паттернов: без ТОЧНЫХ дубликатов
    /// и (в CI) без фолд-дубликатов — индексы Teddy после дедупликации
    /// обязаны совпадать с AC; префиксные пары разрешены — LL-семантика
    /// должна держать и их.
    fn gen_patterns(rng: &mut Rng, count: usize, alpha: &[u8], ci: bool) -> Vec<Vec<u8>> {
        let foldv = |p: &[u8]| -> Vec<u8> {
            if ci {
                p.iter().map(|&b| ascii_fold(b)).collect()
            } else {
                p.to_vec()
            }
        };
        let mut pats: Vec<Vec<u8>> = Vec::new();
        let mut guard = 0;
        while pats.len() < count && guard < 2000 {
            guard += 1;
            let len = 1 + rng.below(6) as usize;
            let p: Vec<u8> = (0..len).map(|_| alpha[rng.below(alpha.len() as u64) as usize]).collect();
            let fp = foldv(&p);
            if !pats.iter().any(|q| foldv(q) == fp) {
                pats.push(p);
            }
        }
        pats
    }

    fn gen_haystack(rng: &mut Rng, alpha: &[u8], pats: &[Vec<u8>]) -> Vec<u8> {
        let n = rng.below(180) as usize;
        let mut h: Vec<u8> = (0..n).map(|_| alpha[rng.below(alpha.len() as u64) as usize]).collect();
        // Подсадка совпадений: плотный поток хитов для итерации.
        for _ in 0..rng.below(8) {
            if h.is_empty() {
                break;
            }
            let p = &pats[rng.below(pats.len() as u64) as usize];
            let at = rng.below(h.len() as u64).saturating_sub(p.len() as u64 / 2) as usize;
            if at + p.len() <= h.len() {
                h[at..at + p.len()].copy_from_slice(p);
            }
        }
        h
    }

    fn diff_once(seed: u64, ci: bool) -> (usize, usize) {
        let mut rng = Rng::new(seed);
        let alpha: &[u8] = if ci { b"abAB" } else { b"abcde\x00\xff" };
        let count = 1 + rng.below(16) as usize;
        let pv = gen_patterns(&mut rng, count, alpha, ci);
        let pats: Vec<&[u8]> = pv.iter().map(|v| v.as_slice()).collect();
        let t = if ci {
            Teddy::build_ascii_ci(&pats).unwrap()
        } else {
            Teddy::build(&pats).unwrap()
        };

        // Эталон 1: классический LeftmostLongest перебором.
        // Эталон 2: aho-corasick LeftmostLongest (при CI — ascii_ci).
        let mut acb = aho_corasick::AhoCorasick::builder();
        acb.match_kind(aho_corasick::MatchKind::LeftmostLongest);
        if ci {
            acb.ascii_case_insensitive(true);
        }
        let ac = acb.build(pats.clone()).unwrap();

        let mut checks = 0usize;
        let mut matches = 0usize;
        for k in 0..4 {
            let h = gen_haystack(&mut rng, alpha, &pv);
            let mine = teddy_list(&t, &h);
            let naive = naive_ll(&h, &pats, ci);
            assert_eq!(mine, naive, "seed={seed} k={k} ci={ci} (наивный LL)");
            let ac_list: Vec<(usize, usize, usize)> = ac
                .find_iter(&h)
                .map(|m| (m.pattern().as_usize(), m.start(), m.end()))
                .collect();
            assert_eq!(
                mine, ac_list,
                "seed={seed} k={k} ci={ci} (AC-LeftmostLongest)"
            );
            let pres = naive_present(&h, &pats, ci);
            assert_eq!(t.is_present(&h), pres, "seed={seed} k={k} ci={ci} (is_present)");
            checks += 1;
            matches += mine.len();
        }
        (checks, matches)
    }

    #[test]
    fn differential_vs_ac_and_naive_cs() {
        let mut total = 0usize;
        let mut matches = 0usize;
        for seed in 1..=300u64 {
            let (c, m) = diff_once(seed, false);
            total += c;
            matches += m;
        }
        // Плотность проверок не должна быть вырожденной.
        assert!(matches > 1000, "слишком мало совпадений: {matches}");
        assert_eq!(total, 1200);
    }

    #[test]
    fn differential_vs_ac_and_naive_ci() {
        let mut matches = 0usize;
        for seed in 500..=700u64 {
            let (_, m) = diff_once(seed, true);
            matches += m;
        }
        assert!(matches > 1000, "слишком мало совпадений: {matches}");
    }

    #[test]
    fn utf8_cyrillic_exact() {
        // Сценарий epsilon/streaming: паттерны и поток — UTF-8 байты.
        let pats: Vec<&[u8]> = vec!["критично".as_bytes(), "unsafe".as_bytes(), "риск".as_bytes()];
        let t = Teddy::build(&pats).unwrap();
        let hay = "обычный текст, критично! и unsafe вызов, риск".as_bytes();
        let list = teddy_list(&t, hay);
        let at = hay
            .windows("критично".len())
            .position(|w| w == "критично".as_bytes())
            .unwrap();
        assert!(list.contains(&(0, at, at + "критично".len())));
        assert_eq!(list.len(), 3);
        // Нулевой поток.
        assert!(!t.is_present(b""));
    }

    #[test]
    fn long_patterns_span_windows() {
        // Паттерн длиннее SIMD-окна: верификация через memcmp.
        let p: Vec<u8> = (b'a'..=b'z').collect();
        let t = Teddy::build(&[p.as_slice()]).unwrap();
        let mut h = vec![b'.'; 100];
        let at = 37usize;
        h[at..at + p.len()].copy_from_slice(&p);
        let m = t.find(&h).unwrap();
        assert_eq!((m.start, m.end), (at, at + p.len()));
        // Наивный эталон.
        assert_eq!(naive_ll(&h, &[p.as_slice()], false), vec![(0, at, at + p.len())]);
    }

    #[test]
    fn iterator_is_lazy_and_terminates() {
        let t = Teddy::build(&[b"ab"]).unwrap();
        let h = b"ababab";
        let v: Vec<_> = t.find_iter(h).collect();
        assert_eq!(v.len(), 3);
        // Пустой поток.
        assert_eq!(t.find_iter(b"").count(), 0);
        // Кандидаты без матчей: 'z' ∈ S, но «zx» не совпадает.
        let t2 = Teddy::build(&[b"zx"]).unwrap();
        assert_eq!(t2.find_iter(&vec![b'z'; 100]).count(), 0);
    }

    #[test]
    fn fold_ascii_cyrillic_equals_to_lowercase() {
        // Байт-в-байт равенство с полным Unicode-fold на поддерживаемом
        // подмножестве (ASCII + современная кириллица D0/D1).
        let texts = [
            "",
            "plain ascii text 123",
            "Plain ASCII With MiXeD case",
            "Здесь Нокс действует, СОБОЛЬ молчит",
            "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
            "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
            "Ёё Ёлки ЁЖИК",
            "РаЗнЫй РеГиСтР + English MIX 42",
            "Ѐ Ђ Ѓ Є Ѕ І Ї Ј Ќ Ћ Џ",  // D0 80-8F → D1 90-9F
            "ѐ ђ ѓ є ѕ і ї ј ќ ћ џ",
            "смесь: Rust движок и КИРИЛЛИЦА mixed 50/50",
        ];
        for t in texts {
            let fast = fold_ascii_cyrillic(t.as_bytes()).expect("подмножество");
            assert_eq!(
                fast,
                t.to_lowercase().as_bytes(),
                "несовпадение фолда: {t}"
            );
        }
    }

    #[test]
    fn fold_ascii_cyrillic_falls_back_on_other_scripts() {
        // Историческая кириллица (U+0460+, D1 A0+), украинские
        // дополнения (U+0490+, D2) и прочие письменности → None.
        assert!(fold_ascii_cyrillic("Ѡ ѡ Ѣ".as_bytes()).is_none());
        assert!(fold_ascii_cyrillic("Ґ ґ Ғ".as_bytes()).is_none());
        assert!(fold_ascii_cyrillic("Greek ΛΟΓΟΣ".as_bytes()).is_none());
        assert!(fold_ascii_cyrillic("日本語".as_bytes()).is_none());
        // Обрыв двухбайтовой пары — тоже фолбэк.
        assert!(fold_ascii_cyrillic(&[0xD0]).is_none());
        // Чистый ASCII и кириллица — быстрый путь.
        assert!(fold_ascii_cyrillic(b"ok").is_some());
        assert!(fold_ascii_cyrillic("окей".as_bytes()).is_some());
    }

    #[test]
    fn fold_preserves_prefilter_semantics() {
        // Интеграция: буквальный регистронезависимый поиск по фолду
        // находит вхождения любого регистра (семантика прежнего пути).
        let pats: Vec<String> = ["нокс", "соболь"].iter().map(|s| s.to_string()).collect();
        let q = || pats.clone();
        let pre = || crate::streaming::literal_prefilter(&pats).unwrap();
        assert!(crate::streaming::literal_present(
            "Здесь Нокс действует",
            &q(),
            &Some(pre())
        ));
        assert!(crate::streaming::literal_present(
            "НОКС! Соболь и нокс",
            &q(),
            &Some(pre())
        ));
        assert!(!crate::streaming::literal_present(
            "здесь лисица",
            &q(),
            &Some(pre())
        ));
    }
}
