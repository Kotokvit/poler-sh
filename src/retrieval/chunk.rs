//! Слой B Native Retrieval: passage-уровень (RAG-чанки).
//!
//! Назначение — заменить агенту внешний RAG-конвейер нарезки: документ
//! режется на фрагменты с якорями (byte range, номера строк, breadcrumb
//! заголовков), агент получает КУСОК текста, а не URL. Эталон —
//! benbrandt/text-splitter + LangChain RecursiveCharacterTextSplitter
//! (см. `docs/native-retrieval-analysis.md`); ключевые идеи взяты
//! (иерархия семантических уровней, вместимость в токенах, слияние
//! соседей, перекрытие), реализация — своя, на токенизаторе POLER.
//!
//! Иерархия уровней (выше = целостнее):
//! * Markdown: секция заголовка → абзац → предложение → слово;
//! * Plain:    абзац → предложение → слово;
//! * Code:     блок между пустыми строками → строка.
//!
//! Инварианты чанка:
//! * `text == original[byte_start..byte_end]` — точный срез исходника
//!   (агент может верифицировать совпадение по диапазону);
//! * чанк никогда не пересекает границу секции заголовка (breadcrumb
//!   однороден внутри чанка);
//!* внутри code-fence markdown-документа разрезы только по строкам;
//! * `tokens <= target` для всех чанков, кроме атомарных
//!   (одно слово/строка больше лимита — не режем);
//! * перекрытие берёт начало следующего чанка назад по ГРАНИЦАМ
//!   юнитов (предложений/строк) — слово никогда не режется.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::parser::ast_code::{detect_lang, CodeLang};
use crate::web::extract::web_tokenize;

/// Целевой размер чанка по умолчанию (токены POLER) — классика RAG.
pub const DEFAULT_TARGET_TOKENS: usize = 384;
/// Перекрытие соседних чанков по умолчанию.
pub const DEFAULT_OVERLAP_TOKENS: usize = 48;
/// Минимум токенов в хвостовом чанке (меньше — приклеивается к предыдущему).
pub const DEFAULT_MIN_TOKENS: usize = 32;
/// Жёсткие границы конфигурации.
const MIN_TARGET_TOKENS: usize = 16;

/// Формат документа: определяет иерархию уровней нарезки.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkFormat {
    /// Заголовки → абзацы → предложения → слова; code-fence целиком.
    Markdown,
    /// Абзацы → предложения → слова.
    Plain,
    /// Блоки между пустыми строками → строки (никогда внутри строки).
    Code,
}

impl ChunkFormat {
    /// Определение формата по расширению (Markdown优先, затем код).
    pub fn detect(path: &Path) -> Self {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        match ext.as_str() {
            "md" | "markdown" | "mdx" => ChunkFormat::Markdown,
            _ => match detect_lang(path) {
                CodeLang::Plain => ChunkFormat::Plain,
                CodeLang::Brace | CodeLang::Python => ChunkFormat::Code,
            },
        }
    }
}

/// Конфигурация нарезки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkConfig {
    /// Целевой размер чанка в токенах POLER.
    pub target_tokens: usize,
    /// Перекрытие соседних чанков в токенах.
    pub overlap_tokens: usize,
    /// Минимальный размер хвостового чанка.
    pub min_tokens: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            target_tokens: DEFAULT_TARGET_TOKENS,
            overlap_tokens: DEFAULT_OVERLAP_TOKENS,
            min_tokens: DEFAULT_MIN_TOKENS,
        }
    }
}

impl ChunkConfig {
    /// Нормализация: защита от бессмысленных комбинаций.
    fn sanitized(&self) -> Self {
        let target = self.target_tokens.max(MIN_TARGET_TOKENS);
        // Перекрытие — максимум четверть чанка (иначе чанки почти дубль).
        let overlap = self.overlap_tokens.min(target / 4);
        let min = self.min_tokens.min(target / 2);
        Self { target_tokens: target, overlap_tokens: overlap, min_tokens: min }
    }
}

/// Эпистемический статус происхождения текста чанка (Суверенный Гиппокамп,
/// v0.29.0).
///
/// Боль: RAG-выдачи смешивают машинно доказанные факты, первоисточники и
/// свободный нарратив в один неотличимый список — агент не может взвесить
/// доверие к цитате. Решение: чанк несёт метку провенанса, гибридное
/// ранжирование умножает скор на детерминированный коэффициент. Движок
/// не решает, что «истинно», — он честно маркирует происхождение.
///
/// Порядок вариантов — ВОСХОДЯЩЕЕ доверие (производный `Ord`):
/// `Narrative < SourceDocument < MvrVerified` — фильтр `min_provenance`
/// и сортировки сравнивают значения напрямую.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Нарратив без верификации: описания, синтез, манифесты (том VI).
    /// Коэффициент ×0.7.
    Narrative,
    /// Первоисточник: секция 4 PTS, оригинальные тексты и код, транскрипты.
    /// Коэффициент ×1.0.
    SourceDocument,
    /// Машинно доказано: MVR-паспорта (тома I–V трактата), golden-векторы,
    /// теоремы с инструментальной верификацией. Коэффициент ×1.5.
    MvrVerified,
}

impl Provenance {
    /// Коэффициент ранжирования: гибридный скор умножается на него.
    pub fn coefficient(self) -> f64 {
        match self {
            Provenance::MvrVerified => 1.5,
            Provenance::SourceDocument => 1.0,
            Provenance::Narrative => 0.7,
        }
    }

    /// Стабильное строковое представление (БД, MCP, CLI, JSON).
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::MvrVerified => "mvr_verified",
            Provenance::SourceDocument => "source_document",
            Provenance::Narrative => "narrative",
        }
    }

    /// Парсинг с короткими синонимами: mvr / source / narrative.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "mvr_verified" | "mvr" | "verified" => Some(Provenance::MvrVerified),
            "source_document" | "source" | "src" | "original" => {
                Some(Provenance::SourceDocument)
            }
            "narrative" | "nar" => Some(Provenance::Narrative),
            _ => None,
        }
    }

    /// Человекочитаемый бейдж для выдачи.
    pub fn badge(self) -> &'static str {
        match self {
            Provenance::MvrVerified => "MVR-VERIFIED ×1.5",
            Provenance::SourceDocument => "SOURCE ×1.0",
            Provenance::Narrative => "NARRATIVE ×0.7",
        }
    }
}

impl Default for Provenance {
    /// Произвольный документ по умолчанию — первоисточник (сам о себе):
    /// без явной разметки движок не занижает и не завышает доверие.
    fn default() -> Self {
        Provenance::SourceDocument
    }
}

/// Один чанк — пассаж с якорями.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Порядковый номер (0-базный, сквозной по документу).
    pub index: usize,
    /// Текст чанка — точный срез исходника.
    pub text: String,
    /// Начало чанка в байтах исходника (включительно).
    pub byte_start: usize,
    /// Конец чанка в байтах исходника (исключительно).
    pub byte_end: usize,
    /// Первая строка чанка, 1-базная (включительно).
    pub line_start: usize,
    /// Последняя строка чанка, 1-базная (включительно).
    pub line_end: usize,
    /// Путь заголовков («Глава › Раздел») — пуст для Plain/Code.
    pub breadcrumb: Vec<String>,
    /// Число токенов POLER в чанке.
    pub tokens: usize,
    /// Эпистемический статус происхождения. Для нарезки произвольных
    /// документов — `SourceDocument` (по умолчанию); инжест библиотеки
    /// POLER проставляет послойно/посекционно (Суверенный Гиппокамп).
    #[serde(default)]
    pub provenance: Provenance,
}

/// Итог нарезки документа.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkReport {
    /// Чанки по порядку.
    pub chunks: Vec<Chunk>,
    /// Суммарные токены документа.
    pub total_tokens: usize,
    /// Формат, использованный при нарезке.
    pub format: ChunkFormat,
    /// Конфигурация (после нормализации).
    pub config: ChunkConfig,
}

// ---------------------------------------------------------------------------
// Внутренние структуры
// ---------------------------------------------------------------------------

/// Уровень границы разреза: выше — семантически целостнее.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    /// Граница слова (последняя линия обороны).
    Word = 1,
    /// Граница строки (для кода).
    Line = 2,
    /// Граница предложения.
    Sentence = 3,
    /// Граница абзаца.
    Paragraph = 4,
    /// Граница секции заголовка.
    Section = 5,
}

/// Секция markdown: от строки заголовка до следующего заголовка.
struct Section {
    start: usize,
    end: usize,
    breadcrumb: Vec<String>,
}

/// Граница разреза: позиция + уровень.
struct Boundary {
    pos: usize,
    level: Level,
}

// ---------------------------------------------------------------------------
// Разметка границ
// ---------------------------------------------------------------------------

/// Секции markdown по ATX-заголовкам (`#`..`######`). Документ без
/// заголовков — одна секция с пустым breadcrumb.
fn split_sections(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut breadcrumb: Vec<String> = Vec::new();
    let mut cur_start = 0usize;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let hashes = trimmed.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) {
            let rest = &trimmed[hashes..];
            if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
                // Заголовок открывает новую секцию: закрыть предыдущую.
                if offset > cur_start || !sections.is_empty() || offset > 0 {
                    sections.push(Section {
                        start: cur_start,
                        end: offset,
                        breadcrumb: breadcrumb.clone(),
                    });
                }
                let title: String = rest.trim().trim_end_matches('#').trim().to_string();
                breadcrumb.truncate(hashes.saturating_sub(1));
                breadcrumb.push(if title.is_empty() {
                    format!("H{hashes}")
                } else {
                    title
                });
                cur_start = offset;
            }
        }
        offset += line.len();
    }
    sections.push(Section { start: cur_start, end: text.len(), breadcrumb });
    sections.retain(|s| s.end > s.start);
    sections
}

/// Абзацы внутри диапазона: пустые строки (вне code-fence) разделяют.
/// Возвращает (начало, конец, был_ли_забор_внутри).
fn split_paragraphs(text: &str, range: (usize, usize)) -> Vec<(usize, usize, bool)> {
    let (rs, re) = range;
    let mut out = Vec::new();
    let mut para_start: Option<usize> = None;
    let mut para_end = rs;
    let mut para_fenced = false;
    let mut in_fence = false;
    let mut offset = rs;
    for line in text[rs..re].split_inclusive('\n') {
        let line_end = offset + line.len();
        let trimmed = line.trim();
        let opens_fence =
            !in_fence && (trimmed.starts_with("```") || trimmed.starts_with("~~~"));
        let closes_fence =
            in_fence && (trimmed.starts_with("```") || trimmed.starts_with("~~~"));
        if !in_fence && trimmed.is_empty() {
            if let Some(start) = para_start.take() {
                out.push((start, para_end, para_fenced));
            }
            para_fenced = false;
        } else {
            if opens_fence {
                in_fence = true;
            } else if closes_fence {
                in_fence = false;
            }
            if para_start.is_none() {
                para_start = Some(offset);
                para_fenced = false;
            }
            if in_fence {
                para_fenced = true;
            }
            para_end = line_end;
        }
        offset = line_end;
    }
    if let Some(start) = para_start {
        out.push((start, para_end, para_fenced));
    }
    out
}

/// Начала предложений внутри диапазона (эвристика: терминатор
/// [.!?…] + закрывающие кавычки/скобки + ОБЯЗАТЕЛЬНЫЙ пробел —
/// иначе «3.14» и «т.д.» дают ложные границы). Позиция — начало
/// первого непробельного символа следующего предложения.
fn sentence_starts(text: &str, range: (usize, usize)) -> Vec<usize> {
    let (rs, re) = range;
    let mut out = Vec::new();
    let mut pending = false;
    let mut saw_ws = false;
    for (i, c) in text[rs..re].char_indices() {
        let abs = rs + i;
        if matches!(c, '.' | '!' | '?' | '。' | '！' | '？' | '…') {
            pending = true;
            saw_ws = false;
            continue;
        }
        if pending {
            if matches!(c, '"' | '\'' | '»' | '«' | ')' | ']' | '”' | '’') {
                continue; // закрывающая пунктуация после терминатора
            }
            if c.is_whitespace() {
                saw_ws = true;
                continue; // пробелы между предложениями
            }
            // Первый значимый символ: граница только если был пробел.
            if saw_ws {
                out.push(abs);
            }
            pending = false;
            saw_ws = false;
        }
    }
    out.retain(|&p| p > rs && p < re);
    out
}

/// Начала слов внутри диапазона (alnum после не-alnum).
fn word_starts(text: &str, range: (usize, usize)) -> Vec<usize> {
    let (rs, re) = range;
    let mut out = Vec::new();
    let mut prev_alnum = false;
    for (i, c) in text[rs..re].char_indices() {
        let alnum = c.is_alphanumeric();
        if alnum && !prev_alnum {
            out.push(rs + i);
        }
        prev_alnum = alnum;
    }
    out.retain(|&p| p > rs && p < re);
    out
}

/// Начала строк внутри диапазона.
fn line_starts(text: &str, range: (usize, usize)) -> Vec<usize> {
    let (rs, re) = range;
    let mut out = Vec::new();
    for (i, b) in text[rs..re].bytes().enumerate() {
        if b == b'\n' && rs + i + 1 < re {
            out.push(rs + i + 1);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Сборка чанков
// ---------------------------------------------------------------------------

/// Построить все границы разреза внутри диапазона секции.
fn build_boundaries(
    text: &str,
    range: (usize, usize),
    format: ChunkFormat,
    fenced_paragraphs: &[(usize, usize, bool)],
) -> Vec<Boundary> {
    let (rs, re) = range;
    let mut bounds: Vec<Boundary> = Vec::new();
    // Абзацы — границы уровня Paragraph.
    for &(ps, pe, _) in fenced_paragraphs {
        if ps > rs {
            bounds.push(Boundary { pos: ps, level: Level::Paragraph });
        }
        if pe < re {
            bounds.push(Boundary { pos: pe, level: Level::Paragraph });
        }
    }
    match format {
        ChunkFormat::Code => {
            for p in line_starts(text, range) {
                bounds.push(Boundary { pos: p, level: Level::Line });
            }
        }
        ChunkFormat::Plain | ChunkFormat::Markdown => {
            for &(ps, pe, fenced) in fenced_paragraphs {
                if fenced {
                    // Внутри code-fence — только построчные разрезы.
                    let mut lines = line_starts(text, (ps, pe));
                    lines.retain(|&p| p > ps);
                    for p in lines {
                        bounds.push(Boundary { pos: p, level: Level::Line });
                    }
                    continue;
                }
                for p in sentence_starts(text, (ps, pe)) {
                    bounds.push(Boundary { pos: p, level: Level::Sentence });
                }
                for p in word_starts(text, (ps, pe)) {
                    bounds.push(Boundary { pos: p, level: Level::Word });
                }
            }
        }
    }
    bounds.sort_by_key(|b| b.pos);
    bounds.dedup_by_key(|b| b.pos);
    bounds
}

/// Нарезка документа на чанки.
pub fn chunk_document(text: &str, format: ChunkFormat, cfg: &ChunkConfig) -> ChunkReport {
    let cfg = cfg.sanitized();
    let total_tokens = web_tokenize(text).len();
    let mut chunks: Vec<Chunk> = Vec::new();

    let sections: Vec<(usize, usize, Vec<String>)> = match format {
        ChunkFormat::Markdown => split_sections(text)
            .into_iter()
            .map(|s| (s.start, s.end, s.breadcrumb))
            .collect(),
        _ => vec![(0usize, text.len(), Vec::new())],
    };

    for (sec_start, sec_end, breadcrumb) in sections {
        if sec_end <= sec_start {
            continue;
        }
        let paragraphs = split_paragraphs(text, (sec_start, sec_end));
        let bounds = build_boundaries(text, (sec_start, sec_end), format, &paragraphs);
        // Позиции: начало секции + все внутренние границы + конец.
        let mut positions: Vec<(usize, Level)> = Vec::with_capacity(bounds.len() + 2);
        positions.push((sec_start, Level::Section));
        for b in bounds {
            if b.pos > sec_start && b.pos < sec_end {
                positions.push((b.pos, b.level));
            }
        }
        positions.push((sec_end, Level::Section));

        // Префикс-суммы токенов по сегментам между границами.
        let mut seg_tok = Vec::with_capacity(positions.len());
        for w in positions.windows(2) {
            seg_tok.push(web_tokenize(&text[w[0].0..w[1].0]).len());
        }
        let mut prefix = vec![0usize];
        for (i, t) in seg_tok.iter().enumerate() {
            prefix.push(prefix[i] + t);
        }

        // Жадная сборка: пары (начало, конец) в индексах positions.
        // Конец чанка — граница `end` ДО оттягивания перекрытия:
        // следующий чанк ЗАХОДИТ в предыдущий, а не сдвигает его конец.
        let mut chunk_idx: Vec<(usize, usize)> = Vec::new();
        let mut i = 0usize;
        loop {
            if i + 1 >= positions.len() {
                break;
            }
            // Лучшая граница конца j: токены(i..j) <= target, максимум
            // (level, j) — целостнее и крупнее.
            let mut best: Option<usize> = None;
            let mut j = i + 1;
            while j < positions.len() {
                let tok = prefix[j] - prefix[i];
                if tok > cfg.target_tokens {
                    break;
                }
                let lvl = positions[j].1;
                let better = match best {
                    None => true,
                    Some(b) => (lvl, j) > (positions[b].1, b),
                };
                if better {
                    best = Some(j);
                }
                j += 1;
            }
            // Атомарный сегмент больше лимита: не режем слово/строку.
            let end = best.unwrap_or(i + 1);
            if end >= positions.len() - 1 {
                // Финальный чанк: [i .. конец секции].
                chunk_idx.push((i, positions.len() - 1));
                break;
            }
            chunk_idx.push((i, end));
            // Перекрытие: оттянуть начало следующего чанка назад по
            // границам, суммарно <= overlap токенов, уровень выше — лучше.
            let mut next_start = end;
            if cfg.overlap_tokens > 0 {
                let mut k = end;
                let mut best_k: Option<usize> = None;
                while k > i + 1 {
                    k -= 1;
                    let tok = prefix[end] - prefix[k];
                    if tok > cfg.overlap_tokens {
                        break;
                    }
                    let lvl = positions[k].1;
                    let better = match best_k {
                        None => true,
                        Some(b) => lvl > positions[b].1,
                    };
                    if better {
                        best_k = Some(k);
                    }
                }
                if let Some(k) = best_k {
                    next_start = k;
                }
            }
            i = next_start;
        }

        // Хвост слишком мал → приклеить к предыдущему чанку: конец
        // предпоследнего продлевается до конца секции, хвост выбрасывается.
        if chunk_idx.len() > 1 {
            let last_tok =
                prefix[positions.len() - 1] - prefix[chunk_idx.last().unwrap().0];
            if last_tok < cfg.min_tokens {
                chunk_idx.pop();
                if let Some(tail) = chunk_idx.last_mut() {
                    tail.1 = positions.len() - 1;
                }
            }
        }

        for (si, ei) in chunk_idx {
            let (s, e) = (positions[si].0, positions[ei].0);
            if e <= s {
                continue;
            }
            let chunk_text = &text[s..e];
            let tokens = web_tokenize(chunk_text).len();
            chunks.push(Chunk {
                index: chunks.len(),
                text: chunk_text.to_string(),
                byte_start: s,
                byte_end: e,
                line_start: line_of(text, s),
                line_end: line_of(text, e.saturating_sub(1)),
                breadcrumb: breadcrumb.clone(),
                tokens,
                provenance: Provenance::default(),
            });
        }
    }

    // ---------- v0.21 hardening: никакого чанкового мусора ----------
    // Жадная сборка максимизирует УРОВЕНЬ границы, а не объём: при абзацах
    // ≈ target она оставляет (а) пустые чанки-разделители «\n\n» и
    // (б) микро-чанки-островки (голый заголовок секции < min_tokens).
    // Пост-проход: пустые выбрасываются, микро-приклеиваются к следующему
    // куску ТОЙ ЖЕ секции (заголовок + первый абзац — классика RAG).
    // Итог: merged.tokens < target + min_tokens (ограниченный перелимит),
    // text по-прежнему точный срез исходника.
    loop {
        let mut changed = false;
        let mut out: Vec<Chunk> = Vec::with_capacity(chunks.len());
        let mut i = 0usize;
        while i < chunks.len() {
            let mut c = chunks[i].clone();
            // пустой (только пробелы) чанк информации не несёт — выброс
            if c.tokens == 0 && c.text.trim().is_empty() {
                i += 1;
                changed = true;
                continue;
            }
            // микро-чанк: слить со следующим куском той же секции
            if c.tokens < cfg.min_tokens
                && i + 1 < chunks.len()
                && c.breadcrumb == chunks[i + 1].breadcrumb
            {
                let next = &chunks[i + 1];
                c.byte_end = next.byte_end.max(c.byte_end);
                c.text = text[c.byte_start..c.byte_end].to_string();
                c.tokens = web_tokenize(&c.text).len();
                c.line_end = line_of(text, c.byte_end.saturating_sub(1));
                i += 2;
                changed = true;
                out.push(c);
                continue;
            }
            out.push(c);
            i += 1;
        }
        chunks = out;
        if !changed {
            break;
        }
    }
    // сквозная перенумерация после слияний/выбросов
    for (idx, c) in chunks.iter_mut().enumerate() {
        c.index = idx;
    }

    ChunkReport { chunks, total_tokens, format, config: cfg }
}

/// Номер строки (1-базный) для байтового смещения.
fn line_of(text: &str, byte: usize) -> usize {
    let mut line = 1usize;
    for (i, b) in text.as_bytes().iter().enumerate() {
        if i >= byte {
            break;
        }
        if *b == b'\n' {
            line += 1;
        }
    }
    line
}

/// Человекочитаемый рендер: заголовок-карточка + текст чанка.
pub fn render_chunks_text(report: &ChunkReport, path: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# POLER-чанки: {path}\n\nформат: {:?}, чанков: {}, токенов в документе: {}, \
         target/overlap: {}/{}\n\n",
        report.format,
        report.chunks.len(),
        report.total_tokens,
        report.config.target_tokens,
        report.config.overlap_tokens
    ));
    for c in &report.chunks {
        let crumb = if c.breadcrumb.is_empty() {
            String::new()
        } else {
            format!(" | {}", c.breadcrumb.join(" › "))
        };
        out.push_str(&format!(
            "## [{}] строки {}–{}, байты {}..{}, {} ток.{crumb}\n",
            c.index, c.line_start, c.line_end, c.byte_start, c.byte_end, c.tokens
        ));
        out.push_str(c.text.trim_end());
        out.push_str("\n\n---\n\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_document_single_chunk() {
        let text = "Короткий документ. Один абзац, мало токенов.";
        let report = chunk_document(text, ChunkFormat::Plain, &ChunkConfig::default());
        assert_eq!(report.chunks.len(), 1);
        let c = &report.chunks[0];
        assert_eq!(c.text, text);
        assert_eq!((c.byte_start, c.byte_end), (0, text.len()));
        assert_eq!(c.line_start, 1);
        assert_eq!(c.line_end, 1);
    }

    #[test]
    fn chunk_text_is_exact_slice() {
        // Инвариант: text == original[byte_start..byte_end]
        let text = format!("{}\n\n{}", "слово ".repeat(300), "хвост ".repeat(300));
        let report = chunk_document(&text, ChunkFormat::Plain, &ChunkConfig::default());
        assert!(report.chunks.len() >= 2);
        for c in &report.chunks {
            assert_eq!(&text[c.byte_start..c.byte_end], c.text);
        }
    }

    #[test]
    fn capacity_respected_except_atomic() {
        let mut text = String::new();
        for i in 0..200 {
            text.push_str(&format!("Предложение номер {i} с парой слов. "));
        }
        let cfg = ChunkConfig { target_tokens: 50, ..Default::default() };
        let report = chunk_document(&text, ChunkFormat::Plain, &cfg);
        assert!(report.chunks.len() >= 3);
        for c in &report.chunks {
            // Атомарный (одно предложение) может превысить только если
            // сам больше лимита — здесь предложения маленькие.
            assert!(c.tokens <= 50, "чанк {} токенов: {c:?}", c.tokens);
        }
    }

    #[test]
    fn sentence_boundaries_preferred_over_words() {
        let mut text = String::new();
        for i in 0..60 {
            text.push_str(&format!("Это предложение {i} тестовое. "));
        }
        let cfg = ChunkConfig { target_tokens: 20, overlap_tokens: 0, ..Default::default() };
        let report = chunk_document(&text, ChunkFormat::Plain, &cfg);
        // Все разрезы — по границам предложений: текст чанка начинается
        // с «Это» (или с начала) и не начинается mid-word.
        for c in &report.chunks {
            let t = c.text.trim_start();
            assert!(
                t.starts_with("Это") || t.starts_with("хвост") || c.byte_start == 0,
                "начало: {:?}",
                &t[..t.len().min(20)]
            );
        }
    }

    #[test]
    fn markdown_sections_produce_breadcrumbs() {
        let mut text = String::new();
        text.push_str("# Глава\n\n");
        text.push_str(&format!("{}\n\n", "текст главы ".repeat(100)));
        text.push_str("## Раздел\n\n");
        text.push_str(&format!("{}\n\n", "текст раздела ".repeat(100)));
        let report = chunk_document(&text, ChunkFormat::Markdown, &ChunkConfig::default());
        assert!(report.chunks.len() >= 2);
        // Ни один чанк не пересекает секцию: breadcrumb однороден
        for c in &report.chunks {
            if c.text.contains("текст главы") {
                assert_eq!(c.breadcrumb, vec!["Глава".to_string()]);
                assert!(!c.text.contains("текст раздела"));
            } else if c.text.contains("текст раздела") {
                assert_eq!(c.breadcrumb, vec!["Глава".to_string(), "Раздел".to_string()]);
                assert!(!c.text.contains("текст главы"));
            }
        }
        // Заголовок входит в текст чанка своей секции
        let section2 = report.chunks.iter().find(|c| c.breadcrumb.len() == 2).unwrap();
        assert!(section2.text.contains("## Раздел"));
    }

    #[test]
    fn nested_headings_breadcrumb_stack() {
        let text = "# A\n\nx\n\n## B\n\ny\n\n### C\n\nz\n\n## D\n\nw\n";
        let report = chunk_document(text, ChunkFormat::Markdown, &ChunkConfig::default());
        let crumbs: Vec<Vec<String>> =
            report.chunks.iter().map(|c| c.breadcrumb.clone()).collect();
        assert!(crumbs.contains(&vec!["A".into()]));
        assert!(crumbs.contains(&vec!["A".into(), "B".into()]));
        assert!(crumbs.contains(&vec!["A".into(), "B".into(), "C".into()]));
        assert!(crumbs.contains(&vec!["A".into(), "D".into()]));
    }

    #[test]
    fn code_fence_not_split_by_blank_lines() {
        let mut text = String::new();
        text.push_str("Интро абзац.\n\n");
        text.push_str("```rust\nfn a() {\n\n    let x = 1;\n\n}\n```\n\n");
        text.push_str("Заключение.\n");
        let report = chunk_document(&text, ChunkFormat::Markdown, &ChunkConfig::default());
        // Забор целиком в одном чанке: пустые строки внутри не режут
        let fence_chunk = report
            .chunks
            .iter()
            .find(|c| c.text.contains("```rust"))
            .expect("забор в чанках");
        assert!(fence_chunk.text.contains("fn a() {"));
        assert!(fence_chunk.text.contains("let x = 1;"));
        assert!(fence_chunk.text.contains("}"));
        // И забор не порезан между чанками
        let fence_starts: usize =
            report.chunks.iter().filter(|c| c.text.contains("```rust")).count();
        assert_eq!(fence_starts, 1);
    }

    #[test]
    fn oversized_fence_cuts_by_lines_not_midline() {
        let mut fence = String::from("```rust\n");
        for i in 0..120 {
            fence.push_str(&format!("let var_{i}_long_name = compute_something({i});\n"));
        }
        fence.push_str("```\n");
        let cfg = ChunkConfig { target_tokens: 40, overlap_tokens: 0, ..Default::default() };
        let report = chunk_document(&fence, ChunkFormat::Markdown, &cfg);
        assert!(report.chunks.len() >= 3);
        for c in &report.chunks {
            // Разрезы только по строкам: чанк начинается с начала строки
            assert!(
                c.byte_start == 0 || &fence[c.byte_start - 1..c.byte_start] == "\n",
                "разрез внутри строки на {}",
                c.byte_start
            );
        }
    }

    #[test]
    fn code_format_never_cuts_midline() {
        let mut code = String::new();
        for i in 0..100 {
            code.push_str(&format!("statement_number_{i}(arg_{i}, other_{i});\n"));
            if i % 10 == 9 {
                code.push('\n');
            }
        }
        let cfg = ChunkConfig { target_tokens: 30, ..Default::default() };
        let report = chunk_document(&code, ChunkFormat::Code, &cfg);
        assert!(report.chunks.len() >= 3);
        for c in &report.chunks {
            assert!(
                c.byte_start == 0 || &code[c.byte_start - 1..c.byte_start] == "\n"
            );
        }
    }

    #[test]
    fn overlap_makes_neighbor_chunks_share_text() {
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("Предложение {i} о чем-то важном. "));
        }
        let cfg = ChunkConfig { target_tokens: 40, overlap_tokens: 10, ..Default::default() };
        let report = chunk_document(&text, ChunkFormat::Plain, &cfg);
        assert!(report.chunks.len() >= 3);
        // Соседние чанки пересекаются по байтовым диапазонам
        for w in report.chunks.chunks(2).map(|p| (&p[0], p.get(1))) {
            if let Some(next) = w.1 {
                assert!(
                    next.byte_start < w.0.byte_end,
                    "нет перекрытия: {}..{} vs {}..{}",
                    w.0.byte_start,
                    w.0.byte_end,
                    next.byte_start,
                    next.byte_end
                );
            }
        }
    }

    #[test]
    fn tiny_tail_merges_into_previous() {
        let mut text = String::new();
        for i in 0..80 {
            text.push_str(&format!("Предложение {i} содержательное. "));
        }
        text.push_str("Хвостик.");
        let cfg = ChunkConfig { target_tokens: 40, overlap_tokens: 0, min_tokens: 30,
            ..Default::default() };
        let report = chunk_document(&text, ChunkFormat::Plain, &cfg);
        let last = report.chunks.last().unwrap();
        assert!(last.tokens >= 30, "хвост {} токенов не приклеен", last.tokens);
    }

    #[test]
    fn line_numbers_are_correct() {
        let text = "первая\n\nвторая\nтретья\n\nчетвёртая\n";
        let report = chunk_document(text, ChunkFormat::Plain, &ChunkConfig::default());
        assert_eq!(report.chunks.len(), 1);
        let c = &report.chunks[0];
        assert_eq!(c.line_start, 1);
        assert_eq!(c.line_end, 6);
    }

    #[test]
    fn empty_text_no_chunks_no_panic() {
        let report = chunk_document("", ChunkFormat::Plain, &ChunkConfig::default());
        assert!(report.chunks.is_empty());
        assert_eq!(report.total_tokens, 0);
    }

    #[test]
    fn format_detect_by_extension() {
        assert_eq!(ChunkFormat::detect(Path::new("doc.md")), ChunkFormat::Markdown);
        assert_eq!(ChunkFormat::detect(Path::new("lib.rs")), ChunkFormat::Code);
        assert_eq!(ChunkFormat::detect(Path::new("script.py")), ChunkFormat::Code);
        assert_eq!(ChunkFormat::detect(Path::new("notes.txt")), ChunkFormat::Plain);
    }

    #[test]
    fn config_sanitizer_clamps_nonsense() {
        let cfg = ChunkConfig { target_tokens: 4, overlap_tokens: 1000, min_tokens: 900,
            ..Default::default() };
        let s = cfg.sanitized();
        assert_eq!(s.target_tokens, 16);
        assert!(s.overlap_tokens <= s.target_tokens / 4);
        assert!(s.min_tokens <= s.target_tokens / 2);
    }

    #[test]
    fn russian_text_tokenized_and_chunked() {
        let mut text = String::new();
        for i in 0..80 {
            text.push_str(&format!("Предложение на русском языке номер {i}. "));
        }
        let report = chunk_document(&text, ChunkFormat::Plain, &ChunkConfig::default());
        assert!(!report.chunks.is_empty());
        assert!(report.total_tokens > 300);
    }

    #[test]
    fn report_serializes_to_json() {
        let text = "# Тема\n\nАбзац текста для сериализации отчёта.\n";
        let report = chunk_document(text, ChunkFormat::Markdown, &ChunkConfig::default());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"byte_start\""));
        assert!(json.contains("\"breadcrumb\""));
    }

    #[test]
    fn render_text_contains_headers() {
        let text = "Абзац.\n\nВторой абзац.\n";
        let report = chunk_document(text, ChunkFormat::Plain, &ChunkConfig::default());
        let out = render_chunks_text(&report, "test.txt");
        assert!(out.contains("POLER-чанки"));
        assert!(out.contains("test.txt"));
        assert!(out.contains("Абзац."));
    }

    #[test]
    fn sentence_starts_ignores_decimals() {
        let text = "Число 3.14 не ломает. Граница тут.";
        let starts = sentence_starts(text, (0, text.len()));
        // Граница только после «ломает.» — не после «3.14»
        let heads: Vec<String> = starts
            .iter()
            .map(|&p| text[p..].chars().take(8).collect::<String>())
            .collect();
        assert!(heads.iter().any(|s| s.starts_with("Граница")));
        assert!(!heads.iter().any(|s| s.starts_with("14")));
    }
}
