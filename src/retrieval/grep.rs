//! Слой 0 Native Retrieval: точный поиск в семантике grep.
//!
//! Назначение — заменить агенту внешний grep: ВСЕ совпадения по файлам,
//! без индекса, мгновенно, с гарантией полноты («ноль значит ноль»).
//! Эталон поведения — GNU grep (см. `docs/native-retrieval-analysis.md`):
//! exit-коды 0/1/2 для скриптов, контекст `-A/-B/-C` с групповым
//! разделителем `--`, режимы `-c/-l/-L`, бинарные файлы («Binary file
//! … matches»).
//!
//! Отличия от GNU grep (осознанные):
//! * обход — `ignore::WalkBuilder` (ripgrep-класс): .gitignore/.ignore,
//!   скрытые файлы по флагу, симлинки не преследуются;
//! * результат — машинно-читаемый [`GrepReport`] (serde): каждая строка
//!   несёт `byte_offset` и байтовые диапазоны вхождений — для ИИ-агента;
//! * регистронезависимость — Unicode-fold через крейт `regex` (шире,
//!   чем ASCII-fold grep);
//! * файлы с NUL-байтом считаются бинарными: содержимое не выводится,
//!   но count/list досканировываются полностью;
//! * диапазоны вхождений относятся к lossy-UTF8 тексту строки (файлы с
//!   невалидным UTF-8 дают текст с U+FFFD); `byte_offset` начала строки
//!   всегда точен.
//!
//! Сопоставители: фиксированная строка — Aho-Corasick (крейт
//! `aho-corasick`, тот же класс, что kwset GNU grep); регулярное
//! выражение — крейт `regex`. Оба уже были зависимостями движка.

use std::collections::VecDeque;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use aho_corasick::AhoCorasick;
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Потолок размера файла для сканирования (защита от mmap-гигантов).
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Потолок подсвечиваемых вхождений на строку (минифицированный JS).
const MAX_RANGES_PER_LINE: usize = 256;

/// Режим сопоставления шаблоном.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrepMode {
    /// Фиксированная строка (grep -F): Aho-Corasick.
    Literal,
    /// Расширенное регулярное выражение (grep -E).
    Regex,
}

/// Режим вывода результатов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrepOutput {
    /// Строки с совпадениями (+контекст) — как grep без ключей.
    Content,
    /// Только счётчик совпавших строк на файл (grep -c).
    Count,
    /// Только пути файлов с совпадениями (grep -l).
    ListMatching,
    /// Только пути файлов без совпадений (grep -L).
    ListNonMatching,
}

/// Конфигурация одного прогона точного поиска.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepConfig {
    /// Искомый шаблон (фиксированная строка либо regex — по `mode`).
    pub pattern: String,
    /// Literal / Regex.
    pub mode: GrepMode,
    /// Регистронезависимость (Unicode-fold).
    pub case_insensitive: bool,
    /// Строк контекста до совпадения (grep -B).
    pub before: usize,
    /// Строк контекста после совпадения (grep -A).
    pub after: usize,
    /// Останов после N совпавших строк на файл (grep -m; N на файл).
    pub max_count: Option<usize>,
    /// Режим вывода.
    pub output: GrepOutput,
    /// Включить скрытые файлы.
    pub include_hidden: bool,
    /// Уважать .gitignore/.ignore (по умолчанию — да, как ripgrep).
    pub respect_ignore: bool,
    /// Скан архивов без распаковки (v0.28.1): zip/tar/tar.gz/tar.zst/gz/zst
    /// внутри корней поиска раскрываются виртуальными файлами
    /// «архив::запись». Сам архивный файл как бинарник НЕ сканируется
    /// (исключаются дубли-маркеры бинарности).
    #[serde(default)]
    pub scan_archives: bool,
    /// Пароль зашифрованных записей zip (ZipCrypto/AES). CLI резолвит:
    /// --archive-password → POLER_ARCHIVE_KEY → TTY-промпт.
    #[serde(default)]
    pub archive_password: Option<String>,
    /// Лимит несжатой записи архива, байт (0 → DEFAULT_MAX_ENTRY_BYTES,
    /// 64 МиБ). Защита от zip-бомб: запись свыше лимита пропускается.
    #[serde(default)]
    pub archive_max_entry_bytes: u64,
}

impl Default for GrepConfig {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            mode: GrepMode::Literal,
            case_insensitive: false,
            before: 0,
            after: 0,
            max_count: None,
            output: GrepOutput::Content,
            include_hidden: false,
            respect_ignore: true,
            scan_archives: false,
            archive_password: None,
            archive_max_entry_bytes: 0,
        }
    }
}

/// Скомпилированный сопоставитель.
enum Matcher {
    /// Aho-Corasick по фиксированной строке (байты lossy-строки).
    Literal { ac: AhoCorasick },
    /// regex-крейт (regex-режим либо icase-literal через escape).
    Regex(regex::Regex),
}

impl Matcher {
    /// Компиляция шаблона. Ошибка — человекочитаемой строкой (exit 2).
    fn build(config: &GrepConfig) -> Result<Self, String> {
        match config.mode {
            GrepMode::Literal if !config.case_insensitive => {
                let ac = AhoCorasick::new([&config.pattern])
                    .map_err(|e| format!("шаблон не компилируется: {e}"))?;
                Ok(Matcher::Literal { ac })
            }
            _ => {
                // icase-literal: escape → та же семантика, но Unicode-fold.
                let src = match config.mode {
                    GrepMode::Literal => regex::escape(&config.pattern),
                    GrepMode::Regex => config.pattern.clone(),
                };
                let re = regex::RegexBuilder::new(&src)
                    .case_insensitive(config.case_insensitive)
                    .build()
                    .map_err(|e| format!("некорректный шаблон «{}»: {e}", config.pattern))?;
                Ok(Matcher::Regex(re))
            }
        }
    }

    /// Непересекающиеся вхождения в строке: байтовые диапазоны
    /// относительно `text` (lossy-UTF8). Пустой шаблон матчит все строки
    /// без подсветки (семантика grep "").
    fn find_ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        match self {
            Matcher::Literal { ac } => {
                for m in ac.find_iter(text.as_bytes()) {
                    if !m.is_empty() && ranges.len() < MAX_RANGES_PER_LINE {
                        ranges.push((m.start(), m.end()));
                    }
                }
            }
            Matcher::Regex(re) => {
                for m in re.find_iter(text) {
                    if !m.is_empty() && ranges.len() < MAX_RANGES_PER_LINE {
                        ranges.push((m.start(), m.end()));
                    }
                }
            }
        }
        ranges
    }
}

/// Одна выходная строка (совпадение или контекст).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepLineOut {
    /// Номер строки, 1-базный.
    pub line_no: usize,
    /// Байтовое смещение начала строки в файле.
    pub byte_offset: usize,
    /// Текст строки (lossy-UTF8, без завершающего \n/\r).
    pub text: String,
    /// Строка-совпадение (true) или контекстная (false).
    pub matched: bool,
    /// Байтовые диапазоны вхождений внутри `text` (только для matched).
    pub ranges: Vec<(usize, usize)>,
}

/// Контекстная группа: непрерывный блок вывода одного файла
/// (несколько совпадений со слипшимся контекстом — одна группа).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepGroup {
    /// Путь файла.
    pub path: String,
    /// Бинарный файл: содержимое не выводилось, но совпадения есть.
    pub binary: bool,
    /// Строки группы (до + совпадения + после, по порядку).
    pub lines: Vec<GrepLineOut>,
}

/// Счётчик на файл (режимы Count / List*).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepFileCounts {
    /// Путь файла.
    pub path: String,
    /// Число совпавших строк.
    pub count: usize,
    /// Файл содержит NUL-байты.
    pub binary: bool,
}

/// Сводка прогона.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepStats {
    /// Просканировано файлов.
    pub files_scanned: usize,
    /// Файлов с совпадениями.
    pub files_matched: usize,
    /// Совпавших строк (суммарно).
    pub lines_matched: usize,
    /// Вхождений шаблона (суммарно, включая повторы в строке).
    pub occurrences: usize,
    /// Время прогона, мс.
    pub elapsed_ms: u128,
    /// Накопленные ошибки обхода (права доступа и т.п.).
    pub errors: Vec<String>,
}

/// Полный результат точного поиска (машинно-читаемый).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepReport {
    /// Шаблон прогона.
    pub pattern: String,
    /// Режим вывода.
    pub output: GrepOutput,
    /// Контекстные группы (Content-режим).
    pub groups: Vec<GrepGroup>,
    /// Счётчики на файл (Count / List*).
    pub files: Vec<GrepFileCounts>,
    /// Сводка.
    pub stats: GrepStats,
}

impl GrepReport {
    /// Есть ли результат: критерий exit-кода 0. Для ListNonMatching
    /// «успех» = выведен хотя бы один файл без совпадений.
    pub fn any_match(&self) -> bool {
        if self.output == GrepOutput::ListNonMatching {
            return self.files.iter().any(|f| f.count == 0);
        }
        self.stats.files_matched > 0
    }

    /// Exit-код в семантике grep: 0 — есть результат, 1 — пусто.
    pub fn exit_code(&self) -> i32 {
        if self.any_match() {
            0
        } else {
            1
        }
    }
}

/// Результат сканирования одного файла.
struct FileScan {
    path: String,
    binary: bool,
    matched_lines: usize,
    occurrences: usize,
    /// Content-режим: контекстные группы.
    groups: Vec<GrepGroup>,
    error: Option<String>,
}

/// Сканирование одного файла: построчный проход с контекстом.
/// M6: `cache` — резидентный RAM-кэш (None — классическое чтение с диска).
fn scan_file(path: &Path, matcher: &Matcher, config: &GrepConfig, cache: Option<&crate::retrieval::filecache::FileCache>) -> FileScan {
    let mut scan = FileScan {
        path: path.display().to_string(),
        binary: false,
        matched_lines: 0,
        occurrences: 0,
        groups: Vec::new(),
        error: None,
    };
    // Аудит-фикс №F1: размер по metadata ДО чтения. Раньше файл целиком
    // попадал в память и только потом отбрасывался за превышение лимита —
    // на rayon-пуле (16 потоков × гигантские файлы) это врыв RAM.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_FILE_BYTES {
            scan.error = Some(format!(
                "{}: {} байт > лимита {MAX_FILE_BYTES} — пропущен",
                path.display(),
                meta.len()
            ));
            return scan;
        }
    }
    let bytes: std::sync::Arc<Vec<u8>> = match cache {
        Some(c) => match c.get_or_read(path) {
            Ok(b) => b,
            Err(e) => {
                scan.error = Some(format!("{}: {e}", path.display()));
                return scan;
            }
        },
        None => match std::fs::read(path) {
            Ok(b) => std::sync::Arc::new(b),
            Err(e) => {
                scan.error = Some(format!("{}: {e}", path.display()));
                return scan;
            }
        },
    };
    scan_bytes(&scan.path.clone(), &bytes, matcher, config)
}

/// v0.22.0 (Terminal Gateway): сканирование БУФЕРА из памяти (stdin
/// конвейера) с той же семантикой контекста/бинарности, что и файлы.
fn scan_bytes(name: &str, bytes: &[u8], matcher: &Matcher, config: &GrepConfig) -> FileScan {
    let mut scan = FileScan {
        path: name.to_string(),
        binary: false,
        matched_lines: 0,
        occurrences: 0,
        groups: Vec::new(),
        error: None,
    };
    if bytes.len() as u64 > MAX_FILE_BYTES {
        scan.error = Some(format!(
            "{name}: {} байт > лимита {MAX_FILE_BYTES} — пропущен",
            bytes.len()
        ));
        return scan;
    }

    let want_content = config.output == GrepOutput::Content;
    // Состояние контекста (grep -A/-B): pending-буфер «до», счётчик «после».
    let mut before_buf: VecDeque<(usize, usize, String)> = VecDeque::new();
    let mut after_left = 0usize;
    let mut last_emitted: Option<usize> = None;
    let mut group: Option<Vec<GrepLineOut>> = None;
    let mut closing = false; // max_count достигнут: добираем хвост -A

    let mut line_no = 0usize;
    let mut offset = 0usize;
    for (start, end) in split_lines(&bytes[..]) {
        line_no += 1;
        let line_bytes = &bytes[start..end];
        let text = String::from_utf8_lossy(line_bytes)
            .trim_end_matches('\r')
            .to_string();

        // Бинарность: NUL-байт в строке. Содержимое не выводим,
        // но счётчики (count/list) продолжаем добывать.
        if line_bytes.contains(&0) {
            scan.binary = true;
        }

        let ranges = matcher.find_ranges(&text);
        let matched = !ranges.is_empty() || config.pattern.is_empty();
        if matched {
            scan.matched_lines += 1;
            scan.occurrences += ranges.len();
        }

        if want_content && !scan.binary {
            if matched {
                // Разрыв между группами → закрыть предыдущую (разделитель
                // «--» рендерится между группами одного файла).
                let first_new = before_buf
                    .front()
                    .map(|(n, _, _)| *n)
                    .unwrap_or(line_no);
                if let Some(last) = last_emitted {
                    if first_new > last + 1 && group.is_some() {
                        scan.groups.push(GrepGroup {
                            path: scan.path.clone(),
                            binary: false,
                            lines: group.take().unwrap(),
                        });
                    }
                }
                let g = group.get_or_insert_with(Vec::new);
                // Ведущий контекст: только ещё не выведенные строки.
                while let Some(&(n, off, ref t)) = before_buf.front() {
                    if Some(n) <= last_emitted {
                        before_buf.pop_front();
                        continue;
                    }
                    g.push(GrepLineOut {
                        line_no: n,
                        byte_offset: off,
                        text: t.clone(),
                        matched: false,
                        ranges: Vec::new(),
                    });
                    last_emitted = Some(n);
                    before_buf.pop_front();
                }
                g.push(GrepLineOut {
                    line_no,
                    byte_offset: offset,
                    text: text.clone(),
                    matched: true,
                    ranges,
                });
                last_emitted = Some(line_no);
                after_left = config.after;
                // -m: совпадений достаточно — добрать хвост -A и выйти.
                if let Some(max) = config.max_count {
                    if scan.matched_lines >= max {
                        closing = true;
                    }
                }
            } else if after_left > 0 {
                let g = group.get_or_insert_with(Vec::new);
                g.push(GrepLineOut {
                    line_no,
                    byte_offset: offset,
                    text: text.clone(),
                    matched: false,
                    ranges: Vec::new(),
                });
                last_emitted = Some(line_no);
                after_left -= 1;
            } else {
                // Кандидат ведущего контекста будущей группы.
                before_buf.push_back((line_no, offset, text.clone()));
                if before_buf.len() > config.before {
                    before_buf.pop_front();
                }
            }
        }

        offset = end + 1; // за \n
        if closing && after_left == 0 {
            break;
        }
    }
    if let Some(lines) = group.take() {
        if !lines.is_empty() {
            scan.groups.push(GrepGroup {
                path: scan.path.clone(),
                binary: false,
                lines,
            });
        }
    }
    scan
}

/// Разбивка байтов на строки: (начало, конец) БЕЗ завершающего \n.
/// Последняя строка без \n включается; пустой хвост — нет.
fn split_lines(bytes: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        if pos >= bytes.len() {
            return None;
        }
        match memchr::memchr(b'\n', &bytes[pos..]) {
            Some(i) => {
                let start = pos;
                let end = pos + i;
                pos = end + 1;
                Some((start, end))
            }
            None => {
                let start = pos;
                let end = bytes.len();
                pos = end + 1;
                Some((start, end))
            }
        }
    })
}

/// Сбор файлов для поиска: файл напрямую либо рекурсивный обход
/// (ripgrep-класс: .gitignore/.ignore, скрытые, SKIP_DIRS движка).
fn collect_grep_files(root: &Path, config: &GrepConfig) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    WalkBuilder::new(root)
        .hidden(!config.include_hidden)
        .git_ignore(config.respect_ignore)
        .git_global(config.respect_ignore)
        .git_exclude(config.respect_ignore)
        .ignore(config.respect_ignore)
        .require_git(false)
        .filter_entry(move |e| {
            e.file_type().map_or(true, |t| !t.is_dir())
                || !crate::SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref())
        })
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .collect()
}

/// Полный прогон точного поиска. `roots` — файлы или каталоги
/// (несуществующий корень → Err, exit 2).
pub fn grep_run(roots: &[PathBuf], config: &GrepConfig) -> Result<GrepReport, String> {
    grep_run_inner(roots, config, None)
}

/// M6: grep с резидентным RAM-кэшем файлов — тёплые запросы
/// резидентного MCP-сервера идут без дискового чтения корпуса.
pub fn grep_run_cached(
    roots: &[PathBuf],
    config: &GrepConfig,
    cache: &crate::retrieval::filecache::FileCache,
) -> Result<GrepReport, String> {
    grep_run_inner(roots, config, Some(cache))
}

fn grep_run_inner(
    roots: &[PathBuf],
    config: &GrepConfig,
    cache: Option<&crate::retrieval::filecache::FileCache>,
) -> Result<GrepReport, String> {
    let started = std::time::Instant::now();
    let matcher = Matcher::build(config)?;

    let mut files: Vec<PathBuf> = Vec::new();
    for root in roots {
        if !root.exists() {
            return Err(format!("путь не найден: {}", root.display()));
        }
        files.extend(collect_grep_files(root, config));
    }
    files.sort();
    files.dedup();

    // Архивы (с --archives) сканируются ИЗНУТРИ виртуальными файлами
    // «архив::запись»; как обычные бинарники они не читаются.
    let (plain, archives): (Vec<PathBuf>, Vec<PathBuf>) = if config.scan_archives {
        files
            .into_iter()
            .partition(|p| !crate::archive::is_archive(p))
    } else {
        (files, Vec::new())
    };

    // Плоские файлы — параллельно (как раньше); архивы — тоже параллельно,
    // но каждый архив читается одним потоком последовательно (zip-дескриптор
    // не разделяем между потоками: seek + несинхронный контекст).
    let mut scans: Vec<FileScan> = plain
        .par_iter()
        .map(|p| scan_file(p, &matcher, config, cache))
        .collect();
    if !archives.is_empty() {
        let pw = config.archive_password.as_deref();
        let limits = archive_limits(config);
        // Порядок записей внутри архива уже отсортирован
        // (archive::for_each_entry); порядок самих архивов задан
        // отсортированным списком файлов, rayon .collect() сохраняет
        // индексы — вывод детерминирован.
        let arch_scans: Vec<FileScan> = archives
            .par_iter()
            .map(|a| scan_archive(a, &matcher, config, pw, &limits))
            .flatten()
            .collect();
        scans.extend(arch_scans);
    }

    let report = assemble_report(scans, config, started);
    Ok(report)
}

/// Лимиты чтения записей архива из конфига grep (0 → 64 МиБ).
fn archive_limits(config: &GrepConfig) -> crate::archive::ReadLimits {
    crate::archive::ReadLimits {
        max_entry_bytes: if config.archive_max_entry_bytes == 0 {
            crate::archive::DEFAULT_MAX_ENTRY_BYTES
        } else {
            config.archive_max_entry_bytes
        },
    }
}

/// Сканирование одного архива: каждая запись — виртуальный файл
/// «архив::запись», семантика контекста/бинарности идентична плоским
/// файлам. Ошибки отдельной записи (пароль/лимит/повреждение) —
/// сканом с error, обход продолжается.
fn scan_archive(
    path: &Path,
    matcher: &Matcher,
    config: &GrepConfig,
    password: Option<&str>,
    limits: &crate::archive::ReadLimits,
) -> Vec<FileScan> {
    let mut out: Vec<FileScan> = Vec::new();
    let res = crate::archive::for_each_entry(path, password, limits, |meta, bytes| {
        let vname = crate::archive::virtual_name(path, &meta.name);
        match bytes {
            Ok(b) => out.push(scan_bytes(&vname, &b, matcher, config)),
            Err(e) => out.push(FileScan {
                path: vname,
                binary: false,
                matched_lines: 0,
                occurrences: 0,
                groups: Vec::new(),
                error: Some(e),
            }),
        }
    });
    if let Err(e) = res {
        out.push(FileScan {
            path: path.display().to_string(),
            binary: false,
            matched_lines: 0,
            occurrences: 0,
            groups: Vec::new(),
            error: Some(e),
        });
    }
    out
}

/// Сбор архивов по корням поиска (для CLI-резолва пароля до старта
/// параллельного grep: промпт на TTY нельзя звать из rayon-воркеров).
pub fn collect_archives(
    roots: &[PathBuf],
    include_hidden: bool,
    respect_ignore: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        if root.is_file() {
            if crate::archive::is_archive(root) {
                out.push(root.to_path_buf());
            }
            continue;
        }
        let walker = WalkBuilder::new(root)
            .hidden(!include_hidden)
            .git_ignore(respect_ignore)
            .git_global(respect_ignore)
            .git_exclude(respect_ignore)
            .ignore(respect_ignore)
            .require_git(false)
            .filter_entry(move |e| {
                e.file_type().map_or(true, |t| !t.is_dir())
                    || !crate::SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref())
            })
            .build();
        for e in walker.filter_map(|e| e.ok()) {
            if e.file_type().is_some_and(|t| t.is_file()) && crate::archive::is_archive(e.path()) {
                out.push(e.into_path());
            }
        }
    }
    out
}

/// Сборка GrepReport из набора сканов (общая для grep_run и grep_buffer).
fn assemble_report(scans: Vec<FileScan>, config: &GrepConfig, started: std::time::Instant) -> GrepReport {
    let mut report = GrepReport {
        pattern: config.pattern.clone(),
        output: config.output,
        groups: Vec::new(),
        files: Vec::new(),
        stats: GrepStats {
            files_scanned: scans.len(),
            ..Default::default()
        },
    };
    for s in scans {
        if let Some(e) = s.error {
            report.stats.errors.push(e);
        }
        if s.matched_lines > 0 {
            report.stats.files_matched += 1;
        }
        report.stats.lines_matched += s.matched_lines;
        report.stats.occurrences += s.occurrences;
        match config.output {
            GrepOutput::Content => {
                // Бинарный файл: одна группа-маркер «совпадения есть».
                if s.binary && s.matched_lines > 0 {
                    report.groups.push(GrepGroup {
                        path: s.path.clone(),
                        binary: true,
                        lines: Vec::new(),
                    });
                } else {
                    report.groups.extend(s.groups);
                }
            }
            _ => report.files.push(GrepFileCounts {
                path: s.path,
                count: s.matched_lines,
                binary: s.binary,
            }),
        }
    }
    report.stats.elapsed_ms = started.elapsed().as_millis();
    report
}

/// v0.22.0 (Terminal Gateway): точный поиск по БУФЕРУ из памяти —
/// stdin конвейера (`cat notes.md | poler grep TODO`). Та же семантика
/// (контекст, бинарность, exit-коды), что и у файлового grep_run;
/// `name` — псевдоним источника в выводе (обычно "stdin").
pub fn grep_buffer(name: &str, text: &str, config: &GrepConfig) -> Result<GrepReport, String> {
    let started = std::time::Instant::now();
    let matcher = Matcher::build(config)?;
    let scan = scan_bytes(name, text.as_bytes(), &matcher, config);
    Ok(assemble_report(vec![scan], config, started))
}

/// Человекочитаемый рендер в семантике grep: `path:LINE:text`,
/// контекст через `path-LINE-text`, `--` между группами, бинарные —
/// «Binary file … matches». `color` — ANSI-подсветка вхождений.
pub fn render_text(report: &GrepReport, color: bool) -> String {
    let mut out = String::new();
    let mut prev_path: Option<&str> = None;
    match report.output {
        GrepOutput::Content => {
            for g in &report.groups {
                if g.binary {
                    out.push_str(&format!("Binary file {} matches\n", g.path));
                    continue;
                }
                if let Some(p) = prev_path {
                    if p == g.path {
                        out.push_str("--\n");
                    }
                }
                prev_path = Some(&g.path);
                for l in &g.lines {
                    let sep = if l.matched { ':' } else { '-' };
                    out.push_str(&format!("{}{}{}:", g.path, sep, l.line_no));
                    if color && !l.ranges.is_empty() {
                        out.push_str(&highlight(&l.text, &l.ranges));
                    } else {
                        out.push_str(&l.text);
                    }
                    out.push('\n');
                }
            }
        }
        GrepOutput::Count => {
            for f in &report.files {
                out.push_str(&format!("{}:{}\n", f.path, f.count));
            }
        }
        GrepOutput::ListMatching => {
            for f in report.files.iter().filter(|f| f.count > 0) {
                out.push_str(&format!("{}\n", f.path));
            }
        }
        GrepOutput::ListNonMatching => {
            for f in report.files.iter().filter(|f| f.count == 0) {
                out.push_str(&format!("{}\n", f.path));
            }
        }
    }
    out
}

/// Подсветка вхождений ANSI-красным (диапазоны не пересекаются и
/// выровнены по границам символов — см. инварианты Matcher).
fn highlight(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len() + ranges.len() * 8);
    let mut pos = 0usize;
    for &(s, e) in ranges {
        if s < pos {
            continue; // защита от пересечений
        }
        out.push_str(&text[pos..s]);
        out.push_str("\x1b[31m\x1b[1m");
        out.push_str(&text[s..e]);
        out.push_str("\x1b[0m");
        pos = e;
    }
    out.push_str(&text[pos..]);
    out
}

/// Автовыбор подсветки: терминал — да, пайп — нет.
pub fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn cfg(pattern: &str) -> GrepConfig {
        GrepConfig {
            pattern: pattern.to_string(),
            ..Default::default()
        }
    }

    fn write(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let p = dir.path().join(name);
        let parent = p.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn literal_finds_all_lines_with_numbers_and_offsets() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "a.txt", "alpha\nbeta gamma\nALPHA\n");
        let report = grep_run(&[p], &cfg("alpha")).unwrap();
        assert_eq!(report.stats.files_matched, 1);
        assert_eq!(report.stats.lines_matched, 1);
        // «ALPHA» не совпал: регистрозависимый literal
        let lines: Vec<&GrepLineOut> =
            report.groups.iter().flat_map(|g| g.lines.iter()).collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line_no, 1);
        assert_eq!(lines[0].byte_offset, 0);
        assert_eq!(lines[0].text, "alpha");
        assert_eq!(lines[0].ranges, vec![(0, 5)]);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn case_insensitive_literal_uses_unicode_fold() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "a.txt", "ГАММА-лучи\nгамма rays\nконтроль\n");
        let mut c = cfg("Гамма");
        c.case_insensitive = true;
        let report = grep_run(&[p], &c).unwrap();
        assert_eq!(report.stats.lines_matched, 2);
    }

    #[test]
    fn regex_mode_supports_classes_and_anchors() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "r.txt", "foo123\n123foo\nfoo\n");
        let mut c = cfg("^foo[0-9]+$");
        c.mode = GrepMode::Regex;
        let report = grep_run(&[p], &c).unwrap();
        assert_eq!(report.stats.lines_matched, 1);
        let l = &report.groups[0].lines[0];
        assert_eq!(l.text, "foo123");
        assert_eq!(l.ranges, vec![(0, 6)]);
    }

    #[test]
    fn invalid_regex_is_error() {
        let mut c = cfg("[unclosed");
        c.mode = GrepMode::Regex;
        assert!(grep_run(&[PathBuf::from(".")], &c).is_err());
    }

    #[test]
    fn missing_root_is_error() {
        let err =
            grep_run(&[PathBuf::from("/no/such/path/xyz")], &cfg("q")).unwrap_err();
        assert!(err.contains("не найден"));
    }

    #[test]
    fn context_after_and_before_grouping() {
        let dir = TempDir::new().unwrap();
        let text = "l1\nl2\nHIT\nl4\nl5\nl6\nHIT\nl8\nl9\n";
        let p = write(&dir, "c.txt", text);
        let mut c = cfg("HIT");
        c.before = 1;
        c.after = 1;
        let report = grep_run(&[p], &c).unwrap();
        // Два совпадения далеко друг от друга → две группы с разрывом
        assert_eq!(report.groups.len(), 2);
        let g1: Vec<(usize, bool)> = report.groups[0]
            .lines
            .iter()
            .map(|l| (l.line_no, l.matched))
            .collect();
        assert_eq!(g1, vec![(2, false), (3, true), (4, false)]);
        let g2: Vec<(usize, bool)> = report.groups[1]
            .lines
            .iter()
            .map(|l| (l.line_no, l.matched))
            .collect();
        assert_eq!(g2, vec![(6, false), (7, true), (8, false)]);
        // Рендер: разделитель -- между группами одного файла
        let rendered = render_text(&report, false);
        assert!(rendered.contains("--\n"));
        assert!(rendered.contains(":3:HIT"));
        assert!(rendered.contains("-2:l2"));
    }

    #[test]
    fn adjacent_context_merges_into_one_group() {
        let dir = TempDir::new().unwrap();
        let text = "a\nHIT\nb\nHIT\nc\n";
        let p = write(&dir, "m.txt", text);
        let mut c = cfg("HIT");
        c.before = 1;
        c.after = 2;
        let report = grep_run(&[p], &c).unwrap();
        // Контексты перекрываются → одна группа без разделителя
        assert_eq!(report.groups.len(), 1);
        let seq: Vec<(usize, bool)> = report.groups[0]
            .lines
            .iter()
            .map(|l| (l.line_no, l.matched))
            .collect();
        assert_eq!(
            seq,
            vec![(1, false), (2, true), (3, false), (4, true), (5, false)]
        );
        assert!(!render_text(&report, false).contains("--"));
    }

    #[test]
    fn count_mode_reports_per_file() {
        let dir = TempDir::new().unwrap();
        let p1 = write(&dir, "one.txt", "x\nx\ny\n");
        let p2 = write(&dir, "two.txt", "y\ny\ny\n");
        let mut c = cfg("x");
        c.output = GrepOutput::Count;
        let report = grep_run(&[p1.clone(), p2], &c).unwrap();
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files[0].count, 2);
        assert_eq!(report.files[1].count, 0);
        let rendered = render_text(&report, false);
        assert!(rendered.contains(&format!("{}:2", p1.display())));
    }

    #[test]
    fn list_matching_and_non_matching() {
        let dir = TempDir::new().unwrap();
        let p1 = write(&dir, "hit.txt", "needle here\n");
        let p2 = write(&dir, "miss.txt", "nothing\n");
        let mut c = cfg("needle");
        c.output = GrepOutput::ListMatching;
        let r = grep_run(&[p1.clone(), p2.clone()], &c).unwrap();
        let out = render_text(&r, false);
        assert!(out.contains("hit.txt") && !out.contains("miss.txt"));
        assert_eq!(r.exit_code(), 0);

        let mut c2 = cfg("needle");
        c2.output = GrepOutput::ListNonMatching;
        let r2 = grep_run(&[p1, p2], &c2).unwrap();
        let out2 = render_text(&r2, false);
        assert!(out2.contains("miss.txt") && !out2.contains("hit.txt"));
        assert_eq!(r2.exit_code(), 0); // список непуст
    }

    #[test]
    fn empty_result_exit_code_one() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "e.txt", "aaa\n");
        let report = grep_run(&[p], &cfg("zzz")).unwrap();
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.stats.files_matched, 0);
    }

    #[test]
    fn binary_files_report_marker() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "bin.dat", "ok\n\x00needle\x00\nmore\n");
        let report = grep_run(&[p], &cfg("needle")).unwrap();
        assert_eq!(report.stats.files_matched, 1);
        assert_eq!(report.groups.len(), 1);
        assert!(report.groups[0].binary);
        assert!(report.groups[0].lines.is_empty());
        let out = render_text(&report, false);
        assert!(out.contains("Binary file") && out.contains("matches"));
    }

    #[test]
    fn max_count_stops_after_n_matches() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "mm.txt", "hit\nhit\nhit\nhit\n");
        let mut c = cfg("hit");
        c.max_count = Some(2);
        let report = grep_run(&[p], &c).unwrap();
        assert_eq!(report.stats.lines_matched, 2);
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].lines.len(), 2);
    }

    #[test]
    fn max_count_flushes_trailing_context() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "mm.txt", "hit\na\nb\nc\n");
        let mut c = cfg("hit");
        c.max_count = Some(1);
        c.after = 2;
        let report = grep_run(&[p], &c).unwrap();
        // Хвост -A добирается даже после остановки по -m
        assert_eq!(report.groups[0].lines.len(), 3);
    }

    #[test]
    fn gitignore_and_skip_dirs_are_respected() {
        let dir = TempDir::new().unwrap();
        write(&dir, "keep.txt", "needle\n");
        write(&dir, "skip.log", "needle\n");
        fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();
        // .git — SKIP_DIRS движка
        let hidden = dir.path().join(".git");
        fs::create_dir_all(&hidden).unwrap();
        fs::write(hidden.join("config"), "needle\n").unwrap();

        let report = grep_run(&[dir.path().to_path_buf()], &cfg("needle")).unwrap();
        let paths: Vec<&str> = report.groups.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].ends_with("keep.txt"));
    }

    #[test]
    fn hidden_files_included_by_flag() {
        let dir = TempDir::new().unwrap();
        write(&dir, ".hidden.txt", "needle\n");
        let mut c = cfg("needle");
        c.include_hidden = true;
        let report = grep_run(&[dir.path().to_path_buf()], &c).unwrap();
        assert_eq!(report.stats.files_matched, 1);
    }

    #[test]
    fn unicode_offsets_are_byte_accurate() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "u.txt", "кириллица — текст\nsecond линия\n");
        let report = grep_run(&[p], &cfg("second")).unwrap();
        let l = &report.groups[0].lines[0];
        // «кириллица — текст\n»: 18 байт + « — » 5 байт + «текст» 10 + \n = 34
        assert_eq!(l.byte_offset, 34);
        assert_eq!(l.line_no, 2);
    }

    #[test]
    fn last_line_without_newline_is_scanned() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "n.txt", "one\ntwo");
        let report = grep_run(&[p], &cfg("two")).unwrap();
        assert_eq!(report.stats.lines_matched, 1);
        assert_eq!(report.groups[0].lines[0].line_no, 2);
    }

    #[test]
    fn crlf_lines_are_trimmed_for_display() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "crlf.txt", "aaa\r\nneedle\r\n");
        let report = grep_run(&[p], &cfg("needle")).unwrap();
        assert_eq!(report.groups[0].lines[0].text, "needle");
    }

    #[test]
    fn empty_pattern_matches_every_line() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "empty.txt", "a\nb\n");
        let report = grep_run(&[p], &cfg("")).unwrap();
        assert_eq!(report.stats.lines_matched, 2);
    }

    #[test]
    fn occurrences_count_includes_repeats_in_line() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "rep.txt", "ab ab ab\n");
        let report = grep_run(&[p], &cfg("ab")).unwrap();
        assert_eq!(report.stats.occurrences, 3);
        assert_eq!(report.stats.lines_matched, 1);
    }

    #[test]
    fn highlight_wraps_ranges_in_ansi() {
        let t = "xx needle yy";
        let h = highlight(t, &[(3, 9)]);
        assert!(h.contains("\x1b[31m\x1b[1mneedle\x1b[0m"));
    }

    #[test]
    fn report_serializes_to_json() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "j.txt", "needle\n");
        let report = grep_run(&[p], &cfg("needle")).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"byte_offset\""));
        assert!(json.contains("\"lines_matched\":1"));
    }

    #[test]
    fn multiple_roots_dedupe_paths() {
        let dir = TempDir::new().unwrap();
        let p = write(&dir, "d.txt", "needle\n");
        let report = grep_run(&[p.clone(), p.clone()], &cfg("needle")).unwrap();
        assert_eq!(report.stats.files_scanned, 1);
    }

    #[test]
    fn split_lines_handles_edge_cases() {
        let cases: Vec<(&str, Vec<(usize, usize)>)> = vec![
            ("", vec![]),
            ("\n", vec![(0, 0)]),
            ("a", vec![(0, 1)]),
            ("a\n", vec![(0, 1)]),
            ("a\nb", vec![(0, 1), (2, 3)]),
            ("\n\nx", vec![(0, 0), (1, 1), (2, 3)]),
        ];
        for (input, expected) in cases {
            let got: Vec<(usize, usize)> = split_lines(input.as_bytes()).collect();
            assert_eq!(got, expected, "input: {input:?}");
        }
    }

    // ---------- v0.28.1: скан архивов без распаковки ----------

    fn write_fixture_zip(path: &std::path::Path) {
        use std::io::Write as _;
        let f = std::fs::File::create(path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zw.start_file("docs/alpha.md", opts).unwrap();
        zw.write_all(b"# Title\n\nneedle inside archive\n").unwrap();
        zw.start_file("docs/beta.md", opts).unwrap();
        zw.write_all(b"no match here\n").unwrap();
        zw.finish().unwrap();
    }

    #[test]
    fn archives_grep_without_unpacking() {
        let dir = TempDir::new().unwrap();
        write_fixture_zip(&dir.path().join("corpus.zip"));
        write(&dir, "plain.txt", "needle in plain file\n");
        let mut config = cfg("needle");
        config.scan_archives = true;
        let report = grep_run(&[dir.path().to_path_buf()], &config).unwrap();
        // Виртуальный путь «архив::запись» в выводе
        let joined = render_text(&report, false);
        assert!(
            joined.contains("corpus.zip::docs/alpha.md"),
            "виртуальный путь в выводе:\n{joined}"
        );
        assert!(!joined.contains("beta.md"), "без совпадений не показывается");
        assert_eq!(report.stats.files_matched, 2); // запись архива + плоский файл
        assert_eq!(report.exit_code(), 0);
        // Записи архива в статистике сканирования
        assert_eq!(report.stats.files_scanned, 3); // alpha, beta, plain.txt
    }

    #[test]
    fn archives_off_by_default() {
        let dir = TempDir::new().unwrap();
        write_fixture_zip(&dir.path().join("corpus.zip"));
        let report = grep_run(&[dir.path().to_path_buf()], &cfg("needle")).unwrap();
        // Без --archives совпадений из недр архива нет (бинарный zip)
        assert_eq!(report.stats.lines_matched, 0);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn archives_encrypted_error_is_reported() {
        let dir = TempDir::new().unwrap();
        let zip_path = dir.path().join("enc.zip");
        std::fs::write(&zip_path, include_bytes!("../archive/fixtures/zipcrypto_poler.zip"))
            .unwrap();
        let mut config = cfg("субквантовая");
        config.scan_archives = true;
        // Без пароля — ошибка с подсказкой, не падение всего прогона
        let report = grep_run(&[zip_path], &config).unwrap();
        assert!(
            report
                .stats
                .errors
                .iter()
                .any(|e| e.contains("--archive-password")),
            "ошибка с подсказкой пароля: {:?}",
            report.stats.errors
        );
        // С паролем — совпадение внутри зашифрованной записи
        config.archive_password = Some("полер-ключ-2026".to_string());
        let report = grep_run(&[dir.path().join("enc.zip")], &config).unwrap();
        assert_eq!(report.stats.lines_matched, 1);
        assert!(render_text(&report, false).contains("enc.zip::secret_note.md"));
    }

    /// M6: кэшированный grep даёт ТОТ ЖЕ отчёт, что и холодный,
    /// а второй прогон идёт из RAM (hits > 0, misses не растут).
    #[test]
    fn grep_cached_matches_cold_and_warms_up() {
        use crate::retrieval::filecache::FileCache;
        let dir = TempDir::new().unwrap();
        for i in 0..12 {
            std::fs::write(
                dir.path().join(format!("doc{i}.md")),
                format!("трактат {i}: резонанс семантики повтор {i}\nпосторонняя строка\n"),
            )
            .unwrap();
        }
        let config = cfg("резонанс");

        let cold = grep_run(&[dir.path().to_path_buf()], &config).unwrap();
        let cache = FileCache::new(0);
        let warm1 = grep_run_cached(&[dir.path().to_path_buf()], &config, &cache).unwrap();
        assert_eq!(
            render_text(&cold, false), render_text(&warm1, false),
            "кэшированный прогон обязан совпадать побайтово с холодным"
        );

        let s1 = cache.stats();
        assert_eq!(s1.misses, 12, "первый прогон читает с диска");

        let warm2 = grep_run_cached(&[dir.path().to_path_buf()], &config, &cache).unwrap();
        assert_eq!(render_text(&cold, false), render_text(&warm2, false));
        let s2 = cache.stats();
        assert_eq!(s2.hits, 12, "второй прогон целиком из RAM");
        assert_eq!(s2.misses, 12, "повторных чтений диска нет");
        assert_eq!(s2.invalidated, 0);
    }
}
