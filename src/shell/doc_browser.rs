//! # Doc Browser: источник → документы → просмотр (TUI v0.17.3+)
//!
//! Чистая логика двухуровневой навигации Sources panel:
//!
//! ```text
//! Sources panel          Doc Browser (popup)      Doc Viewer (popup)
//! ┌────────────────┐  Enter/клик  ┌──────────────┐  Enter/клик  ┌────────────┐
//! │ 📄 My PDF      │ ───────────► │ 📜 My PDF    │ ───────────► │ # My PDF   │
//! │ 🎬 Video       │              │ 🖼 Слайд 1   │              │ текст…     │
//! │ 📁 ./src       │              │ 📁 ..        │              │ (scroll)   │
//! └────────────────┘              └──────────────┘              └────────────┘
//! ```
//!
//! Локальные источники (v2.0: NLM-источники удалены вместе с Google):
//!
//! | Источник | Документы внутри |
//! |---|---|
//! | локальный `file`-каталог | файлы и подкаталоги (с «..» наверх) |
//! | локальный `file`-файл | сам файл |
//! | локальный `url` | страница (фетч `ureq` при открытии) |
//! | локальный `repo` | инфо + ссылка на GitHub |
//!
//! Модуль не знает про ratatui/crossterm — только данные, поэтому всё
//! покрыто юнит-тестами без TTY. TUI-обвязка (Mode/оверлеи/мышь) — в
//! [`crate::shell::tui`].

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::sources::{Source, SourceKind};

/// Лимит тела документа для просмотрщика (2 МБ) — защита от гигантских
/// файлов, которые убили бы рендер Paragraph.
pub const MAX_DOC_BYTES: usize = 2 * 1024 * 1024;

/// Максимум записей при листинге директории.
pub const MAX_DIR_ENTRIES: usize = 500;

/// Ссылка на источник в Sources panel — локальный (poler_sources).
/// v2.0: вариант `Nlm` удалён вместе с Google/NotebookLM.
#[derive(Debug, Clone)]
pub enum SourceRef {
    /// Локальный источник из таблицы poler_sources.
    Local { src: Source },
}

/// Что открывает Doc Viewer, когда на документе нажали Enter/клик.
/// v2.0: варианты `NlmText`/`NlmMedia` удалены вместе с Google/NotebookLM.
#[derive(Debug, Clone)]
pub enum DocKind {
    /// Локальный файл — чтение с диска при открытии.
    LocalFile { path: PathBuf },
    /// Каталог — клик drill-down'ом уходит в новый листинг.
    LocalDir { path: PathBuf },
    /// Веб-страница — ureq-фетч при открытии.
    WebPage { url: String },
    /// Инфо-текст (ошибки, подсказки); опционально внешняя ссылка для «o».
    Info {
        text: String,
        open_url: Option<String>,
    },
}

/// Строка в списке документов.
#[derive(Debug, Clone)]
pub struct DocEntry {
    pub title: String,
    /// Подсказка справа: размер, «текст • N симв.», «медиа»…
    pub hint: String,
    pub kind: DocKind,
}

/// Иконка документа для списка.
pub fn doc_icon(kind: &DocKind) -> &'static str {
    match kind {
        DocKind::LocalFile { .. } => "📄",
        DocKind::LocalDir { .. } => "📁",
        DocKind::WebPage { .. } => "🌐",
        DocKind::Info { .. } => "ℹ",
    }
}

/// Human-readable размер файла: `980 B`, `1.4 KB`, `2.1 MB`.
pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn info_entry(text: impl Into<String>, open_url: Option<String>) -> DocEntry {
    DocEntry {
        title: "Инфо".into(),
        hint: String::new(),
        kind: DocKind::Info {
            text: text.into(),
            open_url,
        },
    }
}

/// Список документов локального источника (poler_sources).
pub fn local_source_documents(src: &Source) -> Vec<DocEntry> {
    match src.kind {
        SourceKind::File => {
            let p = Path::new(&src.value);
            if !p.exists() {
                vec![info_entry(
                    format!(
                        "Файл или каталог не найден на диске:\n  {}\n\nИсточнику #{} нужен `sources test` / актуальный путь.",
                        src.value, src.id
                    ),
                    None,
                )]
            } else if p.is_dir() {
                match dir_documents(p, MAX_DIR_ENTRIES) {
                    Ok(mut docs) => {
                        // «..» — наверх по дереву (добавляем первым).
                        if let Some(parent) = p.parent() {
                            docs.insert(
                                0,
                                DocEntry {
                                    title: "..".into(),
                                    hint: "родительский каталог".into(),
                                    kind: DocKind::LocalDir {
                                        path: parent.to_path_buf(),
                                    },
                                },
                            );
                        }
                        docs
                    }
                    Err(e) => vec![info_entry(format!("⚠ {e}"), None)],
                }
            } else {
                let hint = std::fs::metadata(p)
                    .map(|m| human_size(m.len()))
                    .unwrap_or_default();
                vec![DocEntry {
                    title: p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| src.value.clone()),
                    hint,
                    kind: DocKind::LocalFile {
                        path: p.to_path_buf(),
                    },
                }]
            }
        }
        SourceKind::Url => vec![DocEntry {
            title: short_url(&src.value),
            hint: "веб".into(),
            kind: DocKind::WebPage {
                url: src.value.clone(),
            },
        }],
        SourceKind::Repo => {
            let url = format!("https://github.com/{}", src.value);
            vec![info_entry(
                format!(
                    "Репозиторий: {}\n\nФайлы репозитория не загружены локально.\nНажмите o — открыть {} в браузере,\nили `gh repos {}` в строке ввода — REST-профиль.",
                    src.value, url, src.value
                ),
                Some(url),
            )]
        }
    }
}

/// Короткое имя URL для списка: без схемы, обрезано до 48 символов.
pub fn short_url(url: &str) -> String {
    let s = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    if s.chars().count() > 48 {
        let cut: String = s.chars().take(45).collect();
        format!("{cut}…")
    } else {
        s.to_string()
    }
}

/// Листинг директории: сначала каталоги, потом файлы, оба сортированы.
/// Без «..» — его добавляет вызывающий код (он знает о корне источника).
pub fn dir_documents(path: &Path, limit: usize) -> Result<Vec<DocEntry>, String> {
    let entries =
        std::fs::read_dir(path).map_err(|e| format!("read_dir {}: {e}", path.display()))?;
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    let mut files: Vec<(String, PathBuf, u64)> = Vec::new();
    let mut total = 0usize;
    for e in entries.flatten() {
        total += 1;
        let name = e.file_name().to_string_lossy().to_string();
        let p = e.path();
        let meta = e.metadata().ok();
        if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
            dirs.push((name, p));
        } else {
            files.push((name, p, meta.map(|m| m.len()).unwrap_or(0)));
        }
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut docs: Vec<DocEntry> = Vec::new();
    let mut truncated = false;
    for (name, p) in dirs {
        if docs.len() >= limit {
            truncated = true;
            break;
        }
        docs.push(DocEntry {
            title: name,
            hint: "каталог".into(),
            kind: DocKind::LocalDir { path: p },
        });
    }
    for (name, p, len) in files {
        if docs.len() >= limit {
            truncated = true;
            break;
        }
        docs.push(DocEntry {
            title: name,
            hint: human_size(len),
            kind: DocKind::LocalFile { path: p },
        });
    }
    if truncated {
        docs.push(info_entry(
            format!("Лимит {limit} записей; всего в каталоге {total}."),
            None,
        ));
    }
    Ok(docs)
}

/// Похоже ли содержимое на бинарник (NUL-байт в первых 8 КБ).
fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

/// Прочитать локальный файл как текст для просмотрщика.
///
/// Ошибки (нет файла / слишком большой / бинарный) — честными строками:
/// просмотрщик покажет их вместо контента, «o» откроет внешним редактором.
pub fn read_local_document(path: &Path, max_bytes: usize) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        return Err(format!("{} — это каталог.", path.display()));
    }
    let len = meta.len() as usize;
    if len > max_bytes {
        return Err(format!(
            "файл слишком большой: {} (лимит {})",
            human_size(len as u64),
            human_size(max_bytes as u64)
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if is_binary(&bytes) {
        return Err(format!(
            "бинарный файл — просмотр в терминале недоступен (o — открыть внешне)"
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Скачивание веб-страницы (или иного ресурса) для просмотрщика.
///
/// `ureq` — тот же синхронный клиент, что в VCS-адаптерах (без tokio).
/// HTML чистится через [`html_to_text`] (теги/script/style → текст),
/// остальное отдаётся как есть. Тело читается с лимитом `max_bytes`.
pub fn fetch_web_document(url: &str, max_bytes: usize) -> Result<String, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .build();
    let resp = agent
        .get(url)
        .set(
            "User-Agent",
            concat!("poler-engine/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let is_html = resp
        .header("content-type")
        .map(|v| v.to_ascii_lowercase().contains("html"))
        .unwrap_or(true);
    let mut reader = resp.into_reader().take(max_bytes.saturating_add(1) as u64);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("чтение тела {url}: {e}"))?;
    let truncated = bytes.len() > max_bytes;
    if truncated {
        bytes.truncate(max_bytes);
    }
    let mut text = String::from_utf8_lossy(&bytes).to_string();
    if is_html {
        text = html_to_text(&text);
    }
    if truncated {
        text.push_str("\n\n… (обрезано по лимиту ");
        text.push_str(&human_size(max_bytes as u64));
        text.push(')');
    }
    Ok(text)
}

/// HTML → читаемый текст: выкинуть script/style, снять теги, подставить
/// переводы строк у блочных элементов, декодировать базовые сущности,
/// схлопнуть пустые строки (`clean_text`).
pub fn html_to_text(html: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<(Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    let (re_script, re_style, re_br, re_block, re_tag) = RE.get_or_init(|| {
        (
            Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap(),
            Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap(),
            Regex::new(r"(?i)<br\s*/?>").unwrap(),
            Regex::new(r"(?i)</(p|div|li|tr|h[1-6])>").unwrap(),
            Regex::new(r"(?s)<[^>]*>").unwrap(),
        )
    });
    let mut s = re_script.replace_all(html, "").to_string();
    s = re_style.replace_all(&s, "").to_string();
    s = re_br.replace_all(&s, "\n").to_string();
    s = re_block.replace_all(&s, "\n").to_string();
    s = re_tag.replace_all(&s, "").to_string();
    s = decode_entities(&s);
    crate::web::extract::clean_text(&s, MAX_DOC_BYTES)
}

/// Декодирование HTML-сущностей: именные + числовые (`&#39;`, `&#x27;`).
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find('&') {
        out.push_str(&rest[..idx]);
        let tail = &rest[idx..];
        let Some(end) = tail.find(';') else {
            // нет закрывающей ';' — это просто амперсанд
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..end]; // между '&' и ';'
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "rsquo" => Some('\''),
            "nbsp" => Some(' '),
            "mdash" => Some('—'),
            "ndash" => Some('–'),
            "hellip" => Some('…'),
            "laquo" => Some('«'),
            "raquo" => Some('»'),
            _ => {
                if let Some(num) = entity.strip_prefix('#') {
                    let code = if let Some(hex) =
                        num.strip_prefix('x').or_else(|| num.strip_prefix('X'))
                    {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        num.parse::<u32>().ok()
                    };
                    code.and_then(char::from_u32)
                } else {
                    None
                }
            }
        };
        match decoded {
            Some(c) => out.push(c),
            None => {
                // неизвестная сущность — оставляем как есть
                out.push_str(&tail[..end + 1]);
            }
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn file_entry(path: &Path) -> DocEntry {
        DocEntry {
            title: path.file_name().unwrap().to_string_lossy().to_string(),
            hint: String::new(),
            kind: DocKind::LocalFile {
                path: path.to_path_buf(),
            },
        }
    }

    // ---- human_size ----

    #[test]
    fn human_size_units() {
        assert_eq!(human_size(980), "980 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(2 * 1024 * 1024), "2.0 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    // ---- dir_documents ----

    #[test]
    fn dir_documents_dirs_first_sorted() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("b.txt"), "bbb").unwrap();
        std::fs::write(dir.path().join("a.txt"), "aaa").unwrap();
        std::fs::create_dir(dir.path().join("zdir")).unwrap();
        std::fs::create_dir(dir.path().join("adir")).unwrap();

        let docs = dir_documents(dir.path(), 100).unwrap();
        let titles: Vec<&str> = docs.iter().map(|d| d.title.as_str()).collect();
        assert_eq!(titles, vec!["adir", "zdir", "a.txt", "b.txt"]);
        assert!(matches!(docs[0].kind, DocKind::LocalDir { .. }));
        assert!(matches!(docs[2].kind, DocKind::LocalFile { .. }));
        assert_eq!(docs[2].hint, "3 B");
    }

    #[test]
    fn dir_documents_truncation_marks_limit() {
        let dir = tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), "x").unwrap();
        }
        let docs = dir_documents(dir.path(), 3).unwrap();
        assert_eq!(docs.len(), 4); // 3 файла + инфо о лимите
        assert!(matches!(docs[3].kind, DocKind::Info { .. }));
        let DocKind::Info { text, .. } = &docs[3].kind else {
            unreachable!()
        };
        assert!(text.contains("Лимит 3"), "текст: {text}");
    }

    #[test]
    fn dir_documents_missing_dir_is_err() {
        assert!(dir_documents(Path::new("/nonexistent-xyz"), 10).is_err());
    }

    // ---- local_source_documents ----

    #[test]
    fn local_source_dir_lists_with_dotdot() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("x.md"), "hello").unwrap();

        let src = Source {
            id: 1,
            kind: SourceKind::File,
            value: sub.to_string_lossy().to_string(),
            label: None,
            added_at: 0,
            last_tested_at: None,
            last_status: "ok".into(),
        };
        let docs = local_source_documents(&src);
        // «..» (родитель tempdir) + каталог dir? нет — sub содержит только x.md
        let titles: Vec<&str> = docs.iter().map(|d| d.title.as_str()).collect();
        assert_eq!(titles.first(), Some(&".."));
        assert!(titles.contains(&"x.md"));
        let DocKind::LocalDir { path } = &docs[0].kind else {
            panic!("первая запись должна быть LocalDir «..»");
        };
        assert_eq!(path, sub.parent().unwrap());
    }

    #[test]
    fn local_source_single_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("note.txt");
        std::fs::write(&f, "привет").unwrap();
        let src = Source {
            id: 2,
            kind: SourceKind::File,
            value: f.to_string_lossy().to_string(),
            label: None,
            added_at: 0,
            last_tested_at: None,
            last_status: "ok".into(),
        };
        let docs = local_source_documents(&src);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].title, "note.txt");
        assert_eq!(docs[0].hint, "12 B"); // «привет» = 12 байт UTF-8
        assert!(matches!(docs[0].kind, DocKind::LocalFile { .. }));
    }

    #[test]
    fn local_source_missing_file_is_info() {
        let src = Source {
            id: 3,
            kind: SourceKind::File,
            value: "/nonexistent-xyz/f.txt".into(),
            label: None,
            added_at: 0,
            last_tested_at: None,
            last_status: "unknown".into(),
        };
        let docs = local_source_documents(&src);
        assert_eq!(docs.len(), 1);
        assert!(matches!(docs[0].kind, DocKind::Info { .. }));
    }

    #[test]
    fn local_source_url_and_repo() {
        let url_src = Source {
            id: 4,
            kind: SourceKind::Url,
            value: "https://doc.rust-lang.org/std/".into(),
            label: None,
            added_at: 0,
            last_tested_at: None,
            last_status: "ok".into(),
        };
        let docs = local_source_documents(&url_src);
        assert!(matches!(docs[0].kind, DocKind::WebPage { .. }));
        assert_eq!(docs[0].title, "doc.rust-lang.org/std/");

        let repo_src = Source {
            id: 5,
            kind: SourceKind::Repo,
            value: "rust-lang/rust".into(),
            label: None,
            added_at: 0,
            last_tested_at: None,
            last_status: "ok".into(),
        };
        let docs = local_source_documents(&repo_src);
        let DocKind::Info { open_url, .. } = &docs[0].kind else {
            panic!("repo должен давать Info");
        };
        assert_eq!(
            open_url.as_deref(),
            Some("https://github.com/rust-lang/rust")
        );
    }

    // ---- read_local_document ----

    #[test]
    fn read_local_document_text_ok() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("a.md");
        std::fs::write(&f, "# Заголовок\n\nтекст").unwrap();
        let text = read_local_document(&f, 1024).unwrap();
        assert!(text.contains("Заголовок"));
    }

    #[test]
    fn read_local_document_binary_rejected() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("blob.bin");
        std::fs::write(&f, [0x50u8, 0x4b, 0x00, 0x01, 0x02]).unwrap();
        let err = read_local_document(&f, 1024).unwrap_err();
        assert!(err.contains("бинарный"));
    }

    #[test]
    fn read_local_document_too_big_rejected() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("big.txt");
        std::fs::write(&f, "0123456789").unwrap();
        let err = read_local_document(&f, 5).unwrap_err();
        assert!(err.contains("слишком большой"));
    }

    #[test]
    fn read_local_document_missing_is_err() {
        assert!(read_local_document(Path::new("/no-such-file.txt"), 100).is_err());
    }

    // ---- html_to_text / decode_entities ----

    #[test]
    fn html_to_text_strips_script_style_tags() {
        let html = r#"<html><head><style>body { color: red }</style></head>
<body><script>alert("x")</script><h1>Привет</h1><p>Мир &amp; <b>люди</b></p>
<a href="x">ссылка</a><br>хвост</body></html>"#;
        let text = html_to_text(html);
        assert!(!text.contains("<"), "остались теги: {text}");
        assert!(!text.contains("alert"), "script не выкинут: {text}");
        assert!(!text.contains("color: red"), "style не выкинут: {text}");
        assert!(text.contains("Привет"), "нет заголовка: {text}");
        assert!(
            text.contains("Мир & люди"),
            "сущность не декодирована: {text}"
        );
        assert!(text.contains("ссылка"));
        assert!(text.contains("хвост"));
    }

    #[test]
    fn decode_entities_named_and_numeric() {
        assert_eq!(decode_entities("a&amp;b"), "a&b");
        assert_eq!(decode_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(
            decode_entities("&#1042;&#1110;&#1090;"),
            "Вітаю".chars().take(3).collect::<String>()
        );
        assert_eq!(decode_entities("it&apos;s"), "it's");
        assert_eq!(decode_entities("a&nbsp;b"), "a b");
        assert_eq!(decode_entities("&unknown;"), "&unknown;");
        assert_eq!(decode_entities("bare & amp"), "bare & amp");
        assert_eq!(decode_entities("&#x41;"), "A");
    }

    // ---- short_url ----

    #[test]
    fn short_url_truncates_long() {
        assert_eq!(short_url("https://a.b/c"), "a.b/c");
        let long = format!("https://example.com/{}", "x".repeat(80));
        let s = short_url(&long);
        assert!(s.chars().count() <= 49);
        assert!(s.ends_with('…'));
    }

    // ---- doc_icon ----

    #[test]
    fn doc_icon_covers_all_kinds() {
        assert_eq!(
            doc_icon(&DocKind::LocalFile {
                path: PathBuf::from("/tmp/a")
            }),
            "📄"
        );
        assert_eq!(
            doc_icon(&DocKind::LocalDir {
                path: PathBuf::from("/tmp")
            }),
            "📁"
        );
        assert_eq!(doc_icon(&DocKind::WebPage { url: String::new() }), "🌐");
        assert_eq!(
            doc_icon(&DocKind::Info {
                text: String::new(),
                open_url: None
            }),
            "ℹ"
        );
    }

    #[test]
    fn file_entry_helper_compiles() {
        let e = file_entry(Path::new("/tmp/x.rs"));
        assert_eq!(e.title, "x.rs");
    }
}
