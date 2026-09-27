//! Shell-state: shared state for the interactive `poler>` REPL and `--tui`
//! Dashboard. Holds lazily-opened `WebIndex` so multiple commands in one
//! session reuse the same DB connection (saves ~1 s per command over the
//! standalone CLI dispatch).
//!
//! Архитектурный инвариант: ядро движка (`poler_engine::*`) не
//! трогается — `Shell` только собирает указатели на существующие функции
//! и форматирует вывод.
//!
//! v2.0 (sovereign stack): NlmSession удалён вместе с Google/NotebookLM.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::calc::CalcState;
use crate::web::WebIndex;
use crate::notes;
use crate::sources;

/// Путь к каталогу кэша poler-engine (`~/.cache/poler-engine/`).
pub fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".cache").join("poler-engine")
}

/// Путь к файлу истории команд REPL (`~/.cache/poler-engine/shell-history.txt`).
pub fn history_path() -> PathBuf {
    cache_dir().join("shell-history.txt")
}

/// Состояние одной интерактивной сессии `poler-shell`.
///
/// `db_path` фиксируется при запуске (по умолчанию
/// `crate::web::default_db_path()`); `WebIndex` и соединения к
/// notes/sources открываются **лениво** — первый `search`/`stats` открывает
/// БД. После этого переиспользуются до выхода из шелла.
pub struct ShellState {
    db_path: PathBuf,
    /// Ленимо открываемый web-index. None = ещё не открывали.
    ix: Option<WebIndex>,
    /// Ленимо открываемое соединение к poler_notes (та же БД, другая таблица).
    notes_conn: Option<rusqlite::Connection>,
    /// Ленимо открываемое соединение к poler_sources (та же БД).
    sources_conn: Option<rusqlite::Connection>,
    /// Текущий формат вывода (переключается `poler> set format md|json|ai-json`).
    pub format: OutputFormat,
    /// Top-K по умолчанию для `search` (переключается `set top N`).
    pub top: usize,
    /// Последний ответ команды (для TUI: правая нижняя панель показывает это).
    pub last_output: String,
    /// v0.48.0: состояние «Калькулятора Всего» — переменные + история.
    pub calc: CalcState,
}

/// Формат вывода, как в CLI `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum OutputFormat {
    /// JSON для LLM-агентов (по умолчанию).
    AiJson,
    /// Markdown для человека.
    #[default]
    Md,
    /// Простой текст.
    Simple,
}


impl ShellState {
    /// Создать состояние шелла с путём к web-index.db.
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            ix: None,
            notes_conn: None,
            sources_conn: None,
            format: OutputFormat::default(),
            top: 10,
            last_output: String::new(),
            calc: CalcState::new(),
        }
    }

    /// Путь к web-index.db (для статус-бара TUI).
    pub fn db_path(&self) -> &PathBuf {
        &self.db_path
    }

    /// Список доступных команд для Tab-completion и `help`.
    pub fn commands() -> &'static [&'static str] {
        static COMMANDS: OnceLock<Vec<&'static str>> = OnceLock::new();
        COMMANDS.get_or_init(|| {
            vec![
                "help", "quit", "exit", "?",
                "search", "web", "stats",
                "crawl", "impact",
                "set", "version",
                // v0.16.0: Unified VCS & Data Mesh
                "gh", "gl", "gt", "gix",
                // v0.17.0: Notes & Sources CRUD
                "notes", "sources",
                // v0.16.0: vcs-sync alias
                "sync",
                // v0.47.0: Win+Linux словарь и среда агента
                "cd", "pwd", "clear", "engine",
                "sysinfo", "env", "agent", "pty", "win",
                // v0.47.0: POLER Reader
                "read", "reader",
                // v0.48.0: Калькулятор Всего
                "calc", "hw",
                // v0.51.0 (цикл P): квантовый мост
                "quantum", "qm",
            ]
        })
    }

    /// v0.16.0: Подкоманды `gh`/`gl`/`gt` (одинаковые для всех REST-адаптеров).
    pub fn vcs_subcommands() -> &'static [&'static str] {
        &["search", "repos", "commits", "issues"]
    }

    /// v0.16.0: Подкоманды `gix` (Pure-Rust git).
    pub fn gix_subcommands() -> &'static [&'static str] {
        &["log", "clone"]
    }

    /// v0.16.0: Схемы VCS для `sync vcs <scheme>` completion.
    pub fn vcs_schemes() -> &'static [&'static str] {
        &["gh", "gl", "gt", "gix", "all"]
    }

    /// Именованные параметры `set ...` для Tab-completion.
    pub fn set_keys() -> &'static [&'static str] {
        &["format", "top"]
    }

    /// v0.17.0: Подкоманды `notes ...` для Tab-completion.
    pub fn notes_subcommands() -> &'static [&'static str] {
        &["list", "add", "show", "edit", "rm"]
    }

    /// v0.17.0: Подкоманды `sources ...` для Tab-completion.
    pub fn sources_subcommands() -> &'static [&'static str] {
        &["list", "add", "rm", "test", "open"]
    }

    /// v0.17.0: Подкоманды `sources add --kind ...`.
    pub fn source_kinds() -> &'static [&'static str] {
        &["file", "url", "repo"]
    }

    /// Заимствовать `&mut WebIndex`, открыв ленимо если нужно.
    pub fn ensure_index(&mut self) -> Result<&mut WebIndex, String> {
        if self.ix.is_none() {
            let ix = WebIndex::open(&self.db_path)
                .map_err(|e| format!("web-index {:?}: {e}", self.db_path))?;
            self.ix = Some(ix);
        }
        Ok(self.ix.as_mut().expect("ix just set"))
    }

    /// Установить формат вывода по имени.
    pub fn set_format(&mut self, name: &str) -> Result<(), String> {
        self.format = match name.to_ascii_lowercase().as_str() {
            "md" | "markdown" => OutputFormat::Md,
            "json" | "ai-json" | "aijson" => OutputFormat::AiJson,
            "simple" | "text" | "txt" => OutputFormat::Simple,
            other => return Err(format!("неизвестный формат: {other} (md|json|simple)")),
        };
        Ok(())
    }

    /// Записать последний вывод (для отображения в TUI).
    pub fn set_output(&mut self, s: impl Into<String>) {
        self.last_output = s.into();
    }

    /// v0.17.0: Ленимо открыть соединение к poler_notes (та же БД, таблица poler_notes).
    pub fn ensure_notes_conn(&mut self) -> Result<&mut rusqlite::Connection, String> {
        if self.notes_conn.is_none() {
            self.notes_conn = Some(notes::open(&self.db_path)?);
        }
        Ok(self.notes_conn.as_mut().expect("notes_conn just set"))
    }

    /// v0.17.0: Ленимо открыть соединение к poler_sources (та же БД).
    pub fn ensure_sources_conn(&mut self) -> Result<&mut rusqlite::Connection, String> {
        if self.sources_conn.is_none() {
            self.sources_conn = Some(sources::open(&self.db_path)?);
        }
        Ok(self.sources_conn.as_mut().expect("sources_conn just set"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_state_lazy_open() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("test.db");
        let mut s = ShellState::new(db.clone());
        assert!(s.ix.is_none(), "ix should be None until first call");
        let _ = s.ensure_index();
        assert!(s.ix.is_some(), "ix should be Some after ensure_index");
    }

    #[test]
    fn set_format_parsing() {
        let mut s = ShellState::new(PathBuf::from("/tmp/x.db"));
        assert_eq!(s.format, OutputFormat::Md);
        s.set_format("json").unwrap();
        assert_eq!(s.format, OutputFormat::AiJson);
        s.set_format("markdown").unwrap();
        assert_eq!(s.format, OutputFormat::Md);
        s.set_format("text").unwrap();
        assert_eq!(s.format, OutputFormat::Simple);
        assert!(s.set_format("xml").is_err(), "xml should be rejected");
    }

    #[test]
    fn commands_list_is_stable() {
        let cmds = ShellState::commands();
        assert!(cmds.contains(&"search"));
        assert!(cmds.contains(&"notes"));
        assert!(cmds.contains(&"quit"));
        assert!(cmds.contains(&"exit"));
        assert!(!cmds.contains(&"nlm"), "v2.0: nlm удалён");
        assert!(cmds.contains(&"calc"), "v0.48.0: калькулятор");
        assert!(cmds.contains(&"hw"), "v0.48.0: зонд железа");
    }
}
