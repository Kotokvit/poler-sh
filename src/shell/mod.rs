//! # poler-shell — интерактивный терминал poler-engine
//!
//! Две поверхности для человеческого удобства поверх существующих режимов
//! движка (ядро `poler_engine::*` не трогается):
//!
//! 1. **REPL `poler-engine --shell`** (rustyline) — быстрый командный режим
//!    с Tab-completion и историей `↑/↓`, без перезапуска процесса:
//!    ```text
//!    poler> search "Касіопея Astra-Nic" --top 5
//!    poler> stats
//!    poler> set format json
//!    poler> quit
//!    ```
//! 2. **TUI Dashboard `poler-engine --tui`** (ratatui + crossterm) — layout:
//!    центр (chat + ввод), правая колонка (notes + sources).
//!    Tab — смена фокуса, Esc — выход.
//!
//! ## Архитектурные инварианты
//!
//! - **Ноль изменений в ядре** — `poler_engine::*` остаётся как есть.
//!   Shell только заимствует `WebIndex` и форматирует вывод для человека.
//! - **Ленивое открытие ресурсов** — `WebIndex` открывается только при
//!   первом использовании (первый `search`/`stats` открывает БД). После
//!   этого переиспользуется до выхода из шелла.
//! - **История команд** сохраняется в `~/.cache/poler-engine/shell-history.txt`
//!   (до 2000 команд, max_history по умолчанию в rustyline).
//!
//! v2.0: NLM/Google-интеграции удалены (суверенный стек) — см. PLAN_POLER_V2.

pub mod commands;
pub mod completer;
pub mod confirm;
pub mod doc_browser;
pub mod help;
pub mod mouse;
pub mod state;
pub mod transcript;
pub mod tui;
// v0.47.0: Windows-словарь + среда для ИИ-агентов
pub mod agentenv;
pub mod wincompat;

pub use commands::{dispatch, run_shell, tokenize, CmdResult};
pub use state::{ShellState, OutputFormat};
pub use tui::run_tui;

/// Тихо открыть URL в браузере пользователя (xdg-open и аналоги).
/// В песочнице/SSH xdg-open может отсутствовать — тогда URL просто
/// печатается в терминал вызывающим кодом.
///
/// v2.0: перенесено из `google/mod.rs` при отвязке от Google — утилита
/// общесистемная (открыть источник/ссылку), к облачным сервисам отношения
/// не имеет.
pub fn open_in_user_browser(url: &str) {
    for opener in ["xdg-open", "sensible-browser", "x-www-browser"] {
        if std::process::Command::new(opener)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            return;
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn tokenize_handles_quoted_args() {
        let t = tokenize("search \"запрос с пробелами\" --top 5");
        assert_eq!(t, vec!["search", "запрос с пробелами", "--top", "5"]);
    }

    #[test]
    fn state_default_format_is_md_for_humans() {
        let s = ShellState::new(PathBuf::from("/tmp/x.db"));
        assert_eq!(s.format, OutputFormat::Md, "interactive shell defaults to markdown for humans");
    }

    #[test]
    fn commands_dispatch_unknown_returns_message() {
        let mut s = ShellState::new(PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "zzzbadcmd") {
            CmdResult::Done(out) => assert!(out.contains("неизвестная команда")),
            _ => panic!(),
        }
    }
}
