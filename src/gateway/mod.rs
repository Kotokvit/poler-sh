//! # POLER Terminal Gateway (v0.22.0)
//!
//! **Unified Host Shell / Terminal REPL** — верхний уровень управления
//! POLER Engine на Linux/macOS. Единое окно терминала с двойным контуром
//! исполнения:
//!
//! 1. **Engine Native (приоритет)** — команды движка (`search`, `grep`,
//!    `chunk`, `crawl`, `notes`, `weblens`, `impact`, `benchmark`…)
//!    исполняются внутри процесса, без спавна внешних шеллов;
//! 2. **Controlled Host OS Proxy** — прочие команды идут в хостовую ОС
//!    через Sandboxed OS Subshell: блок деструктивного, подтверждение
//!    эскалаций, кап вывода, таймаут, фильтр env.
//!
//! Конвейеры смешивают контуры (`ls | chunk`, `grep x --stdin | wc -l`),
//! сервисный слой управляется командами `service`/`attach`.
//!
//! Запуск: `poler-engine --gateway`.
//! Архитектура: docs/terminal-gateway-architecture.md.
//! Лицензия: banner ниже — Source-Available EULA v1.0 (TERMS.md).

pub mod completer;
pub mod containers;
pub mod dispatch;
pub mod hostexec;
pub mod hunter;
pub mod pipeline;
pub mod rootbroker;
pub mod sandbox;
pub mod sentinel;
pub mod service;
pub mod shim;

pub use dispatch::{exec_line, GatewayResult, GatewayState};

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// ANSI-подсветка только в tty (канон из v0.20.0 grep).
fn stdout_is_tty() -> bool {
    // избегаем новой зависимости: isatty через /proc/self/fd недоступен
    // на macOS; используем TERM-эвристику + rustyline-контекст невозможен
    // здесь. Практика движка: std::io::IsTerminal (stable с 1.70).
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Баннер запуска: версия, EULA-условия (Source-Available),
/// контуры + PTY.
/// v2.0: тир лицензии удалён вместе с Ed25519-гейтом.
pub fn banner() -> String {
    let tty = stdout_is_tty();
    let (bold, dim, cyan, reset) = if tty {
        ("\x1b[1m", "\x1b[2m", "\x1b[36m", "\x1b[0m")
    } else {
        ("", "", "", "")
    };
    let mut s = String::new();
    s.push_str(&format!(
        "{bold}POLER Engine {} — Terminal Gateway{reset}\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str(&format!("{cyan}Лицензия: Sovereign (v2.0).{reset} {}\n", crate::license::eula_banner_line()));
    s.push('\n');
    s.push_str("Контуры исполнения:\n");
    s.push_str(&format!(
        "  1 {bold}engine-native{reset} — search · grep · chunk · crawl · impact · notes · benchmark …\n"
    ));
    s.push_str(&format!(
        "  2 {dim}host-os-proxy{reset} — системные команды в sandbox (деструктивное блокируется)\n"
    ));
    s.push_str(&format!(
        "  3 {dim}pty-passthrough{reset} — TUI/IDE/агенты (vim · htop · agy); агенты — в медиации\n"
    ));
    s.push_str(&format!(
        "  {bold}🛡 workspace-guard{reset} — доступ вне корня проекта — только по подтверждению;\n   cd/workspace на выход — тоже; allow <путь> — сессионное исключение\n"
    ));
    s.push_str(&format!(
        "  {bold}📦 box — Container Jail{reset} — контуры 2/3 внутри Docker: агент заперт физически; агенты пробрасываются без установки (ro); runner — контур исполнения MCP-брокера (poler_box_exec); 🔐 рут-брокер (box sudo — рут остаётся у хоста, агент просит; box sudo passwd — рут по паролю владельца); 🎯 jailbreak-sentinel + 🤖 builtin-hunter (box hunt — свой красный суб-агент POLER атакует клетку чёрным ящиком изнутри; kill-switch)\n"
    ));
    s.push('\n');
    s.push_str("help — список команд · quit — выход · docs/terminal-gateway-architecture.md\n");
    s
}

/// Красный баннер danger-режима (v0.23.0): печатается при старте с
/// --dangerously-allow-all и при `set sandbox off`.
pub fn danger_banner() -> String {
    let tty = stdout_is_tty();
    let (red, bold, reset) = if tty {
        ("\x1b[31m", "\x1b[1m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    format!(
        "{red}{bold}☠ DANGER MODE: sandbox ПОЛНОСТЬЮ ОТКЛЮЧЁН ВЛАДЕЛЬЦЕМ.{reset}\n{red}Все команды, включая деструктивные, исполняются без проверок.\nВся ответственность за безопасность хоста лежит на операторе.{reset}\n\n"
    )
}

/// Файл истории gateway (отдельный от внутреннего --shell).
fn history_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache/poler-engine/gateway-history.txt")
}

/// Точка входа: `poler-engine --gateway [--dangerously-allow-all]`.
/// `danger_allow_all` — явный отказ от sandbox владельцем (красный баннер,
/// ответственность оператора; см. v0.23.0).
pub fn run_gateway(db_path: PathBuf, danger_allow_all: bool) -> ExitCode {
    use rustyline::config::Configurer;
    use rustyline::error::ReadlineError;
    use rustyline::history::DefaultHistory;
    use rustyline::Editor;

    // SIGINT во время исполнения хостовых команд: флаг проверяет hostexec.
    // Регистрация может «занять место» хендлера watcher-режима — но они
    // не работают одновременно (gateway = самостоятельный режим).
    let _ = ctrlc::set_handler(|| {
        hostexec::INTERRUPT.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let hist = history_path();
    if let Some(parent) = hist.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut rl = match Editor::<completer::GatewayCompleter, DefaultHistory>::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("poler-gateway: rustyline init: {e}");
            return ExitCode::from(2);
        }
    };
    let _ = rl.set_max_history_size(5000);
    let _ = rl.set_history_ignore_dups(true);
    rl.set_completion_type(rustyline::config::CompletionType::List);
    rl.set_auto_add_history(true);
    rl.set_helper(Some(completer::GatewayCompleter::default()));
    let _ = rl.load_history(&hist);

    print!("{}", banner());
    if danger_allow_all {
        print!("{}", danger_banner());
    }
    let _ = std::io::stdout().flush();

    let mut state = GatewayState::new(db_path);
    state.danger_mode = danger_allow_all;
    // живой REPL: workspace/cd двигают process-cwd (движковые команды
    // и подпроцессы — от одного корня); юнит-тесты работают без синка
    state.sync_cwd = true;
    println!(
        "{}",
        state.cwd.display()
    );

    let interactive = stdout_is_tty();
    loop {
        let cwd_short = shorten_cwd(&state.cwd);
        let danger_mark = if state.danger_mode { " ☠DANGER" } else { "" };
        let prompt = format!("poler {cwd_short}{danger_mark} $ ");
        let line = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(ReadlineError::WindowResized) => continue, // SIGWINCH: перерисовать
            Err(ReadlineError::Interrupted) => {
                hostexec::clear_interrupt();
                println!("^C (сброс строки; quit — выход)");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("\nвыход (EOF)");
                break;
            }
            Err(e) => {
                eprintln!("poler-gateway: ошибка ввода: {e}");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = rl.add_history_entry(trimmed);

        match exec_line(&mut state, trimmed, interactive) {
            GatewayResult::Empty => continue,
            GatewayResult::Quit => {
                println!("до свидания ✌");
                break;
            }
            GatewayResult::Done(out) => {
                if !out.is_empty() {
                    print!("{out}");
                    if !out.ends_with('\n') {
                        println!();
                    }
                }
                let _ = std::io::stdout().flush();
            }
        }
    }

    let _ = rl.save_history(&hist);
    // v0.27.0: рут-брокер не переживает шлюз (маркер живости протухнет сам,
    // но чистый stop честнее); контейнер живёт своей жизнью (docker -d)
    if let Some(mut b) = state.sudo_broker.take() {
        println!("{}", b.stop());
    }
    // v0.28.0: builtin-охота (loop-наблюдение) останавливается тоже
    if let Some(mut h) = state.hunt_builtin.take() {
        println!("{}", h.stop());
    }
    // v0.25.0: контейнер живёт своей жизнью (docker -d) — честно сказать
    if let Some(jail) = &state.box_jail {
        println!(
            "📦 box jail {} продолжает работать (box off — разобрать)",
            jail.name
        );
    }
    ExitCode::SUCCESS
}

/// `~/projects/x` → `~/projects/x`; `/home/user/x` → `~/x` (компактный cwd).
fn shorten_cwd(cwd: &std::path::Path) -> String {
    let s = cwd.display().to_string();
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() && s.starts_with(&home) {
            let rest = &s[home.len()..];
            return format!("~{rest}");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn banner_contains_license_and_circuits() {
        let b = super::banner();
        assert!(b.contains("Terminal Gateway"));
        assert!(b.contains("Лицензия"));
        assert!(b.contains("dev@poler-engine.org"), "EULA-адрес в баннере обязателен");
        assert!(b.contains("engine-native"));
        assert!(b.contains("host-os-proxy"));
        assert!(b.contains("pty-passthrough"), "v0.23.0: PTY-контур в баннере");
        assert!(b.contains("workspace-guard"), "v0.24.0: граница workspace в баннере");
        assert!(b.contains("Container Jail"), "v0.25.0: box в баннере");
        assert!(b.contains("runner"), "v0.26.0: runner-брокер в баннере");
        assert!(b.contains("poler_box_exec"), "v0.26.0: MCP-брокер в баннере");
        assert!(b.contains("рут-брокер"), "v0.27.0: рут-брокер в баннере");
        assert!(b.contains("jailbreak-sentinel"), "v0.27.0: sentinel в баннере");
        assert!(b.contains("builtin-hunter"), "v0.28.0: builtin-охотник в баннере");
        assert!(b.contains("box sudo passwd"), "v0.28.0: пароль-режим в баннере");
    }

    #[test]
    fn danger_banner_warns_explicitly() {
        let b = super::danger_banner();
        assert!(b.contains("DANGER MODE"));
        assert!(b.contains("ответственность"));
        assert!(b.contains("без проверок"));
    }

    #[test]
    fn shorten_cwd_home_tilde() {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let p = std::path::Path::new(&home).join("work");
            assert_eq!(super::shorten_cwd(&p), "~/work");
        }
    }
}
