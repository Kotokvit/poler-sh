//! Confirmation Gate (v0.17.5 → v2.0): Human-in-the-Loop для
//! деструктивных операций.
//!
//! Дизайн согласован с принципом «минимум удивления»:
//!
//! 1. **CLI-режим**: интерактивный `[y/N]`-вопрос в терминал — stdin свободен.
//! 2. **Shell/TUI/MCP** (stdin занят rustyline / ratatui / JSON-RPC):
//!    двухшаговое подтверждение — первый вызов показывает ПЛАН и просит
//!    повторить команду с `--yes` (паттерн `terraform plan → apply`).
//! 3. **Скрипты/CI**: env `POLER_YES=1` снимает вопросы целиком.
//! 4. **`--dry-run`**: показать план и НЕ выполнять ничего — работает
//!    везде, всегда безопасен.
//!
//! Правило по умолчанию — ОТКАЗ: если ответ не распознан, stdin закрыт
//! или нет TTY — операция НЕ выполняется.
//!
//! v2.0: перенесено из `google/confirm.rs` при отвязке от Google —
//! утилита общесистемная (--yes/--dry-run для notes rm и др.), к
//! облачным сервисам отношения не имеет.

use std::io::BufRead;

/// Env-флаг «не спрашивать» (скрипты/CI). `POLER_YES=1|true|yes`.
pub fn env_yes() -> bool {
    std::env::var("POLER_YES")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "д"
        })
        .unwrap_or(false)
}

/// Распарсить `--yes` / `-y` и `--dry-run` из аргументов shell-команды.
///
/// Возвращает `(yes, dry_run, позиционные_аргументы)` — флаги из
/// позиционных вырезаются, чтобы не ломать существующие парсеры.
pub fn split_gate_flags(args: &[String]) -> (bool, bool, Vec<String>) {
    let mut yes = false;
    let mut dry = false;
    let mut rest = Vec::with_capacity(args.len());
    for a in args {
        match a.as_str() {
            "--yes" | "-y" => yes = true,
            "--dry-run" | "-n" => dry = true,
            _ => rest.push(a.clone()),
        }
    }
    (yes, dry, rest)
}

/// Интерактивное подтверждение `[y/N]` для CLI-режима.
///
/// * `env_yes()` → true без вопроса;
/// * stdin не TTY или EOF → false (безопасный отказ);
/// * ответ `y`/`yes`/`д`/`да` (в любом регистре) → true; всё прочее → false.
pub fn confirm_interactive(prompt: &str) -> bool {
    if env_yes() {
        return true;
    }
    if !stdin_is_tty() {
        eprintln!("poler-confirm: stdin не интерактивен — подтверждение невозможно.");
        eprintln!("  Скриптовый запуск: добавь --yes (или env POLER_YES=1).");
        return false;
    }
    print!("{prompt} [y/N] ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => return false, // EOF — отказ
        Ok(_) => {}
        Err(_) => return false,
    }
    let ans = line.trim().to_ascii_lowercase();
    matches!(ans.as_str(), "y" | "yes" | "д" | "да")
}

/// stdin подключён к терминалу? `/dev/stdin` → fstat → isatty через
/// std (без libc): tty-устройства в Linux имеют char-major 136 (pts)
/// или 4 (tty); надёжнее проверить через metadata файла устройства.
pub fn stdin_is_tty() -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata("/dev/stdin") {
        Ok(md) => md.file_type().is_char_device(),
        Err(_) => false,
    }
}

/// Двухшаговое подтверждение для shell/TUI: показать план и попросить
/// перезапуск с `--yes`. Возвращает текст-подсказку (не выполняет операцию).
pub fn replan_hint(command: &str, plan_summary: &str) -> String {
    format!(
        "🔒 План изменений (не выполнено — нужен явный запуск):\n{plan_summary}\n\
         \nПодтверди запись: {command} --yes   (или --dry-run для просмотра)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn split_gate_flags_extracts_yes_and_dry() {
        let (y, d, rest) = split_gate_flags(&args(&["nb-123", "--yes", "--dry-run"]));
        assert!(y && d);
        assert_eq!(rest, vec!["nb-123".to_string()]);
    }

    #[test]
    fn split_gate_flags_keeps_plain_args() {
        let (y, d, rest) = split_gate_flags(&args(&["nb-123", "extra"]));
        assert!(!y && !d);
        assert_eq!(rest.len(), 2);
    }

    #[test]
    fn split_gate_flags_short_forms() {
        let (y, d, _) = split_gate_flags(&args(&["-y", "-n"]));
        assert!(y && d);
    }

    #[test]
    fn replan_hint_mentions_yes_and_dry_run() {
        let h = replan_hint("notes rm 5", "заметка «черновик»");
        assert!(h.contains("--yes"));
        assert!(h.contains("--dry-run"));
        assert!(h.contains("черновик"));
    }

    #[test]
    fn env_yes_parse() {
        // читаем без мутации env: любое значение кроме 1/true/yes/д — false
        let saved = std::env::var("POLER_YES");
        std::env::remove_var("POLER_YES");
        assert!(!env_yes());
        std::env::set_var("POLER_YES", "1");
        assert!(env_yes());
        std::env::set_var("POLER_YES", "TRUE");
        assert!(env_yes(), "регистронезависимо");
        std::env::set_var("POLER_YES", "no");
        assert!(!env_yes());
        match saved {
            Ok(v) => std::env::set_var("POLER_YES", v),
            Err(_) => std::env::remove_var("POLER_YES"),
        }
    }
}
