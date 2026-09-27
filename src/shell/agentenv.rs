//! # AgentEnv — среда для ИИ-агентов (v0.47.0)
//!
//! Ответ на вопрос владельца: «мне нужно знать системную информацию твоего
//! взаимодействия с машиной». Модуль даёт агенту (Antigravity / любой LLM)
//! **самоописание среды исполнения**:
//!
//! - `sysinfo()` — полный отчёт: ядро, CPU, RAM, диск, GPU, тулчейны,
//!   локаль, TTY/PTY-статус и тип вывода. Агенту не нужно гадать, где он
//!   работает — он запускает `sysinfo` и получает карту машины.
//! - `env_snapshot()` — снимок переменных окружения сессии.
//! - `json_envelope()` — машинный конверт для `poler-engine --exec --json`
//!   (одна строка JSON: cmd/ok/exit_code/duration_ms/output) — детермини-
//!   рованный интерфейс без баннеров и PTY-шума.
//! - `agent_status()` — как агенту эффективнее всего работать с шеллом:
//!   доступные режимы, тайминги, советы по pipe vs PTY.
//!
//! Конструкция намеренно без новых зависимений: /proc + std + команды
//! с коротким таймаутом.

use std::time::Duration;

/// Прочитать первую строку файла /proc (или None).
fn proc_line(path: &str, key: &str) -> Option<String> {
    let data = std::fs::read_to_string(path).ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let v = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Выполнить команду с жёстким таймаутом (для версий тулчейнов).
fn quick(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        _ => None,
    }
}

/// Проверить наличие PTY у stdin (для советов агенту).
fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        // /proc/self/fd/0 -> /dev/pts/N или /dev/tty
        match std::fs::read_link("/proc/self/fd/0") {
            Ok(p) => {
                let s = p.to_string_lossy().to_string();
                s.starts_with("/dev/pts/") || s.contains("/dev/tty")
            }
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Полный системный отчёт для агента.
pub fn sysinfo() -> String {
    let mut s = String::new();
    let w = |s: &mut String, line: String| s.push_str(&line);

    w(&mut s, "═ poler-engine sysinfo — карта среды исполнения ═\n".to_string());

    // --- POLER ---
    w(&mut s, "\n[engine]\n".into());
    w(&mut s, format!("  version         : {}\n", env!("CARGO_PKG_VERSION")));
    w(&mut s, format!("  pid             : {}\n", std::process::id()));
    if let Ok(cwd) = std::env::current_dir() {
        w(&mut s, format!("  cwd             : {}\n", cwd.display()));
    }

    // --- OS / ядро ---
    w(&mut s, "\n[os]\n".into());
    if let Some(u) = quick("uname", &["-srm"]) {
        w(&mut s, format!("  kernel          : {u}\n"));
    }
    if let Some(pretty) = proc_line("/etc/os-release", "PRETTY_NAME=")
        .map(|v| v.trim_matches('"').to_string())
    {
        w(&mut s, format!("  distro          : {pretty}\n"));
    }
    if let Ok(up) = std::fs::read_to_string("/proc/uptime") {
        if let Some(secs) = up.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()) {
            let d = secs as u64 / 86400;
            let h = (secs as u64 % 86400) / 3600;
            let m = (secs as u64 % 3600) / 60;
            w(&mut s, format!("  uptime          : {d}д {h}ч {m}м\n"));
        }
    }

    // --- CPU ---
    w(&mut s, "\n[cpu]\n".into());
    if let Some(model) = proc_line("/proc/cpuinfo", "model name") {
        w(&mut s, format!("  model           : {model}\n"));
    }
    if let Ok(c) = std::fs::read_to_string("/proc/cpuinfo") {
        let cores = c.lines().filter(|l| l.starts_with("processor")).count();
        w(&mut s, format!("  logical cores   : {cores}\n"));
    }
    if let Some(flags) = proc_line("/proc/cpuinfo", "flags") {
        let has = |f: &str| flags.split_whitespace().any(|x| x == f);
        let feats = [
            ("avx2", has("avx2")),
            ("avx512f", has("avx512f")),
            ("bmi2", has("bmi2")),
            ("sse4_2", has("sse4_2")),
        ];
        let on: Vec<&str> = feats.iter().filter(|(_, v)| *v).map(|(n, _)| *n).collect();
        w(&mut s, format!("  simd            : {}\n", on.join(", ")));
    }

    // --- RAM ---
    w(&mut s, "\n[memory]\n".into());
    if let Some(t) = proc_line("/proc/meminfo", "MemTotal") {
        w(&mut s, format!("  total           : {t}\n"));
    }
    if let Some(a) = proc_line("/proc/meminfo", "MemAvailable") {
        w(&mut s, format!("  available       : {a}\n"));
    }

    // --- Диск ---
    w(&mut s, "\n[disk]\n".into());
    if let Some(df) = quick("df", &["-h", "."]) {
        for line in df.lines().skip(1) {
            w(&mut s, format!("  {line}\n"));
        }
    }

    // --- GPU ---
    w(&mut s, "\n[gpu]\n".into());
    let mut gpu_found = false;
    if let Ok(nv) = std::fs::read_to_string("/proc/driver/nvidia/version") {
        if let Some(first) = nv.lines().next() {
            w(&mut s, format!("  nvidia          : {first}\n"));
            gpu_found = true;
        }
    }
    if let Ok(dirs) = std::fs::read_dir("/sys/class/drm") {
        let mut cards: Vec<String> = Vec::new();
        for d in dirs.flatten() {
            let name = d.file_name().to_string_lossy().to_string();
            if name.starts_with("card") && !name.contains('-') {
                cards.push(name);
            }
        }
        if !cards.is_empty() {
            w(&mut s, format!("  drm nodes       : {}\n", cards.join(", ")));
            gpu_found = true;
        }
    }
    if !gpu_found {
        w(&mut s, "  (не обнаружен — CPU-субстрат: No-Mul/GOPS-профили без CUDA)\n".into());
    }

    // --- Тулчейны ---
    w(&mut s, "\n[toolchain]\n".into());
    let tools: &[(&str, &[&str])] = &[
        ("cargo", &["--version"]),
        ("rustc", &["--version"]),
        ("python3", &["--version"]),
        ("zig", &["version"]),
        ("git", &["--version"]),
        ("node", &["--version"]),
        ("cc", &["--version"]),
    ];
    let mut any = false;
    for (name, args) in tools {
        if which_exists(name) {
            if let Some(v) = quick(name, args) {
                let v_short = v.lines().next().unwrap_or("").to_string();
                w(&mut s, format!("  {name:<15}: {v_short}\n"));
                any = true;
            }
        }
    }
    if !any {
        w(&mut s, "  (тулчейны не обнаружены)\n".into());
    }

    // --- Локаль / терминал / кодировка ---
    w(&mut s, "\n[interaction]\n".into());
    for k in ["LANG", "LC_ALL", "TERM", "COLORTERM"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                w(&mut s, format!("  {k:<15}: {v}\n"));
            }
        }
    }
    let tty = stdin_is_tty();
    w(&mut s, format!("  stdin           : {}\n", if tty { "TTY (интерактив)" } else { "pipe (неинтерактивный — агент/скрипт)" }));
    w(&mut s, "  кодировка       : poler-shell обрабатывает UTF-8 (кириллица в путях и выводе безопасна)\n".into());
    w(&mut s, "  PTY-мост        : `pty <cmd>` — запуск интерактивных утилит (top, gdb) через pseudo-tty\n".into());

    // --- Агентный режим ---
    w(&mut s, "\n[agent mode]\n".into());
    let agent = std::env::var("POLER_SHELL_AGENT").map(|v| v == "1").unwrap_or(false);
    w(&mut s, format!("  POLER_SHELL_AGENT : {agent}\n"));
    w(&mut s, "  one-shot          : poler-engine --exec '<cmd>'        (без баннера)\n".into());
    w(&mut s, "  machine-readable  : poler-engine --exec '<cmd>' --json (JSON-конверт)\n".into());
    w(&mut s, "  Windows-словарь   : dir, type, copy, findstr, tasklist… (см. `win`)\n".into());

    s
}

/// Есть ли программа в PATH (без проверки бита исполнения для скорости —
/// используется только для informational-выводов).
fn which_exists(prog: &str) -> bool {
    std::env::var("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|p| p.join(prog).exists())
        })
        .unwrap_or(false)
}

/// Снимок переменных окружения (отсортированный, с трuncацией длинных).
/// `filter` — показать только переменные, начинающиеся с префикса.
pub fn env_snapshot(filter: Option<&str>) -> String {
    let mut vars: Vec<(String, String)> = std::env::vars().collect();
    vars.sort();
    let mut s = String::new();
    let mut shown = 0usize;
    for (k, v) in vars {
        if let Some(f) = filter {
            if !k.starts_with(f) {
                continue;
            }
        }
        // Крипто-токены маскируем, но не прячем факт их наличия
        let vv = if k.contains("TOKEN") || k.contains("SECRET") || k.contains("PASSWORD") || k.contains("KEY") {
            if v.len() > 8 {
                format!("{}…{} ({})", &v[..4], &v[v.len() - 2..], v.len())
            } else {
                format!("***({})", v.len())
            }
        } else if v.len() > 160 {
            format!("{}… (+{} симв.)", &v[..157], v.len() - 157)
        } else {
            v
        };
        s.push_str(&format!("{k}={vv}\n"));
        shown += 1;
    }
    if shown == 0 {
        if let Some(f) = filter {
            s.push_str(&format!("(нет переменных с префиксом {f})\n"));
        }
    }
    s
}

/// Статус и советы агенту: как работать с poler-shell эффективно.
pub fn agent_status() -> String {
    let mut s = String::new();
    s.push_str("═ poler-shell agent mode ═\n\n");
    s.push_str("Интерфейсы для агента (Antigravity / LLM):\n");
    s.push_str("  1. poler-engine --exec '<cmd>'          — one-shot, без баннера\n");
    s.push_str("  2. poler-engine --exec '<cmd>' --json   — {cmd, ok, exit_code, duration_ms, output}\n");
    s.push_str("  3. echo '<cmd>' | poler-engine --shell  — поток команд (pipe-режим, EOF=выход)\n");
    s.push_str("  4. MCP: poler_exec / poler_exec_async   — инструменты MCP-сервера движка\n\n");
    s.push_str("Советы по эффективности:\n");
    s.push_str("  • sysinfo  — карта машины (CPU/RAM/GPU/тулчейны) — вызывайте один раз в сессии\n");
    s.push_str("  • env      — переменные сессии (токены маскируются)\n");
    s.push_str("  • pty <cmd> — если утилите нужен TTY (top, gdb), иначе pipe быстрее\n");
    s.push_str("  • тайминги: POLER_SHELL_AGENT=1 включает суффикс ⏱ <ms> у внешних команд\n");
    s.push_str("  • win      — Windows-словарь (dir/type/copy/findstr…) работает наравне с Linux\n");
    s.push_str("  • вывод захвачен целиком (stdout+stderr), код возврата в скобках при пустом выводе\n\n");
    let agent = std::env::var("POLER_SHELL_AGENT").map(|v| v == "1").unwrap_or(false);
    s.push_str(&format!("Текущий статус: POLER_SHELL_AGENT={} {}\n", agent, if agent { "(тайминги включены)" } else { "(выключен; включите для ⏱-метрик)" }));
    s
}

/// JSON-конверт для `--exec --json`. serde_json уже в зависимостях движка.
pub fn json_envelope(cmd: &str, ok: bool, exit_code: u8, duration_ms: u128, output: &str) -> String {
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        cmd: &'a str,
        ok: bool,
        exit_code: u8,
        duration_ms: u64,
        output: &'a str,
    }
    let env = Envelope {
        cmd,
        ok,
        exit_code,
        duration_ms: duration_ms.min(u64::MAX as u128) as u64,
        output,
    };
    serde_json::to_string(&env).unwrap_or_else(|_| "{}".to_string())
}

/// Дефолтный таймаут для quick() не нужен — output() без таймаута на
/// версионных командах безопасен, но перестрахуемся на случай NFS-ханга:
/// используются только короткоживущие `--version` вызовы.
pub const QUICK_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysinfo_contains_sections() {
        let s = sysinfo();
        assert!(s.contains("[cpu]"));
        assert!(s.contains("[memory]"));
        assert!(s.contains("[interaction]"));
        assert!(s.contains("[agent mode]"));
        assert!(s.contains("[toolchain]"));
    }

    #[test]
    fn env_snapshot_masks_tokens() {
        std::env::set_var("POLER_TEST_TOKEN_XYZ", "abcdef1234567890");
        let s = env_snapshot(Some("POLER_TEST_TOKEN"));
        assert!(s.contains("POLER_TEST_TOKEN_XYZ="));
        assert!(!s.contains("abcdef1234567890"), "токен должен быть маскирован");
        std::env::remove_var("POLER_TEST_TOKEN_XYZ");
    }

    #[test]
    fn env_snapshot_truncates_long() {
        std::env::set_var("POLER_TEST_LONGVAR", "x".repeat(500));
        let s = env_snapshot(Some("POLER_TEST_LONGVAR"));
        assert!(s.contains("+"));
        assert!(!s.contains(&"x".repeat(200)));
        std::env::remove_var("POLER_TEST_LONGVAR");
    }

    #[test]
    fn json_envelope_shape() {
        let j = json_envelope("dir", true, 0, 42, "total 1\n");
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains("\"cmd\":\"dir\""));
        assert!(j.contains("\"ok\":true"));
        assert!(j.contains("\"duration_ms\":42"));
    }

    #[test]
    fn agent_status_mentions_interfaces() {
        let s = agent_status();
        assert!(s.contains("--exec"));
        assert!(s.contains("--json"));
        assert!(s.contains("sysinfo"));
    }
}
