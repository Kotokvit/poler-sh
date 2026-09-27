//! # Mediated Agent Mode — PATH-shim медиация PTY-агентов (v0.24.0)
//!
//! Живой кейс из эксплуатации (v0.23.0): агент, запущенный в PTY-контуре
//! (`agy`, `claude`, `codex`…), дергает свой Bash-tool напрямую — команды
//! агента **не проходят** через sandbox-судью шлюза. Ядровая песочница
//! (seccomp/landlock) вне философии движка (pure userspace), поэтому
//! медиация построена на PATH-shim — честный best-effort слой:
//!
//! 1. При запуске агента шлюз кладёт в `~/.poler-engine/shim/` обёртки
//!    для `bash`/`sh`/`zsh`/`dash`/`ksh`/`fish` и ставит этот каталог
//!    ПЕРВЫМ в PATH (и в `$SHELL`) процесса агента.
//! 2. Обёртка — две строки: `exec <poler-engine> __gateway-shim bash "$@"`.
//!    Если агент разрешает shell через PATH/$SHELL — его вызов приходит
//!    в hidden-команду `__gateway-shim`, которая судит payload
//!    (`sandbox::judge_shell_payload`) тем же судьёй, что и REPL.
//! 3. Вердикты в mediated-режиме: Allow → исполняется; Block/Confirm →
//!    **отказ 126**. Подтвердить агент НЕ может в принципе (Zero Silent
//!    Escalation): граница расширяется только владельцем — `allow <путь>`
//!    в шлюзе и перезапуск агента. Sudo внутри агента — всегда отказ.
//! 4. Каждый вызов пишется в журнал (TSV); после выхода агента шлюз
//!    печатает телеметрию. Ноль перехваченных вызовов = предупреждение:
//!    агент вызывает shell по абсолютному пути — его команды НЕ
//!    фильтровались (медиация best-effort, честность важнее иллюзии).
//!
//! Ограничения (docs/terminal-gateway-architecture.md §4.3): агент,
//! хардкодящий `/bin/sh` или делающий execve мимо shell, медиацией не
//! накрывается; произвольные syscall не видны userspace-фильтру. Для
//! гарантированной изоляции нужен уровень ядра (Landlock/seccomp) —
//! направление будущих версий.

use super::sandbox::{self, Policy, WsGuard};
use std::path::{Path, PathBuf};

/// CLI-агенты (не инструменты владельца!): их shell-вызовы медиируются.
/// vim/htop/less — пользовательские TUI, владелец за терминалом сам.
pub const AGENT_CMDS: &[&str] = &[
    "agy", "claude", "codex", "gemini", "aider", "qwen", "goose", "opencode",
    "cursor-agent", "copilot", "droid", "crush",
];

/// Шеллы, для которых кладутся shim-обёртки (PATH-lookup имена).
pub const SHIM_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "fish"];

/// Команда — агент (по базовому имени, как в sandbox-судье).
pub fn is_agent_cmd(cmd: &str) -> bool {
    let base = cmd.rsplit('/').next().unwrap_or(cmd);
    AGENT_CMDS.contains(&base)
}

/// Каталог shim-обёрток: `~/.poler-engine/shim`.
fn shim_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".poler-engine").join("shim")
}

/// База сессионных файлов медиации (allow-файл, журнал).
fn med_base() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".poler-engine")
}

/// Ресурс запуска агента в mediated-режиме.
pub struct Mediation {
    /// env для PTY-спавна агента (PATH/SHELL/POLER_*).
    pub env: Vec<(String, String)>,
    /// allow-файл (корень + allowlist, по пути на строку).
    pub allow_file: PathBuf,
    /// Журнал вызовов (TSV: решение\tshell\tкоманда).
    pub log_file: PathBuf,
}

/// Подготовить медиацию: shim-обёртки + allow-файл + env. Вызывается
/// ДО `hostexec::run_pty` для агентных команд (auto/explicit PTY).
pub fn setup(root: &Path, allow: &[PathBuf]) -> std::io::Result<Mediation> {
    let dir = shim_dir();
    std::fs::create_dir_all(&dir)?;
    let exe = std::env::current_exe()?;
    let exe_str = exe.display().to_string();
    for s in SHIM_SHELLS {
        let script = format!("#!/bin/bash\nexec \"{exe_str}\" __gateway-shim {s} \"$@\"\n");
        std::fs::write(dir.join(s), script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir.join(s), std::fs::Permissions::from_mode(0o755));
        }
    }
    let base = med_base();
    std::fs::create_dir_all(&base)?;
    let stamp = std::process::id();
    let allow_file = base.join(format!("med-{stamp}.allow"));
    let mut txt = String::new();
    txt.push_str(
        &root
            .canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .display()
            .to_string(),
    );
    txt.push('\n');
    for a in allow {
        txt.push_str(&a.display().to_string());
        txt.push('\n');
    }
    std::fs::write(&allow_file, txt)?;
    let log_file = base.join(format!("med-{stamp}.jsonl"));
    let _ = std::fs::remove_file(&log_file); // свежий журнал на сессию
    let orig_path = std::env::var("PATH").unwrap_or_default();
    let env = vec![
        (
            "PATH".to_string(),
            format!("{}:{}", dir.display(), orig_path),
        ),
        ("SHELL".to_string(), dir.join("bash").display().to_string()),
        ("POLER_WORKSPACE".to_string(), root.display().to_string()),
        ("POLER_SHIM".to_string(), "1".to_string()),
        (
            "POLER_SHIM_ALLOW".to_string(),
            allow_file.display().to_string(),
        ),
        ("POLER_SHIM_LOG".to_string(), log_file.display().to_string()),
    ];
    Ok(Mediation {
        env,
        allow_file,
        log_file,
    })
}

/// Телеметрия после выхода агента: сколько shell-вызовов перехвачено,
/// сколько отклонено и почему; ноль вызовов — предупреждение.
pub fn telemetry(log: &Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let (mut total, mut allow_n, mut deny_boundary, mut deny_block, mut deny_sudo, mut deny_stream) =
        (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    for line in text.lines() {
        let mut it = line.split('\t');
        let Some(dec) = it.next() else { continue };
        total += 1;
        match dec {
            "allow" => allow_n += 1,
            "deny-boundary" => deny_boundary += 1,
            "deny-block" => deny_block += 1,
            "deny-sudo" => deny_sudo += 1,
            "deny-stream" => deny_stream += 1,
            _ => {}
        }
    }
    if total == 0 {
        return format!(
            "⚠ Медиация: агент ни разу не вызвал shell через PATH — его команды\n\
              НЕ фильтровались (вызывает /bin/sh по абсолютному пути?). Медиация\n\
             best-effort на PATH/$SHELL; детали и честные границы — docs §4.3.\n"
        );
    }
    let deny = deny_boundary + deny_block + deny_sudo + deny_stream;
    format!(
        "🛡 Медиация агента: {total} shell-вызовов · пропущено {allow_n} · отклонено {deny}\n\
         (вне workspace: {deny_boundary} · деструктив: {deny_block} · sudo: {deny_sudo} · потоковый shell: {deny_stream})\n"
    )
}

/// Точка входа hidden-команды `poler-engine __gateway-shim <shell> [args…]`.
/// Возвращает код возврата процесса (exec при успехе не возвращается).
pub fn shim_main(args: &[String]) -> i32 {
    let Some(shell) = args.first() else {
        eprintln!("poler-gateway shim: shell не указан");
        return 126;
    };
    let rest = &args[1..];
    let real = real_shell(shell);
    let cmd_disp = rest
        .iter()
        .map(|s| s.replace(['\t', '\n'], " "))
        .collect::<Vec<_>>()
        .join(" ");

    // Контекст mediated? Нет POLER_WORKSPACE — ручной вызов shim-файла
    // (например, из чужого PATH после выхода из gateway): прозрачный
    // pass-through на реальный shell, без изменений поведения.
    let ws = match WsGuard::from_env() {
        Some(w) => w,
        None => return exec_real(&real, rest),
    };

    let log = std::env::var("POLER_SHIM_LOG").ok();

    // payload: `bash -c '…'`, `bash -lc '…'`, `bash --command '…'`
    let payload = extract_c_payload(rest);
    let (decision, kind) = match payload {
        None => (
            Err("интерактивный/потоковый shell внутри агента: код пришёл бы по stdin \
                 мимо фильтра — заблокировано медиацией"
                .to_string()),
            "deny-stream",
        ),
        Some(p) => {
            if sandbox::has_stream_shell(&p) {
                (
                    Err("потоковый shell/интерпретатор внутри payload (bash, bash -i, \
                         python3 без кода в аргументах) — обход медиации, заблокировано"
                        .to_string()),
                    "deny-stream",
                )
            } else {
                match sandbox::judge_shell_payload(&p, Some(&ws), 0) {
                    Policy::Allow => (Ok(()), "allow"),
                    Policy::Block(why) => (Err(why), "deny-block"),
                    Policy::Confirm(why) => {
                        if sandbox::is_privilege_escalation(&why) {
                            (
                                Err(format!(
                                    "{why} — sudo внутри агента недоступен; запускайте sudo сами в шлюзе"
                                )),
                                "deny-sudo",
                            )
                        } else {
                            (
                                Err(format!(
                                    "{why} — в mediated-режиме подтверждение агенту \
                                     недоступно; владелец: `allow <путь>` в шлюзе + перезапуск агента"
                                )),
                                "deny-boundary",
                            )
                        }
                    }
                }
            }
        }
    };

    match decision {
        Ok(()) => {
            log_event(&log, "allow", shell, &cmd_disp);
            exec_real(&real, rest)
        }
        Err(why) => {
            log_event(&log, kind, shell, &cmd_disp);
            eprintln!("⛔ poler-gateway (медиация): {why}");
            126
        }
    }
}

/// Реальный shell по абсолютному пути (НЕ из PATH — иначе рекурсия shim).
fn real_shell(shell: &str) -> Option<PathBuf> {
    ["/bin", "/usr/bin"]
        .iter()
        .map(|d| PathBuf::from(d).join(shell))
        .find(|p| p.exists())
}

/// exec(3) реального шелла с исходными аргументами.
fn exec_real(real: &Option<PathBuf>, rest: &[String]) -> i32 {
    let Some(r) = real else {
        eprintln!("poler-gateway shim: реальный shell не найден");
        return 127;
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(r).args(rest).exec();
        eprintln!("poler-gateway shim: exec {}: {err}", r.display());
        127
    }
    #[cfg(not(unix))]
    {
        let _ = (real, rest);
        127
    }
}

/// payload `-c` из аргументов шелла: `bash -c CMD …` / `bash -lc CMD …`.
fn extract_c_payload(rest: &[String]) -> Option<String> {
    let a0 = rest.first()?;
    let payload_at = if a0 == "-c" || a0 == "--command" {
        1
    } else if a0.starts_with('-')
        && !a0.starts_with("--")
        && a0 != "-"
        && a0.chars().any(|c| c == 'c')
    {
        1
    } else {
        return None;
    };
    rest.get(payload_at).cloned()
}

/// Событие в журнал (TSV: решение\tshell\tкоманда).
fn log_event(log: &Option<String>, dec: &str, shell: &str, cmd: &str) {
    if let Some(path) = log {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{dec}\t{shell}\t{cmd}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_detection() {
        assert!(is_agent_cmd("agy"));
        assert!(is_agent_cmd("/usr/local/bin/agy"));
        assert!(is_agent_cmd("claude"));
        assert!(!is_agent_cmd("vim"));
        assert!(!is_agent_cmd("htop"));
        assert!(!is_agent_cmd("bash"));
    }

    #[test]
    fn c_payload_extraction() {
        let rest = ["-c".to_string(), "ls -la".to_string()];
        assert_eq!(extract_c_payload(&rest), Some("ls -la".to_string()));
        let rest = ["-lc".to_string(), "echo hi".to_string()];
        assert_eq!(extract_c_payload(&rest), Some("echo hi".to_string()));
        let rest = ["-l".to_string()];
        assert_eq!(extract_c_payload(&rest), None);
        let rest = ["--login".to_string(), "x".to_string()];
        assert_eq!(extract_c_payload(&rest), None);
        let rest: Vec<String> = vec![];
        assert_eq!(extract_c_payload(&rest), None);
    }

    #[test]
    fn real_shell_found() {
        // bash есть на любом Linux/macOS CI
        assert!(real_shell("bash").is_some());
        assert!(real_shell("definitely-not-a-shell-xyz").is_none());
    }

    #[test]
    fn telemetry_zero_calls_warns() {
        let dir = std::env::temp_dir().join(format!("poler-shim-tel-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let log = dir.join("empty.jsonl");
        std::fs::write(&log, "").unwrap();
        let out = telemetry(&log);
        assert!(out.contains("НЕ фильтровались"), "ноль вызовов = предупреждение: {out}");
        std::fs::write(&log, "allow\tbash\tls\nallow\tbash\tcat x\ndeny-boundary\tbash\tcat /etc/passwd\n").unwrap();
        let out = telemetry(&log);
        assert!(out.contains("3"), "итог: {out}");
        assert!(out.contains("вне workspace: 1"), "итог: {out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shim_setup_creates_wrappers() {
        // изолированный HOME, чтобы не трогать реальный ~/.poler-engine
        let home = std::env::temp_dir().join(format!("poler-shim-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&home);
        let prev = std::env::var("HOME").ok();
        // SAFETY: тест однопоточный по этому коду; env-мутация видна процессу
        unsafe { std::env::set_var("HOME", &home) };
        let root = home.join("ws");
        std::fs::create_dir_all(&root).unwrap();
        let med = setup(&root, &[home.join("allowed")]).unwrap();
        let shim = home.join(".poler-engine/shim/bash");
        let text = std::fs::read_to_string(&shim).unwrap();
        assert!(text.contains("__gateway-shim bash"), "обёртка: {text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&shim).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "обёртка исполняемая");
        }
        assert!(med.env.iter().any(|(k, v)| k == "POLER_WORKSPACE" && *v == root.display().to_string()));
        let allow_text = std::fs::read_to_string(&med.allow_file).unwrap();
        assert!(allow_text.contains(&root.display().to_string()));
        match prev {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}
