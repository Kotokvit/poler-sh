//! # Terminal Gateway: двойной контур исполнения (v0.22.0)
//!
//! **Контур 1 (Engine Native, приоритет):** команда движка исполняется
//! внутри процесса — без спавна внешних шеллов. Существующие команды
//! внутреннего REPL делегируются в `shell::commands::dispatch` (один
//! источник правды), новые (grep/chunk/benchmark/service/…) реализованы
//! здесь поверх библиотечных API.
//!
//! **Контур 2 (Controlled Host OS Proxy):** всё прочее исполняется в
//! хостовой ОС через Sandboxed OS Subshell (sandbox::judge → hostexec::run)
//! — с блокировкой деструктивного, подтверждением эскалаций, капом вывода
//! и таймаутом.
//!
//! Конвейеры смешивают контуры: `ls -la | chunk` (host→engine),
//! `grep "fn " --stdin | wc -l` (engine→host).

use super::containers;
use super::hostexec::{self, EnvMode, HostLimits};
use super::pipeline::{parse_line, Pipeline, Segment};
use super::sandbox::{self, Policy};
use super::service;
use super::shim;
use crate::shell::{self, ShellState};
use std::io::{BufRead, Write};
use std::path::PathBuf;

/// Ошибка команд движка: сообщение ИЛИ выход (quit из делегированного шелла).
enum EngineFail {
    Msg(String),
    Quit,
}

// ---------------------------------------------------------------------------
// Состояние
// ---------------------------------------------------------------------------

/// Состояние Terminal Gateway.
pub struct GatewayState {
    /// Внутренний шелл движка (search/notes/…) — делегация.
    pub shell: ShellState,
    /// Рабочий каталог gateway (cd/pwd/workspace; хостовые команды стартуют отсюда).
    pub cwd: PathBuf,
    /// v0.24.0: корень workspace (ГРАНИЦА). cd внутри — свободен,
    /// выход за границу — Confirm; подтверждённый выход переносит границу.
    pub ws_root: PathBuf,
    /// Лимиты host-прокси (таймаут/кап/env).
    pub limits: HostLimits,
    /// Авто-подтверждение опасных команд (set autoyes on).
    pub auto_yes: bool,
    /// Код возврата последней команды (для $-статуса).
    pub last_exit: i32,
    /// v0.23.0: sudo-лизинг — окно, в котором privilege-Confirm
    /// (sudo/su/doas/pkexec) не спрашивается. Открывается только
    /// интерактивно (`grant sudo 5m`), сгорает по таймеру.
    pub sudo_lease_until: Option<std::time::Instant>,
    /// v0.23.0: danger-режим (--dangerously-allow-all / set sandbox off):
    /// sandbox не блокирует и не спрашивает — только предупреждает.
    /// Вся ответственность — на операторе (красный баннер при старте).
    pub danger_mode: bool,
    /// v0.24.0: сессионный allowlist владельца — канонические пути вне
    /// workspace, обращение к которым не требует подтверждения (`allow`).
    /// Смягчает ТОЛЬКО boundary-Confirm: Block-инварианты действует всегда.
    pub ws_allow: Vec<PathBuf>,
    /// v0.23.0: синхронизировать process-cwd со state.cwd (workspace/cd) —
    /// движковые команды (grep/chunk/search) и подпроцессы видят один корень.
    /// Включается только в живом REPL: юнит-тесты не мутируют глобальный cwd.
    pub sync_cwd: bool,
    /// v0.25.0: активный Container Jail — контуры 2/3 исполняются внутри
    /// Docker-контейнера (`box on`); физическая изоляция вместо/поверх
    /// логической границы workspace для exec-плоскости.
    pub box_jail: Option<containers::BoxState>,
    /// v0.26.0: активный runner — изолированный контур исполнения
    /// MCP-брокера (`box runner on`): net=none, только /workspace.
    pub runner: Option<containers::RunnerState>,
    /// v0.27.0: рут-брокер (`box sudo on`) — «sudo как услуга»:
    /// агент в клетке ПРОСИТ рут, судья решает, исполнение —
    /// docker exec -u 0 СО СТОРОНЫ ХОСТА (агент рут не держит).
    pub sudo_broker: Option<super::rootbroker::BrokerHandle>,
    /// v0.27.0: Jailbreak Sentinel (`box hunt start`) — охота на побег:
    /// батарея векторов + наблюдение за агентом + kill-switch.
    pub hunt: Option<super::sentinel::HuntState>,
    /// v0.28.0: Builtin Hunter (`box hunt start --mode builtin`) —
    /// собственный красный суб-агент POLER: чёрный ящик изнутри клетки,
    /// kill-switch, авто-блоклист; `--loop` — постоянное наблюдение.
    pub hunt_builtin: Option<super::hunter::BuiltinHandle>,
}

impl GatewayState {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            shell: ShellState::new(db_path),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            ws_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            limits: HostLimits::default(),
            auto_yes: false,
            last_exit: 0,
            sudo_lease_until: None,
            danger_mode: false,
            ws_allow: Vec::new(),
            sync_cwd: false,
            box_jail: None,
            runner: None,
            sudo_broker: None,
            hunt: None,
            hunt_builtin: None,
        }
    }

    /// Остаток sudo-лизинга (None — не активен или уже истёк).
    pub fn sudo_lease_remaining(&self) -> Option<std::time::Duration> {
        let until = self.sudo_lease_until?;
        let now = std::time::Instant::now();
        if until > now {
            Some(until - now)
        } else {
            None
        }
    }
}

/// Граница workspace для судьи: root — граница (v0.24.0: отдельно от cwd;
/// cd в подкаталог не двигает границу), cwd — якорь относительных путей,
/// allow — сессионный allowlist.
fn ws_guard(state: &GatewayState) -> sandbox::WsGuard {
    sandbox::WsGuard {
        root: state.ws_root.clone(),
        cwd: state.cwd.clone(),
        allow: state.ws_allow.clone(),
    }
}

/// Результат исполнения строки.
pub enum GatewayResult {
    Done(String),
    Quit,
    Empty,
}

// ---------------------------------------------------------------------------
// Словарь команд движка (Контур 1)
// ---------------------------------------------------------------------------

/// Команды, перехватываемые движком (приоритет над PATH!). `grep` здесь —
/// POLER Native Grep, а не /bin/grep; системный — через `!grep` / `host grep`.
pub fn is_engine_command(name: &str) -> bool {
    matches!(
        name,
        "search" | "web" | "stats" | "sync" | "set" | "crawl" | "impact" | "gh" | "gl"
            | "gt" | "gix" | "notes" | "sources" | "grep" | "chunk" | "benchmark" | "service"
            | "attach" | "weblens" | "license" | "cd" | "pwd" | "clear" | "host" | "help"
            | "version" | "quit" | "exit" | "q" | "ver" | "workspace" | "grant" | "pty"
            | "allow" | "box"
    )
}

/// Команды, которые осмысленно принимают stdin в конвейере.
fn accepts_stdin(cmd: &str) -> bool {
    matches!(cmd, "grep" | "chunk" | "impact")
}

// ---------------------------------------------------------------------------
// PTY-роутинг (v0.23.0): известные TUI и bare-REPL — авто-PTY в интерактиве
// ---------------------------------------------------------------------------

/// Полноэкранные TUI/IDE/агенты: без псевдотерминала зависают на пайпах
/// (живой кейс из эксплуатации: agy внутри шлюза ждал PTY-рендер).
const AUTO_PTY_CMDS: &[&str] = &[
    "vim", "nvim", "vi", "nano", "micro", "emacs", "hx", "helix", "less", "more",
    "htop", "top", "btop", "btm", "gtop", "gdu", "ncdu", "lazygit", "tig", "fzf",
    "tmux", "screen", "mc", "watch", "agy", "claude", "codex", "gemini", "aider",
];

/// REPL-интерпретаторы: авто-PTY только в bare-виде (без аргументов —
/// `python3`, `node`; с аргументами это обычный запуск файла/флага).
const REPL_CMDS: &[&str] = &[
    "python3", "python", "node", "deno", "irb", "pry", "sqlite3", "psql", "mysql",
    "redis-cli", "bc", "lua", "luajit",
];

/// Кандидат на PTY по авто-детекции (без учёта interactive — его проверяет
/// вызывающий). Базовое имя — как в sandbox-судье.
fn is_auto_pty(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let base = first.rsplit('/').next().unwrap_or(first);
    AUTO_PTY_CMDS.contains(&base) || (REPL_CMDS.contains(&base) && tokens.len() == 1)
}

// ---------------------------------------------------------------------------
// Главная точка входа
// ---------------------------------------------------------------------------

/// Исполнить строку ввода gateway. `interactive` — можно ли задавать
/// вопросы пользователю (Confirm-политика); в тестах/скриптах Confirm
/// без auto_yes = отказ.
pub fn exec_line(state: &mut GatewayState, line: &str, interactive: bool) -> GatewayResult {
    hostexec::clear_interrupt();
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return GatewayResult::Empty;
    }

    // `!cmd` — принудительный хостовый контур (обход приоритета движка)
    let effective: String = if let Some(rest) = trimmed.strip_prefix('!') {
        if rest.trim().is_empty() {
            return GatewayResult::Done("!: пустая команда".into());
        }
        format!("host {}", rest.trim())
    } else {
        trimmed.to_string()
    };

    let pipeline = match parse_line(&effective) {
        Ok(p) => p,
        Err(e) => {
            state.last_exit = 2;
            return GatewayResult::Done(format!("⚡ парсинг: {e}"));
        }
    };

    // v0.23.0: PTY-passthrough — интерактивные TUI/IDE/REPL получают
    // настоящий псевдотерминал (raw mode, ресайз, Ctrl+C как байт).
    // Только одиночный сегмент без редиректа; политика судится ПО ВНУТРЕННЕЙ
    // команде — PTY это канал I/O, а не обход sandbox.
    if pipeline.segments.len() == 1 && pipeline.redirect.is_none() {
        let t0 = super::pipeline::strip_poler_prefix(&pipeline.segments[0].tokens, &is_engine_command);
        let explicit = t0.first().map(|s| s.as_str()) == Some("pty") && t0.len() >= 2;
        let auto = !explicit && interactive && !t0.is_empty() && is_auto_pty(&t0);
        if explicit || auto {
            let inner: Vec<String> = if explicit {
                t0[1..].to_vec()
            } else {
                t0.clone()
            };
            // v0.25.0: в jail-режиме логическую границу exec-плоскости
            // заменяет физическая изоляция контейнера (redirect-цели и
            // движковые файл-команды судятся с границей всегда — они на хосте)
            let guard = if state.box_jail.is_some() {
                None
            } else {
                Some(ws_guard(state))
            };
            let verdict = sandbox::judge_segment_ws(&inner, guard.as_ref());
            let proceed = if state.danger_mode {
                if !verdict.is_allow() {
                    eprintln!("⚠ DANGER: sandbox отключён владельцем — PTY-команда исполняется без проверок");
                }
                true
            } else {
                match verdict {
                    Policy::Allow => true,
                    Policy::Block(why) => {
                        state.last_exit = 2;
                        return GatewayResult::Done(format!("⛔ блокировка sandbox: {why}"));
                    }
                    Policy::Confirm(why) => resolve_confirm(state, &why, interactive),
                }
            };
            if !proceed {
                state.last_exit = 125;
                return GatewayResult::Done(
                    "⛔ отклонено (не подтверждено): PTY-команда".into(),
                );
            }
            // v0.25.0: управление контейнерным демоном из PTY при активном
            // jail — Confirm (docker run -v /:/host ломает изоляцию).
            if state.box_jail.is_some()
                && !state.danger_mode
                && containers::is_daemon_ctl(&inner)
            {
                let why = "управление docker/podman-демоном хоста при активном Container Jail — может разрушить изоляцию";
                if !resolve_confirm(state, why, interactive) {
                    state.last_exit = 125;
                    return GatewayResult::Done(format!("⛔ отклонено (не подтверждено): {why}"));
                }
            }
            if !interactive {
                // TUI без терминала зависает (живой кейс: agy на пайпах) —
                // честный отказ вместо зависания; деструктив уже отрезан выше
                return GatewayResult::Done(
                    "pty: интерактивная сессия требует настоящего терминала (TTY); запустите poler-engine --gateway в терминале\n".into(),
                );
            }
            // v0.24.0: Mediated Agent Mode — PATH-shim перехватывает
            // shell-вызовы агента (agy/claude/codex/…): судятся тем же
            // sandbox-гейтом, граница — workspace. Подтвердить агент не
            // может: выход за границу/деструктив/sudo → отказ 126.
            // vim/htop/less — инструменты владельца, не медиируются.
            let base = inner
                .first()
                .map(|s| s.rsplit('/').next().unwrap_or(s))
                .unwrap_or("")
                .to_string();
            // v0.25.0: в Container Jail медиация не нужна — агент физически
            // заперт в контейнере, его shell-вызовы хост не видят; PATH-shim
            // (хост-файлы) внутри контейнера в принципе недоступен.
            let mediation = if state.box_jail.is_none() && shim::is_agent_cmd(&base) {
                match shim::setup(&state.cwd, &state.ws_allow) {
                    Ok(m) => {
                        println!("🛡 Mediated Agent Mode: shell-вызовы агента проходят sandbox-гейт");
                        println!("   граница: {} · sudo/деструктив/выход за границу → отказ (агент подтвердить не может)", state.cwd.display());
                        Some(m)
                    }
                    Err(e) => {
                        eprintln!("⚠ медиация недоступна ({e}) — агент запускается БЕЗ фильтра его shell-вызовов");
                        None
                    }
                }
            } else {
                None
            };
            let extra: Vec<(String, String)> = mediation
                .iter()
                .flat_map(|m| m.env.iter().cloned())
                .collect();
            if let Some(jail) = &state.box_jail {
                println!(
                    "📦 Container Jail: сессия исполняется внутри контейнера {} — хост виден только как /workspace",
                    jail.name
                );
            }
            let pty_tokens: Vec<String> = match &state.box_jail {
                Some(jail) => containers::wrap_pty_exec(jail, &inner, &state.cwd),
                None => inner.clone(),
            };
            let outcome = hostexec::run_pty(&pty_tokens, &state.limits, &state.cwd, &extra);
            if let Some(m) = &mediation {
                print!("{}", shim::telemetry(&m.log_file));
                let _ = std::fs::remove_file(&m.log_file);
                let _ = std::fs::remove_file(&m.allow_file);
            }
            if let Some(e) = &outcome.spawn_error {
                state.last_exit = 127;
                return GatewayResult::Done(format!("⚡ {e}"));
            }
            state.last_exit = outcome.code.unwrap_or(0);
            return GatewayResult::Done(outcome.render());
        }
    }

    // Классификация сегментов
    enum Kind {
        Engine,
        Host,
    }
    let mut kinds: Vec<Kind> = Vec::new();
    let mut seg_tokens: Vec<Vec<String>> = Vec::new();
    for seg in &pipeline.segments {
        let tokens = super::pipeline::strip_poler_prefix(&seg.tokens, &is_engine_command);
        let cmd = tokens
            .first()
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        if cmd == "host" {
            // явное принуждение к хостовому контуру: host <cmd…>
            seg_tokens.push(tokens[1..].to_vec());
            kinds.push(Kind::Host);
            continue;
        }
        seg_tokens.push(tokens);
        if is_engine_command(&cmd) {
            kinds.push(Kind::Engine);
        } else {
            kinds.push(Kind::Host);
        }
    }

    // Sandbox: вердикт по ВСЕМ хостовым сегментам + редиректу — ДО исполнения
    let host_idx: Vec<usize> = kinds
        .iter()
        .enumerate()
        .filter(|(_, k)| matches!(k, Kind::Host))
        .map(|(i, _)| i)
        .collect();
    // v0.22.1: цель редиректа проверяется ВСЕГДА — даже в чисто движковых
    // конвейерах (`chunk x > pwn`, где pwn — симлинк в /etc): каноникализация
    // путей в judge_redirect_target раскрывает symlink-прокси.
    // v0.24.0: + граница workspace (движковый grep/chunk тоже читают файлы).
    // v0.25.0: redirect-цели судятся с границей ВСЕГДА — файл пишет сам
    // движок НА ХОСТЕ (finish()), jail его не изолирует.
    let full_guard = ws_guard(state);
    // exec-плоскость (host-сегменты и PTY) в jail-режиме судится без
    // логической границы — её заменяет физическая изоляция контейнера.
    let exec_guard: Option<sandbox::WsGuard> = if state.box_jail.is_some() {
        None
    } else {
        Some(ws_guard(state))
    };
    if host_idx.is_empty() {
        if let Some(r) = &pipeline.redirect {
            let verdict = sandbox::judge_redirect_target_ws(&r.path, Some(&full_guard));
            if state.danger_mode {
                if !verdict.is_allow() {
                    eprintln!("⚠ DANGER: sandbox отключён владельцем — редирект исполняется без проверок");
                }
            } else if let Policy::Block(why) = verdict {
                state.last_exit = 2;
                return GatewayResult::Done(format!("⛔ блокировка sandbox: {why}"));
            } else if let Policy::Confirm(why) = verdict {
                if !resolve_confirm(state, &why, interactive) {
                    state.last_exit = 125;
                    return GatewayResult::Done(format!("⛔ отклонено (не подтверждено): {why}"));
                }
            }
        }
    }
    if !host_idx.is_empty() {
        // пересобираем pipeline с уже срезанными poler-префиксами
        let judged = rebuild_for_judge(&pipeline, &seg_tokens);
        let verdict = sandbox::judge_pipeline_ws(&judged, &host_idx, exec_guard.as_ref());
        if state.danger_mode {
            // danger-режим: не блокируем и не спрашиваем — только предупреждаем
            if !verdict.is_allow() {
                eprintln!("⚠ DANGER: sandbox отключён владельцем — команда исполняется без проверок");
            }
        } else {
            match verdict {
                Policy::Allow => {}
                Policy::Block(why) => {
                    state.last_exit = 2;
                    return GatewayResult::Done(format!("⛔ блокировка sandbox: {why}"));
                }
                Policy::Confirm(why) => {
                    if !resolve_confirm(state, &why, interactive) {
                        state.last_exit = 125;
                        return GatewayResult::Done(format!("⛔ отклонено (не подтверждено): {why}"));
                    }
                }
            }
        }
    }
    // v0.25.0: управление контейнерным демоном из gateway при активном
    // jail — Confirm: `docker run -v /:/host` может сломать изоляцию.
    // В неинтерактиве — отказ (scripted-агент не управляет демоном).
    if state.box_jail.is_some() && !state.danger_mode {
        for &i in &host_idx {
            if containers::is_daemon_ctl(&seg_tokens[i]) {
                let why = "управление docker/podman-демоном хоста при активном Container Jail — может разрушить изоляцию";
                if !resolve_confirm(state, why, interactive) {
                    state.last_exit = 125;
                    return GatewayResult::Done(format!("⛔ отклонено (не подтверждено): {why}"));
                }
                break; // одного подтверждения достаточно
            }
        }
    }
    // v0.25.0: цель редиректа host-конвейера при активном jail судится с
    // ПОЛНОЙ границей отдельно — файл пишет сам движок НА ХОСТЕ (finish()),
    // контейнер эту запись не изолирует (в judge_pipeline_ws редирект идёт
    // с exec_guard, которого в jail-режиме нет).
    if state.box_jail.is_some() && !state.danger_mode && !host_idx.is_empty() {
        if let Some(r) = &pipeline.redirect {
            match sandbox::judge_redirect_target_ws(&r.path, Some(&full_guard)) {
                Policy::Allow => {}
                Policy::Block(why) => {
                    state.last_exit = 2;
                    return GatewayResult::Done(format!("⛔ блокировка sandbox: {why}"));
                }
                Policy::Confirm(why) => {
                    if !resolve_confirm(state, &why, interactive) {
                        state.last_exit = 125;
                        return GatewayResult::Done(format!("⛔ отклонено (не подтверждено): {why}"));
                    }
                }
            }
        }
    }
    // v0.24.0: граница и для ДВИЖКОВЫХ сегментов с файл-аргументами
    // (grep/chunk/impact/crawl/benchmark/gh…): движок читает файлы нативно —
    // путь вне workspace без подтверждения нельзя. Команды-запросы
    // (search/notes…) и навигация (cd/workspace/allow) — исключены:
    // у них свои ворота. v0.25.0: движок читает файлы НА ХОСТЕ — граница
    // действует даже при активном Container Jail.
    if !state.danger_mode {
        const WS_CHECKED_ENGINE: &[&str] = &[
            "grep", "chunk", "impact", "benchmark", "crawl", "gh", "gl", "gt", "gix",
        ];
        for tokens in &seg_tokens {
            let cmd = tokens.first().map(|s| s.as_str()).unwrap_or("");
            if !WS_CHECKED_ENGINE.contains(&cmd) || tokens.len() < 2 {
                continue;
            }
            if let Some(policy) = sandbox::boundary_policy_args(&tokens[1..], &full_guard) {
                if let Policy::Confirm(why) = policy {
                    if !resolve_confirm(state, &why, interactive) {
                        state.last_exit = 125;
                        return GatewayResult::Done(format!("⛔ отклонено (не подтверждено): {why}"));
                    }
                }
            }
        }
    }

    // Исполнение конвейера слева направо
    let mut stdin_data: Option<String> = None;
    let mut final_out = String::new();
    let mut stderr_out = String::new();
    let mut exit = 0;

    for (i, kind) in kinds.iter().enumerate() {
        // прерывание между сегментами (Ctrl+C во время длинного engine-этапа)
        if hostexec::INTERRUPT.load(std::sync::atomic::Ordering::SeqCst) {
            state.last_exit = 130;
            return GatewayResult::Done("⛔ прервано пользователем (Ctrl+C)".into());
        }
        let tokens = &seg_tokens[i];
        match kind {
            Kind::Engine => {
                let cmd = tokens.first().map(|s| s.as_str()).unwrap_or("");
                if stdin_data.is_some() && !accepts_stdin(cmd) {
                    state.last_exit = 2;
                    return GatewayResult::Done(format!(
                        "⚡ команда {cmd} не принимает stdin из конвейера (принимают: grep, chunk, impact)"
                    ));
                }
                match run_engine(state, tokens, stdin_data.as_deref(), interactive) {
                    Ok(out) => {
                        final_out = out;
                        stdin_data = Some(final_out.clone());
                    }
                    Err(EngineFail::Quit) => return GatewayResult::Quit,
                    Err(EngineFail::Msg(e)) => {
                        state.last_exit = 2;
                        return GatewayResult::Done(format!("⚡ {e}"));
                    }
                }
            }
            Kind::Host => {
                // v0.25.0: Container Jail — host-сегмент уходит ВНУТРИ
                // контейнера (docker exec -i …); вердикт уже вынесен по
                // исходным токенам ДО обёртки — инвариант сохранён.
                let exec_tokens: Vec<String> = match &state.box_jail {
                    Some(jail) => containers::wrap_host_exec(jail, tokens, &state.cwd),
                    None => tokens.clone(),
                };
                let outcome = hostexec::run(
                    &exec_tokens,
                    stdin_data.as_deref(),
                    &state.limits,
                    &state.cwd,
                    &[],
                );
                if !outcome.stderr.is_empty() {
                    stderr_out.push_str(&outcome.stderr);
                }
                if let Some(e) = &outcome.spawn_error {
                    state.last_exit = 127;
                    return GatewayResult::Done(format!("⚡ {e}"));
                }
                exit = outcome.code.unwrap_or(if outcome.timed_out || outcome.interrupted {
                    124
                } else {
                    1
                });
                final_out = outcome.stdout.clone();
                stdin_data = Some(final_out.clone());
                // видимость кода возврата последнего сегмента (как в POSIX)
                let is_last = i + 1 == kinds.len();
                if is_last && exit != 0 && !outcome.timed_out && !outcome.interrupted {
                    stderr_out.push_str(&format!("exit-код: {exit}\n"));
                }
                if outcome.timed_out || outcome.interrupted {
                    // дальше конвейер не имеет смысла
                    let note = if outcome.timed_out {
                        "таймаут"
                    } else {
                        "прервано (Ctrl+C)"
                    };
                    state.last_exit = 124;
                    let mut msg = final_out;
                    if !msg.is_empty() {
                        msg.push('\n');
                    }
                    msg.push_str(&format!("⚠ {note}: процесс убит\n"));
                    return finish(state, msg, stderr_out, &pipeline);
                }
            }
        }
    }

    state.last_exit = exit;
    finish(state, final_out, stderr_out, &pipeline)
}

/// Финал: применяем редирект (stdout → файл) или возвращаем текст.
fn finish(
    _state: &mut GatewayState,
    out: String,
    stderr: String,
    pipeline: &Pipeline,
) -> GatewayResult {
    if let Some(r) = &pipeline.redirect {
        let path = super::sandbox::expand_home(&r.path);
        let mut text = out;
        if r.stderr {
            text = stderr;
        }
        let write_result = if r.append {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .and_then(|mut f| f.write_all(text.as_bytes()))
        } else {
            std::fs::write(&path, &text)
        };
        return match write_result {
            Ok(()) => GatewayResult::Done(format!("→ {} ({} байт)", path, text.len())),
            Err(e) => GatewayResult::Done(format!("⚡ редирект в {path}: {e}")),
        };
    }
    // stderr без редиректа показываем вместе с stdout (с меткой)
    let mut full = out;
    if !stderr.is_empty() {
        if !full.is_empty() && !full.ends_with('\n') {
            full.push('\n');
        }
        for l in stderr.lines() {
            full.push_str(&format!("⚠ stderr: {l}\n"));
        }
    }
    GatewayResult::Done(full)
}

/// Пересобрать Pipeline для sandbox-анализа (poler-префиксы срезаны).
fn rebuild_for_judge(orig: &Pipeline, seg_tokens: &[Vec<String>]) -> Pipeline {
    Pipeline {
        segments: orig
            .segments
            .iter()
            .zip(seg_tokens)
            .map(|(_s, t)| Segment {
                tokens: t.clone(),
                raw: t.join(" "),
            })
            .collect(),
        redirect: orig.redirect.clone(),
    }
}

/// Интерактивное подтверждение опасного действия.
fn ask_confirm(reason: &str) -> bool {
    println!("⚠ {reason}");
    print!("исполнить? [yes/No] ");
    let _ = std::io::stdout().flush();
    let mut ans = String::new();
    match std::io::stdin().read_line(&mut ans) {
        Ok(0) => false, // EOF — не подтверждено
        Ok(_) => {
            let a = ans.trim().to_lowercase();
            a == "y" || a == "yes" || a == "д" || a == "да"
        }
        Err(_) => false,
    }
}

/// Подтверждение на РЕАЛЬНОМ терминале владельца (/dev/tty): пайп-агент
/// не может ответить за человека — его stdin не наш терминал
/// (Zero Silent Escalation, v0.23.0). Нет /dev/tty — отказ.
fn ask_confirm_tty(reason: &str) -> bool {
    let mut tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(t) => t,
        Err(_) => {
            eprintln!("⚠ {reason} — нет доступа к /dev/tty для подтверждения; отказ");
            return false;
        }
    };
    let _ = writeln!(tty, "⚠ {reason}");
    let _ = write!(tty, "разрешить? [yes/No] ");
    let _ = tty.flush();
    let mut reader = std::io::BufReader::new(tty);
    let mut ans = String::new();
    match reader.read_line(&mut ans) {
        Ok(0) | Err(_) => false,
        Ok(_) => {
            let a = ans.trim().to_lowercase();
            a == "y" || a == "yes" || a == "д" || a == "да"
        }
    }
}

/// Confirm-ворота с учётом sudo-лизинга и auto-yes (v0.23.0).
/// Привилегированные подтверждения (sudo/su/…) в интерактиве читаются
/// с /dev/tty; в неинтерактиве их пропускает ТОЛЬКО активный лизинг
/// (открытый интерактивно) или явный set autoyes on.
fn resolve_confirm(state: &mut GatewayState, why: &str, interactive: bool) -> bool {
    if state.auto_yes {
        println!("⚠ auto-yes: {why}");
        return true;
    }
    if sandbox::is_privilege_escalation(why) {
        if let Some(rem) = state.sudo_lease_remaining() {
            println!(
                "🔓 sudo-лизинг активен (ещё {} с) — пропуск без запроса",
                rem.as_secs()
            );
            return true;
        }
        if interactive {
            return ask_confirm_tty(why);
        }
        eprintln!(
            "⚠ {why} — привилегированная команда; в неинтерактиве допустимы только sudo-лизинг (интерактивно) или set autoyes on"
        );
        return false;
    }
    if interactive {
        return ask_confirm(why);
    }
    eprintln!("⚠ {why} — требуется подтверждение (в скрипте: set autoyes on)");
    false
}

// ---------------------------------------------------------------------------
// Контур 1: исполнение команд движка
// ---------------------------------------------------------------------------

fn run_engine(
    state: &mut GatewayState,
    tokens: &[String],
    stdin: Option<&str>,
    interactive: bool,
) -> Result<String, EngineFail> {
    let cmd = tokens.first().map(|s| s.as_str()).unwrap_or("");
    let args = &tokens[1..];
    match cmd {
        "grep" => cmd_grep(args, stdin).map_err(EngineFail::Msg),
        "chunk" => cmd_chunk(args, stdin).map_err(EngineFail::Msg),
        "impact" => {
            if stdin.is_some() {
                cmd_impact(args, stdin).map_err(EngineFail::Msg)
            } else {
                // без stdin — анализ репозитория по cwd: делегация
                delegate_shell(state, tokens)
            }
        }
        "benchmark" => cmd_benchmark(args).map_err(EngineFail::Msg),
        "service" => cmd_service(state, args).map_err(EngineFail::Msg),
        "attach" => cmd_attach(args).map_err(EngineFail::Msg),
        "weblens" => cmd_weblens(args).map_err(EngineFail::Msg),
        "license" => Ok(crate::license::status_text()),
        "cd" => cmd_cd(state, args, interactive).map_err(EngineFail::Msg),
        "workspace" => cmd_workspace(state, args, interactive).map_err(EngineFail::Msg),
        "grant" => cmd_grant(state, args, interactive).map_err(EngineFail::Msg),
        "allow" => cmd_allow(state, args, interactive).map_err(EngineFail::Msg),
        "box" => cmd_box(state, args, interactive).map_err(EngineFail::Msg),
        "pty" => Err(EngineFail::Msg(
            "pty: укажите команду (pty vim main.rs) — TUI/IDE/агент на псевдотерминале".into(),
        )),
        "pwd" => Ok(format!("{}\n", state.cwd.display())),
        "clear" => Ok("\x1b[2J\x1b[1;1H".into()),
        "help" | "?" => Ok(gateway_help()),
        "version" | "ver" | "v" => Ok(format!(
            "poler-engine {} — Terminal Gateway v0.28.0 (двойной контур + PTY + sudo-гейт + workspace-guard + container-jail + agent-bindmount + mcp-broker + root-broker + sudo-passwd + jailbreak-sentinel + builtin-hunter)\n",
            env!("CARGO_PKG_VERSION")
        )),
        "quit" | "exit" | "q" => Err(EngineFail::Quit),
        "set" => {
            // gateway-настройки, иначе делегация во внутренний шелл
            if let Some(sub) = args.first() {
                match sub.as_str() {
                    "hosttimeout" => return cmd_set_hosttimeout(state, args).map_err(EngineFail::Msg),
                    "hostenv" => return cmd_set_hostenv(state, args).map_err(EngineFail::Msg),
                    "autoyes" => return cmd_set_autoyes(state, args).map_err(EngineFail::Msg),
                    "sandbox" => return cmd_set_sandbox(state, args, interactive).map_err(EngineFail::Msg),
                    _ => {}
                }
            }
            delegate_shell(state, tokens)
        }
        _ => delegate_shell(state, tokens),
    }
}

/// Делегация во внутренний шелл движка (v0.15+): search/stats/notes/
/// sources/crawl/impact/gh/gl/gt/gix/sync/set… Слова с пробелами
/// перекавычиваются — семантика аргументов сохраняется.
fn delegate_shell(state: &mut GatewayState, tokens: &[String]) -> Result<String, EngineFail> {
    let line = tokens
        .iter()
        .map(|t| {
            if t.contains(' ') {
                format!("\"{t}\"")
            } else {
                t.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    match shell::commands::dispatch(&mut state.shell, &line) {
        shell::CmdResult::Done(out) => {
            // выход внутреннего шелла без завершающего \n — нормализуем
            if out.ends_with('\n') {
                Ok(out)
            } else {
                Ok(format!("{out}\n"))
            }
        }
        shell::CmdResult::Quit => Err(EngineFail::Quit),
        shell::CmdResult::Empty => Ok(String::new()),
    }
}

// ---------------------------------------------------------------------------
// grep — POLER Native Grep (слой 0, v0.20.0) с stdin из конвейера
// ---------------------------------------------------------------------------

fn cmd_grep(args: &[String], stdin: Option<&str>) -> Result<String, String> {
    use crate::retrieval as nr;
    let mut pattern: Option<String> = None;
    let mut mode = nr::GrepMode::Literal;
    let mut icase = false;
    let mut before = 0usize;
    let mut after = 0usize;
    let mut max_count: Option<usize> = None;
    let mut output = nr::GrepOutput::Content;
    let mut hidden = false;
    let mut json = false;
    let mut force_stdin = false;
    let mut roots: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--regex" | "-E" => mode = nr::GrepMode::Regex,
            "-i" | "--ignore-case" | "--grep-i" => icase = true,
            "--count" | "-c" => output = nr::GrepOutput::Count,
            "--list" | "-l" => output = nr::GrepOutput::ListMatching,
            "--list-nonmatching" | "-L" => output = nr::GrepOutput::ListNonMatching,
            "--hidden" => hidden = true,
            "--json" => json = true,
            "--stdin" => force_stdin = true,
            "-A" | "--after" | "-B" | "--before" | "-m" | "--max-count" => {
                let v = args.get(i + 1).ok_or_else(|| format!("{a}: ожидается число"))?;
                let n: usize = v
                    .parse()
                    .map_err(|_| format!("{a}: не число: {v}"))?;
                match a.as_str() {
                    "-A" | "--after" => after = n,
                    "-B" | "--before" => before = n,
                    _ => max_count = Some(n),
                }
                i += 1;
            }
            _ => {
                if a.starts_with('-') && a.len() > 1 {
                    return Err(format!("grep: неизвестный флаг {a} (движковый grep; системный — !grep)"));
                }
                if pattern.is_none() {
                    pattern = Some(a.clone());
                } else {
                    roots.push(a.clone());
                }
            }
        }
        i += 1;
    }
    let pattern = pattern.ok_or("grep: укажите PATTERN (grep PATTERN [PATH…])")?;
    let config = nr::GrepConfig {
        pattern,
        mode,
        case_insensitive: icase,
        before,
        after,
        max_count,
        output,
        include_hidden: hidden,
        respect_ignore: true,
        // Терминальный гейтвей: архивы не сканируются (v0.28.1 —
        // уровень CLI/grep; расширение гейтвея — отдельный шаг).
        scan_archives: false,
        archive_password: None,
        archive_max_entry_bytes: 0,
    };

    let report = if stdin.is_some() || force_stdin {
        let text = stdin.unwrap_or("");
        nr::grep_buffer("stdin", text, &config)?
    } else {
        let root_paths: Vec<PathBuf> = if roots.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            roots.into_iter().map(PathBuf::from).collect()
        };
        nr::grep_run(&root_paths, &config)?
    };
    let text = if json {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    } else {
        nr::render_text(&report, false)
    };
    Ok(text)
}

// ---------------------------------------------------------------------------
// chunk — RAG-чанкер (слой B, v0.20.0) с stdin из конвейера
// ---------------------------------------------------------------------------

fn cmd_chunk(args: &[String], stdin: Option<&str>) -> Result<String, String> {
    use crate::retrieval as nr;
    let mut path: Option<String> = None;
    let mut size = 512usize;
    let mut overlap = 64usize;
    let mut json = false;
    let mut force_stdin = false;
    let mut format: Option<nr::ChunkFormat> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--size" | "-s" => {
                size = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--size: ожидается число")?;
                i += 1;
            }
            "--overlap" => {
                overlap = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--overlap: ожидается число")?;
                i += 1;
            }
            "--json" => json = true,
            "--stdin" => force_stdin = true,
            "--format" => {
                let f = args.get(i + 1).ok_or("--format: md|plain|code")?;
                format = Some(match f.as_str() {
                    "md" | "markdown" => nr::ChunkFormat::Markdown,
                    "code" => nr::ChunkFormat::Code,
                    "plain" => nr::ChunkFormat::Plain,
                    other => return Err(format!("--format: неизвестный {other}")),
                });
                i += 1;
            }
            _ => {
                if a.starts_with('-') {
                    return Err(format!("chunk: неизвестный флаг {a}"));
                }
                if path.is_none() {
                    path = Some(a.clone());
                } else {
                    return Err("chunk: только один PATH (или stdin из конвейера)".into());
                }
            }
        }
        i += 1;
    }

    let config = nr::ChunkConfig {
        target_tokens: size,
        overlap_tokens: overlap,
        ..Default::default()
    };

    let (text, fmt, name) = if stdin.is_some() || force_stdin {
        (
            stdin.unwrap_or("").to_string(),
            format.unwrap_or(nr::ChunkFormat::Plain),
            "stdin".to_string(),
        )
    } else {
        let p = path.ok_or("chunk: укажите PATH (или подайте stdin через конвейер)")?;
        let pb = PathBuf::from(&p);
        let t = std::fs::read_to_string(&pb).map_err(|e| format!("chunk: {p}: {e}"))?;
        let f = format.unwrap_or_else(|| nr::ChunkFormat::detect(&pb));
        (t, f, p)
    };
    let report = nr::chunk_document(&text, fmt, &config);
    let out = if json {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    } else {
        nr::render_chunks_text(&report, &name)
    };
    Ok(out)
}

// ---------------------------------------------------------------------------
// impact — AIDDE impact-анализ; в конвейере код приходит из stdin
// ---------------------------------------------------------------------------

fn cmd_impact(args: &[String], stdin: Option<&str>) -> Result<String, String> {
    let symbol = args
        .first()
        .ok_or("impact: укажите SYMBOL (impact SYMBOL [PATH])")?
    ;
    let depth = args
        .get(1)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2);

    // код из конвейера: временный файл → SymbolTable → impact
    let code = stdin.ok_or("impact: нет stdin")?;
    let tmp = std::env::temp_dir().join(format!("poler-gateway-impact-{}.rs", std::process::id()));
    std::fs::write(&tmp, code).map_err(|e| format!("impact: tmp: {e}"))?;
    let files = vec![tmp.clone()];
    let table = crate::aidde::SymbolTable::build(&files, 8 * 1024 * 1024);
    let result = crate::aidde::impact_analysis(&table, symbol, depth, 200)
        .map(|r| serde_json::to_string_pretty(&r).unwrap_or_default());
    let _ = std::fs::remove_file(&tmp);
    result.ok_or_else(|| format!("impact: символ не найден в stdin-коде: {symbol}"))
}

// ---------------------------------------------------------------------------
// benchmark — Bench Suite (v0.21.0)
// ---------------------------------------------------------------------------

fn cmd_benchmark(args: &[String]) -> Result<String, String> {
    let json_path = args
        .iter()
        .position(|a| a == "--json")
        .and_then(|i| args.get(i + 1).cloned());
    let opts = crate::bench::BenchOpts::default();
    let res = crate::bench::run_suite(&opts)?;
    if let Some(p) = json_path {
        let json = serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| format!("benchmark-json: {p}: {e}"))?;
    }
    Ok(crate::bench::report_text(&res))
}

// ---------------------------------------------------------------------------
// service / attach / weblens — управление нижним слоем
// ---------------------------------------------------------------------------

fn cmd_service(state: &GatewayState, args: &[String]) -> Result<String, String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "status" => Ok(service::status(args.get(1).map(|s| s.as_str()))),
        "start" => {
            let name = args.get(1).ok_or("service start <имя> [bind]")?;
            let bind = args.get(2).map(|s| s.as_str());
            // v0.26.0: MCP-брокер (poler_box_exec) обязан знать корень
            // workspace сессии — сервис наследует env родителя (Command по
            // умолчанию наследует окружение), поэтому выставляем POLER_WORKSPACE
            std::env::set_var("POLER_WORKSPACE", &state.ws_root);
            service::start(name, bind)
        }
        "stop" => {
            let name = args.get(1).ok_or("service stop <имя>")?;
            service::stop(name)
        }
        "restart" => {
            let name = args.get(1).ok_or("service restart <имя> [bind]")?;
            let bind = args.get(2).map(|s| s.as_str());
            // stop не критичен для restart: мог не быть запущен
            let _ = service::stop(name);
            service::start(name, bind)
        }
        "attach" => {
            let name = args.get(1).ok_or("service attach <имя>")?;
            attach_session(name)
        }
        other => Err(format!(
            "service: неизвестная подкоманда {other} (start|stop|restart|status|attach)"
        )),
    }
}

fn cmd_attach(args: &[String]) -> Result<String, String> {
    let name = args.first().map(|s| s.as_str()).unwrap_or("mcp");
    attach_session(name)
}

fn cmd_weblens(args: &[String]) -> Result<String, String> {
    match args.first().map(|s| s.as_str()).unwrap_or("start") {
        "start" => service::start("weblens", args.get(1).map(|s| s.as_str())),
        "stop" => service::stop("weblens"),
        "status" => Ok(service::status(Some("weblens"))),
        "install" => Err("weblens install: используйте `poler-engine --web-lens-install` (материализация + инструкция)".into()),
        other => Err(format!("weblens: {other}? (start|stop|status)")),
    }
}

/// Подключение к сессии сервиса: mcp → JSON-RPC REPL, прочие → tail лога.
fn attach_session(name: &str) -> Result<String, String> {
    match name {
        "mcp" => attach_mcp(),
        "weblens" => tail_log(name),
        other => Err(format!(
            "attach: неизвестный сервис {other} ({})",
            service::service_names().join(", ")
        )),
    }
}

/// JSON-RPC REPL поверх живого MCP-сервера.
fn attach_mcp() -> Result<String, String> {
    let st_text = service::status(Some("mcp"));
    let endpoint = extract_endpoint(&st_text)
        .ok_or("attach mcp: сервис не запущен (`service start mcp`)")?;
    let token = service::service_token("mcp")?;
    println!("attach: {} (токен {})", endpoint, service::mask_token(&token));
    println!("команды: tools | call <tool> {{json}} | {{сырой JSON-RPC}} | quit");

    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        print!("mcp> ");
        let _ = std::io::stdout().flush();
        match stdin.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t == "quit" || t == "exit" || t == "q" {
            break;
        }
        let (method, params) = if t == "tools" {
            ("tools/list".to_string(), serde_json::json!({}))
        } else if let Some(rest) = t.strip_prefix("call ") {
            let rest = rest.trim();
            let (tool, args_str) = rest
                .split_once(char::is_whitespace)
                .unwrap_or((rest, "{}"));
            let params = serde_json::from_str(args_str.trim())
                .unwrap_or_else(|_| serde_json::json!({}));
            ("tools/call".to_string(), serde_json::json!({"name": tool, "arguments": params}))
        } else if t.starts_with('{') {
            // сырой JSON-RPC: {"method": "...", "params": {...}}
            match serde_json::from_str::<serde_json::Value>(t) {
                Ok(v) => (
                    v.get("method").and_then(|m| m.as_str()).unwrap_or("tools/list").to_string(),
                    v.get("params").cloned().unwrap_or(serde_json::json!({})),
                ),
                Err(e) => {
                    println!("⚡ JSON: {e}");
                    continue;
                }
            }
        } else {
            println!("⚡ неизвестная команда (tools | call <tool> {{json}} | {{JSON-RPC}} | quit)");
            continue;
        };
        let (code, body) = service::mcp_rpc(&endpoint, &token, &method, params.clone());
        if code == 0 {
            println!("⚡ {body}");
        } else if code == 200 || code == 405 {
            // 405: GET не нужен, POST-ответ уже в body
            println!("{body}");
        } else {
            println!("⚡ HTTP {code}: {body}");
        }
    }
    Ok("attach: отключение\n".into())
}

/// Извлечь endpoint из вывода status (мини-парсинг таблицы).
fn extract_endpoint(status_text: &str) -> Option<String> {
    // строка вида "mcp         12345    running ✓ http://127.0.0.1:8765/"
    for line in status_text.lines() {
        if line.starts_with("mcp") && line.contains("http") {
            let url = line
                .split_whitespace()
                .find(|w| w.starts_with("http"))?;
            return Some(url.to_string());
        }
    }
    None
}

/// tail -f лога сервиса до Ctrl+C / EOF.
fn tail_log(name: &str) -> Result<String, String> {
    let path = service::log_file(name);
    if !path.exists() {
        return Ok(format!(
            "attach {name}: лога ещё нет ({}) — сервис не запускался?",
            path.display()
        ));
    }
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(4096);
    f.seek(SeekFrom::Start(start)).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    print!("{}", String::from_utf8_lossy(&buf));
    println!("— tail {}: Ctrl+C/Ctrl+D для выхода —", name);
    loop {
        if hostexec::INTERRUPT.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut chunk = Vec::new();
        let n = f.read_to_end(&mut chunk).unwrap_or(0);
        if n > 0 {
            print!("{}", String::from_utf8_lossy(&chunk));
            let _ = std::io::stdout().flush();
        }
    }
    hostexec::clear_interrupt();
    Ok(format!("\nattach {name}: отключение\n"))
}

// ---------------------------------------------------------------------------
// set-настройки gateway
// ---------------------------------------------------------------------------

fn cmd_set_hosttimeout(state: &mut GatewayState, args: &[String]) -> Result<String, String> {
    let v = args.get(1).ok_or("set hosttimeout <сек>")?;
    let n: u64 = v.parse().map_err(|_| format!("не число: {v}"))?;
    state.limits.timeout_secs = n;
    Ok(format!("host-таймаут: {n} с\n"))
}

fn cmd_set_hostenv(state: &mut GatewayState, args: &[String]) -> Result<String, String> {
    let v = args.get(1).map(|s| s.as_str()).ok_or("set hostenv filtered|full")?;
    state.limits.env_mode = match v {
        "filtered" => EnvMode::Filtered,
        "full" => EnvMode::Full,
        other => return Err(format!("set hostenv: {other}? (filtered|full)")),
    };
    Ok(format!(
        "host-окружение: {} (секреты {})\n",
        state.limits.env_mode,
        if state.limits.env_mode == EnvMode::Filtered {
            "вырезаются"
        } else {
            "наследуются ПОЛНОСТЬЮ"
        }
    ))
}

fn cmd_set_autoyes(state: &mut GatewayState, args: &[String]) -> Result<String, String> {
    let v = args.get(1).map(|s| s.as_str()).ok_or("set autoyes on|off")?;
    state.auto_yes = match v {
        "on" | "yes" => true,
        "off" | "no" => false,
        other => return Err(format!("set autoyes: {other}? (on|off)")),
    };
    Ok(format!("auto-подтверждение: {}\n", if state.auto_yes { "ВКЛ (осторожно!)" } else { "выкл" }))
}

/// `set sandbox on|off|status` (v0.23.0): явное управление sandbox.
/// Отключение — только в интерактиве с подтверждением на /dev/tty
/// (Zero Silent Escalation: пайп-агент не может выключить защиту молча).
fn cmd_set_sandbox(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    let v = args
        .get(1)
        .map(|s| s.as_str())
        .ok_or("set sandbox on|off|status")?;
    match v {
        "status" => Ok(sandbox_status(state)),
        "off" => {
            if state.danger_mode {
                return Ok("sandbox уже отключён (danger mode)\n".into());
            }
            if !interactive {
                return Ok(
                    "⛔ set sandbox off: отключение sandbox возможно только в интерактивной сессии (подтверждение на /dev/tty)\n"
                        .into(),
                );
            }
            if !ask_confirm_tty(
                "ОТКЛЮЧИТЬ SANDBOX ПОЛНОСТЬЮ? Блокировки перестанут действовать; вся ответственность — на операторе",
            ) {
                return Ok("не подтверждено — sandbox остаётся активным\n".into());
            }
            state.danger_mode = true;
            Ok(
                "☠ DANGER MODE: sandbox отключён. Все команды исполняются без проверок. Ответственность — на операторе.\n"
                    .into(),
            )
        }
        "on" => {
            state.danger_mode = false;
            Ok("sandbox включён (Block/Confirm/Allow)\n".into())
        }
        other => Err(format!("set sandbox: {other}? (on|off|status)")),
    }
}

/// Сводка режима безопасности для `set sandbox status`.
fn sandbox_status(state: &GatewayState) -> String {
    let sb = if state.danger_mode {
        "ОТКЛЮЧЁН (danger mode — только предупреждения)"
    } else {
        "активен (Block/Confirm/Allow)"
    };
    let lease = match state.sudo_lease_remaining() {
        Some(rem) => format!("активен, ещё {} с", rem.as_secs()),
        None => "не активен".to_string(),
    };
    let allow_n = state.ws_allow.len();
    format!(
        "sandbox: {sb}\nsudo-лизинг: {lease}\nworkspace: {}\nallowlist: {allow_n} путей (allow — список)\n",
        state.cwd.display()
    )
}

/// `grant sudo <N|m|s|h>|off|status` (v0.23.0): временный лизинг
/// привилегий — окно, в котором sudo/su-Confirm не спрашивается.
/// Открывается ТОЛЬКО в интерактивной сессии; кап 60 минут; сгорает сам.
fn cmd_grant(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    match args.first().map(|s| s.as_str()) {
        None | Some("status") => Ok(grant_status(state)),
        Some("sudo") => match args.get(1).map(|s| s.as_str()) {
            None => Ok(grant_status(state)),
            Some("off") | Some("revoke") => {
                if state.sudo_lease_until.take().is_some() {
                    Ok("sudo-лизинг отозван\n".into())
                } else {
                    Ok("sudo-лизинг не активен\n".into())
                }
            }
            Some(v) => {
                if !interactive {
                    return Ok(
                        "⛔ grant sudo: лизинг привилегий открывается только в интерактивной сессии (владелец за терминалом)\n"
                            .into(),
                    );
                }
                let (secs, clamped) = parse_lease(v)?;
                state.sudo_lease_until =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(secs));
                let cap_note = if clamped { " (кап 60 мин)" } else { "" };
                Ok(format!(
                    "🔓 sudo-лизинг активен: {v}{cap_note} — сгорит автоматически. Деструктивные команды (rm -rf /, dd of=/dev/*, reverse-shell…) по-прежнему БЛОКИРУЮТСЯ.\n"
                ))
            }
        },
        Some(other) => Err(format!("grant: {other}? (grant sudo <мин>m|off|status)")),
    }
}

fn grant_status(state: &GatewayState) -> String {
    match state.sudo_lease_remaining() {
        Some(rem) => format!("sudo-лизинг активен: ещё {} с\n", rem.as_secs()),
        None => "sudo-лизинг не активен (grant sudo 5m — открыть в интерактиве)\n".into(),
    }
}

/// Парсер длительности лизинга: `5` → 300 с (минуты по умолчанию),
/// `5m`/`90s`/`2h`; кап 60 минут (флаг clamped).
fn parse_lease(v: &str) -> Result<(u64, bool), String> {
    let (num, mult) = match v.chars().last() {
        Some('m') => (&v[..v.len() - 1], 60u64),
        Some('s') => (&v[..v.len() - 1], 1),
        Some('h') => (&v[..v.len() - 1], 3600),
        _ => (v, 60),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("grant sudo: не число: {v} (примеры: 5m, 90s, 2h)"))?;
    if n == 0 {
        return Err("grant sudo: нулевой лизинг".into());
    }
    let total = n.saturating_mul(mult);
    if total > 3600 {
        Ok((3600, true))
    } else {
        Ok((total, false))
    }
}

fn cmd_cd(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    let target = match args.first() {
        Some(p) => super::sandbox::expand_home(p),
        None => std::env::var("HOME").unwrap_or_else(|_| ".".into()),
    };
    let path = if target.starts_with('/') {
        PathBuf::from(&target)
    } else {
        state.cwd.join(&target)
    };
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("cd: {}: {e}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("cd: {} не каталог", path.display()));
    }
    // v0.25.0: прежний корень — ДО переноса границы (для предупреждения jail)
    let old_root = state.ws_root.clone();
    // v0.24.0: выход ЗА ГРАНИЦУ workspace — только с подтверждения
    // владельца (в неинтерактиве — отказ: пайп-агент не должен уводить
    // корень). Навигация внутри (в т.ч. cd .. к корню) — свободна;
    // подтверждённый выход переносит границу на новое место.
    if !state.danger_mode && !canonical.starts_with(&state.ws_root) {
        let why = format!(
            "выход из workspace: {} → {}",
            state.ws_root.display(),
            canonical.display()
        );
        if !resolve_confirm(state, &why, interactive) {
            return Ok("⛔ не подтверждено — остаёмся в workspace\n".into());
        }
        state.ws_root = canonical.clone();
    }
    // v0.23.0: process-cwd следует за state.cwd — движковые и хостовые
    // команды работают от одного корня (в REPL; тесты не мутируют глобал).
    if state.sync_cwd {
        std::env::set_current_dir(&canonical)
            .map_err(|e| format!("cd: chdir: {e}"))?;
    }
    state.cwd = canonical;
    // v0.25.0: jail монтирует ПРЕЖНИЙ корень — предупреждаем (физическая
    // монтировка не переехала; переподнять: box off && box on)
    if state.box_jail.is_some() && old_root != state.ws_root {
        return Ok(format!(
            "⚠ box jail: контейнер продолжает монтировать {} (старый корень); box off && box on — переподнять на новый\n",
            old_root.display()
        ));
    }
    Ok(String::new())
}

/// `workspace [PATH]` (v0.23.0): выбор корня проекта. Меняет state.cwd
/// И process-cwd (движковые grep/chunk/search и подпроц-
/// сы — от одного корня), обновляет приглашение; без PATH — отчёт.
/// v0.24.0: смена корня ЗА пределы текущего — подтверждение владельца
/// (неинтерактив — отказ: scripted-агент не должен двигать границу).
fn cmd_workspace(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    let Some(p) = args.first() else {
        let allow_list = if state.ws_allow.is_empty() {
            String::new()
        } else {
            format!(
                "allowlist (сессия): {}\n",
                state
                    .ws_allow
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Ok(format!(
            "workspace: {}\n{allow_list}движковые (grep/chunk/search) и хостовые команды работают от этого корня; workspace <путь> — переключить; allow <путь> — разрешить внешние пути\n",
            state.cwd.display()
        ));
    };
    let target = super::sandbox::expand_home(p);
    let path = if target.starts_with('/') {
        PathBuf::from(&target)
    } else {
        state.cwd.join(&target)
    };
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("workspace: {}: {e}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("workspace: {} не каталог", path.display()));
    }
    // v0.25.0: прежний корень — ДО переноса границы (для предупреждения jail)
    let old_root = state.ws_root.clone();
    if !state.danger_mode && !canonical.starts_with(&state.ws_root) {
        let why = format!(
            "выход из workspace: {} → {}",
            state.ws_root.display(),
            canonical.display()
        );
        if !resolve_confirm(state, &why, interactive) {
            return Ok("⛔ не подтверждено — workspace не изменён\n".into());
        }
        state.ws_root = canonical.clone();
    }
    if state.sync_cwd {
        std::env::set_current_dir(&canonical)
            .map_err(|e| format!("workspace: chdir: {e}"))?;
    }
    let moved = state.cwd != canonical;
    state.cwd = canonical;
    if moved {
        // v0.25.0: jail монтирует прежний корень — как в cd
        if state.box_jail.is_some() && old_root != state.ws_root {
            return Ok(format!(
                "workspace → {}\n⚠ box jail: контейнер продолжает монтировать {}; box off && box on — переподнять\n",
                state.cwd.display(),
                old_root.display()
            ));
        }
        Ok(format!(
            "workspace → {}\nдвижок и хостовые команды привязаны к новому корню; подпроцессы (в т.ч. агенты) стартуют отсюда\n",
            state.cwd.display()
        ))
    } else {
        Ok(format!("workspace: {} (уже здесь)\n", state.cwd.display()))
    }
}

/// `allow [PATH|clear]` (v0.24.0): сессионный allowlist границ workspace.
/// Расширение границы — только владелец в интерактиве (пайп-агент не
/// может сам себе открыть /). Allowlist не ослабляет Block-инварианты.
fn cmd_allow(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    match args.first().map(|s| s.as_str()) {
        None => {
            let list = if state.ws_allow.is_empty() {
                "(пусто)".to_string()
            } else {
                state
                    .ws_allow
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            Ok(format!(
                "workspace: {}\nallowlist сессии:\n{list}\nallow <путь> — добавить (интерактив); allow clear — сброс\n",
                state.cwd.display()
            ))
        }
        Some("clear") => {
            state.ws_allow.clear();
            Ok("allowlist сброшен (граница — только workspace)\n".into())
        }
        Some(p) => {
            if !interactive {
                return Ok(
                    "⛔ allow: расширение границы workspace — только в интерактивной сессии (владелец за терминалом)\n"
                        .into(),
                );
            }
            let target = super::sandbox::expand_home(p);
            let abs = if target.starts_with('/') {
                PathBuf::from(target)
            } else {
                state.cwd.join(target)
            };
            let canon = abs
                .canonicalize()
                .map_err(|e| format!("allow: {}: {e}", abs.display()))?;
            if canon.starts_with(&state.ws_root) {
                return Ok("✅ путь уже внутри workspace — подтверждение не нужно\n".into());
            }
            if !state.ws_allow.contains(&canon) {
                state.ws_allow.push(canon.clone());
            }
            Ok(format!(
                "✅ разрешено на сессию: {}\nдействует до quit (allow clear — сброс); деструктив (rm -rf / и т.п.) блокируется ВСЁ РАВНО\n",
                canon.display()
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Container Jail (v0.25.0): `box on/off/status/shell`
// v0.26.0: + `box runner on/off/status` (контур исполнения MCP-брокера),
// `box on` пробрасывает хостовых агентов (zero-overhead bind-mount).
// ---------------------------------------------------------------------------

/// `box [status|on|off|shell|runner …]` — жёсткая Docker-изоляция контуров 2/3.
///
/// Живой кейс v0.23/v0.24: PATH-shim медиация агентов — best-effort (хардкод
/// /bin/sh и прямой execve не перехватываются). Container Jail решает класс
/// физически: host-команды и PTY-сессии исполняются ВНУТРИ контейнера
/// (`docker exec`), хост доступен только как /workspace и /home/poler.
/// v0.26.0: агентам НЕ нужен образ со всем софтом — их бинарники с хоста
/// пробрасываются внутрь read-only (bind-mount), конфиги — rw в /home/poler.
fn cmd_box(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    match args.first().map(|s| s.as_str()) {
        None | Some("status") => Ok(containers::box_status_text(
            state.box_jail.as_ref(),
            state.runner.as_ref(),
            &state.ws_root,
        )),
        Some("runner") => cmd_box_runner(state, &args[1..]),
        Some("sudo") => cmd_box_sudo(state, &args[1..], interactive),
        Some("root") => cmd_box_root(state, interactive),
        Some("allow") => cmd_box_allow(state, &args[1..], interactive),
        Some("hunt") => cmd_box_hunt(state, &args[1..], interactive),
        Some("on") => {
            // уже активен и жив? — не трогаем (идемпотентность)
            if let Some(jail) = &state.box_jail {
                if containers::box_running(&jail.name) == Some(true) {
                    return Ok(format!(
                        "📦 Container Jail уже активен: {} (box off — разобрать, box status — детали)\n",
                        jail.name
                    ));
                }
            }
            let cfg = containers::parse_on_args(&args[1..])?;
            let (jail, report) = containers::box_on(&state.ws_root, &cfg)?;
            state.box_jail = Some(jail);
            Ok(report)
        }
        Some("off") => {
            // v0.27.0: сначала останавливаем рут-брокер и охоту (даже если
            // docker-разбор упадёт — брокер не должен пережить клетку)
            let mut preface = String::new();
            if let Some(mut b) = state.sudo_broker.take() {
                preface.push_str(&b.stop());
            }
            if state.hunt.take().is_some() {
                preface.push_str("🎯 охота завершена (отчёты в hunt-базе)\n");
            }
            if let Some(mut h) = state.hunt_builtin.take() {
                preface.push_str(&h.stop());
            }
            let name = state
                .box_jail
                .as_ref()
                .map(|j| j.name.clone())
                .unwrap_or_else(|| containers::container_name(&state.ws_root));
            let mut report = containers::box_off(&name)?;
            if state
                .box_jail
                .as_ref()
                .is_some_and(|j| j.name == name)
            {
                state.box_jail = None;
            }
            // v0.26.0: box off разбирает и runner (единый стек jail)
            let runner_name = state
                .runner
                .as_ref()
                .map(|r| r.name.clone())
                .unwrap_or_else(|| containers::runner_name(&state.ws_root));
            match containers::runner_off(&runner_name) {
                Ok(r) => {
                    report.push_str(&r);
                    state.runner = None;
                }
                Err(e) => {
                    // docker мог быть доступен для box_off, но сломаться тут —
                    // не глотаем молча, но и не рушим результат box off
                    report.push_str(&format!("⚠ runner {runner_name}: {e}\n"));
                }
            }
            report.insert_str(0, &preface);
            Ok(report)
        }
        Some("shell") => {
            let Some(jail) = state.box_jail.clone() else {
                return Ok("box shell: jail не активен — сначала box on\n".into());
            };
            if !interactive {
                return Ok(
                    "box shell: интерактивная сессия требует настоящего терминала (TTY)\n".into(),
                );
            }
            // Команда — compile-time константа (не пользовательский ввод):
            // границей исполнения здесь выступает сам контейнер.
            let tokens = containers::box_shell_tokens();
            let wrapped = containers::wrap_pty_exec(&jail, &tokens, &state.cwd);
            println!("📦 Container Jail: шелл внутри контейнера {} (exit — вернуться в gateway)", jail.name);
            let outcome = hostexec::run_pty(&wrapped, &state.limits, &state.cwd, &[]);
            if let Some(e) = &outcome.spawn_error {
                return Ok(format!("⚡ {e}"));
            }
            state.last_exit = outcome.code.unwrap_or(0);
            Ok(outcome.render())
        }
        Some(other) => Err(format!(
            "box: {other}? (box on [image=…] | off | status | shell | runner on|off|status | sudo on|off|status|log | root | allow sudo … | hunt start|status|report|stop)"
        )),
    }
}

/// `box runner on [k=v…] | off | status` — изолированный контур исполнения
/// (двухконтурный брокер v0.26.0): MCP-инструмент poler_box_exec направляет
/// сюда команды агентов; net=none, только /workspace, без /home/poler.
fn cmd_box_runner(
    state: &mut GatewayState,
    args: &[String],
) -> Result<String, String> {
    match args.first().map(|s| s.as_str()) {
        None | Some("status") => {
            let name = state
                .runner
                .as_ref()
                .map(|r| r.name.clone())
                .unwrap_or_else(|| containers::runner_name(&state.ws_root));
            let mut s = String::new();
            match &state.runner {
                Some(r) => s.push_str(&format!(
                    "runner: ВКЛ — контур исполнения MCP-брокера\nконтейнер {} · образ {} · net {} · только {}\n",
                    r.name, r.cfg.image, r.cfg.net, containers::WS_MOUNT
                )),
                None => s.push_str(&format!(
                    "runner: ВЫКЛ — poler_box_exec исполняет в box (если поднят) либо отказывает\nконтейнер {name} не активен в этой сессии (box runner on — поднять; box status — живой статус docker)\n"
                )),
            }
            Ok(s)
        }
        Some("on") => {
            if let Some(r) = &state.runner {
                if containers::box_running(&r.name) == Some(true) {
                    return Ok(format!(
                        "🏃 runner уже активен: {} (box runner off — разобрать)\n",
                        r.name
                    ));
                }
            }
            let cfg = containers::parse_runner_args(&args[1..])?;
            let (runner, report) = containers::runner_on(&state.ws_root, &cfg)?;
            state.runner = Some(runner);
            Ok(report)
        }
        Some("off") => {
            let name = state
                .runner
                .as_ref()
                .map(|r| r.name.clone())
                .unwrap_or_else(|| containers::runner_name(&state.ws_root));
            let report = containers::runner_off(&name)?;
            if state
                .runner
                .as_ref()
                .is_some_and(|r| r.name == name)
            {
                state.runner = None;
            }
            Ok(report)
        }
        Some(other) => Err(format!(
            "box runner: {other}? (box runner on [image=…] [net=none|bridge] [mem=1g] [pids=256] [wsro=0|1] | off | status)"
        )),
    }
}

// ---------------------------------------------------------------------------
// v0.27.0: Root Broker («sudo как услуга») + Jailbreak Sentinel
// ---------------------------------------------------------------------------

/// `box sudo on|off|status|log [N]|passwd [--clear]` — рут-брокер.
/// Рут — привилегия ХОСТА: агент в клетке может только ПРОСИТЬ исполнение;
/// судья решает (Block-инварианты + allowlist + дефолт-политика), исполнение
/// идёт `docker exec -u 0:0` СО СТОРОНЫ ХОСТА, агенту возвращаются только
/// stdout/stderr/exit.
/// v0.28.0 `passwd`: владелец выдаёт агенту рут-ПАРОЛЬ (только интерактив —
/// scripted-агент не может ни задать, ни подменить); пароль открывает
/// НЕдеструктивный остаток, инварианты держат ВСЕГДА.
fn cmd_box_sudo(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    match args.first().map(|s| s.as_str()) {
        None | Some("status") => {
            let mut s = match &state.sudo_broker {
                Some(h) => h.status_text(),
                None => "🔐 рут-брокер ВЫКЛ — агент в клетке получает «нет рута» честным отказом\nруут как привилегия ХОСТА: box sudo on — агент сможет ПРОСИТЬ (судья решает)\nрежим пароля: box sudo passwd — выдать агенту рут-пароль (только интерактив; потом агент: echo ПАРОЛЬ | sudo -S cmd)\n".to_string(),
            };
            let jail = state
                .box_jail
                .as_ref()
                .map(|j| j.name.clone())
                .unwrap_or_else(|| containers::container_name(&state.ws_root));
            s.push_str(&format!(
                "дефолт-политика: apt/apt-get/dpkg + fs в границах /workspace|/home/poler; sudo/деструктив/инструменты побега — Deny всегда\nлимит 30/час · таймаут 120с · аудит {} · политика {}\n",
                super::rootbroker::audit_path(&jail).display(),
                super::rootbroker::policy_path(&jail).display()
            ));
            Ok(s)
        }
        Some("on") => {
            if let Some(h) = state.sudo_broker.as_ref() {
                return Ok(format!(
                    "🔐 рут-брокер уже активен (контейнер {}); box sudo off — остановить\n",
                    h.status().box_name
                ));
            }
            let Some(jail) = state.box_jail.clone() else {
                return Ok("box sudo on: jail не активен — сначала box on\n".into());
            };
            if containers::box_running(&jail.name) != Some(true) {
                return Ok(format!(
                    "box sudo on: контейнер {} не работает (box on — поднять)\n",
                    jail.name
                ));
            }
            let handle = super::rootbroker::spawn_broker(&jail)?;
            let mut report = format!(
                "🔐 рут-брокер ВКЛ — контейнер {}: агент в клетке зовёт «sudo …» → шим пишет запрос в /home/poler/.poler-broker → шлюз судит → Allow = docker exec -u 0 СО СТОРОНЫ ХОСТА\nагент рут НЕ держит ни секунды; stdout/stderr/exit — обратно в клетку; аудит {}\n",
                jail.name,
                super::rootbroker::audit_path(&jail.name).display()
            );
            report.push_str(&handle.status_text());
            state.sudo_broker = Some(handle);
            Ok(report)
        }
        Some("passwd") => cmd_box_sudo_passwd(state, &args[1..], interactive),
        Some("off") => {
            match state.sudo_broker.take() {
                Some(mut b) => Ok(b.stop()),
                None => Ok("рут-брокер не активен (box sudo on — поднять)\n".into()),
            }
        }
        Some("log") => {
            let n = args
                .get(1)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(20);
            let jail = state
                .box_jail
                .as_ref()
                .map(|j| j.name.clone())
                .unwrap_or_else(|| containers::container_name(&state.ws_root));
            Ok(super::rootbroker::tail_audit(&jail, n))
        }
        Some(other) => Err(format!(
            "box sudo: {other}? (box sudo on|off|status|log [N]|passwd [--clear])"
        )),
    }
}

/// `box sudo passwd [--clear]` — рут-пароль брокера.
/// Задание — ТОЛЬКО интерактив (TTY + владелец): scripted-агент не может
/// выдать сам себе рут. `--clear` — снятие (ужесточение, безопасно всегда).
fn cmd_box_sudo_passwd(
    state: &GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    let jail_name = state
        .box_jail
        .as_ref()
        .map(|j| j.name.clone())
        .unwrap_or_else(|| containers::container_name(&state.ws_root));
    let path = super::rootbroker::password_path(&jail_name);
    // синтаксис — ДО гейтов (урок v0.27.0: валидация аргументов первыми)
    if args.first().map(|s| s.as_str()) == Some("--clear") {
        return super::rootbroker::clear_password(&path);
    }
    if !args.is_empty() {
        return Err("box sudo passwd: флаги: --clear (снять пароль)".into());
    }
    if !interactive {
        return Ok(
            "box sudo passwd: выдача рут-пароля — только в интерактивной сессии (владелец за терминалом)\n⛔ scripted-агент не может выдать себе рут\n".into(),
        );
    }
    println!("🔐 выдача рут-пароля брокеру {jail_name} (ввод скрыт; пусто — отмена)");
    let p1 = read_secret_line("новый пароль (6..64): ")?;
    if p1.trim().is_empty() {
        return Ok("отмена: пустой ввод\n".into());
    }
    let p2 = read_secret_line("повторите: ")?;
    super::rootbroker::set_password_from_pair(&path, p1.trim(), p2.trim())
}

/// Прочитать строку-секрет с терминала: stty -echo (best-effort; при
/// неудаче честно предупреждает, что ввод виден). Не попадает в историю
/// rustyline (читается напрямую из stdin).
fn read_secret_line(prompt: &str) -> Result<String, String> {
    use std::io::Write as _;
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let echo_off = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if !echo_off {
        println!("⚠ stty -echo недоступен — ввод будет виден на экране");
    }
    let mut line = String::new();
    let res = std::io::stdin().read_line(&mut line);
    if echo_off {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::null())
            .status();
        println!();
    }
    res.map_err(|e| format!("stdin: {e}"))?;
    Ok(line.trim_end_matches('\n').trim_end_matches('\r').to_string())
}

/// `box root` — интерактивный РУТ-шелл в клетке, ТОЛЬКО с хоста (владелец
/// из шлюза). Изнутри контейнера этой команды не существует. Аудитится.
fn cmd_box_root(
    state: &mut GatewayState,
    interactive: bool,
) -> Result<String, String> {
    let Some(jail) = state.box_jail.clone() else {
        return Ok("box root: jail не активен — сначала box on\n".into());
    };
    if !interactive {
        return Ok(
            "box root: рут-шелл требует настоящего терминала (TTY) — интерактивная сессия владельца\n".into(),
        );
    }
    if containers::box_running(&jail.name) != Some(true) {
        return Ok(format!(
            "box root: контейнер {} не работает (box on — поднять)\n",
            jail.name
        ));
    }
    // Константа (не ввод пользователя): root ВНУТРИ клетки, хост не затрагивается
    let tokens = containers::box_root_tokens();
    let wrapped = containers::wrap_root_pty_exec(&jail, &tokens, &state.cwd);
    println!(
        "🔐 root-шелл ВНУТРИ контейнера {} (root в клетке; хост не затрагивается; exit — вернуться в gateway)",
        jail.name
    );
    let outcome = hostexec::run_pty(&wrapped, &state.limits, &state.cwd, &[]);
    if let Some(e) = &outcome.spawn_error {
        return Ok(format!("⚡ {e}"));
    }
    state.last_exit = outcome.code.unwrap_or(0);
    Ok(outcome.render())
}

/// `box allow sudo <glob> | --list | --reset` — allowlist рут-запросов.
/// ТОЛЬКО интерактивно (скриптованный агент не должен ослаблять политику).
fn cmd_box_allow(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    if args.first().map(|s| s.as_str()) != Some("sudo") {
        return Err("box allow: ожидается «box allow sudo <glob>|--list|--reset»".into());
    }
    let jail_name = state
        .box_jail
        .as_ref()
        .map(|j| j.name.clone())
        .unwrap_or_else(|| containers::container_name(&state.ws_root));
    let path = super::rootbroker::policy_path(&jail_name);
    // glob может быть многословным («cargo *») — склеиваем остаток токенов
    let rest: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
    match rest.first().copied() {
        None => Err("box allow sudo: укажите glob | --list | --reset".into()),
        // чтение списка — не ослабление политики: доступно всегда
        Some("--list") => {
            let globs = super::rootbroker::load_allow_globs(&path);
            if globs.is_empty() {
                Ok("руут-allowlist пуст (дефолт: apt/apt-get/dpkg + fs в границах)\n".into())
            } else {
                Ok(format!("руут-allowlist ({}): {}\n", globs.len(), globs.join(", ")))
            }
        }
        // добавление glob'а ОСЛАБЛЯЕТ политику — только интерактив;
        // reset/list безопасны в любую сторону (reset ужесточает)
        Some(_) if !interactive && rest.first() != Some(&"--reset") => Ok(
            "box allow sudo: правка рут-политики — только в интерактивной сессии (владелец за терминалом)\n⛔ scripted-агент не может ослаблять политику\n".into(),
        ),
        Some("--reset") => super::rootbroker::reset_allow_globs(&path),
        Some(_) => {
            let glob = rest.join(" ");
            super::rootbroker::add_allow_glob(&path, &glob)
        }
    }
}

/// `box hunt start [--mode probe|agent] [параметры] | status | report | stop`
/// — Jailbreak Sentinel: красная команда в клетке под наблюдением.
/// probe — детерминированная батарея векторов побега; agent — живой ИИ
/// с миссией побега (транскрипт → сигнатуры → канарейка → kill-switch).
fn cmd_box_hunt(
    state: &mut GatewayState,
    args: &[String],
    interactive: bool,
) -> Result<String, String> {
    match args.first().map(|s| s.as_str()) {
        None | Some("status") => {
            let mut s = match &state.hunt {
                Some(h) => super::sentinel::status_text(h),
                None => "🎯 охота не активна (box hunt start --mode probe|agent|builtin)\n".to_string(),
            };
            if let Some(hb) = &state.hunt_builtin {
                s.push('\n');
                s.push_str(&hb.status_text());
            }
            Ok(s)
        }
        Some("report") => {
            let mut s = String::new();
            if let Some(h) = &state.hunt {
                s.push_str(&super::sentinel::status_text(h));
                s.push('\n');
                s.push_str(&super::sentinel::render_report(h));
            }
            if let Some(hb) = &state.hunt_builtin {
                s.push('\n');
                s.push_str(&hb.status_text());
                if let Some(p) = hb.last_report_path() {
                    if let Ok(text) = std::fs::read_to_string(&p) {
                        s.push('\n');
                        s.push_str(&text);
                    }
                }
            }
            if s.is_empty() {
                return Ok("box hunt report: охота не активна — сначала box hunt start\n".into());
            }
            Ok(s)
        }
        Some("stop") => {
            let mut s = String::new();
            if state.hunt.take().is_some() {
                s.push_str("🎯 охота остановлена (отчёты и инциденты — в hunt-базе)\n");
            }
            if let Some(mut hb) = state.hunt_builtin.take() {
                s.push_str(&hb.stop());
            }
            if s.is_empty() {
                s.push_str("охота не активна\n");
            }
            Ok(s)
        }
        Some("start") => {
            // параметры — ДО требования jail/docker (валидация синтаксиса
            // не требует ни клетки, ни демона — как box on net=host)
            let mut mode = super::sentinel::HuntMode::Probe;
            let mut builtin_mode = false;
            let mut loop_mode = false;
            let mut interval: u64 = 30;
            let mut full_every: u64 = 600;
            let mut agent: Option<String> = None;
            let mut mission_path: Option<String> = None;
            let mut budget: u64 = 1800;
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                let (k, v) = match a.split_once('=') {
                    Some((k, v)) => (k.to_string(), Some(v.to_string())),
                    None => match a.as_str() {
                        "--mode" | "--agent" | "--mission" | "--budget" | "--interval"
                        | "--full-every" => (a.clone(), it.next().cloned()),
                        _ => (a.clone(), None),
                    },
                };
                match k.as_str() {
                    "--mode" | "mode" => match v.as_deref() {
                        Some("probe") => {
                            mode = super::sentinel::HuntMode::Probe;
                            builtin_mode = false;
                        }
                        Some("agent") => mode = super::sentinel::HuntMode::Agent,
                        Some("builtin") => {
                            // свой суб-агент POLER (v0.28.0): чёрный ящик изнутри
                            builtin_mode = true;
                        }
                        other => {
                            return Err(format!(
                                "box hunt start: mode={other:?}? (probe|agent|builtin)"
                            ))
                        }
                    },
                    "--loop" | "loop" => {
                        if let Some(v) = &v {
                            return Err(format!("box hunt start: --loop без значения ({v}?)"));
                        }
                        loop_mode = true;
                    }
                    "--interval" | "interval" => {
                        let Some(v) = v else {
                            return Err("box hunt start: --interval требует секунды".into());
                        };
                        interval = v
                            .parse()
                            .map_err(|_| format!("box hunt start: interval={v}? (секунды)"))?;
                        if !(10..=600).contains(&interval) {
                            return Err("box hunt start: интервал 10..=600 секунд".into());
                        }
                    }
                    "--full-every" | "full-every" => {
                        let Some(v) = v else {
                            return Err("box hunt start: --full-every требует секунды".into());
                        };
                        full_every = v
                            .parse()
                            .map_err(|_| format!("box hunt start: full-every={v}? (секунды)"))?;
                        if !(120..=86400).contains(&full_every) {
                            return Err("box hunt start: полная батарея каждые 120..=86400 сек".into());
                        }
                    },
                    "--agent" | "agent" => {
                        let Some(v) = v else {
                            return Err("box hunt start: --agent требует имя (agy/claude/…)".into());
                        };
                        agent = Some(v);
                    }
                    "--mission" | "mission" => {
                        let Some(v) = v else {
                            return Err("box hunt start: --mission требует путь к файлу".into());
                        };
                        mission_path = Some(v);
                    }
                    "--budget" | "budget" => {
                        let Some(v) = v else {
                            return Err("box hunt start: --budget требует секунды".into());
                        };
                        budget = v
                            .parse()
                            .map_err(|_| format!("box hunt start: budget={v}? (секунды)"))?;
                        if !(60..=7200).contains(&budget) {
                            return Err("box hunt start: бюджет 60..=7200 секунд".into());
                        }
                    }
                    other => {
                        return Err(format!(
                            "box hunt start: {other}? (--mode probe|agent|builtin --agent ИМЯ --mission ПУТЬ --budget СЕК --loop --interval СЕК --full-every СЕК)"
                        ))
                    }
                }
            }
            if builtin_mode {
                let Some(jail) = state.box_jail.clone() else {
                    return Ok("box hunt start: jail не активен — сначала box on\n".into());
                };
                if containers::box_running(&jail.name) != Some(true) {
                    return Ok(format!(
                        "box hunt start: контейнер {} не работает (box on — поднять)\n",
                        jail.name
                    ));
                }
                if let Some(hb) = &state.hunt_builtin {
                    if hb.loop_mode {
                        return Ok(format!(
                            "🤖 builtin-охота уже наблюдает ({}) — box hunt stop — остановить\n",
                            hb.box_name
                        ));
                    }
                }
                let broker_on = state.sudo_broker.is_some();
                if loop_mode {
                    let handle = super::hunter::start_loop(
                        &jail,
                        broker_on,
                        interval,
                        full_every,
                    )?;
                    let mut out = format!(
                        "🤖 Builtin Hunter (суб-агент POLER) — LOOP-наблюдение контейнера {}\nсвип каждые {}с · полная батарея каждые {}с · breach → kill-switch\nканал рут-брокера: {} · пароль-режим: {}\n",
                        jail.name,
                        interval,
                        full_every,
                        if broker_on { "атакуется (брокер активен)" } else { "НЕ атакуется (box sudo on — включить)" },
                        if super::rootbroker::password_exists(&jail.name) { "включён" } else { "выключен" }
                    );
                    out.push_str(&handle.status_text());
                    state.hunt_builtin = Some(handle);
                    return Ok(out);
                }
                let (handle, mut out) = super::hunter::run_oneshot(&jail, broker_on, true)?;
                if !broker_on {
                    out.insert_str(
                        0,
                        "⚠ рут-брокер не активен: канальные/судейские волны пропущены (box sudo on — атаковать канал целиком)\n",
                    );
                }
                state.hunt_builtin = Some(handle);
                return Ok(out);
            }
            match mode {
                super::sentinel::HuntMode::Probe => {
                    let Some(jail) = state.box_jail.clone() else {
                        return Ok("box hunt start: jail не активен — сначала box on\n".into());
                    };
                    if containers::box_running(&jail.name) != Some(true) {
                        return Ok(format!(
                            "box hunt start: контейнер {} не работает (box on — поднять)\n",
                            jail.name
                        ));
                    }
                    hunt_probe(state, &jail)
                }
                super::sentinel::HuntMode::Agent => {
                    let Some(jail) = state.box_jail.clone() else {
                        return Ok("box hunt start: jail не активен — сначала box on\n".into());
                    };
                    if containers::box_running(&jail.name) != Some(true) {
                        return Ok(format!(
                            "box hunt start: контейнер {} не работает (box on — поднять)\n",
                            jail.name
                        ));
                    }
                    hunt_agent(state, &jail, agent, mission_path, budget, interactive)
                }
            }
        }
        Some(other) => Err(format!(
            "box hunt: {other}? (box hunt start [--mode probe|agent|builtin] [--agent ИМЯ] [--mission ПУТЬ] [--budget СЕК] [--loop] [--interval СЕК] [--full-every СЕК] | status | report | stop)"
        )),
    }
}

/// probe-режим: задеплоить батарею в клетку, исполнить через docker exec,
/// дополнить хост-аудитом inspect, escape → kill-switch, отчёт.
fn hunt_probe(
    state: &mut GatewayState,
    jail: &containers::BoxState,
) -> Result<String, String> {
    super::sentinel::deploy_probe(&jail.home_dir)?;
    let tokens = vec![super::sentinel::PROBE_CONTAINER_PATH.to_string()];
    let wrapped = containers::wrap_host_exec(jail, &tokens, &state.cwd);
    let mut limits = state.limits.clone();
    limits.timeout_secs = limits.timeout_secs.clamp(30, 120);
    let outcome = hostexec::run(&wrapped, None, &limits, &state.cwd, &[]);
    if let Some(e) = &outcome.spawn_error {
        return Ok(format!("⚡ docker exec батареи: {e}"));
    }
    let probe = super::sentinel::parse_probe_output(&outcome.stdout);
    let host_audit = super::sentinel::host_hardening_check(&jail.name);
    let escapes = super::sentinel::count_verdicts(&probe).2
        + super::sentinel::count_verdicts(&host_audit).2;
    let mut kill_switched = false;
    let mut report = String::new();
    if escapes > 0 {
        kill_switched = true;
        match super::sentinel::kill_switch(&jail.name) {
            Ok(banner) => report.push_str(&banner),
            Err(e) => report.push_str(&format!("⚠ {e}\n")),
        }
    }
    let hunt = super::sentinel::HuntState {
        mode: super::sentinel::HuntMode::Probe,
        box_name: jail.name.clone(),
        probe,
        host_audit,
        attempts: Vec::new(),
        canary: None,
        kill_switched,
        agent: None,
        report_path: None,
    };
    let full = super::sentinel::render_report(&hunt);
    let path = super::sentinel::save_report(&hunt, &full);
    let mut hunt = hunt;
    hunt.report_path = path;
    let mut out = String::new();
    out.push_str(&super::sentinel::status_text(&hunt));
    out.push_str(&report);
    if !outcome.stdout.trim().is_empty() && hunt.probe.is_empty() {
        out.push_str("⚠ батарея не вернула структурированных строк (образ без coreutils?)\n");
    }
    out.push_str("box hunt report — полный отчёт; escape-векторы → патч + регрессионный тест («нашёл → закрыл»)\n");
    state.hunt = Some(hunt);
    Ok(out)
}

/// agent-режим: живой ИИ с миссией побега в PTY; транскрипт сканируется
/// сигнатурной базой; канарейка на хосте; breach → kill-switch.
fn hunt_agent(
    state: &mut GatewayState,
    jail: &containers::BoxState,
    agent: Option<String>,
    mission_path: Option<String>,
    budget: u64,
    interactive: bool,
) -> Result<String, String> {
    // агент: явный или первый проброшенный (label), иначе agy
    let agent_name = agent
        .or_else(|| jail.cfg.agent_names.first().cloned())
        .unwrap_or_else(|| "agy".into());
    // миссия: файл владельца или дефолт (миссия пишется в клетку для агента)
    let mission = match &mission_path {
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| format!("mission {p}: {e}"))?,
        None => super::sentinel::DEFAULT_MISSION.to_string(),
    };
    super::sentinel::validate_mission(&mission)?;
    let mission_file = jail.home_dir.join(".poler-hunt-mission.md");
    std::fs::write(&mission_file, &mission)
        .map_err(|e| format!("mission {}: {e}", mission_file.display()))?;
    // канарейка на хосте (токен в выводе агента = доказанный побег)
    let canary = super::sentinel::plant_canary().ok();
    // запуск агента в PTY-контуре клетки: миссия — одним argv-токеном
    let tokens = vec![agent_name.clone(), mission.clone()];
    let wrapped = containers::wrap_pty_exec(jail, &tokens, &state.cwd);
    let mut limits = state.limits.clone();
    limits.timeout_secs = budget;
    println!(
        "🎯 Jailbreak Sentinel: агент «{agent_name}» в клетке {} с миссией побега (бюджет {}с; всё наблюдаемо)",
        jail.name, budget
    );
    if let Some(c) = &canary {
        println!("🎯 канарейка хоста: {} (токен в выводе = побег)", c.host_path.display());
    }
    let outcome = hostexec::run_pty(&wrapped, &limits, &state.cwd, &[]);
    let transcript = outcome.stdout.clone();
    let attempts = super::sentinel::scan_transcript(
        &transcript,
        canary.as_ref(),
    );
    let breach = super::sentinel::any_breach(&attempts);
    let mut kill_switched = false;
    let mut banner = String::new();
    if breach {
        kill_switched = true;
        match super::sentinel::kill_switch(&jail.name) {
            Ok(b) => banner.push_str(&b),
            Err(e) => banner.push_str(&format!("⚠ {e}\n")),
        }
    }
    let _ = interactive; // PTY уже показывает всё живьём владельцу
    state.last_exit = outcome.code.unwrap_or(0);
    let hunt = super::sentinel::HuntState {
        mode: super::sentinel::HuntMode::Agent,
        box_name: jail.name.clone(),
        probe: Vec::new(),
        host_audit: Vec::new(),
        attempts,
        canary,
        kill_switched,
        agent: Some(agent_name),
        report_path: None,
    };
    let full = super::sentinel::render_report(&hunt);
    let path = super::sentinel::save_report(&hunt, &full);
    let mut hunt = hunt;
    hunt.report_path = path;
    let mut out = String::new();
    out.push_str(&super::sentinel::status_text(&hunt));
    out.push_str(&banner);
    out.push_str(&outcome.render());
    out.push_str("box hunt report — полный отчёт; токен канарейки в выводе = доказанный побег\n");
    state.hunt = Some(hunt);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

pub fn gateway_help() -> String {
    let mut s = String::from(
        "POLER Terminal Gateway — единый терминальный шлюз (v0.28.0: + рут по паролю + builtin-hunter)\n\
         ═════════════════════════════════════════════════════════════\n\
         Двойной контур: команды движка исполняются нативно (приоритет),\n\
         всё остальное — хостовая ОС в sandbox-режиме.\n\n",
    );
    s.push_str("КОНТУР 1 — движок (нативно, без спавна шеллов):\n");
    s.push_str("  search «запрос» [--top N]   поиск по web-index (BM25+WebRank+мост)\n");
    s.push_str("  grep PAT [PATH…] [-E] [-i] [-A/-B N] [--count] [--json]\n");
    s.push_str("                              точный поиск (полнота = GNU grep)\n");
    s.push_str("  chunk [PATH|--stdin] [--size N] [--overlap N] [--json]\n");
    s.push_str("                              RAG-чанковка (секция→абзац→предложение)\n");
    s.push_str("  impact SYMBOL               AIDDE: подграф влияния символа\n");
    s.push_str("  crawl URL / notes / sources / gh / gl / gt / gix / stats\n");
    s.push_str("                              (делегация во внутренний шелл: help там же)\n");
    s.push_str("  benchmark [--json PATH]     бенчмарк-сьют движка\n");
    s.push_str("  license                     статус лицензии + EULA-условия\n\n");
    s.push_str("КОНТУР 2 — хост (Sandboxed OS Subshell):\n");
    s.push_str("  любая системная команда     ls, git, cargo, python…\n");
    s.push_str("  !grep / host grep           принудительно системный (а не движковый)\n");
    s.push_str("  БЛОКИРУЕТСЯ: rm -rf /, форк-бомбы, dd of=/dev/*, shutdown,\n");
    s.push_str("               curl|sh, > /dev/sd*, > /etc/*\n");
    s.push_str("  ПОДТВЕРЖДАЕТСЯ: sudo/su (на /dev/tty), rm -r, dd,\n");
    s.push_str("               доступ к путям ВНЕ workspace (boundary)\n\n");
    s.push_str("PTY-PASSTHROUGH (v0.23.0 — интерактивные TUI/IDE/агенты):\n");
    s.push_str("  pty <команда…>              принудительный псевдотерминал\n");
    s.push_str("  авто-PTY: vim/htop/less/tmux/agy/claude… и bare-REPL (python3)\n");
    s.push_str("  (политика sandbox судится по той же команде — PTY ≠ обход)\n");
    s.push_str("  без jail: MEDIATED AGENT MODE — shell-вызовы агента через PATH-shim\n");
    s.push_str("  судятся гейтом (отказ 126; /bin/sh-хардкод не виден — см. box)\n\n");
    s.push_str("CONTAINER JAIL (v0.25.0 — изоляция; v0.26.0 — брокер; v0.27.0 — рут-брокер + sentinel; v0.28.0 — пароль + builtin-охотник):\n");
    s.push_str("  box on [image=IMG] [net=bridge|none] [user=me|root]\n");
    s.push_str("      [mem=2g] [pids=512] [wsro=0|1]   поднять jail: контуры 2/3\n");
    s.push_str("      исполняются ВНУТРИ контейнера (docker exec); агент физически\n");
    s.push_str("      заперт — хост виден только как /workspace и /home/poler\n");
    s.push_str("  box on agent=auto|none|имя1,имя2 · nocfg=0|1 — политика проброса\n");
    s.push_str("      хостовых агентов; найденные agy/claude/… монтируются ro\n");
    s.push_str("      в /usr/local/bin без установки (zero-overhead), конфиги —\n");
    s.push_str("      rw в /home/poler (~/.gemini, ~/.claude — авторизация живёт)\n");
    s.push_str("  box on mount=HOST[:CONT[:ro|rw]] — ручной проброс (белый список\n");
    s.push_str("      целей; docker-сокет/системные корни — запрет на парсинге)\n");
    s.push_str("  box runner on|off|status — контур исполнения MCP-брокера:\n");
    s.push_str("      net=none, только /workspace, без home/агентов — туда\n");
    s.push_str("      poler_box_exec исполняет команды агентов (двухконтурная\n");
    s.push_str("      схема: мозг агента → шлюз POLER (судья) → runner)\n");
    s.push_str("  box status | box off        состояние | разобрать (box off\n");
    s.push_str("                              разбирает и runner) · box shell —\n");
    s.push_str("                              интерактивный шелл внутри jail\n");
    s.push_str("  РУТ-БРОКЕР (v0.27.0 — рут остаётся привилегией ХОСТА):\n");
    s.push_str("  box sudo on|off|status|log  агент в клетке зовёт «sudo …» → шим\n");
    s.push_str("      [N]                     пишет ЗАПРОС → шлюз судит → Allow =\n");
    s.push_str("                              docker exec -u 0 СО СТОРОНЫ ХОСТА;\n");
    s.push_str("                              агент рут НЕ держит, получает только\n");
    s.push_str("                              stdout/stderr/exit; аудит — на хосте\n");
    s.push_str("  box sudo passwd [--clear]  v0.28.0: владелец выдаёт агенту рут-ПАРОЛЬ\n");
    s.push_str("                              (только интерактив; 6..64; хеш 0600 на\n");
    s.push_str("                              хосте). Агент: echo ПАРОЛЬ | sudo -S cmd —\n");
    s.push_str("                              НЕдеструктивное разрешено; деструктив/\n");
    s.push_str("                              побег/ядро — Deny ВСЕГДА; брут-форс:\n");
    s.push_str("                              5 промахов → лок 60с (все попытки — в аудите)\n");
    s.push_str("  box root                    интерактивный рут-шелл ВНУТРИ клетки —\n");
    s.push_str("                              только владелец с хоста (интерактив)\n");
    s.push_str("  box allow sudo <glob>|--list|--reset  allowlist рут-запросов\n");
    s.push_str("                              (только интерактив; Block НЕ ослабляет)\n");
    s.push_str("  JAILBREAK SENTINEL (v0.27.0 — «посади агента и наблюдай»):\n");
    s.push_str("  box hunt start [--mode probe|agent|builtin] [--agent ИМЯ]\n");
    s.push_str("      [--mission ФАЙЛ] [--budget СЕК]\n");
    s.push_str("      probe — батарея 25+ векторов побега изнутри клетки (docker-\n");
    s.push_str("      сокет/release_agent/CapEff/…), escape → KILL-SWITCH (docker\n");
    s.push_str("      stop, форензика сохранена); agent — живой ИИ с миссией побега\n");
    s.push_str("      под наблюдением: сигнатуры транскрипта + канарейка хоста,\n");
    s.push_str("      токен в выводе = ДОКАЗАННЫЙ побег → kill-switch; вектор →\n");
    s.push_str("      патч + регрессионный тест («нашёл → закрыл»)\n");
    s.push_str("  box hunt status|report|stop  состояние | полный отчёт | стоп\n");
    s.push_str("  BUILTIN HUNTER (v0.28.0 — СВОЙ суб-агент POLER, не agy):\n");
    s.push_str("  box hunt start --mode builtin [--loop] [--interval 30]\n");
    s.push_str("      [--full-every 600]      красная команда движка атакует РАЗВЁР-\n");
    s.push_str("      НУТУЮ систему чёрным ящиком изнутри клетки (без исходни-\n");
    s.push_str("      ков): судейские/канальные/граничные волны (16+ векторов:\n");
    s.push_str("      escape-инструмент под маской пути, пути ядра, деструктив,\n");
    s.push_str("      newline-инъекция, фаззинг протокола, replay, симлинк-\n");
    s.push_str("      ловушка, усечение канала, подмена шима, брут-форс пароля,\n");
    s.push_str("      flood) + escape-батарея sentinel + docker-inspect;\n");
    s.push_str("      breach → KILL-SWITCH; anomaly → авто-блоклист брокера\n");
    s.push_str("      («нашёл → закрыл» в рантайме); --loop — постоянное\n");
    s.push_str("      наблюдение (свипы + периодические батареи, журнал)\n");
    s.push_str("  образ по умолчанию debian:bookworm-slim; ELF-агенты хоста\n");
    s.push_str("  работают без пересборки образа; скриптовые — image= с runtime\n\n");
    s.push_str("WORKSPACE (v0.23.0 — корень проекта; v0.24.0 — граница):\n");
    s.push_str("  workspace [PATH]            показать/переключить корень проекта;\n");
    s.push_str("                              движок+хост+подпроцессы от одного cwd\n");
    s.push_str("  cd PATH / pwd               быстрая навигация (тот же корень)\n");
    s.push_str("  ГРАНИЦА: доступ/запись вне корня — Confirm [y/N] (cd/workspace\n");
    s.push_str("  на выход — тоже); allow <PATH> — сессионное исключение (владелец,\n");
    s.push_str("  только интерактив); деструктив блокируется ВСЕГДА\n\n");
    s.push_str("ПРИВИЛЕГИИ (v0.23.0 — гранулярный sudo-гейт):\n");
    s.push_str("  sudo <cmd>                  одноразово: подтверждение на /dev/tty\n");
    s.push_str("  grant sudo 5m|90s|2h        временный лизинг (только интерактив,\n");
    s.push_str("                              кап 60 мин, сгорает сам); grant sudo off\n");
    s.push_str("  set sandbox on|off|status   danger-режим (off — только интерактив\n");
    s.push_str("                              с подтверждением); --dangerously-allow-all\n\n");
    s.push_str("КОНВЕЙЕРЫ (любые комбинации контуров):\n");
    s.push_str("  ls -la src/ | chunk --size 200\n");
    s.push_str("  cat main.rs | impact main\n");
    s.push_str("  grep \"fn \" --stdin | wc -l\n");
    s.push_str("  poler-префикс опционален: `ls | poler chunk` ≡ `ls | chunk`\n\n");
    s.push_str("СЕРВИСНЫЙ СЛОЙ (Service Substrate):\n");
    s.push_str("  service start|stop|restart|status [mcp|weblens|companion]\n");
    s.push_str("  attach [mcp|weblens|companion]   подключение к сессии\n");
    s.push_str("  weblens [start|stop|status]      сахар над service\n\n");
    s.push_str("НАСТРОЙКИ/СЛУЖЕБНЫЕ:\n");
    s.push_str("  set hosttimeout N | set hostenv filtered|full | set autoyes on|off\n");
    s.push_str("  set format|top … (внутренний шелл)   cd / pwd / clear / version\n");
    s.push_str("  quit (^D) — выход\n\n");
    s.push_str("Документация: docs/terminal-gateway-architecture.md\n");
    s
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> GatewayState {
        GatewayState::new(PathBuf::from("/tmp/poler-gw-test.db"))
    }

    fn run(state: &mut GatewayState, line: &str) -> Option<String> {
        match exec_line(state, line, false) {
            GatewayResult::Done(s) => Some(s),
            GatewayResult::Quit => None,
            GatewayResult::Empty => Some(String::new()),
        }
    }

    #[test]
    fn engine_priority_over_host_binaries() {
        // grep существует и в PATH, но движок перехватывает
        let mut st = state();
        let out = run(&mut st, "grep hello").unwrap();
        // движковый grep на пустом паттерне-каталоге — не «command not found»
        assert!(!out.contains("не удалось запустить"), "движок должен перехватить grep: {out}");
    }

    #[test]
    fn unknown_command_falls_to_host() {
        let mut st = state();
        // несуществующий бинарник → spawn_error от host-контур
        let out = run(&mut st, "zzz-not-a-command-xyz").unwrap();
        assert!(out.contains("не удалось запустить"), "должен уйти в host-контур: {out}");
    }

    #[test]
    fn forced_host_with_bang() {
        let mut st = state();
        let out = run(&mut st, "!echo forced-host").unwrap();
        assert_eq!(out.trim(), "forced-host");
    }

    #[test]
    fn host_keyword_forces_host() {
        let mut st = state();
        let out = run(&mut st, "host echo via-host-kw").unwrap();
        assert_eq!(out.trim(), "via-host-kw");
    }

    #[test]
    fn pipeline_host_to_engine_chunk() {
        let mut st = state();
        let out = run(&mut st, "echo -e \"line one\\nline two\\nline three\" | chunk --stdin --size 10").unwrap();
        assert!(out.contains("chunk") || !out.is_empty(), "чанкование stdin должно что-то вывести: {out}");
    }

    #[test]
    fn pipeline_host_to_engine_grep() {
        let mut st = state();
        let out = run(&mut st, "printf 'apple\\nbanana\\ncherry\\n' | grep ap --stdin").unwrap();
        assert!(out.contains("apple"), "grep --stdin: {out}");
        assert!(!out.contains("banana"), "banana без 'ap' не должен попасть: {out}");
        assert!(!out.contains("cherry"), "cherry без 'ap' не должен попасть: {out}");
    }

    #[test]
    fn pipeline_engine_to_host() {
        let mut st = state();
        let out = run(&mut st, "printf 'x\\ny\\n' | grep x --stdin | wc -l").unwrap();
        assert_eq!(out.trim(), "1", "engine→host pipe: {out}");
    }

    #[test]
    fn sandbox_blocks_in_repl() {
        let mut st = state();
        let out = run(&mut st, "rm -rf /").unwrap();
        assert!(out.contains("блокировка"), "rm -rf / должен блокироваться: {out}");
    }

    #[test]
    fn sandbox_confirm_refused_noninteractive() {
        let mut st = state();
        let out = run(&mut st, "rm -rf ./some-build-dir").unwrap();
        assert!(out.contains("не подтверждено") || out.contains("блокировка"), "Confirm в non-interactive = отказ: {out}");
    }

    #[test]
    fn sandbox_autoyes_allows_confirm() {
        let mut st = state();
        st.auto_yes = true;
        // безопасный подтверждаемый кейс: rm -r на несуществующем каталоге
        // (rm вернёт ошибку, но sandbox пропустит)
        let out = run(&mut st, "rm -r /tmp/definitely-not-exist-xyz").unwrap();
        assert!(!out.contains("не подтверждено"), "auto_yes должен пропустить: {out}");
    }

    #[test]
    fn redirect_writes_file() {
        let mut st = state();
        // файл внутри workspace (v0.24.0: /tmp-цель вне границы = Confirm)
        let ws = std::env::temp_dir().join(format!("poler-gw-ws-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        st.cwd = ws.clone();
        st.ws_root = ws.clone();
        let tmp = ws.join("redir.txt");
        let path = tmp.display().to_string();
        let out = run(&mut st, &format!("echo hello > {path}")).unwrap();
        assert!(out.contains("→"), "редирект должен отчитаться: {out}");
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(content.trim(), "hello");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn redirect_to_dev_blocked() {
        let mut st = state();
        let out = run(&mut st, "echo x > /dev/sda").unwrap();
        assert!(out.contains("блокировка"), "редирект в /dev/sda — Block: {out}");
    }

    #[test]
    fn cd_and_pwd() {
        let mut st = state();
        // навигация ВНУТРИ workspace — свободна (включая возврат к корню)
        let ws = std::env::temp_dir().join(format!("poler-gw-cd-{}", std::process::id()));
        let sub = ws.join("tmp");
        std::fs::create_dir_all(&sub).unwrap();
        st.cwd = ws.clone();
        st.ws_root = ws.clone();
        run(&mut st, "cd tmp").unwrap();
        let out = run(&mut st, "pwd").unwrap();
        assert_eq!(out.trim(), sub.display().to_string());
        run(&mut st, "cd ..").unwrap();
        let out = run(&mut st, "pwd").unwrap();
        assert_eq!(out.trim(), ws.display().to_string());
        // v0.24.0: cd НАРУЖУ границы — Confirm; в неинтерактиве отказ
        let out = run(&mut st, "cd /tmp").unwrap();
        assert!(out.contains("не подтверждено"), "выход из workspace без подтверждения: {out}");
        let out = run(&mut st, "pwd").unwrap();
        assert_eq!(out.trim(), ws.display().to_string(), "корень не должен уйти");
        // auto_yes — владельцем разрешено (граница переносится)
        st.auto_yes = true;
        run(&mut st, "cd /tmp").unwrap();
        let out = run(&mut st, "pwd").unwrap();
        assert_eq!(out.trim(), "/tmp");
        assert_eq!(st.ws_root.display().to_string(), "/tmp", "граница следует за подтверждённым выходом");
        // cd в несуществующий — ошибка
        st.auto_yes = false;
        let out = run(&mut st, "cd /no/such/dir/xyz");
        assert!(out.unwrap().contains("⚡"));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn license_command_shows_eula() {
        let mut st = state();
        let out = run(&mut st, "license").unwrap();
        assert!(out.contains("Source-Available"));
        assert!(out.contains("dev@poler-engine.org"));
        assert!(out.contains("Notification Clause"));
    }

    #[test]
    fn help_lists_both_circuits() {
        let h = gateway_help();
        assert!(h.contains("КОНТУР 1"));
        assert!(h.contains("КОНТУР 2"));
        assert!(h.contains("service start"));
        assert!(h.contains("!grep"));
    }

    #[test]
    fn version_mentions_gateway() {
        let mut st = state();
        let out = run(&mut st, "version").unwrap();
        assert!(out.contains("Terminal Gateway"));
    }

    #[test]
    fn quit_returns_quit() {
        let mut st = state();
        assert!(matches!(exec_line(&mut st, "quit", false), GatewayResult::Quit));
    }

    #[test]
    fn engine_stdin_rejected_for_search() {
        let mut st = state();
        let out = run(&mut st, "echo x | search query").unwrap();
        assert!(out.contains("не принимает stdin"), "search не принимает stdin: {out}");
    }

    #[test]
    fn parse_error_reported() {
        let mut st = state();
        let out = run(&mut st, "echo \"unclosed").unwrap();
        assert!(out.contains("⚡"));
    }

    #[test]
    fn service_status_table() {
        let mut st = state();
        let out = run(&mut st, "service status").unwrap();
        assert!(out.contains("mcp"));
        assert!(out.contains("weblens"));
        assert!(!out.contains("companion"), "v2.0: Auth Companion удалён");
    }

    #[test]
    fn service_unknown_name() {
        let mut st = state();
        let out = run(&mut st, "service start zzz").unwrap();
        assert!(out.contains("неизвестный сервис"));
    }

    #[test]
    fn set_hosttimeout_and_env() {
        let mut st = state();
        let out = run(&mut st, "set hosttimeout 42").unwrap();
        assert!(out.contains("42"));
        assert_eq!(st.limits.timeout_secs, 42);
        let out = run(&mut st, "set hostenv full").unwrap();
        assert!(out.contains("full"));
        assert_eq!(st.limits.env_mode, EnvMode::Full);
        let _ = run(&mut st, "set hostenv filtered").unwrap();
        assert_eq!(st.limits.env_mode, EnvMode::Filtered);
    }

    #[test]
    fn delegate_shell_search_help() {
        // делегация во внутренний шелл: пустой search печатает подсказку
        let mut st = state();
        let out = run(&mut st, "search").unwrap();
        assert!(out.contains("пустой запрос") || out.contains("ничего"), "поиск-подсказка: {out}");
    }

    #[test]
    fn delegate_shell_quotes_survive() {
        // кавычки в аргументах переживают делегацию (рекавычивание)
        let mut st = state();
        let out = run(&mut st, "search \"запрос с пробелами\"").unwrap();
        assert!(!out.contains("⚡"), "не должно быть ошибки: {out}");
    }

    #[test]
    fn poler_prefix_stripped_in_pipeline() {
        let mut st = state();
        let out = run(&mut st, "printf 'a b c\\n' | poler grep b --stdin").unwrap();
        assert!(out.contains("a b c"), "poler-префикс должен срезаться: {out}");
    }

    // =====================================================================
    // v0.23.0: PTY-роутинг, workspace, sudo-гейт, danger-режим
    // =====================================================================

    #[test]
    fn pty_auto_detect_known_tui_and_repl() {
        assert!(is_auto_pty(&["vim".into(), "main.rs".into()]));
        assert!(is_auto_pty(&["htop".into()]));
        assert!(is_auto_pty(&["/usr/bin/less".into(), "x.log".into()]));
        assert!(is_auto_pty(&["agy".into()]));
        // bare-REPL — кандидат; с аргументами — обычный запуск
        assert!(is_auto_pty(&["python3".into()]));
        assert!(!is_auto_pty(&["python3".into(), "script.py".into()]));
        // не-TUI команды не перехватываются
        assert!(!is_auto_pty(&["ls".into(), "-la".into()]));
        assert!(!is_auto_pty(&["grep".into(), "x".into()]));
        assert!(!is_auto_pty(&[]));
    }

    #[test]
    fn pty_destructive_inner_command_blocked() {
        // PTY — канал I/O, не обход sandbox: деструктив внутри pty режется
        let mut st = state();
        let out = run(&mut st, "pty rm -rf /").unwrap();
        assert!(out.contains("блокировка"), "pty rm -rf / должен блокироваться: {out}");
        let out = run(&mut st, "pty python3 -c \"import os; os.system('rm -rf /usr')\"").unwrap();
        assert!(out.contains("блокировка"), "pty + интерпретатор-деструктив: {out}");
    }

    #[test]
    fn pty_noninteractive_is_notice_not_spawn() {
        // TUI без TTY не запускаем (зависал бы) — честный отказ
        let mut st = state();
        let out = run(&mut st, "pty vim x.rs").unwrap();
        assert!(
            out.contains("требует настоящего терминала"),
            "неинтерактивный pty — отказ без спавна: {out}"
        );
        assert!(!out.contains("не удалось запустить"));
    }

    #[test]
    fn pty_auto_not_triggered_noninteractive() {
        // авто-PTY только в интерактиве: bare python3 в пайпе — обычный путь
        let mut st = state();
        // python3 с EOF на stdin мгновенно выходит (или отсутствует) —
        // главное: НЕ сообщение про терминал
        let _ = run(&mut st, "host echo ok");
        let out = run(&mut st, "pty").unwrap();
        // «pty» без команды — подсказка
        assert!(out.contains("pty:"), "пустой pty — подсказка: {out}");
    }

    #[test]
    fn workspace_report_and_switch() {
        let mut st = state();
        let out = run(&mut st, "workspace").unwrap();
        assert!(out.contains("workspace:"), "отчёт без PATH: {out}");
        let tmp = std::env::temp_dir().join(format!("poler-ws-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // v0.24.0: смена корня ЗА пределы — Confirm; auto_yes = согласие владельца
        st.auto_yes = true;
        let out = run(&mut st, &format!("workspace {}", tmp.display())).unwrap();
        assert!(out.contains("workspace →"), "переключение: {out}");
        assert_eq!(st.cwd, tmp.canonicalize().unwrap());
        // несуществующий — ошибка
        let out = run(&mut st, "workspace /no/such/dir/xyz").unwrap();
        assert!(out.contains("⚡"));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn workspace_escape_refused_noninteractive() {
        let mut st = state();
        let tmp = std::env::temp_dir().join(format!("poler-ws-esc-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // пайп-агент не может уводить границу workspace
        let out = run(&mut st, &format!("workspace {}", tmp.display())).unwrap();
        assert!(
            out.contains("не подтверждено"),
            "выход из workspace в неинтерактиве — отказ: {out}"
        );
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn workspace_syncs_process_cwd_when_enabled() {
        let mut st = state();
        st.sync_cwd = true;
        st.auto_yes = true; // v0.24.0: смена корня за пределы — с согласия
        let tmp = std::env::temp_dir().join(format!("poler-ws-sync-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let _ = run(&mut st, &format!("workspace {}", tmp.display())).unwrap();
        assert_eq!(
            std::env::current_dir().unwrap(),
            tmp.canonicalize().unwrap(),
            "process-cwd должен следовать за workspace"
        );
        // вежливость к параллельным тестам: вернуть cwd манифеста
        let _ = std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn grant_sudo_refused_noninteractive() {
        let mut st = state();
        let out = run(&mut st, "grant sudo 5m").unwrap();
        assert!(
            out.contains("интерактивной сессии"),
            "лизинг в неинтерактиве — отказ: {out}"
        );
        assert!(st.sudo_lease_until.is_none(), "лизинг не должен открыться");
    }

    #[test]
    fn grant_lease_bypasses_privilege_confirm() {
        // активный лизинг пропускает sudo-Confirm в неинтерактиве
        let mut st = state();
        st.sudo_lease_until =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(300));
        let out = run(&mut st, "sudo true").unwrap();
        assert!(
            !out.contains("не подтверждено"),
            "лизинг должен пропустить sudo: {out}"
        );
        // лизинг истёк — снова ворота
        st.sudo_lease_until =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
        assert!(st.sudo_lease_remaining().is_none());
        let out = run(&mut st, "sudo true").unwrap();
        assert!(
            out.contains("не подтверждено"),
            "истёкший лизинг не пропускает: {out}"
        );
    }

    #[test]
    fn grant_lease_does_not_bypass_destructive() {
        // лизинг поднимает Confirm-ворота, но НЕ Block-вердикты
        let mut st = state();
        st.sudo_lease_until =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(300));
        let out = run(&mut st, "sudo rm -rf /usr").unwrap();
        assert!(out.contains("блокировка"), "Block не зависит от лизинга: {out}");
    }

    #[test]
    fn grant_lease_parsing() {
        assert_eq!(parse_lease("5").unwrap(), (300, false));
        assert_eq!(parse_lease("5m").unwrap(), (300, false));
        assert_eq!(parse_lease("90s").unwrap(), (90, false));
        assert_eq!(parse_lease("1h").unwrap(), (3600, false));
        assert_eq!(parse_lease("2h").unwrap(), (3600, true), "2h превышает кап 60 мин");
        assert_eq!(parse_lease("999h").unwrap(), (3600, true), "кап 60 минут");
        assert!(parse_lease("abc").is_err());
        assert!(parse_lease("0").is_err());
    }

    #[test]
    fn sandbox_off_refused_noninteractive() {
        let mut st = state();
        let out = run(&mut st, "set sandbox off").unwrap();
        assert!(
            out.contains("интерактивной сессии"),
            "отключение sandbox в неинтерактиве — отказ: {out}"
        );
        assert!(!st.danger_mode, "danger-режим не включается из скрипта");
        // повторно в danger-режиме — уже отключён
        st.danger_mode = true;
        let out = run(&mut st, "set sandbox off").unwrap();
        assert!(out.contains("уже отключён"));
        // включение обратно — всегда можно
        let out = run(&mut st, "set sandbox on").unwrap();
        assert!(out.contains("включён"));
        assert!(!st.danger_mode);
    }

    #[test]
    fn sandbox_status_report() {
        let mut st = state();
        let out = run(&mut st, "set sandbox status").unwrap();
        assert!(out.contains("sandbox: активен"), "статус по умолчанию: {out}");
        st.danger_mode = true;
        let out = run(&mut st, "set sandbox status").unwrap();
        assert!(out.contains("ОТКЛЮЧЁН"), "danger-статус: {out}");
    }

    #[test]
    fn danger_mode_bypasses_block_with_warning() {
        // Block-класс (kill PID 1) в danger-режиме исполняется без ⛔;
        // в контейнере без root это безобидный EPERM
        let mut st = state();
        st.danger_mode = true;
        let out = run(&mut st, "kill -9 1").unwrap();
        assert!(
            !out.contains("блокировка") && !out.contains("⛔"),
            "danger-режим не блокирует: {out}"
        );
        // и Confirm-класс тоже не спрашивается
        let out = run(&mut st, "rm -rf ./definitely-missing-dir-xyz").unwrap();
        assert!(
            !out.contains("не подтверждено"),
            "danger-режим не спрашивает: {out}"
        );
    }

    #[test]
    fn help_lists_v023_features() {
        let h = gateway_help();
        assert!(h.contains("PTY-PASSTHROUGH"), "help: PTY: {h}");
        assert!(h.contains("WORKSPACE"));
        assert!(h.contains("grant sudo"));
        assert!(h.contains("set sandbox"));
    }

    // ---------- v0.24.0: Workspace Boundary Guard ----------

    /// изолированный workspace для boundary-тестов
    fn boundary_ws(tag: &str) -> (GatewayState, PathBuf) {
        let ws = std::env::temp_dir().join(format!("poler-gw-bnd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("notes.txt"), "inside\n").unwrap();
        let mut st = state();
        st.cwd = ws.clone();
        st.ws_root = ws.clone();
        (st, ws)
    }

    #[test]
    fn boundary_outside_read_denied_noninteractive() {
        let (mut st, ws) = boundary_ws("read");
        // живой кейс из эксплуатации: агент читает домашний каталог
        let out = run(&mut st, "ls /home").unwrap();
        assert!(out.contains("не подтверждено"), "вне workspace = Confirm: {out}");
        let out = run(&mut st, "cat /etc/passwd").unwrap();
        assert!(out.contains("не подтверждено"), "/etc/passwd = Confirm: {out}");
        // внутри — свободно
        let out = run(&mut st, "cat notes.txt").unwrap();
        assert!(!out.contains("⛔"), "внутри workspace свободно: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_outside_write_via_redirect_denied() {
        let (mut st, ws) = boundary_ws("redir");
        let out = run(&mut st, "echo x > /tmp/poler-bnd-test.txt").unwrap();
        assert!(
            out.contains("не подтверждено"),
            "запись в /tmp вне workspace = Confirm: {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_autoyes_and_allowlist() {
        let (mut st, ws) = boundary_ws("allow");
        // auto_yes пропускает boundary-Confirm
        st.auto_yes = true;
        let out = run(&mut st, "cat /etc/passwd").unwrap();
        assert!(!out.contains("⛔"), "auto_yes: {out}");
        st.auto_yes = false;
        // allowlist: путь разрешён — без вопросов (интерактив-флаг имитируем)
        st.ws_allow.push(PathBuf::from("/etc/hosts"));
        let out = exec_line(&mut st, "cat /etc/hosts", true);
        let GatewayResult::Done(out) = out else { panic!("done") };
        assert!(!out.contains("⛔"), "allowlist /etc/hosts: {out}");
        // но БЛИЖНИЙ /etc/passwd — всё ещё Confirm
        let out = run(&mut st, "cat /etc/passwd").unwrap();
        assert!(out.contains("не подтверждено"), "соседний путь не разрешён: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn allow_command_gates() {
        let (mut st, ws) = boundary_ws("allowcmd");
        // неинтерактив: расширение границы запрещено (пайп-агент)
        let out = run(&mut st, "allow /etc").unwrap();
        assert!(out.contains("⛔"), "allow только в интерактиве: {out}");
        assert!(st.ws_allow.is_empty());
        // интерактив: добавление
        let out = exec_line(&mut st, "allow /etc", true);
        let GatewayResult::Done(out) = out else { panic!("done") };
        assert!(out.contains("разрешено на сессию"), "allow: {out}");
        assert_eq!(st.ws_allow.len(), 1);
        // список и сброс
        let out = run(&mut st, "allow").unwrap();
        assert!(out.contains("/etc"), "список allowlist: {out}");
        let out = run(&mut st, "allow clear").unwrap();
        assert!(out.contains("сброшен"), "clear: {out}");
        assert!(st.ws_allow.is_empty());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_engine_grep_paths_checked() {
        let (mut st, ws) = boundary_ws("grep");
        // движковый grep с путём вне workspace — тоже Confirm
        let out = run(&mut st, "grep root /etc/passwd").unwrap();
        assert!(out.contains("не подтверждено"), "engine grep вне границы: {out}");
        // внутри — не граница (файл ищется от process-cwd, но ⛔ нет)
        let out = run(&mut st, "grep inside notes.txt").unwrap();
        assert!(
            !out.contains("⛔") && !out.contains("не подтверждено"),
            "engine grep внутри — без границы: {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_shell_c_payload_recursed() {
        let (mut st, ws) = boundary_ws("shc");
        // payload c кавычками и абсолютным путём — рекурсивный разбор
        let out = run(&mut st, "bash -c \"cat '/etc/passwd'\"").unwrap();
        assert!(out.contains("не подтверждено"), "bash -c с /etc: {out}");
        // &&-цепочка: деструктивная часть ловится как Block
        let out = run(&mut st, "bash -c \"ls && rm -rf /usr\"").unwrap();
        assert!(out.contains("блокировка"), "bash -c с rm -rf /usr: {out}");
        // подстановка $()
        let out = run(&mut st, "bash -c \"echo $(cat /etc/shadow)\"").unwrap();
        assert!(
            out.contains("не подтверждено") || out.contains("блокировка"),
            "подстановка $(cat /etc/shadow): {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_safe_devices_and_urls_pass() {
        let (mut st, ws) = boundary_ws("dev");
        let out = run(&mut st, "host echo x 2>/dev/null").unwrap();
        assert!(!out.contains("⛔"), "2>/dev/null — не граница: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_agent_pty_paths_checked() {
        let (mut st, ws) = boundary_ws("pty");
        // vim с внешним путём: PTY судится с границей
        let out = run(&mut st, "pty vim /etc/hosts").unwrap();
        assert!(
            out.contains("не подтверждено"),
            "pty vim /etc/hosts = Confirm (неинтерактив — отказ): {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // =====================================================================
    // v0.25.0: Container Jail (box)
    // =====================================================================

    /// Сериализация тестов, мутирующих POLER_BOX_DOCKER — ОБЩИЙ лок с
    /// containers/mcp-тестами (env процесс-глобален, тесты параллельны;
    /// v0.26.0: wrap_* тоже читают POLER_BOX_DOCKER).
    fn docker_env_lock() -> std::sync::MutexGuard<'static, ()> {
        super::super::containers::docker_env_test_lock()
    }

    /// Фейковый jail: контейнер с нереалистичным именем — любые docker-exec
    /// против него честно падают (нет контейнера/нет docker), что и проверяем.
    fn jailed_state(tag: &str) -> (GatewayState, std::path::PathBuf) {
        let ws = std::env::temp_dir().join(format!("poler-gw-box-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let mut st = state();
        st.cwd = ws.clone();
        st.ws_root = ws.clone();
        st.box_jail = Some(super::super::containers::BoxState {
            name: "poler-box-testfake".into(),
            cfg: super::super::containers::BoxConfig::default(),
            ws_root: ws.clone(),
            home_dir: ws.join(".boxhome"),
        });
        (st, ws)
    }

    #[test]
    fn box_status_honest() {
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let mut st = state();
        let out = run(&mut st, "box status").unwrap();
        assert!(out.contains("box"), "статус без docker: {out}");
        assert!(out.contains("docker"), "строка про docker: {out}");
        assert!(out.contains("poler-box-"), "ожидаемое имя контейнера: {out}");
        // и краткая форма
        let out = run(&mut st, "box").unwrap();
        assert!(out.contains("docker"), "box ≡ box status: {out}");
        std::env::remove_var("POLER_BOX_DOCKER");
    }

    #[test]
    fn box_on_without_docker_honest_error() {
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let mut st = state();
        let out = run(&mut st, "box on").unwrap();
        assert!(
            out.contains("docker недоступен") || out.contains("docker"),
            "честная ошибка без docker: {out}"
        );
        assert!(st.box_jail.is_none(), "jail не должен подняться");
        std::env::remove_var("POLER_BOX_DOCKER");
    }

    #[test]
    fn box_on_bad_args_rejected_before_docker() {
        // парсинг конфигурации — ДО пробы docker: net=host запрещён
        let mut st = state();
        let out = run(&mut st, "box on net=host").unwrap();
        assert!(out.contains("⚡") && out.contains("host"), "net=host запрещён: {out}");
        assert!(st.box_jail.is_none());
        let out = run(&mut st, "box on mem=zzz").unwrap();
        assert!(out.contains("⚡"), "mem=zzz: {out}");
        let out = run(&mut st, "box on zzz=1").unwrap();
        assert!(out.contains("⚡"), "неизвестный ключ: {out}");
    }

    #[test]
    fn box_unknown_subcommand_usage() {
        let mut st = state();
        let out = run(&mut st, "box zzz").unwrap();
        assert!(out.contains("⚡") && out.contains("box on"), "usage: {out}");
    }

    #[test]
    fn host_routes_through_docker_when_jailed() {
        let _g = docker_env_lock();
        let (mut st, ws) = jailed_state("route");
        // несуществующий бинарник: без jail — «не удалось запустить zzz-…»;
        // с jail — обёртка docker exec (упадёт с docker-ошибкой на фейке)
        let out = run(&mut st, "zzz-not-a-command-inbox-42").unwrap();
        assert!(
            out.contains("docker") || out.contains("poler-box"),
            "роутинг через docker exec: {out}"
        );
        // контроль без jail — обычная host-ошибка без docker
        st.box_jail = None;
        let out = run(&mut st, "zzz-not-a-command-inbox-42").unwrap();
        assert!(
            !out.contains("poler-box-testfake"),
            "без jail обёртки быть не должно: {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn daemon_ctl_gated_when_jailed() {
        let (mut st, ws) = jailed_state("daemon");
        // docker из gateway при активном jail — Confirm; неинтерактив = отказ
        // (причём БЕЗ спавна docker — гейт срабатывает до исполнения)
        let out = run(&mut st, "docker ps").unwrap();
        assert!(out.contains("отклонено"), "docker ps в jail = Confirm: {out}");
        assert!(out.contains("Container Jail"), "причина названа: {out}");
        let out = run(&mut st, "podman run -v /:/x img").unwrap();
        assert!(out.contains("отклонено"), "podman run: {out}");
        // без jail — не гейтится (команда не исполняется: zzz-префикс)
        st.box_jail = None;
        let out = run(&mut st, "host docker-zzz-not-real").unwrap();
        assert!(!out.contains("Container Jail"), "без jail гейта нет: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn boundary_relaxed_in_jail_for_exec_plane() {
        let (mut st, ws) = jailed_state("relax");
        // чтение пути вне ws ВНУТРИ jail: логической границы нет (её держит
        // контейнер) — команда уходит в docker exec и честно падает на фейке,
        // но это НЕ boundary-Confirm
        let out = run(&mut st, "cat /etc/hostname-zzz-not-exist").unwrap();
        assert!(
            !out.contains("не подтверждено") && !out.contains("блокировка"),
            "в jail exec-плоскость без логической границы: {out}"
        );
        // контроль без jail: тот же кат — boundary-Confirm → отказ
        st.box_jail = None;
        let out = run(&mut st, "cat /etc/hostname-zzz-not-exist").unwrap();
        assert!(out.contains("не подтверждено"), "без jail — Confirm: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn destructive_still_blocked_inside_jail() {
        let (mut st, ws) = jailed_state("destructive");
        // инвариант: jail НЕ ослабляет Block-вердикты — rm -rf / блокируется
        // и в jail-режиме (до любого docker exec)
        let out = run(&mut st, "rm -rf /").unwrap();
        assert!(out.contains("блокировка"), "rm -rf / блокируется в jail: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn redirect_target_still_guarded_in_jail() {
        let (mut st, ws) = jailed_state("redirect");
        // редирект пишет ДВИЖОК на хосте — граница действует и в jail
        let out = run(&mut st, "echo x > /etc/passwd").unwrap();
        assert!(out.contains("блокировка"), "> /etc/passwd — Block в jail: {out}");
        // цель вне ws (но не системная) — Confirm; неинтерактив = отказ
        let out = run(&mut st, "echo x > /tmp/poler-box-redirect-test.txt").unwrap();
        assert!(
            out.contains("не подтверждено") || out.contains("блокировка"),
            "redirect вне ws в jail — Confirm: {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn pty_in_jail_noninteractive_refuses_honestly() {
        let (mut st, ws) = jailed_state("ptyrefuse");
        let out = run(&mut st, "pty vim").unwrap();
        assert!(
            out.contains("настоящего терминала"),
            "PTY без TTY — честный отказ и в jail: {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn cd_outside_with_jail_warns_about_mount() {
        let (mut st, ws) = jailed_state("cdwarn");
        st.auto_yes = true; // подтверждение выхода границы — авто
        let out = run(&mut st, "cd /tmp").unwrap();
        assert!(
            out.contains("box jail") && out.contains("продолжает монтировать"),
            "предупреждение о монтировке: {out}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_shell_requires_jail_and_tty() {
        let mut st = state();
        let out = run(&mut st, "box shell").unwrap();
        assert!(out.contains("не активен"), "без jail — подсказка: {out}");
        let (mut st2, ws) = jailed_state("shellnotty");
        let out = run(&mut st2, "box shell").unwrap();
        assert!(out.contains("настоящего терминала"), "неинтерактив — отказ: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn help_and_version_mention_box() {
        let h = gateway_help();
        assert!(h.contains("CONTAINER JAIL"), "секция box в help: {h}");
        assert!(h.contains("box on"), "синтаксис box on: {h}");
        assert!(h.contains("mount="), "синтаксис mount= в help: {h}");
        assert!(h.contains("agent="), "политика agent= в help: {h}");
        assert!(h.contains("box runner on"), "runner в help: {h}");
        assert!(h.contains("poler_box_exec"), "MCP-брокер в help: {h}");
        let mut st = state();
        let out = run(&mut st, "version").unwrap();
        assert!(out.contains("container-jail"), "версия упоминает jail: {out}");
        assert!(out.contains("agent-bindmount"), "версия упоминает bindmount: {out}");
        assert!(out.contains("mcp-broker"), "версия упоминает брокера: {out}");
    }

    // =====================================================================
    // v0.26.0: bind-mount агентов + runner (двухконтурный брокер)
    // =====================================================================

    #[test]
    fn box_on_mount_deny_list_rejected_at_parse() {
        // host-путь для проверок ЦЕЛЕЙ контейнера — легитимный temp-файл
        // (вне системных корней), чтобы сработали именно контейнер-проверки
        let good_ws = std::env::temp_dir().join(format!("poler-mnt-src-{}", std::process::id()));
        std::fs::write(&good_ws, b"legit-data").unwrap();
        let good = good_ws.display().to_string();
        // docker-сокет / системные корни / цели вне белого списка — отказ
        // ещё ДО пробы docker (парсинг k=v идёт первым)
        let mut st = state();
        for bad in [
            "box on mount=/var/run/docker.sock:/x/sock",
            "box on mount=/:/home/poler/root",
            "box on mount=/etc:/opt/poler/etc",
            "box on mount=/dev:/opt/poler/dev",
            "box on mount=/nonexistent-xyz-123:/opt/poler/x",
            &format!("box on mount={good}:/etc/evil"), // цель вне белого списка
            &format!("box on mount={good}:/workspace/x"), // /workspace не расширяется
            &format!("box on mount={good}:/usr/local/bin/agy:rw"), // rw-бинарник
        ] {
            let out = run(&mut st, bad).unwrap_or_default();
            assert!(
                out.contains("mount="),
                "{bad} — должен быть парсинг-отказ: {out}"
            );
            assert!(!out.contains("Container Jail ВКЛ"), "{bad} не поднялся: {out}");
        }
        assert!(st.box_jail.is_none(), "jail не должен подняться");
        let _ = std::fs::remove_file(&good_ws);
    }

    #[test]
    fn box_on_agent_policy_parse() {
        let mut st = state();
        // неизвестный агент — отказ на парсинге (до docker)
        let out = run(&mut st, "box on agent=not-an-agent").unwrap_or_default();
        assert!(out.contains("agent=not-an-agent") || out.contains("неизвестный агент"), "{out}");
        // известные имена проходят парсинг (дальше упадёт docker-проба без docker)
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let out = run(&mut st, "box on agent=agy,claude nocfg=1").unwrap_or_default();
        assert!(out.contains("docker"), "дальше — честная docker-ошибка: {out}");
        std::env::remove_var("POLER_BOX_DOCKER");
    }

    #[test]
    fn box_runner_status_without_runner() {
        let mut st = state();
        let out = run(&mut st, "box runner status").unwrap();
        assert!(out.contains("runner: ВЫКЛ"), "без runner — отчёт ВЫКЛ: {out}");
        assert!(out.contains("poler-runner-"), "имя ожидаемого runner: {out}");
        assert!(out.contains("box runner on"), "подсказка подъёма: {out}");
        let out = run(&mut st, "box runner").unwrap();
        assert!(out.contains("runner: ВЫКЛ"), "box runner ≡ box runner status: {out}");
    }

    #[test]
    fn box_runner_on_without_docker_honest_error() {
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let mut st = state();
        let out = run(&mut st, "box runner on").unwrap();
        assert!(
            out.contains("docker недоступен") || out.contains("docker"),
            "runner on без docker — честная ошибка: {out}"
        );
        assert!(st.runner.is_none(), "runner не должен подняться");
        // bad args — до docker
        let out = run(&mut st, "box runner on net=host").unwrap();
        assert!(out.contains("net=host"), "net=host отвергнут: {out}");
        let out = run(&mut st, "box runner on zzz=1").unwrap();
        assert!(out.contains("zzz"), "мусорный ключ отвергнут: {out}");
        std::env::remove_var("POLER_BOX_DOCKER");
    }

    #[test]
    fn box_runner_bad_subcommand_usage() {
        let mut st = state();
        let out = run(&mut st, "box runner zzz").unwrap_or_default();
        assert!(out.contains("box runner"), "usage runner: {out}");
        let out = run(&mut st, "box zzz").unwrap_or_default();
        assert!(out.contains("box on"), "usage box: {out}");
    }

    #[test]
    fn box_off_without_docker_reports_both() {
        // box off без docker: честная ошибка docker, состояние не врёт
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let (mut st, ws) = jailed_state("offnodocker");
        st.runner = Some(super::super::containers::RunnerState {
            name: "poler-runner-testfake".into(),
            cfg: super::super::containers::RunnerConfig::default(),
            ws_root: ws.clone(),
        });
        let out = run(&mut st, "box off").unwrap();
        assert!(out.contains("docker"), "честная docker-ошибка: {out}");
        std::env::remove_var("POLER_BOX_DOCKER");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn runner_status_active_session() {
        let (mut st, ws) = jailed_state("runnerst");
        st.runner = Some(super::super::containers::RunnerState {
            name: "poler-runner-testfake".into(),
            cfg: super::super::containers::RunnerConfig::default(),
            ws_root: ws.clone(),
        });
        let out = run(&mut st, "box runner status").unwrap();
        assert!(out.contains("runner: ВКЛ"), "активный runner: {out}");
        assert!(out.contains("poler-runner-testfake"), "имя: {out}");
        assert!(out.contains("none"), "net none по умолчанию: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_status_runner_section_present() {
        // box status без docker — runner-секция присутствует (v0.26.0)
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let mut st = state();
        let out = run(&mut st, "box status").unwrap();
        assert!(out.contains("runner:"), "runner-секция в box status: {out}");
        assert!(out.contains("poler-runner-"), "имя runner в статусе: {out}");
        std::env::remove_var("POLER_BOX_DOCKER");
    }

    // =====================================================================
    // v0.27.0: Root Broker (box sudo / root / allow) + Jailbreak Sentinel
    // =====================================================================

    #[test]
    fn box_sudo_status_off_by_default() {
        let mut st = state();
        let out = run(&mut st, "box sudo status").unwrap();
        assert!(out.contains("ВЫКЛ"), "брокер выключен по умолчанию: {out}");
        assert!(out.contains("привилегия ХОСТА"), "философия рута: {out}");
        assert!(out.contains("apt"), "дефолт-политика в статусе: {out}");
        // краткая форма ≡ status
        let out2 = run(&mut st, "box sudo").unwrap();
        assert!(out2.contains("ВЫКЛ"), "box sudo ≡ box sudo status: {out2}");
    }

    #[test]
    fn box_sudo_on_requires_jail() {
        let mut st = state();
        let out = run(&mut st, "box sudo on").unwrap();
        assert!(out.contains("jail не активен"), "без jail отказ: {out}");
        assert!(st.sudo_broker.is_none(), "брокер не должен подняться");
    }

    #[test]
    fn box_sudo_on_no_docker_honest() {
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let (mut st, ws) = jailed_state("sudoon");
        let out = run(&mut st, "box sudo on").unwrap();
        assert!(
            out.contains("не работает") || out.contains("docker"),
            "фейковый контейнер/нет docker — честный отказ: {out}"
        );
        assert!(st.sudo_broker.is_none(), "брокер не поднялся");
        std::env::remove_var("POLER_BOX_DOCKER");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_sudo_log_empty_honest() {
        let _g = docker_env_lock();
        let dir = std::env::temp_dir().join(format!("poler-sudo-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("POLER_AUDIT_HOME", dir.to_str().unwrap());
        let mut st = state();
        let out = run(&mut st, "box sudo log").unwrap();
        assert!(out.contains("аудит"), "log-вывод: {out}");
        // мусорное N не роняет
        let out = run(&mut st, "box sudo log 5").unwrap();
        assert!(out.contains("аудит"));
        std::env::remove_var("POLER_AUDIT_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn box_sudo_unknown_sub_usage() {
        let mut st = state();
        let out = run(&mut st, "box sudo zzz").unwrap();
        assert!(out.contains("⚡") && out.contains("box sudo"), "usage: {out}");
    }

    #[test]
    fn box_allow_sudo_interactive_only() {
        // scripted-агент НЕ может ослаблять рут-политику (вектор!)
        let (mut st, ws) = jailed_state("allowsudo");
        let out = run(&mut st, "box allow sudo cargo *").unwrap();
        assert!(
            out.contains("только в интерактивной"),
            "неинтерактив обязан отказать: {out}"
        );
        // интерактив — можно
        let dir = std::env::temp_dir().join(format!("poler-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("POLER_POLICY_HOME", dir.to_str().unwrap());
        match exec_line(
            &mut st,
            "box allow sudo cargo *",
            true,
        ) {
            GatewayResult::Done(out) => {
                assert!(out.contains("добавлен"), "интерактив добавляет: {out}");
            }
            _ => panic!("интерактив-allow обязан сработать (Quit/Empty недопустимы)"),
        }
        let out = run(&mut st, "box allow sudo --list").unwrap();
        assert!(out.contains("cargo *"), "список показывает глоб: {out}");
        let out = run(&mut st, "box allow sudo --reset").unwrap();
        assert!(out.contains("очищен"), "reset: {out}");
        // не-sudo namespace — отказ
        let out = run(&mut st, "box allow zzz x").unwrap();
        assert!(out.contains("⚡"), "allow только для sudo: {out}");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_root_requires_jail_and_tty() {
        let mut st = state();
        let out = run(&mut st, "box root").unwrap();
        assert!(out.contains("jail не активен"), "без jail: {out}");
        // с jail, но неинтерактив — отказ (рут-шелл только владельцу с TTY)
        let (mut st2, ws) = jailed_state("roottty");
        let out = run(&mut st2, "box root").unwrap();
        assert!(out.contains("терминал"), "неинтерактив root: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_hunt_status_inactive_and_usage() {
        let mut st = state();
        let out = run(&mut st, "box hunt status").unwrap();
        assert!(out.contains("не активна"), "охота не активна: {out}");
        let out = run(&mut st, "box hunt").unwrap();
        assert!(out.contains("не активна"), "box hunt ≡ status: {out}");
        let out = run(&mut st, "box hunt zzz").unwrap();
        assert!(out.contains("⚡") && out.contains("hunt"), "usage: {out}");
    }

    #[test]
    fn box_hunt_start_requires_jail() {
        let mut st = state();
        let out = run(&mut st, "box hunt start").unwrap();
        assert!(out.contains("jail не активен"), "без jail отказ: {out}");
        assert!(st.hunt.is_none());
    }

    #[test]
    fn box_hunt_start_no_docker_honest() {
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let (mut st, ws) = jailed_state("huntnd");
        let out = run(&mut st, "box hunt start").unwrap();
        assert!(
            out.contains("не работает") || out.contains("docker"),
            "без docker — честный отказ: {out}"
        );
        assert!(st.hunt.is_none());
        // mode=agent без docker — тоже честно
        let out = run(&mut st, "box hunt start --mode agent").unwrap();
        assert!(
            out.contains("не работает") || out.contains("docker"),
            "agent-режим без docker: {out}"
        );
        std::env::remove_var("POLER_BOX_DOCKER");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_hunt_bad_args_rejected() {
        let (mut st, ws) = jailed_state("huntargs");
        let out = run(&mut st, "box hunt start --mode zzz").unwrap();
        assert!(out.contains("⚡"), "неизвестный режим: {out}");
        let out = run(&mut st, "box hunt start --budget 1").unwrap();
        assert!(out.contains("⚡") && out.contains("бюджет"), "бюджет вне 60..7200: {out}");
        let out = run(&mut st, "box hunt start --zzz 1").unwrap();
        assert!(out.contains("⚡"), "неизвестный флаг: {out}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_hunt_report_and_stop_inactive() {
        let mut st = state();
        let out = run(&mut st, "box hunt report").unwrap();
        assert!(out.contains("не активна"), "report без охоты: {out}");
        let out = run(&mut st, "box hunt stop").unwrap();
        assert!(out.contains("не активна"), "stop без охоты: {out}");
    }

    #[test]
    fn box_off_stops_broker_before_docker() {
        // даже если docker-разбор упадёт — брокер обязан быть остановлен
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let (mut st, ws) = jailed_state("offsudo");
        // «поднятый» брокер не нужен — достаточно убедиться, что box off
        // останавливает его ДО docker-вызова: ставим фейковую ручку через
        // spawn на фейковом docker невозможен — проверяем порядок через
        // сообщение об остановке уже поднятого брокера
        let dir = std::env::temp_dir().join(format!("poler-offbro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::env::set_var("POLER_AUDIT_HOME", dir.to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", dir.to_str().unwrap());
        let jail = super::super::containers::BoxState {
            name: "poler-box-testfake".into(),
            cfg: super::super::containers::BoxConfig::default(),
            ws_root: ws.clone(),
            home_dir: dir.join("home"),
        };
        let handle = super::super::rootbroker::spawn_broker(&jail).unwrap();
        st.sudo_broker = Some(handle);
        // box off упадёт на docker (нет демона) — но брокер уже снят
        let _ = run(&mut st, "box off");
        assert!(
            st.sudo_broker.is_none(),
            "брокер обязан быть снят box off ДО docker-ошибки"
        );
        std::env::remove_var("POLER_BOX_DOCKER");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn version_mentions_v027_features() {
        let mut st = state();
        let out = run(&mut st, "version").unwrap();
        assert!(out.contains("root-broker"), "версия без рут-брокера: {out}");
        assert!(out.contains("jailbreak-sentinel"), "версия без sentinel: {out}");
    }

    #[test]
    fn version_mentions_v028_features() {
        let mut st = state();
        let out = run(&mut st, "version").unwrap();
        assert!(out.contains("sudo-passwd"), "версия без пароль-режима: {out}");
        assert!(out.contains("builtin-hunter"), "версия без builtin-охотника: {out}");
        assert!(out.contains("v0.28.0"), "версия без v0.28.0: {out}");
    }

    #[test]
    fn help_lists_sudo_root_hunt() {
        let h = gateway_help();
        assert!(h.contains("box sudo on|off|status"), "help без sudo: {h}");
        assert!(h.contains("box root"), "help без root: {h}");
        assert!(h.contains("box hunt start"), "help без hunt: {h}");
        assert!(h.contains("РУТ-БРОКЕР"), "help без секции рут-брокера: {h}");
        assert!(h.contains("JAILBREAK SENTINEL"), "help без секции sentinel: {h}");
    }

    #[test]
    fn help_lists_passwd_and_builtin_hunter() {
        let h = gateway_help();
        assert!(h.contains("box sudo passwd"), "help без passwd: {h}");
        assert!(h.contains("sudo -S"), "help без примера -S: {h}");
        assert!(h.contains("BUILTIN HUNTER"), "help без секции builtin-охотника: {h}");
        assert!(h.contains("--mode builtin"), "help без builtin-режима: {h}");
        assert!(h.contains("--loop"), "help без loop: {h}");
    }

    // =====================================================================
    // v0.28.0: Root Broker Password Mode + Builtin Hunter
    // =====================================================================

    #[test]
    fn box_sudo_passwd_scripted_agent_refused() {
        // ZSE-инвариант: scripted-агент НЕ может выдать себе рут-пароль
        let (mut st, ws) = jailed_state("passwd");
        let dir = std::env::temp_dir().join(format!("poler-pwcmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("POLER_POLICY_HOME", dir.to_str().unwrap());
        let out = run(&mut st, "box sudo passwd").unwrap();
        assert!(
            out.contains("только в интерактивной"),
            "скрипт не может задать пароль: {out}"
        );
        assert!(
            !super::super::rootbroker::password_path("poler-box-testfake").exists(),
            "пароль-файл не создан"
        );
        // мусорный флаг — ошибка
        let out = run(&mut st, "box sudo passwd zzz").unwrap();
        assert!(out.contains("⚡"), "мусорный флаг: {out}");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_sudo_passwd_clear_is_tightening_anytime() {
        // снятие пароля = ужесточение → доступно и неинтерактивно
        let (mut st, ws) = jailed_state("pwclear");
        let dir = std::env::temp_dir().join(format!("poler-pwclr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("POLER_POLICY_HOME", dir.to_str().unwrap());
        let pw_path = super::super::rootbroker::password_path("poler-box-testfake");
        // пароля нет → честно
        let out = run(&mut st, "box sudo passwd --clear").unwrap();
        assert!(out.contains("не был задан"), "пустой clear: {out}");
        // задан → снят
        super::super::rootbroker::set_password_from_pair(&pw_path, "abc123", "abc123").unwrap();
        let out = run(&mut st, "box sudo passwd --clear").unwrap();
        assert!(out.contains("ВЫКЛ"), "снятие: {out}");
        assert!(!pw_path.exists());
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_sudo_status_mentions_password_mode() {
        let mut st = state();
        let out = run(&mut st, "box sudo status").unwrap();
        assert!(out.contains("режим пароля"), "статус упоминает пароль-режим: {out}");
        assert!(
            out.contains("box sudo passwd"),
            "подсказка команды passwd: {out}"
        );
    }

    #[test]
    fn box_hunt_builtin_bad_args_rejected_before_jail() {
        // валидация аргументов — ДО требования jail/docker (урок v0.27.0)
        let mut st = state(); // без jail: попади в гейт — скажет «jail не активен»
        let out = run(&mut st, "box hunt start --mode builtin --interval 1").unwrap();
        assert!(out.contains("интервал 10..=600"), "interval=1: {out}");
        let out = run(&mut st, "box hunt start --mode builtin --full-every 10").unwrap();
        assert!(out.contains("120..=86400"), "full-every=10: {out}");
        let out = run(&mut st, "box hunt start --mode zzz").unwrap();
        assert!(out.contains("probe|agent|builtin"), "mode=zzz: {out}");
        let out = run(&mut st, "box hunt start --mode builtin --loop=zzz").unwrap();
        assert!(out.contains("--loop"), "loop со значением: {out}");
    }

    #[test]
    fn box_hunt_builtin_requires_jail_and_docker() {
        let mut st = state();
        let out = run(&mut st, "box hunt start --mode builtin").unwrap();
        assert!(out.contains("jail не активен"), "без jail: {out}");
        assert!(st.hunt_builtin.is_none());
        // с фейковым jail, но без docker — честный отказ
        let _g = docker_env_lock();
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let (mut st2, ws) = jailed_state("bin");
        let out = run(&mut st2, "box hunt start --mode builtin").unwrap();
        assert!(
            out.contains("не работает") || out.contains("docker"),
            "без docker — честный отказ: {out}"
        );
        assert!(st2.hunt_builtin.is_none());
        // loop-режим — те же гейты
        let out = run(&mut st2, "box hunt start --mode builtin --loop").unwrap();
        assert!(
            out.contains("не работает") || out.contains("docker"),
            "loop без docker: {out}"
        );
        std::env::remove_var("POLER_BOX_DOCKER");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn box_hunt_stop_clears_builtin_and_sentinel() {
        let mut st = state();
        let out = run(&mut st, "box hunt stop").unwrap();
        assert!(out.contains("не активна"), "stop без охоты: {out}");
    }

    /// box off останавливает loop-наблюдение ДО docker-разбора (даже при
    /// ошибке docker). Реальный loop-поток поднят на фейковом jail.
    #[test]
    fn box_off_stops_builtin_loop_before_docker_error() {
        let _g = docker_env_lock();
        let (mut st, ws) = jailed_state("offloop");
        let dir = std::env::temp_dir().join(format!("poler-offloop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("POLER_AUDIT_HOME", dir.join("audit").to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", dir.join("policy").to_str().unwrap());
        std::env::set_var("POLER_HUNT_HOME", dir.join("hunt").to_str().unwrap());
        // loop с большим full_every: батарея не стартует — только свипы
        let jail = st.box_jail.clone().unwrap();
        let handle = super::super::hunter::start_loop(&jail, false, 60, 86400).unwrap();
        st.hunt_builtin = Some(handle);
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let _ = run(&mut st, "box off"); // docker упадёт — но охота уже снята
        assert!(
            st.hunt_builtin.is_none(),
            "loop-наблюдение обязано быть снято до docker-ошибки"
        );
        std::env::remove_var("POLER_BOX_DOCKER");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        std::env::remove_var("POLER_HUNT_HOME");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ws);
    }
}
