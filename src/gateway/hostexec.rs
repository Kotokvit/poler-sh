//! # Terminal Gateway: контролируемый запуск хостовых команд (v0.22.0)
//!
//! Sandboxed OS Subshell на уровне исполнения: прямой спавн бинарника
//! (БЕЗ `/bin/sh` — токенизацию сделали мы), отдельная группа процессов
//! (Ctrl+C уходит группе, а не только лидеру), кап вывода (как CDP-кап из
//! аудита v0.21.1), таймаут стены, фильтрация окружения (секреты не
//! наследуются), SIGINT/SIGKILL по группе с grace-периодом.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Кап вывода на поток: 16 МБ (канон CDP HTTP_BODY_CAP из аудита v0.21.1).
pub const OUTPUT_CAP: usize = 16 * 1024 * 1024;
/// Таймаут стены по умолчанию (сек). Меняется через `set hosttimeout N`.
pub const DEFAULT_HOST_TIMEOUT_SECS: u64 = 120;
/// Grace-период между SIGINT и SIGKILL при прерывании пользователем.
const KILL_GRACE: Duration = Duration::from_secs(2);
/// Интервал поллинга try_wait (мс).
const POLL_MS: u64 = 30;

/// Режим окружения дочерних процессов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvMode {
    /// Минимальное окружение: PATH/HOME/LANG/TERM/TMPDIR + POLER_*,
    /// секретные переменные вырезаны (по умолчанию).
    Filtered,
    /// Полное наследование (явное решение пользователя: `set hostenv full`).
    Full,
}

impl std::fmt::Display for EnvMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvMode::Filtered => write!(f, "filtered"),
            EnvMode::Full => write!(f, "full"),
        }
    }
}

/// Лимиты исполнения хостовой команды.
#[derive(Debug, Clone)]
pub struct HostLimits {
    pub timeout_secs: u64,
    pub output_cap: usize,
    pub env_mode: EnvMode,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_HOST_TIMEOUT_SECS,
            output_cap: OUTPUT_CAP,
            env_mode: EnvMode::Filtered,
        }
    }
}

/// Результат исполнения хостовой команды.
#[derive(Debug, Clone, Default)]
pub struct HostOutcome {
    pub stdout: String,
    pub stderr: String,
    /// Код возврата (None — процесс убит сигналом/не запущен).
    pub code: Option<i32>,
    /// Прерван пользователем (Ctrl+C).
    pub interrupted: bool,
    /// Убит по таймауту.
    pub timed_out: bool,
    /// Вывод достиг капа и был обрезан.
    pub truncated: bool,
    /// Не удалось запустить (нет такого бинарника/permission denied).
    pub spawn_error: Option<String>,
}

impl HostOutcome {
    /// Печать в терминал gateway: stdout в общий поток, stderr — с меткой.
    pub fn render(&self) -> String {
        if let Some(e) = &self.spawn_error {
            return format!("⚡ {e}");
        }
        let mut out = String::new();
        out.push_str(&self.stdout);
        if !self.stderr.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            for l in self.stderr.lines() {
                out.push_str(&format!("⚠ stderr: {l}\n"));
            }
        }
        if self.truncated {
            out.push_str(&format!(
                "⚠ вывод обрезан на капе {} байт\n",
                OUTPUT_CAP
            ));
        }
        if self.timed_out {
            out.push_str("⚠ таймаут: процесс убит по лимиту стены\n");
        }
        if self.interrupted {
            out.push_str("⚠ прервано (Ctrl+C)\n");
        }
        if self.code.is_some_and(|c| c != 0) && !self.timed_out && !self.interrupted {
            out.push_str(&format!("⚠ exit-код: {}\n", self.code.unwrap()));
        }
        out
    }
}

/// Прерывание: флаг поднимает ctrlc-обработчик gateway (mod.rs).
pub static INTERRUPT: AtomicBool = AtomicBool::new(false);

/// Сброс флага прерывания перед новой командой.
pub fn clear_interrupt() {
    INTERRUPT.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Фильтрация окружения
// ---------------------------------------------------------------------------

/// Имена переменных, которые наследуются всегда.
const ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "LANG", "TERM", "TMPDIR", "TMP", "USER", "LOGNAME", "SHELL",
    "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
    "LC_MESSAGES", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
    "COLORTERM", "NO_COLOR",
];

/// Секретоподобные подстроки в имени переменной → вырезать.
fn looks_secret(name: &str) -> bool {
    let up = name.to_uppercase();
    up.contains("TOKEN")
        || up.contains("SECRET")
        || up.contains("PASSWORD")
        || up.contains("PASSWD")
        || up.ends_with("_KEY")
        || up.ends_with("_KEYS")
        || up.contains("PRIVATE")
}

/// Собрать фильтрованное окружение: allowlist-переменные + POLER_* без
/// секретов + маркер POLER_GATEWAY=1.
pub fn filtered_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    for (k, v) in std::env::vars() {
        let keep = (ENV_ALLOWLIST.contains(&k.as_str())
            || (k.starts_with("POLER_") && !looks_secret(&k) && !k.starts_with("POLER_MCP_TOKEN"))
            || (k.starts_with("LC_") && !k.starts_with("LC_ALL_")))
            // POLER_GATEWAY задаём сами ниже — не берём из родителя
            && k != "POLER_GATEWAY";
        if keep {
            env.push((k, v));
        }
    }
    env.push(("POLER_GATEWAY".into(), "1".into()));
    env
}

// ---------------------------------------------------------------------------
// Запуск
// ---------------------------------------------------------------------------

/// Исполнить хостовую команду с контролем. `tokens[0]` — бинарник (ищется
/// в PATH), остальное — аргументы. `stdin` — данные предыдущего сегмента
/// конвейера (None — наследовать / закрыть).
#[allow(unused_variables)]
pub fn run(
    tokens: &[String],
    stdin: Option<&str>,
    limits: &HostLimits,
    cwd: &Path,
    extra_env: &[(String, String)],
) -> HostOutcome {
    clear_interrupt();
    if tokens.is_empty() {
        return HostOutcome {
            spawn_error: Some("пустая команда".into()),
            ..Default::default()
        };
    }
    let mut cmd = Command::new(&tokens[0]);
    cmd.args(&tokens[1..]).current_dir(cwd);
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // Окружение: filtered (по умолчанию) или full
    match limits.env_mode {
        EnvMode::Filtered => {
            cmd.env_clear();
            for (k, v) in filtered_env() {
                cmd.env(k, v);
            }
        }
        EnvMode::Full => {}
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    // Отдельная группа процессов: сигналы уходят всей группе
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return HostOutcome {
                spawn_error: Some(format!(
                    "не удалось запустить «{}»: {e} (проверьте PATH; команды движка — смотрите `help`)",
                    tokens[0]
                )),
                ..Default::default()
            }
        }
    };

    // stdin-писатель в отдельном потоке (большой ввод не блокирует пайп)
    if let Some(input) = stdin {
        let mut handle = match child.stdin.take() {
            Some(h) => h,
            None => {
                let _ = child.kill();
                return HostOutcome {
                    spawn_error: Some("stdin-пайп недоступен".into()),
                    ..Default::default()
                };
            }
        };
        let data = input.to_string();
        std::thread::spawn(move || {
            let _ = handle.write_all(data.as_bytes());
            // drop(handle) закрывает пайп → дочерний видит EOF
        });
    } else {
        // stdin не нужен: закрываем сразу (drop)
        drop(child.stdin.take());
    }

    // Читатели stdout/stderr в отдельных потоках с капом
    let out_cap = limits.output_cap;
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();
    let t_out = spawn_reader(stdout_handle, out_cap);
    let t_err = spawn_reader(stderr_handle, out_cap);

    // Ожидание с поллингом: таймаут + прерывание пользователя
    let started = Instant::now();
    let mut interrupted = false;
    let mut timed_out = false;
    let status = 'wait: loop {
        if INTERRUPT.load(Ordering::SeqCst) {
            interrupted = true;
            let _ = kill_group(&mut child, Signal::Int);
            // grace: дать процессу шанс на корректный выход
            let grace_start = Instant::now();
            loop {
                if let Some(st) = child.try_wait().unwrap_or(None) {
                    break 'wait Some(st);
                }
                if grace_start.elapsed() >= KILL_GRACE {
                    let _ = kill_group(&mut child, Signal::Kill);
                    break 'wait child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(POLL_MS));
            }
        }
        if let Some(st) = child.try_wait().unwrap_or(None) {
            break 'wait Some(st);
        }
        if started.elapsed() >= Duration::from_secs(limits.timeout_secs) {
            timed_out = true;
            let _ = kill_group(&mut child, Signal::Kill);
            break 'wait child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    };

    let (stdout, trunc_out) = t_out
        .map(|t| t.join().unwrap_or((String::new(), false)))
        .unwrap_or((String::new(), false));
    let (stderr, trunc_err) = t_err
        .map(|t| t.join().unwrap_or((String::new(), false)))
        .unwrap_or((String::new(), false));

    HostOutcome {
        stdout,
        stderr,
        code: status.and_then(|st| st.code()),
        interrupted,
        timed_out,
        truncated: trunc_out || trunc_err,
        spawn_error: None,
    }
}

/// Читатель потока с капом: читаем до EOF, копим не больше cap байт.
fn spawn_reader<R: Read + Send + 'static>(
    handle: Option<R>,
    cap: usize,
) -> Option<std::thread::JoinHandle<(String, bool)>> {
    handle.map(|mut r| {
        std::thread::spawn(move || {
            let mut collected: Vec<u8> = Vec::new();
            let mut truncated = false;
            let mut buf = [0u8; 8192];
            loop {
                match r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if collected.len() + n > cap {
                            // добираем до cap, остальное сливаем в никуда
                            let room = cap.saturating_sub(collected.len());
                            collected.extend_from_slice(&buf[..room]);
                            truncated = true;
                        } else {
                            collected.extend_from_slice(&buf[..n]);
                        }
                    }
                    Err(_) => break,
                }
            }
            (String::from_utf8_lossy(&collected).to_string(), truncated)
        })
    })
}

// ---------------------------------------------------------------------------
// Сигналы (POSIX)
// ---------------------------------------------------------------------------

enum Signal {
    Int,
    Kill,
}

/// Послать сигнал ГРУППЕ процессов. Группа создана `process_group(0)`
/// при спавне, поэтому pgid == pid потомка; `kill(-pid, sig)` — классика
/// POSIX для доставки сигнала всем членам группы (coreutils делают так же).
#[cfg(unix)]
fn kill_group(child: &mut Child, sig: Signal) -> std::io::Result<()> {
    let pgid = -(child.id() as i32);
    let sig_num = match sig {
        Signal::Int => 2,  // SIGINT
        Signal::Kill => 9, // SIGKILL
    };
    send_signal(pgid, sig_num)
}

/// POSIX kill(2) — единственный unsafe в gateway (изолирован, как mmap
/// в ядре движка). Нулей зависимостей: libc не подключаем.
#[cfg(unix)]
fn send_signal(pid_or_pgid: i32, sig: i32) -> std::io::Result<()> {
    // SAFETY: kill(2) — тонкая обёртка над системным вызовом; отрицательный
    // pid = группа процессов (создана нами), sig ∈ {SIGINT, SIGKILL}.
    // Работы с памятью нет, состояние гонок исключено сигнальной моделью.
    let rc = unsafe { kill_syscall(pid_or_pgid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn kill_syscall(pid: i32, sig: i32) -> i32;
}

/// Публичная обёртка kill(2): signal 0 = liveness-проба (сервисный слой),
/// отрицательный pid = группа. Возвращает код syscall (0 = успех).
#[cfg(unix)]
pub fn kill_raw(pid_or_pgid: i32, sig: i32) -> i32 {
    // SAFETY: см. send_signal — тонкая обёртка, памяти не касается.
    unsafe { kill_syscall(pid_or_pgid, sig) }
}

#[cfg(not(unix))]
pub fn kill_raw(_pid_or_pgid: i32, _sig: i32) -> i32 {
    -1
}

#[cfg(not(unix))]
fn kill_group(child: &mut Child, _sig: Signal) -> std::io::Result<()> {
    child.kill()
}

// ---------------------------------------------------------------------------
// PTY Passthrough (v0.23.0) — интерактивные TUI/IDE/REPL на живом терминале
// ---------------------------------------------------------------------------

/// Спавн команды на собственном псевдотерминале с прозрачной передачей I/O:
/// хост-терминал переводится в raw mode, байты stdin↔master качаются
/// насосом на poll(2), ресайз окна пробрасывается в PTY (TIOCSWINSZ),
/// Ctrl+C идёт байтом 0x03 → line-discipline слейва сам превращает его в
/// SIGINT для foreground-группы потомка. Транскрипт сессии накапливается
/// в stdout (кап limits.output_cap — защита памяти).
///
/// Wall-timeout НЕ применяется: интерактивная сессия управляется владельцем
/// (выход из TUI = конец сессии). Код возврата пробрасывается.
///
/// PTY — это только канал I/O: политику безопасности судит sandbox по
/// той же команде ДО спавна (dispatch), здесь исполнения без вердикта нет.
pub fn run_pty(
    tokens: &[String],
    limits: &HostLimits,
    cwd: &Path,
    extra_env: &[(String, String)],
) -> HostOutcome {
    clear_interrupt();
    if tokens.is_empty() {
        return HostOutcome {
            spawn_error: Some("pty: пустая команда".into()),
            ..Default::default()
        };
    }
    #[cfg(target_os = "linux")]
    {
        pty_linux::run(tokens, limits, cwd, extra_env)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (limits, cwd, extra_env);
        HostOutcome {
            spawn_error: Some(
                "pty: PTY-passthrough в этой сборке поддерживается только на Linux".into(),
            ),
            ..Default::default()
        }
    }
}

/// Linux-реализация PTY: posix_openpt/grantpt/unlockpt/ptsname_r + setsid +
/// TIOCSCTTY в pre_exec. Нулей новых зависимостей — тонкие обёртки над
/// libc (как kill(2) выше), crossterm (уже в дереве) — только raw mode.
#[cfg(target_os = "linux")]
mod pty_linux {
    use super::{filtered_env, kill_raw, EnvMode, HostLimits, HostOutcome, INTERRUPT};
    use std::fs::{File, OpenOptions};
    use std::io::{IsTerminal, Read, Write};
    use std::os::unix::io::FromRawFd;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    const O_RDWR: i32 = 2;
    const O_NOCTTY: i32 = 0o400;
    const TIOCSCTTY: u64 = 0x540E;
    const TIOCSWINSZ: u64 = 0x5414;
    const POLLIN: i16 = 0x001;
    const POLLHUP: i16 = 0x004;
    const POLLERR: i16 = 0x008;
    /// Тик насоса (мс) = poll-таймаут; ресайз проверяется раз в 5 тиков.
    const TICK_MS: i32 = 100;
    /// Дренаж хвоста вывода после выхода потомка (мс).
    const DRAIN_MS: u64 = 300;

    #[repr(C)]
    struct WinSize {
        row: u16,
        col: u16,
        xpixel: u16,
        ypixel: u16,
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    // Два typed-объявления одного C-символа ioctl: сигнатуры различаются
    // типом третьего аргумента (TIOCSWINSZ — указатель, TIOCSCTTY — int).
    // На x86_64/arm64 SysV ABI это корректные тонкие обёртки.
    #[allow(clashing_extern_declarations)]
    extern "C" {
        fn posix_openpt(flags: i32) -> i32;
        fn grantpt(fd: i32) -> i32;
        fn unlockpt(fd: i32) -> i32;
        fn ptsname_r(fd: i32, buf: *mut u8, buflen: usize) -> i32;
        fn setsid() -> i32;
        #[link_name = "ioctl"]
        fn ioctl_winsize(fd: i32, request: u64, arg: *mut WinSize) -> i32;
        #[link_name = "ioctl"]
        fn ioctl_int(fd: i32, request: u64, arg: i32) -> i32;
        fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
    }

    /// RAII-возврат терминала хоста в cooked mode (исключения/ранний выход).
    struct RawGuard(bool);
    impl Drop for RawGuard {
        fn drop(&mut self) {
            if self.0 {
                let _ = crossterm::terminal::disable_raw_mode();
            }
        }
    }

    fn err_outcome(msg: String) -> HostOutcome {
        HostOutcome {
            spawn_error: Some(msg),
            ..Default::default()
        }
    }

    pub fn run(
        tokens: &[String],
        limits: &HostLimits,
        cwd: &Path,
        extra_env: &[(String, String)],
    ) -> HostOutcome {
        // 1) master PTY
        let master_fd = unsafe { posix_openpt(O_RDWR | O_NOCTTY) };
        if master_fd < 0 {
            return err_outcome(format!("pty: posix_openpt: {}", std::io::Error::last_os_error()));
        }
        if unsafe { grantpt(master_fd) } != 0 || unsafe { unlockpt(master_fd) } != 0 {
            return err_outcome(format!("pty: grantpt/unlockpt: {}", std::io::Error::last_os_error()));
        }
        let mut namebuf = [0u8; 64];
        if unsafe { ptsname_r(master_fd, namebuf.as_mut_ptr(), namebuf.len()) } != 0 {
            return err_outcome(format!("pty: ptsname_r: {}", std::io::Error::last_os_error()));
        }
        let slave_path = match std::ffi::CStr::from_bytes_until_nul(&namebuf) {
            Ok(s) => s.to_string_lossy().into_owned(),
            Err(_) => return err_outcome("pty: ptsname_r: путь без NUL".into()),
        };

        // 2) спавн: slave как stdio + setsid + TIOCSCTTY в pre_exec
        let slave = match OpenOptions::new().read(true).write(true).open(&slave_path) {
            Ok(f) => f,
            Err(e) => return err_outcome(format!("pty: open {slave_path}: {e}")),
        };
        let slave_out = match slave.try_clone() {
            Ok(f) => f,
            Err(e) => return err_outcome(format!("pty: dup slave: {e}")),
        };
        let slave_err = match slave.try_clone() {
            Ok(f) => f,
            Err(e) => return err_outcome(format!("pty: dup slave: {e}")),
        };

        let mut cmd = Command::new(&tokens[0]);
        cmd.args(&tokens[1..]).current_dir(cwd);
        cmd.stdin(Stdio::from(slave))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::from(slave_err));
        match limits.env_mode {
            EnvMode::Filtered => {
                cmd.env_clear();
                for (k, v) in filtered_env() {
                    cmd.env(k, v);
                }
            }
            EnvMode::Full => {}
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        // потомок: новая сессия, slave (fd 0) — управляющий терминал
        unsafe {
            cmd.pre_exec(|| {
                if setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if ioctl_int(0, TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return err_outcome(format!(
                    "не удалось запустить «{}» на PTY: {e}",
                    tokens[0]
                ))
            }
        };

        // 3) master в owned File; raw mode хоста; начальный размер окна
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        let live = std::io::stdout().is_terminal();
        let raw_ok = crossterm::terminal::enable_raw_mode().is_ok();
        let _raw_guard = RawGuard(raw_ok);
        let mut last_size: Option<(u16, u16)> = None;
        if let Ok((cols, rows)) = crossterm::terminal::size() {
            last_size = Some((cols, rows));
            let mut ws = WinSize { row: rows, col: cols, xpixel: 0, ypixel: 0 };
            unsafe { ioctl_winsize(master_fd, TIOCSWINSZ, &mut ws) };
        }

        // 4) насос: stdin→master, master→stdout (+ транскрипт с капом).
        // stdin качаем ТОЛЬКО если это настоящий TTY: в живом REPL это
        // терминал владельца (passthrough), а пайп/файл не трогаем —
        // иначе PTY-сессия съест чужой поток ввода (скрипты, тесты).
        let pump_stdin = std::io::stdin().is_terminal();
        let cap = limits.output_cap;
        let mut transcript: Vec<u8> = Vec::new();
        let mut truncated = false;
        let mut stdin_open = pump_stdin;
        let mut tick: u32 = 0;
        let mut out_buf = std::io::stdout();

        let append = |tr: &mut Vec<u8>, chunk: &[u8], trunc: &mut bool| {
            if tr.len() + chunk.len() > cap {
                let room = cap.saturating_sub(tr.len());
                tr.extend_from_slice(&chunk[..room]);
                *trunc = true;
            } else {
                tr.extend_from_slice(chunk);
            }
        };

        let status = 'pump: loop {
            let mut fds = [
                PollFd { fd: 0, events: if stdin_open { POLLIN } else { 0 }, revents: 0 },
                PollFd { fd: master_fd, events: POLLIN, revents: 0 },
            ];
            let n = unsafe { poll(fds.as_mut_ptr(), 2, TICK_MS) };
            if n > 0 {
                if stdin_open && fds[0].revents & (POLLIN | POLLHUP) != 0 {
                    let mut buf = [0u8; 4096];
                    match std::io::stdin().read(&mut buf) {
                        Ok(0) => stdin_open = false,
                        Ok(n) => {
                            let _ = (&master).write_all(&buf[..n]);
                        }
                        Err(_) => stdin_open = false,
                    }
                }
                if fds[1].revents & (POLLIN | POLLHUP | POLLERR) != 0 {
                    let mut buf = [0u8; 8192];
                    match master.read(&mut buf) {
                        Ok(0) => break 'pump child.wait().ok(),
                        Ok(n) => {
                            if live {
                                let _ = out_buf.write_all(&buf[..n]);
                                let _ = out_buf.flush();
                            }
                            append(&mut transcript, &buf[..n], &mut truncated);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break 'pump child.wait().ok(), // EIO: slave закрыт
                    }
                }
            }
            // SIGINT нам (не через raw-байт): переслать группе потомка
            if INTERRUPT.load(Ordering::SeqCst) {
                INTERRUPT.store(false, Ordering::SeqCst);
                let _ = kill_raw(-(child.id() as i32), 2);
            }
            // ресайз окна хоста → PTY (каждые ~500 мс)
            tick += 1;
            if tick % 5 == 0 {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    if Some((cols, rows)) != last_size {
                        last_size = Some((cols, rows));
                        let mut ws = WinSize { row: rows, col: cols, xpixel: 0, ypixel: 0 };
                        unsafe { ioctl_winsize(master_fd, TIOCSWINSZ, &mut ws) };
                    }
                }
            }
            // выход потомка → короткий дренаж хвоста и стоп
            if let Some(st) = child.try_wait().unwrap_or(None) {
                let drain_start = Instant::now();
                while drain_start.elapsed() < Duration::from_millis(DRAIN_MS) {
                    let mut pf = [PollFd { fd: master_fd, events: POLLIN, revents: 0 }];
                    if unsafe { poll(pf.as_mut_ptr(), 1, 50) } > 0
                        && pf[0].revents & (POLLIN | POLLHUP | POLLERR) != 0
                    {
                        let mut buf = [0u8; 8192];
                        match master.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if live {
                                    let _ = out_buf.write_all(&buf[..n]);
                                    let _ = out_buf.flush();
                                }
                                append(&mut transcript, &buf[..n], &mut truncated);
                            }
                            Err(_) => break,
                        }
                    } else if pf[0].revents != 0 {
                        break;
                    }
                }
                break 'pump Some(st);
            }
        };

        // 5) закрыть master, вернуть терминал в человеческий вид
        drop(master);
        if live {
            // TUI мог спрятать курсор/войти в alt-screen — снимаем оба
            let _ = out_buf.write_all(b"\x1b[?25h\x1b[?1049l");
            let _ = out_buf.flush();
        }

        HostOutcome {
            stdout: String::from_utf8_lossy(&transcript).to_string(),
            stderr: String::new(),
            code: status.and_then(|st| st.code()),
            interrupted: false,
            timed_out: false,
            truncated,
            spawn_error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtered_env_strips_secrets() {
        // подменяем окружение теста
        std::env::set_var("POLER_TEST_GREETING", "hi");
        std::env::set_var("POLER_TEST_TOKEN", "secret-value");
        std::env::set_var("GITHUB_TOKEN", "ghp_xxx");
        std::env::set_var("MY_API_KEY", "zzz");
        std::env::set_var("POLER_GATEWAY", "0");
        let env = filtered_env();
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("POLER_TEST_GREETING").as_deref(), Some("hi"));
        assert_eq!(get("POLER_TEST_TOKEN"), None, "POLER_*_TOKEN должен быть вырезан");
        assert_eq!(get("GITHUB_TOKEN"), None);
        assert_eq!(get("MY_API_KEY"), None);
        assert_eq!(get("POLER_GATEWAY").as_deref(), Some("1"), "маркер субшелла");
        // PATH наследуется (иначе дочерние команды не найдутся)
        assert!(get("PATH").is_some());
    }

    #[test]
    fn run_echo_captures_stdout() {
        let lim = HostLimits::default();
        let out = run(&["echo".into(), "hello".into()], None, &lim, Path::new("."), &[]);
        assert!(out.spawn_error.is_none());
        assert_eq!(out.stdout.trim(), "hello");
        assert_eq!(out.code, Some(0));
    }

    #[test]
    fn run_stdin_pipe() {
        let lim = HostLimits::default();
        let out = run(&["cat".into()], Some("piped data"), &lim, Path::new("."), &[]);
        assert_eq!(out.stdout, "piped data");
    }

    #[test]
    fn run_missing_binary_is_spawn_error() {
        let lim = HostLimits::default();
        let out = run(
            &["definitely-not-a-binary-xyz".into()],
            None,
            &lim,
            Path::new("."),
            &[],
        );
        assert!(out.spawn_error.is_some());
    }

    #[test]
    fn run_timeout_kills_sleep() {
        let lim = HostLimits {
            timeout_secs: 1,
            ..Default::default()
        };
        let started = Instant::now();
        let out = run(&["sleep".into(), "30".into()], None, &lim, Path::new("."), &[]);
        assert!(out.timed_out);
        assert!(started.elapsed() < Duration::from_secs(5), "таймаут не сработал");
    }

    #[test]
    fn run_output_cap_truncates() {
        let lim = HostLimits {
            timeout_secs: 30,
            output_cap: 100,
            env_mode: EnvMode::Filtered,
        };
        // seq 1 1000 → ~4 КБ вывода, кап 100 байт
        let out = run(
            &["seq".into(), "1".into(), "1000".into()],
            None,
            &lim,
            Path::new("."),
            &[],
        );
        assert!(out.truncated);
        assert!(out.stdout.len() <= 100);
    }

    #[test]
    fn run_exit_code_propagates() {
        let lim = HostLimits::default();
        let out = run(
            &["sh".into(), "-c".into(), "exit 7".into()],
            None,
            &lim,
            Path::new("."),
            &[],
        );
        assert_eq!(out.code, Some(7));
    }

    #[test]
    fn render_shows_stderr_prefix() {
        let out = HostOutcome {
            stderr: "oops".into(),
            code: Some(2),
            ..Default::default()
        };
        let r = out.render();
        assert!(r.contains("⚠ stderr: oops"));
        assert!(r.contains("exit-код: 2"));
    }

    // ------- PTY Passthrough (v0.23.0) -------

    #[test]
    fn pty_echo_roundtrip() {
        let lim = HostLimits::default();
        let out = run_pty(
            &["echo".into(), "pty-hello-42".into()],
            &lim,
            Path::new("."),
            &[],
        );
        assert!(
            out.spawn_error.is_none(),
            "spawn_error: {:?}",
            out.spawn_error
        );
        assert!(
            out.stdout.contains("pty-hello-42"),
            "транскрипт PTY должен содержать вывод: {:?}",
            out.stdout
        );
        assert_eq!(out.code, Some(0));
    }

    #[test]
    fn pty_exit_code_propagates() {
        let lim = HostLimits::default();
        let out = run_pty(
            &["sh".into(), "-c".into(), "exit 3".into()],
            &lim,
            Path::new("."),
            &[],
        );
        assert!(out.spawn_error.is_none());
        assert_eq!(out.code, Some(3));
    }

    #[test]
    fn pty_missing_binary_is_spawn_error() {
        let lim = HostLimits::default();
        let out = run_pty(
            &["definitely-not-a-binary-xyz".into()],
            &lim,
            Path::new("."),
            &[],
        );
        assert!(out.spawn_error.is_some());
    }

    #[test]
    fn pty_isatty_inside_child() {
        // дочерний процесс на PTY обязан видеть TTY (иначе TUI откажется)
        let lim = HostLimits::default();
        let out = run_pty(
            &["sh".into(), "-c".into(), "tty".into()],
            &lim,
            Path::new("."),
            &[],
        );
        assert!(out.spawn_error.is_none());
        assert!(
            out.stdout.contains("/dev/pts/"),
            "tty внутри PTY: {:?}",
            out.stdout
        );
    }
}
