//! # Terminal Gateway: управление сервисным слоем (v0.22.0)
//!
//! `poler service start/stop/status/restart [name]` + `poler attach` —
//! нижний слой (Service Substrate: MCP-HTTP, WebLens)
//! управляется из единого терминального шлюза.
//!
//! v2.0: сервис Auth Companion удалён вместе с Google-интеграцией.
//!
//! Состояние: `~/.local/state/poler-engine/services/<name>.json` (+pid),
//! логи: `~/.local/state/poler-engine/logs/<name>.log`. Сервис стартует
//! ОТВЯЗАННЫМ от терминала (stdio → лог), в отдельной группе процессов;
//! MCP-токен передаётся через env (POLER_MCP_TOKEN), а не argv —
//! `/proc/<pid>/cmdline` не должен светить секреты (урок аудита v0.21.1).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Реестр
// ---------------------------------------------------------------------------

/// Сервис нижнего слоя. Расширяемо: новый сервис = новая строка здесь.
struct ServiceDef {
    name: &'static str,
    desc: &'static str,
    /// Аргументы для current_exe() (bind подставляется при старте).
    args: fn(bind: &str) -> Vec<String>,
    /// Передавать ли сгенерированный MCP-токен через env.
    token_env: bool,
    /// Дефолтный bind.
    default_bind: &'static str,
}

const SERVICES: &[ServiceDef] = &[
    ServiceDef {
        name: "mcp",
        desc: "MCP-HTTP JSON-RPC сервер (Bearer, 127.0.0.1) — полные инструменты движка для агентов",
        args: |bind| vec!["--mcp-http".into(), bind.to_string()],
        token_env: true,
        default_bind: "127.0.0.1:8765",
    },
    ServiceDef {
        name: "weblens",
        desc: "WebLens: оконный Chromium с MV3-расширением + MCP-демон (Alt+P — панель поиска)",
        args: |bind| vec!["--web-lens".into(), bind.to_string()],
        token_env: false, // токен WebLens управляется самим weblens-модулем (0600)
        default_bind: "127.0.0.1:8765",
    },
];

fn find_def(name: &str) -> Option<&'static ServiceDef> {
    SERVICES.iter().find(|s| s.name == name)
}

/// Исполняемый файл движка для спавна сервисов. Тесты и встраивания
/// подменяют через POLER_GATEWAY_SVC_EXE; продакшн — current_exe().
fn engine_exe() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("POLER_GATEWAY_SVC_EXE") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    std::env::current_exe().map_err(|e| format!("current_exe: {e}"))
}

pub fn service_names() -> Vec<&'static str> {
    SERVICES.iter().map(|s| s.name).collect()
}

// ---------------------------------------------------------------------------
// Пути
// ---------------------------------------------------------------------------

/// ~/.local/state/poler-engine/services (XDG-совместимо: переопределяется
/// POLER_STATE_DIR — используется тестами и встраиванием).
pub fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("POLER_STATE_DIR") {
        return PathBuf::from(d).join("services");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/state/poler-engine/services")
}

/// ~/.local/state/poler-engine/logs (или POLER_STATE_DIR/logs).
pub fn logs_dir() -> PathBuf {
    if let Ok(d) = std::env::var("POLER_STATE_DIR") {
        return PathBuf::from(d).join("logs");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/state/poler-engine/logs")
}

fn state_file_in(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

fn pid_file_in(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.pid"))
}

pub fn log_file(name: &str) -> PathBuf {
    logs_dir().join(format!("{name}.log"))
}

fn token_file(name: &str) -> PathBuf {
    state_dir().join(format!("{name}.token"))
}

// ---------------------------------------------------------------------------
// Состояние
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub pid: u32,
    pub started_utc: u64,
    pub bind: String,
    /// http-endpoint для attach (mcp/weblens).
    pub endpoint: Option<String>,
    /// Путь к файлу токена (0600) для attach mcp.
    pub token_file: Option<String>,
}

impl ServiceState {
    fn load_from(dir: &std::path::Path, name: &str) -> Option<Self> {
        let text = std::fs::read_to_string(state_file_in(dir, name)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn load(name: &str) -> Option<Self> {
        Self::load_from(&state_dir(), name)
    }

    fn save_in(&self, dir: &std::path::Path, name: &str) -> Result<(), String> {
        let f = state_file_in(dir, name);
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&f, json).map_err(|e| format!("{}: {e}", f.display()))?;
        std::fs::write(pid_file_in(dir, name), format!("{}", self.pid))
            .map_err(|e| format!("pidfile: {e}"))?;
        Ok(())
    }

    fn save(&self, name: &str) -> Result<(), String> {
        self.save_in(&state_dir(), name)
    }

    fn remove_in(dir: &std::path::Path, name: &str) {
        let _ = std::fs::remove_file(state_file_in(dir, name));
        let _ = std::fs::remove_file(pid_file_in(dir, name));
    }

    fn remove(name: &str) {
        Self::remove_in(&state_dir(), name)
    }
}

/// Жив ли процесс (kill(pid, 0)). На Linux дополнительно проверяем
/// /proc/<pid>/comm — защита от PID-reuse (сервис мог умереть, pid занят
/// чужим процессом).
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if crate::gateway::hostexec::kill_raw(pid as i32, 0) != 0 {
            return false;
        }
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            let comm = comm.trim();
            return comm.starts_with("poler") || comm.starts_with("chrome")
                || comm.starts_with("node") || comm.starts_with("chromium");
        }
        true // /proc недоступен (macOS) — верим kill(2)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// TCP-проба liveness: порт открыт = сервер слушает.
fn probe_endpoint(bind: &str) -> bool {
    let Some(port) = bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) else {
        return false;
    };
    let addr = format!("127.0.0.1:{port}");
    match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => std::net::TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Запустить сервис. Отказ, если уже жив; bind — override или дефолт.
pub fn start(name: &str, bind_override: Option<&str>) -> Result<String, String> {
    let def = find_def(name).ok_or_else(|| unknown_service(name))?;
    if let Some(st) = ServiceState::load(name) {
        if pid_alive(st.pid) {
            return Err(format!(
                "сервис {name} уже запущен (pid {}); stop/restart — для перезапуска",
                st.pid
            ));
        }
        ServiceState::remove(name); // мёртвый — почистить
    }
    let bind = bind_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| def.default_bind.to_string());

    // Токен MCP: файл 0600, передача через env (не argv!)
    let mut extra_env: Vec<(String, String)> = Vec::new();
    let mut token_path = None;
    if def.token_env {
        let tf = token_file(name);
        let token = match std::fs::read_to_string(&tf) {
            Ok(t) if t.trim().len() >= 32 => t.trim().to_string(),
            _ => crate::mcp_http::generate_token(),
        };
        if let Some(dir) = tf.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
        }
        // 0600-запись (канон oauth/weblens из v0.21.1)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tf, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::write(&tf, format!("{token}\n")).map_err(|e| format!("токен: {e}"))?;
        extra_env.push(("POLER_MCP_TOKEN".into(), token));
        token_path = Some(tf.display().to_string());
    }

    // Лог-файл: сервис отвязан от терминала
    std::fs::create_dir_all(logs_dir()).map_err(|e| format!("mkdir логов: {e}"))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file(name))
        .map_err(|e| format!("лог {}: {e}", log_file(name).display()))?;

    let exe = engine_exe()?;
    let args = (def.args)(&bind);
    let mut cmd = Command::new(&exe);
    cmd.args(&args)
        .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(log))
        .stdin(Stdio::null());
    for (k, v) in &extra_env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // своя группа: сигнал стопа не убивает gateway
    }

    let child = cmd
        .spawn()
        .map_err(|e| format!("не удалось запустить {name} ({:?}): {e}", exe.display()))?;
    let pid = child.id();
    // Отвязываемся: gateway не ждёт сервис (drop child, без wait)
    std::mem::forget(child);

    let endpoint = if bind.is_empty() {
        None
    } else {
        Some(format!("http://{bind}/"))
    };
    let st = ServiceState {
        pid,
        started_utc: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        bind: bind.clone(),
        endpoint,
        token_file: token_path,
    };
    st.save(name)?;

    let mut out = format!("▶ {name} запущен (pid {pid}");
    if !bind.is_empty() {
        out.push_str(&format!(", bind {bind}"));
    }
    out.push_str(&format!("\n  лог: {}", log_file(name).display()));
    if let Some(tf) = &st.token_file {
        out.push_str(&format!("\n  токен: {tf} (0600)"));
    }
    Ok(out)
}

/// Остановить сервис: SIGTERM группе → grace 3с → SIGKILL.
pub fn stop(name: &str) -> Result<String, String> {
    let def = find_def(name).ok_or_else(|| unknown_service(name))?;
    let st = ServiceState::load(name)
        .ok_or_else(|| format!("сервис {name} не запущен (нет состояния)"))?;
    if !pid_alive(st.pid) {
        ServiceState::remove(name);
        return Ok(format!("▪ {name} уже был мёртв (состояние почищено)"));
    }
    let _ = crate::gateway::hostexec::kill_raw(-(st.pid as i32), 15); // SIGTERM группе
    let started = Instant::now();
    while pid_alive(st.pid) && started.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(100));
    }
    if pid_alive(st.pid) {
        let _ = crate::gateway::hostexec::kill_raw(-(st.pid as i32), 9); // SIGKILL
        std::thread::sleep(Duration::from_millis(200));
    }
    ServiceState::remove(name);
    let _ = def; // имя найдено — валидация пройдена
    Ok(format!("▪ {name} остановлен (pid {})", st.pid))
}

/// Статус всех (или одного) сервисов — таблица.
pub fn status(name: Option<&str>) -> String {
    let names: Vec<&str> = match name {
        Some(n) => {
            if find_def(n).is_none() {
                return unknown_service(n);
            }
            vec![n]
        }
        None => service_names(),
    };
    let mut out = String::from("SERVICE     PID      STATE      ENDPOINT\n");
    out.push_str(&"-".repeat(56));
    out.push('\n');
    for n in names {
        match ServiceState::load(n) {
            Some(st) => {
                let alive = pid_alive(st.pid);
                let state = if alive {
                    if !st.bind.is_empty() && probe_endpoint(&st.bind) {
                        "running ✓"
                    } else {
                        "alive?"
                    }
                } else {
                    "dead"
                };
                let endpoint = st.endpoint.clone().unwrap_or_else(|| "—".into());
                out.push_str(&format!(
                    "{:<10}  {:<8} {:<10} {}\n",
                    n, st.pid, state, endpoint
                ));
            }
            None => out.push_str(&format!("{:<10}  {:<8} {:<10} {}\n", n, "—", "stopped", "—")),
        }
    }
    out.push_str("\n(`service attach <name>` — подключение к сессии)\n");
    // краткие описания сервисов — desc из реестра
    if name.is_none() {
        out.push('\n');
        for d in SERVICES {
            out.push_str(&format!("  {:<10} {}\n", d.name, d.desc));
        }
    }
    out
}

fn unknown_service(name: &str) -> String {
    format!(
        "неизвестный сервис «{name}» (доступны: {})",
        service_names().join(", ")
    )
}

// ---------------------------------------------------------------------------
// Attach: MCP JSON-RPC клиент
// ---------------------------------------------------------------------------

/// Запрос к живому MCP-серверу (Bearer из токен-файла сервиса).
/// Возвращает (status, body) — для attach REPL и для тестов.
pub fn mcp_rpc(endpoint: &str, token: &str, method: &str, params: serde_json::Value) -> (u16, String) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let url = format!("{}/mcp", endpoint.trim_end_matches('/'));
    match ureq::post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_secs(30))
        .send_json(body)
    {
        Ok(resp) => {
            let status = resp.status();
            match resp.into_string() {
                Ok(text) => (status, text),
                Err(e) => (status, format!("чтение ответа: {e}")),
            }
        }
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            (code, text)
        }
        Err(e) => (0, format!("соединение: {e}")),
    }
}

/// Токен сервиса из файла (0600), с маской для печати: pier_****ABCD.
pub fn service_token(name: &str) -> Result<String, String> {
    let st = ServiceState::load(name)
        .ok_or_else(|| format!("сервис {name} не запущен"))?;
    let tf = st.token_file.ok_or("у сервиса нет токен-файла")?;
    let t = std::fs::read_to_string(&tf)
        .map_err(|e| format!("{tf}: {e}"))?
        .trim()
        .to_string();
    if t.is_empty() {
        return Err("токен-файл пуст".into());
    }
    Ok(t)
}

/// Маска токена для безопасной печати (урок аудита: не светить целиком).
pub fn mask_token(t: &str) -> String {
    if t.len() <= 8 {
        "****".into()
    } else {
        format!("{}****{}", &t[..4], &t[t.len() - 4..])
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_complete() {
        let names = service_names();
        assert!(names.contains(&"mcp"));
        assert!(names.contains(&"weblens"));
        assert!(!names.contains(&"companion"), "v2.0: Auth Companion удалён");
    }

    #[test]
    fn unknown_service_message_lists_all() {
        let m = unknown_service("zzz");
        assert!(m.contains("mcp"));
        assert!(m.contains("weblens"));
        assert!(!m.contains("companion"), "v2.0: Auth Companion удалён");
    }

    #[test]
    fn state_roundtrip_and_remove() {
        // изолированный каталог состояния — БЕЗ мутации HOME (тесты идут
        // параллельно, гонка за env недопустима)
        let dir = std::env::temp_dir().join(format!("poler-svc-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let st = ServiceState {
            pid: std::process::id(),
            started_utc: 12345,
            bind: "127.0.0.1:8765".into(),
            endpoint: Some("http://127.0.0.1:8765/".into()),
            token_file: None,
        };
        st.save_in(&dir, "mcp").unwrap();
        let loaded = ServiceState::load_from(&dir, "mcp").unwrap();
        assert_eq!(loaded.pid, st.pid);
        assert_eq!(loaded.bind, "127.0.0.1:8765");
        assert!(pid_file_in(&dir, "mcp").exists());
        ServiceState::remove_in(&dir, "mcp");
        assert!(ServiceState::load_from(&dir, "mcp").is_none());
        assert!(!pid_file_in(&dir, "mcp").exists());
        // pid живого тест-процесса определяется корректно
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(u32::MAX - 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mask_token_hides_middle() {
        let m = mask_token("abcdefgh12345678");
        assert!(m.starts_with("abcd****"));
        assert!(m.ends_with("5678"));
        assert!(!m.contains("1234"));
        assert_eq!(mask_token("short"), "****");
    }

    #[test]
    fn status_of_unknown_service_is_error_message() {
        let s = status(Some("nope"));
        assert!(s.contains("неизвестный сервис"));
    }
}
