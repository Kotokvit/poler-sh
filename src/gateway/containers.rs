//! # Container Jail (`box`) — жёсткая Docker-изоляция контуров 2/3 (v0.25.0)
//!
//! Живой кейс из эксплуатации (v0.23/v0.24): агент (`agy`), запущенный в
//! PTY-контуре, дергает свой Bash-tool напрямую на хосте — PATH-shim
//! медиация перехватывает вызовы через PATH/$SHELL, но хардкод `/bin/sh`
//! и прямой execve мимо шелла не накрываются (честно задокументировано в
//! §6.5). Единственная userspace-гарантия — **физическая изоляция**:
//! движок поднимает Docker-контейнер («box») и исполняет host-os-proxy
//! (контур 2) и pty-passthrough (контур 3) ВНУТРИ него через `docker exec`.
//!
//! Модель:
//! * `/workspace` ← bind-mount корня workspace (rw; `wsro=1` — read-only);
//! * `/home/poler` ← персистентный home агентов на хосте
//!   (`~/.local/share/poler-engine/box/<name>`) — конфиги/токены агентов
//!   переживают `box off/on`;
//! * хост НЕ монтируется больше нигде; docker-сокет НЕ пробрасывается —
//!   агент внутри не может управлять демоном;
//! * hardening: `--cap-drop ALL`, `no-new-privileges`, `--init` (tini —
//!   зомби-реапер), лимиты памяти/swap и pids, `--stop-timeout 2`;
//! * юзер по умолчанию — uid:gid владельца (файлы в /workspace остаются
//!   его собственными); `user=root` — root ВНУТРИ контейнера (пакеты),
//! * verdict-плоскость сохраняется: судья по-прежнему выносит вердикт ДО
//!   исполнения (деструктив — Block), но логическая граница workspace для
//!   exec-плоскости снимается — её заменяет сам контейнер (redirect-цели
//!   и движковые файл-команды судятся с границей ВСЕГДА: они физически
//!   исполняются на хосте);
//! * управление docker/podman-демоном из gateway при активном jail —
//!   Confirm (`docker run -v /:/host` ломает изоляцию).
//!
//! Нулей новых зависимостей: docker-клиент вызывается как подпроцесс
//! (как сервисный слой service.rs), pure-хелперы вынесены для юнит-тестов.
//! Тесты подменяют бинарник через `POLER_BOX_DOCKER` (по умолчанию `docker`).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Контейнер-точка монтирования workspace.
pub const WS_MOUNT: &str = "/workspace";
/// Контейнерный home (bind-mount персистентного каталога агентов).
pub const HOME_MOUNT: &str = "/home/poler";
/// Образ по умолчанию: маленький, всегда pullable; для агентов —
/// `box on image=<свой образ с node/agy>`.
pub const DEFAULT_IMAGE: &str = "debian:bookworm-slim";
/// Контейнерный HOME для runner-контейнера (home-монтировки нет — изоляция
/// строже: только /workspace).
pub const RUNNER_HOME: &str = "/tmp";

// ---------------------------------------------------------------------------
// Монтировки (v0.26.0)
// ---------------------------------------------------------------------------

/// Одна bind-монтировка «хост → контейнер».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    /// Хост-путь (канонический, существует).
    pub host: PathBuf,
    /// Путь внутри контейнера (абсолютный, белый список префиксов).
    pub container: String,
    /// Read-only? Бинарники агентов — всегда ro; конфиги — rw (авторизация).
    pub ro: bool,
}

impl MountSpec {
    /// docker-форма `-v host:container[:ro|rw]`.
    pub fn docker_arg(&self) -> String {
        let mode = if self.ro { ":ro" } else { "" };
        format!("{}:{}{}", self.host.display(), self.container, mode)
    }
}

/// Префиксы контейнера, куда ВООБЩЕ можно монтировать (белый список):
/// бинарники — только ro, данные — под /home/poler и /opt/poler.
const CONTAINER_MOUNT_ROOTS: &[&str] = &["/usr/local/bin/", "/opt/poler/", "/home/poler/"];

/// Префиксы контейнера, куда монтировать rw можно (данные, не бинарники).
const CONTAINER_RW_ROOTS: &[&str] = &["/opt/poler/", "/home/poler/"];

/// Хост-корни, монтировка которых запрещена (ломает изоляцию jail).
/// Сюда же — весь docker-сокет где бы он ни лежал (отдельная проверка).
const HOST_DENY_ROOTS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
    "/root", "/run", "/sbin", "/srv", "/sys", "/usr", "/var",
];

/// Разобрать `mount=HOST[:CONT[:ro|rw]]` (k=v для `box on`).
/// Безопасность: канонизация хост-пути, отказ на сокетах/устройствах,
/// docker-сокете, системных корнях хоста и монт-целях вне белого списка.
pub fn parse_mount_spec(s: &str) -> Result<MountSpec, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.is_empty() || parts[0].is_empty() {
        return Err("mount=: пусто (формат: mount=HOST[:CONT[:ro|rw]])".into());
    }
    let host_raw = parts[0];
    let host = PathBuf::from(host_raw);
    if !host.is_absolute() {
        return Err(format!(
            "mount=: хост-путь {host_raw} обязан быть абсолютным"
        ));
    }
    // docker-сокет — главный вектор угона демона: запрет всегда и везде
    if host_raw.contains("docker.sock") || host_raw.contains("podman.sock") {
        return Err("mount=: сокет docker/podman не монтируется — это прямая потеря изоляции".into());
    }
    // канонизация (развяжет симлинки; несуществующий путь — отказ)
    let canon = host.canonicalize().map_err(|e| {
        format!("mount=: хост-путь {} не существует ({e})", host.display())
    })?;
    // файловые типы: только регулярные файлы и каталоги
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let ft = std::fs::metadata(&canon)
            .map_err(|e| format!("mount=: stat {}: {e}", canon.display()))?
            .file_type();
        if ft.is_socket() {
            return Err("mount=: сокеты не монтируются (утечка демона)".into());
        }
        if ft.is_block_device() || ft.is_char_device() {
            return Err("mount=: устройства не монтируются".into());
        }
        if ft.is_fifo() {
            return Err("mount=: fifo/пайпы не монтируются".into());
        }
    }
    // системные корни хоста — запрет (канонический путь может уйти из /var/run в /run)
    let canon_s = canon.display().to_string();
    for deny in HOST_DENY_ROOTS {
        if canon_s == *deny || canon_s.starts_with(&format!("{deny}/")) {
            return Err(format!(
                "mount=: системный корень хоста {deny} не монтируется (изоляция jail)"
            ));
        }
    }
    let container = match parts.get(1) {
        None | Some(&"") => {
            // цель по умолчанию: имя файла/каталога под /home/poler (данные)
            let base = canon
                .file_name()
                .map(|b| b.to_string_lossy().to_string())
                .unwrap_or_default();
            if base.is_empty() {
                return Err("mount=: не удалось вывести имя цели — укажите CONT".into());
            }
            format!("{HOME_MOUNT}/{base}")
        }
        Some(c) => (*c).to_string(),
    };
    // валидация цели контейнера
    if !container.starts_with('/') {
        return Err(format!("mount=: цель {container} обязана быть абсолютной"));
    }
    if container.contains("..") {
        return Err("mount=: «..» в цели контейнера запрещён".into());
    }
    // /workspace не расширяется — состав проекта неизменен (проверка до
    // белого списка: более специфичное сообщение)
    if container.starts_with(WS_MOUNT) {
        return Err(format!(
            "mount=: цель {container} внутри {WS_MOUNT} запрещена — состав workspace неизменен"
        ));
    }
    let under_allowed = CONTAINER_MOUNT_ROOTS.iter().any(|r| {
        container == r.trim_end_matches('/') || container.starts_with(r)
    });
    if !under_allowed {
        return Err(format!(
            "mount=: цель {container} вне белого списка ({}) — и /workspace не расширяется",
            CONTAINER_MOUNT_ROOTS.join(" ")
        ));
    }
    let ro = match parts.get(2) {
        None => true, // ручные монтировки по умолчанию read-only
        Some(&"ro") => true,
        Some(&"rw") => {
            let rw_ok = CONTAINER_RW_ROOTS.iter().any(|r| {
                container == r.trim_end_matches('/') || container.starts_with(r)
            });
            if !rw_ok {
                return Err(format!(
                    "mount=: rw допустим только под {} (бинарники — ro)",
                    CONTAINER_RW_ROOTS.join(" ")
                ));
            }
            false
        }
        Some(other) => {
            return Err(format!("mount=: режим {other}? (ro|rw)"));
        }
    };
    Ok(MountSpec {
        host: canon,
        container,
        ro,
    })
}

// ---------------------------------------------------------------------------
// Обнаружение хостовых агентов (v0.26.0 — Zero-Overhead Bind-Mounting)
// ---------------------------------------------------------------------------

/// Тип найденного бинарника агента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentKind {
    /// Автономный ELF — монтируется как есть (glibc образа должен подходить).
    Elf,
    /// Скрипт с shebang — монтируется файл, но интерпретатор обязан быть
    /// в образе (`box on image=node:22-slim` и т.п.).
    Script,
}

/// Найденный на хосте CLI-агент.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAgent {
    pub name: String,
    /// Канонический путь (симлинки разрешены).
    pub host_path: PathBuf,
    pub kind: AgentKind,
    /// Интерпретатор shebang (только для Script).
    pub interpreter: Option<String>,
}

/// Каталоги поиска агентов: PATH + типичные локации (~/.local/bin и пр.).
fn agent_search_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        for p in path.split(':') {
            if !p.is_empty() {
                v.push(PathBuf::from(p));
            }
        }
    }
    for extra in ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"] {
        let p = PathBuf::from(extra);
        if !v.contains(&p) {
            v.push(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            let p = PathBuf::from(&home).join(".local/bin");
            if !v.contains(&p) {
                v.push(p);
            }
        }
    }
    v
}

/// Классификация файла: ELF (магия \x7fELF) | скрипт (shebang) | прочее.
fn classify_bin(path: &Path) -> Option<(AgentKind, Option<String>)> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 256];
    let n = f.read(&mut head).unwrap_or(0);
    if n >= 4 && head[0] == 0x7f && &head[1..4] == b"ELF" {
        return Some((AgentKind::Elf, None));
    }
    if n >= 2 && &head[0..2] == b"#!" {
        let line: String = head[..n]
            .iter()
            .take_while(|&&b| b != b'\n')
            .map(|&b| b as char)
            .collect();
        let shebang = line[2..].trim();
        // `#!/usr/bin/env node` → интерпретатор node; `#!/usr/bin/python3` → python3
        let interp = shebang
            .rsplit_once("env ")
            .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(rest.trim()).to_string())
            .unwrap_or_else(|| {
                shebang
                    .split_whitespace()
                    .next()
                    .unwrap_or(shebang)
                    .rsplit('/')
                    .next()
                    .unwrap_or(shebang)
                    .to_string()
            });
        return Some((AgentKind::Script, Some(interp)));
    }
    None
}

/// Найти CLI-агентов на хосте. `dirs` — каталоги поиска (тесты подменяют);
/// пустой срез → берём реальную ENV-локацию. Имена — канон шлюза
/// (`shim::AGENT_CMDS`): agy/claude/codex/gemini/aider/…
pub fn discover_host_agents(dirs: &[PathBuf]) -> Vec<HostAgent> {
    let dirs: Vec<PathBuf> = if dirs.is_empty() {
        agent_search_dirs()
    } else {
        dirs.to_vec()
    };
    let mut found: Vec<HostAgent> = Vec::new();
    for name in super::shim::AGENT_CMDS {
        for d in &dirs {
            let p = d.join(name);
            let Ok(meta) = std::fs::metadata(&p) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o111 == 0 {
                    continue; // не исполняемый
                }
            }
            let Some((kind, interpreter)) = classify_bin(&p) else {
                break; // есть файл, но не ELF/скрипт — не агент
            };
            let host_path = p.canonicalize().unwrap_or(p.clone());
            found.push(HostAgent {
                name: (*name).to_string(),
                host_path,
                kind,
                interpreter,
            });
            break; // первое вхождение имени (семантика PATH)
        }
    }
    found
}

/// Каталог конфигурации агента на хосте (авторизация переживает box off/on).
/// Возвращает None для агентов без известного каталога.
pub fn agent_config_dir(name: &str, home: &Path) -> Option<PathBuf> {
    let p = match name {
        // Antigravity CLI и Gemini CLI делят ~/.gemini
        "agy" | "gemini" => home.join(".gemini"),
        "claude" => home.join(".claude"),
        "codex" => home.join(".codex"),
        "cursor-agent" => home.join(".cursor"),
        "copilot" => home.join(".config").join("github-copilot"),
        "goose" => home.join(".config").join("goose"),
        "opencode" => home.join(".config").join("opencode"),
        "qwen" => home.join(".qwen"),
        _ => return None,
    };
    if p.is_dir() {
        Some(p)
    } else {
        None
    }
}

/// Спланировать монтировки агентов: бинарники → /usr/local/bin/<name>:ro,
/// конфиги (если есть и with_configs) → /home/poler/<dirname>:rw.
/// Возвращает (монтировки, заметки для владельца) — pure-функция.
pub fn plan_agent_mounts(
    agents: &[HostAgent],
    with_configs: bool,
    config_dirs: &[PathBuf],
) -> (Vec<MountSpec>, Vec<String>) {
    let mut mounts: Vec<MountSpec> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for a in agents {
        mounts.push(MountSpec {
            host: a.host_path.clone(),
            container: format!("/usr/local/bin/{}", a.name),
            ro: true,
        });
        if a.kind == AgentKind::Script {
            let interp = a.interpreter.clone().unwrap_or_else(|| "?".into());
            notes.push(format!(
                "agy-скрипт {}: интерпретатор {interp} должен быть в образе (box on image=… с {interp})",
                a.name
            ));
        }
    }
    if with_configs {
        for cfg in config_dirs {
            let base = cfg
                .file_name()
                .map(|b| b.to_string_lossy().to_string())
                .unwrap_or_default();
            if base.is_empty() {
                continue;
            }
            mounts.push(MountSpec {
                host: cfg.clone(),
                container: format!("{HOME_MOUNT}/{base}"),
                ro: false, // авторизация обновляет токены
            });
        }
    }
    (mounts, notes)
}

// ---------------------------------------------------------------------------
// Конфигурация
// ---------------------------------------------------------------------------

/// Политика автомонтирования хостовых агентов (v0.26.0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPolicy {
    /// Найти всех известных агентов (agy/claude/codex/…) и пробросить ro.
    Auto,
    /// Ничего не пробрасывать (чистый образ).
    None,
    /// Только перечисленные имена.
    Only(Vec<String>),
}

/// Конфигурация Container Jail (`box on [k=v…]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxConfig {
    /// Образ контейнера (docker run <image>).
    pub image: String,
    /// Сеть: `bridge` (агентам нужен API) | `none` (полная тишина).
    pub net: String,
    /// Root ВНУТРИ контейнера (пакеты) вместо uid владельца.
    pub user_root: bool,
    /// Лимит памяти (docker-нотация: 512m, 2g…). Swap = mem (без резерва).
    pub mem: String,
    /// Лимит процессов (анти-форк-бомба второго эшелона).
    pub pids: u32,
    /// Монтировать workspace read-only (анализ без записи).
    pub ws_readonly: bool,
    /// v0.26.0: какие хостовые агенты пробрасывать внутрь (bind-mount ro).
    pub agents: AgentPolicy,
    /// v0.26.0: ручные монтировки (mount=…) + спланированные агентские
    /// (заполняется в box_on после discovery — argv-билдер pure).
    pub mounts: Vec<MountSpec>,
    /// v0.26.0: имена проброшенных агентов (label docker + отчёт).
    pub agent_names: Vec<String>,
    /// v0.26.0: не монтировать конфиги агентов (~/.gemini и пр.).
    pub no_cfg: bool,
}

impl Default for BoxConfig {
    fn default() -> Self {
        Self {
            image: DEFAULT_IMAGE.into(),
            net: "bridge".into(),
            user_root: false,
            mem: "2g".into(),
            pids: 512,
            ws_readonly: false,
            agents: AgentPolicy::Auto,
            mounts: Vec::new(),
            agent_names: Vec::new(),
            no_cfg: false,
        }
    }
}

impl BoxConfig {
    /// Строка юзера для docker run: uid:gid владельца или 0:0.
    pub fn user_arg(&self) -> String {
        if self.user_root {
            "0:0".into()
        } else {
            let (uid, gid) = uid_gid();
            format!("{uid}:{gid}")
        }
    }
}

/// Разбор аргументов `box on`. Форма: `box on [IMAGE] [k=v…]` — первый
/// позиционный аргумент без `=` трактуется как образ (UX-шорткат).
/// v0.26.0: + `mount=HOST[:CONT[:ro|rw]]` (повторяемый),
/// `agent=auto|none|all|имя1,имя2`, `nocfg=0|1`.
pub fn parse_on_args(args: &[String]) -> Result<BoxConfig, String> {
    let mut cfg = BoxConfig::default();
    for a in args {
        if a.is_empty() {
            continue;
        }
        if !a.contains('=') {
            if !a.starts_with('-') && cfg.image == DEFAULT_IMAGE {
                cfg.image = a.clone();
                continue;
            }
            return Err(format!(
                "box on: {a}? (k=v: image=… net=bridge|none user=me|root mem=2g pids=512 wsro=0|1 agent=… mount=… nocfg=0|1)"
            ));
        }
        let (k, v) = a.split_once('=').ok_or("box on: пустой ключ")?;
        match k {
            "image" => {
                if v.is_empty() || v.contains(char::is_whitespace) {
                    return Err("box on: image= не может быть пустым или с пробелами".into());
                }
                cfg.image = v.into();
            }
            "net" => match v {
                "bridge" | "none" => cfg.net = v.into(),
                "host" => {
                    return Err(
                        "box on: net=host открывает сеть хоста — запрещено (bridge|none)".into(),
                    )
                }
                other => {
                    return Err(format!(
                        "box on: net={other}? (bridge|none; host запрещён)"
                    ))
                }
            },
            "user" => match v {
                "me" => cfg.user_root = false,
                "root" => cfg.user_root = true,
                other => return Err(format!("box on: user={other}? (me|root)")),
            },
            "mem" => {
                if !valid_mem(v) {
                    return Err(format!(
                        "box on: mem={v}? (примеры: 512m, 2g, 8g)"
                    ));
                }
                cfg.mem = v.into();
            }
            "pids" => {
                let n: u32 = v
                    .parse()
                    .map_err(|_| format!("box on: pids={v}? (число 16..=8192)"))?;
                if !(16..=8192).contains(&n) {
                    return Err("box on: pids вне диапазона 16..=8192".into());
                }
                cfg.pids = n;
            }
            "wsro" | "readonly" => match v {
                "1" | "true" | "on" | "yes" => cfg.ws_readonly = true,
                "0" | "false" | "off" | "no" => cfg.ws_readonly = false,
                other => return Err(format!("box on: {k}={other}? (0|1)")),
            },
            "agent" | "agents" => match v {
                "auto" | "all" => cfg.agents = AgentPolicy::Auto,
                "none" | "off" => cfg.agents = AgentPolicy::None,
                list => {
                    let names: Vec<String> = list
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if names.is_empty() {
                        return Err("box on: agent= — пустой список (auto|none|имя1,имя2)".into());
                    }
                    // имена обязаны быть из известного канона (shim::AGENT_CMDS)
                    for n in &names {
                        if !super::shim::AGENT_CMDS.contains(&n.as_str()) {
                            return Err(format!(
                                "box on: agent={n}? — неизвестный агент (канон: agy, claude, codex, …)"
                            ));
                        }
                    }
                    cfg.agents = AgentPolicy::Only(names);
                }
            },
            "mount" => {
                let spec = parse_mount_spec(v)?;
                cfg.mounts.push(spec);
            }
            "nocfg" | "noconfig" => match v {
                "1" | "true" | "on" | "yes" => cfg.no_cfg = true,
                "0" | "false" | "off" | "no" => cfg.no_cfg = false,
                other => return Err(format!("box on: {k}={other}? (0|1)")),
            },
            other => {
                return Err(format!(
                    "box on: {other}=? (ключи: image net user mem pids wsro agent mount nocfg)"
                ))
            }
        }
    }
    Ok(cfg)
}

/// docker-нотация памяти: цифры + опциональный суффикс b/k/m/g/t.
fn valid_mem(v: &str) -> bool {
    let mut chars = v.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => {}
        _ => return false,
    }
    let digits_end = v
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| i)
        .unwrap_or(v.len());
    let suffix = &v[digits_end..];
    suffix.is_empty() || matches!(suffix, "b" | "k" | "m" | "g" | "t")
}

// ---------------------------------------------------------------------------
// Состояние jail
// ---------------------------------------------------------------------------

/// Активный Container Jail (сессионное состояние gateway).
#[derive(Debug, Clone)]
pub struct BoxState {
    /// Имя контейнера (стабильно выводится из корня workspace).
    pub name: String,
    /// Конфигурация (образ — фактический, из label контейнера при adopt).
    pub cfg: BoxConfig,
    /// Хост-путь, смонтированный в /workspace.
    pub ws_root: PathBuf,
    /// Хост-каталог, смонтированный в /home/poler.
    pub home_dir: PathBuf,
}

/// uid/gid владельца процесса (для --user; тонкие обёртки как kill(2)).
#[cfg(unix)]
pub fn uid_gid() -> (u32, u32) {
    extern "C" {
        fn getuid() -> u32;
        fn getgid() -> u32;
    }
    // SAFETY: getuid/getgid — read-only системные вызовы без состояния.
    unsafe { (getuid(), getgid()) }
}

#[cfg(not(unix))]
pub fn uid_gid() -> (u32, u32) {
    (1000, 1000)
}

/// Бинарник docker-клиента (тесты подменяют через POLER_BOX_DOCKER).
fn docker_bin() -> String {
    std::env::var("POLER_BOX_DOCKER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "docker".into())
}

/// fnv1a-32 от канонического пути — общий хеш для box и runner имён.
fn ws_hash(ws_root: &Path) -> u32 {
    let canon = ws_root
        .canonicalize()
        .unwrap_or_else(|_| ws_root.to_path_buf());
    let mut h: u64 = 0xcbf29ce484222325;
    for b in canon.display().to_string().as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h as u32
}

/// Стабильное имя контейнера из корня workspace: `poler-box-<fnv1a-8>`.
/// Один workspace = один контейнер (две сессии gateway на одном корне
/// делят box — docker exec конкурирует корректно).
pub fn container_name(ws_root: &Path) -> String {
    // младшие 32 бита: компактное стабильное имя (8 hex-символов)
    format!("poler-box-{:08x}", ws_hash(ws_root))
}

/// Персистентный home агентов: `~/.local/share/poler-engine/box/<name>`
/// (база переопределяется POLER_BOX_HOME — тесты/встраивание).
pub fn box_home_base() -> PathBuf {
    if let Ok(d) = std::env::var("POLER_BOX_HOME") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/poler-engine/box")
}

// ---------------------------------------------------------------------------
// docker-клиент (подпроцесс с таймаутом и дренажом пайпов)
// ---------------------------------------------------------------------------

/// Дренаж потока в фон (pull-прогресс может превысить буфер пайпа).
/// pub(crate): переиспользуется rootbroker-ом (docker exec -u 0).
pub(crate) fn drain_pipe(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v: Vec<u8> = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if v.len() < 1_048_576 {
                        v.extend_from_slice(&buf[..n]);
                    }
                }
                Err(_) => break,
            }
        }
        v
    })
}

/// Выполнить docker <args> с таймаутом. Успех = exit 0, возврат stdout.
/// НЕ env_clear: клиенту нужны PATH/DOCKER_HOST/XDG_RUNTIME_DIR.
/// pub(crate): переиспользуется sentinel-ом (host-аудит/kill-switch).
pub(crate) fn docker_cmd(args: &[&str], timeout: Duration) -> Result<String, String> {
    let bin = docker_bin();
    let mut cmd = Command::new(&bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child: Child = cmd
        .spawn()
        .map_err(|e| format!("не удалось запустить «{bin}»: {e} (docker установлен?)"))?;
    let t_out = child.stdout.take().map(drain_pipe);
    let t_err = child.stderr.take().map(drain_pipe);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("docker: wait: {e}"));
            }
        }
    };
    let out = String::from_utf8_lossy(&t_out.map(|t| t.join().unwrap_or_default()).unwrap_or_default()).to_string();
    let err = String::from_utf8_lossy(&t_err.map(|t| t.join().unwrap_or_default()).unwrap_or_default()).to_string();
    match status {
        Some(st) if st.success() => Ok(out),
        Some(st) => {
            let sub = args.first().copied().unwrap_or("");
            let tail: String =
                err.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
            Err(format!(
                "docker {sub}: exit {}: {}",
                st.code().unwrap_or(-1),
                if tail.is_empty() { out.trim() } else { &tail }
            ))
        }
        None => {
            let sub = args.first().copied().unwrap_or("");
            Err(format!("docker {sub}: таймаут {timeout:?}"))
        }
    }
}

/// Проба демона: версия Server (клиент без демона бесполезен).
pub fn docker_probe() -> Result<String, String> {
    docker_cmd(
        &["version", "--format", "{{.Server.Version}}"],
        Duration::from_secs(8),
    )
    .map(|v| v.trim().to_string())
}

/// Контейнер существует? → Some(running). Нет → None.
pub fn box_running(name: &str) -> Option<bool> {
    match docker_cmd(
        &["inspect", "-f", "{{.State.Running}}", name],
        Duration::from_secs(10),
    ) {
        Ok(out) => Some(out.trim() == "true"),
        Err(_) => None,
    }
}

/// Label контейнера (конфигурация переживает restart gateway).
fn inspect_label(name: &str, key: &str) -> Option<String> {
    let fmt = format!("{{{{index .Config.Labels \"{key}\"}}}}");
    docker_cmd(&["inspect", "-f", &fmt, name], Duration::from_secs(10))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// argv-билдеры (pure — юнит-тестируемые)
// ---------------------------------------------------------------------------

/// argv `docker run` для box: полный hardening-набор.
/// v0.26.0: + монтировки агентов/ручные (из cfg.mounts) + label состава.
pub fn docker_run_argv(name: &str, cfg: &BoxConfig, ws_root: &Path, home_dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.into(),
        "--hostname".into(),
        "poler-box".into(),
        "--init".into(),
        "--user".into(),
        cfg.user_arg(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--memory".into(),
        cfg.mem.clone(),
        "--memory-swap".into(),
        cfg.mem.clone(),
        "--pids-limit".into(),
        cfg.pids.to_string(),
        "--network".into(),
        cfg.net.clone(),
        "--stop-timeout".into(),
        "2".into(),
    ];
    let ro = if cfg.ws_readonly { ":ro" } else { "" };
    v.push("-v".into());
    v.push(format!("{}:{WS_MOUNT}{ro}", ws_root.display()));
    v.push("-v".into());
    v.push(format!("{}:{HOME_MOUNT}", home_dir.display()));
    // v0.26.0: проброс хостовых агентов и ручные монтировки (deny-list
    // уже отработал в parse_mount_spec/планировщике)
    for m in &cfg.mounts {
        v.push("-v".into());
        v.push(m.docker_arg());
    }
    v.push("-w".into());
    v.push(WS_MOUNT.into());
    v.push("-e".into());
    v.push(format!("HOME={HOME_MOUNT}"));
    v.push("-e".into());
    // v0.27.0: шимы рут-брокера (sudo) и батареи sentinel — первыми в PATH:
    // агент в клетке зовёт «sudo …» → уходит брокеру шлюза, а не в образ
    v.push(format!(
        "PATH={}:{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        super::rootbroker::POLER_BIN_MOUNT,
        "/usr/local/bin"
    ));
    v.push("-e".into());
    // брокер-контекст для процессов внутри: агент видит, что он в box,
    // и знает контейнерный корень workspace
    v.push(format!("POLER_WORKSPACE={WS_MOUNT}"));
    v.push("-e".into());
    v.push("POLER_BOX=1".into());
    v.push("--label".into());
    v.push("poler.box=1".into());
    v.push("--label".into());
    v.push(format!("poler.box.image={}", cfg.image));
    if !cfg.agent_names.is_empty() {
        v.push("--label".into());
        v.push(format!("poler.box.agents={}", cfg.agent_names.join(",")));
    }
    v.push(cfg.image.clone());
    v.extend(["sleep", "infinity"].map(Into::into));
    v
}

/// Хост-путь → путь внутри контейнера (ws_root→/workspace, home→/home/poler;
/// прочее — якорь /workspace: exec-плоскость живёт в jail).
pub fn in_container_path(jail: &BoxState, host_path: &Path) -> String {
    let canon = host_path
        .canonicalize()
        .unwrap_or_else(|_| host_path.to_path_buf());
    if canon.starts_with(&jail.ws_root) {
        let suffix = canon.strip_prefix(&jail.ws_root).unwrap_or(Path::new(""));
        if suffix.as_os_str().is_empty() {
            WS_MOUNT.into()
        } else {
            format!("{WS_MOUNT}/{}", suffix.display())
        }
    } else if canon.starts_with(&jail.home_dir) {
        let suffix = canon.strip_prefix(&jail.home_dir).unwrap_or(Path::new(""));
        if suffix.as_os_str().is_empty() {
            HOME_MOUNT.into()
        } else {
            format!("{HOME_MOUNT}/{}", suffix.display())
        }
    } else {
        WS_MOUNT.into()
    }
}

/// Общие флаги docker exec: рабочая директория + env + имя контейнера.
fn common_exec_args(jail: &BoxState, host_cwd: &Path) -> Vec<String> {
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    vec![
        "-w".into(),
        in_container_path(jail, host_cwd),
        "-e".into(),
        format!("HOME={HOME_MOUNT}"),
        "-e".into(),
        format!("TERM={term}"),
        "-e".into(),
        // v0.26.0: брокер-контекст внутри контейнера
        format!("POLER_WORKSPACE={WS_MOUNT}"),
        "-e".into(),
        "POLER_BOX=1".into(),
        jail.name.clone(),
    ]
}

/// Обёртка host-сегмента (контур 2): `docker exec -i …` — пайповый режим,
/// argv передаётся насквозь (без /bin/sh — тот же принцип, что hostexec).
/// v0.26.0: бинарник — через docker_bin() (POLER_BOX_DOCKER-override
/// действует и на exec-плоскость, не только на lifecycle).
pub fn wrap_host_exec(jail: &BoxState, tokens: &[String], host_cwd: &Path) -> Vec<String> {
    let mut v: Vec<String> = vec![docker_bin(), "exec".into(), "-i".into()];
    v.extend(common_exec_args(jail, host_cwd));
    v.extend(tokens.iter().cloned());
    v
}

/// Обёртка PTY-команды (контур 3): `docker exec -it …` — контейнерный TTY;
/// наш PTY-насос качает байты в docker-клиент, тот — в контейнерный tty.
pub fn wrap_pty_exec(jail: &BoxState, tokens: &[String], host_cwd: &Path) -> Vec<String> {
    let mut v: Vec<String> = vec![docker_bin(), "exec".into(), "-it".into()];
    v.extend(common_exec_args(jail, host_cwd));
    v.extend(tokens.iter().cloned());
    v
}

/// v0.27.0: обёртка РУТ-шелла с хоста (`box root`): `docker exec -it -u 0:0`.
/// Рут — привилегия хоста: интерактивный вход возможен ТОЛЬКО владельцем
/// из шлюза; изнутри клетки этой команды нет.
pub fn wrap_root_pty_exec(_jail: &BoxState, tokens: &[String], _host_cwd: &Path) -> Vec<String> {
    let mut v: Vec<String> = vec![
        docker_bin(),
        "exec".into(),
        "-it".into(),
        "-u".into(),
        "0:0".into(),
        "-w".into(),
        "/".into(),
    ];
    v.extend(tokens.iter().cloned());
    v
}

/// `box root` — константа (не ввод пользователя): root-шелл в клетке.
pub fn box_root_tokens() -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        "exec bash -l 2>/dev/null || exec sh".into(),
    ]
}

/// `box shell` — интерактивный шелл внутри jail. Константа (не ввод
/// пользователя): bash при наличии, иначе sh; судья не нужен — граница
/// здесь сам контейнер (полезная нагрузка не содержит пользовательских
/// данных). Инвариант покрыт тестом box_shell_tokens_constant.
pub fn box_shell_tokens() -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        "exec bash 2>/dev/null || exec sh".into(),
    ]
}

/// Команда управляет контейнерным демоном хоста (docker/podman/…) —
/// при активном jail это способ сломать изоляцию (`docker run -v /:/x`)
/// → Confirm-гейт в dispatch.
pub fn is_daemon_ctl(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let base = first.rsplit('/').next().unwrap_or(first);
    matches!(
        base,
        "docker" | "podman" | "docker-compose" | "podman-compose" | "nerdctl" | "ctr" | "dockerd"
            | "podman-remote" | "lima" | "colima"
    )
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Поднять/принять Container Jail для корня workspace.
/// v0.26.0: перед созданием находит хостовых агентов (agy/claude/…) и
/// добавляет их бинарники (ro) + конфиги (rw) в монтировки — zero-overhead
/// bind-mounting без сборки образа и без двойной установки.
/// Возвращает (состояние, отчёт для владельца).
pub fn box_on(ws_root: &Path, cfg: &BoxConfig) -> Result<(BoxState, String), String> {
    docker_probe().map_err(|e| format!("docker недоступен: {e}"))?;
    let canon = ws_root
        .canonicalize()
        .map_err(|e| format!("workspace {}: {e}", ws_root.display()))?;
    let name = container_name(&canon);

    // уже есть контейнер → принять (running) или стартовать (stopped)
    if let Some(running) = box_running(&name) {
        if !running {
            docker_cmd(&["start", &name], Duration::from_secs(30))
                .map_err(|e| format!("docker start {name}: {e}"))?;
        }
        let image = inspect_label(&name, "poler.box.image").unwrap_or_else(|| cfg.image.clone());
        let agents_label = inspect_label(&name, "poler.box.agents").unwrap_or_default();
        let jail = BoxState {
            name: name.clone(),
            cfg: BoxConfig {
                image: image.clone(),
                agent_names: agents_label
                    .split(',')
                    .map(|s| s.to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                ..cfg.clone()
            },
            ws_root: canon.clone(),
            home_dir: box_home_base().join(&name),
        };
        let verb = if running { "принят работающий" } else { "стартован остановленный" };
        // v0.27.0: шимы рут-брокера — и при adopt (идемпотентно, лечит подмену)
        let shim_note = match super::rootbroker::deploy_shims(&jail.home_dir) {
            Ok(()) => String::new(),
            Err(e) => format!("\n⚠ рут-шимы не развёрнуты: {e}"),
        };
        let agents_line = if agents_label.is_empty() {
            String::new()
        } else {
            format!("\nагенты в контейнере (label): {agents_label}")
        };
        return Ok((
            jail,
            format!(
                "📦 Container Jail ВКЛ — {verb} контейнер {name} (образ {image})\nконтуры 2/3 исполняются внутри; конфигурация контейнера неизменна до box off/on (проброс агентов обновится после пересоздания)\nруут-брокер: box sudo on — агент сможет ПРОСИТЬ рут (судья решает, исполнение со стороны хоста){shim_note}{agents_line}\n"
            ),
        ));
    }

    // v0.26.0: zero-overhead bind-mounting хостовых агентов
    let mut cfg = cfg.clone();
    let mut notes: Vec<String> = Vec::new();
    let discovered = match &cfg.agents {
        AgentPolicy::None => Vec::new(),
        AgentPolicy::Only(names) => {
            let all = discover_host_agents(&[]);
            all.into_iter().filter(|a| names.contains(&a.name)).collect()
        }
        AgentPolicy::Auto => discover_host_agents(&[]),
    };
    if !discovered.is_empty() {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let mut config_dirs: Vec<PathBuf> = Vec::new();
        for a in &discovered {
            if let Some(d) = agent_config_dir(&a.name, &home) {
                if !config_dirs.contains(&d) {
                    config_dirs.push(d);
                }
            }
        }
        let (mut mnts, mut ns) = plan_agent_mounts(&discovered, !cfg.no_cfg, &config_dirs);
        cfg.mounts.append(&mut mnts);
        notes.append(&mut ns);
        cfg.agent_names = discovered.iter().map(|a| a.name.clone()).collect();
    }

    // создание: персистентный home + docker run (pull может занять минуты)
    let home = box_home_base().join(&name);
    std::fs::create_dir_all(&home).map_err(|e| format!("home {}: {e}", home.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700));
    }
    // v0.27.0: шимы рут-брокера (sudo) + маркеры канала — до старта контейнера
    super::rootbroker::deploy_shims(&home)
        .map_err(|e| format!("рут-шимы {}: {e}", home.display()))?;
    let run_args = docker_run_argv(&name, &cfg, &canon, &home);
    let refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();
    docker_cmd(&refs, Duration::from_secs(600))
        .map_err(|e| format!("docker run: {e} (образ тянулся/отсутствует? docker pull {})", cfg.image))?;
    if box_running(&name) != Some(true) {
        // диагностика: контейнер умер сразу (sleep infinity недоступен в образе?)
        let _ = docker_cmd(&["rm", "-f", &name], Duration::from_secs(30));
        return Err(format!(
            "контейнер {name} не пережил запуск — образ {} без coreutils-sleep? попробуйте другой image=",
            cfg.image
        ));
    }
    let ro = if cfg.ws_readonly { "ro" } else { "rw" };
    let user: String = if cfg.user_root {
        "root(в контейнере)".to_string()
    } else {
        cfg.user_arg()
    };
    let agents_report = if cfg.agent_names.is_empty() {
        "агенты хоста не обнаружены (agent=none|имя — политика; mount= — ручной проброс)\n".to_string()
    } else {
        format!(
            "агенты хоста проброшены внутрь (zero-overhead, ro): {}\nконфиги (rw, персистентная авторизация): {}\n",
            cfg.agent_names.join(", "),
            cfg.mounts
                .iter()
                .filter(|m| !m.ro)
                .map(|m| format!("~{}", m.container))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let notes_report = if notes.is_empty() {
        String::new()
    } else {
        format!("⚠ заметки: {}\n", notes.join("; "))
    };
    let report = format!(
        "📦 Container Jail ВКЛ — контуры 2/3 исполняются ВНУТРИ контейнера\n\
         контейнер: {name} · образ {image} · net {net} · user {user} · mem {mem} · pids {pids}\n\
         /workspace ← {ws} ({ro}) · /home/poler ← {home} (персистентный home агентов)\n\
         {agents_report}{notes_report}\
         изоляция: cap-drop ALL · no-new-privileges · mem/pids-лимиты · docker-сокет не проброшен\n\
         агент в PTY (agy/claude/…) физически заперт: хост виден только как /workspace\n\
         MCP-брокер: service start mcp → инструмент poler_box_exec (двухконтурный брокер)\n\
         деструктив по-прежнему блокируется судьёй; box off — разобрать\n",
        name = name,
        image = cfg.image,
        net = cfg.net,
        user = user,
        mem = cfg.mem,
        pids = cfg.pids,
        ws = canon.display(),
        ro = ro,
        home = home.display(),
    );
    let jail = BoxState {
        name: name.clone(),
        cfg: cfg.clone(),
        ws_root: canon.clone(),
        home_dir: home.clone(),
    };
    Ok((jail, report))
}

/// Разобрать jail: `docker rm -f` (home и workspace остаются на хосте).
pub fn box_off(name: &str) -> Result<String, String> {
    docker_probe().map_err(|e| format!("docker недоступен: {e}"))?;
    if box_running(name).is_none() {
        return Ok(format!("контейнер {name} не найден — убирать нечего\n"));
    }
    docker_cmd(&["rm", "-f", name], Duration::from_secs(60))
        .map_err(|e| format!("docker rm {name}: {e}"))?;
    Ok(format!(
        "📦 Container Jail ВЫКЛ — контейнер {name} удалён (workspace и home сохранены на хосте)\n"
    ))
}

/// Текст `box status`: docker-демон, ожидаемый/активный контейнер, монтировки.
/// v0.26.0: + проброшенные агенты + секция runner (контур исполнения брокера).
pub fn box_status_text(
    active: Option<&BoxState>,
    runner: Option<&RunnerState>,
    ws_root: &Path,
) -> String {
    let docker_line = match docker_probe() {
        Ok(v) => format!("docker: сервер {v}"),
        Err(e) => format!("docker: недоступен ({e})"),
    };
    let mut s = String::new();
    match active {
        Some(jail) => {
            let state: String = match box_running(&jail.name) {
                Some(true) => "работает".into(),
                Some(false) => "остановлен (box on — стартовать)".into(),
                None => "не найден (box on — поднять)".into(),
            };
            s.push_str(&format!(
                "box: Container Jail ВКЛ — контуры 2/3 внутри контейнера\n{docker_line}\nконтейнер {}: {} · образ {}\nмонтировано: {WS_MOUNT} ← {} · {HOME_MOUNT} ← {}\n",
                jail.name,
                state,
                jail.cfg.image,
                jail.ws_root.display(),
                jail.home_dir.display(),
            ));
            if !jail.cfg.agent_names.is_empty() {
                s.push_str(&format!(
                    "агенты (zero-overhead ro): {}\n",
                    jail.cfg.agent_names.join(", ")
                ));
            }
        }
        None => {
            let name = container_name(ws_root);
            let state: String = match box_running(&name) {
                Some(true) => "работает (box on — принять)".into(),
                Some(false) => "остановлен (box on — стартовать)".into(),
                None => "не создан".into(),
            };
            s.push_str(&format!(
                "box: Container Jail ВЫКЛ — контуры 2/3 исполняются на хосте (workspace-guard)\n{docker_line}\nконтейнер {name}: {state}\nbox on [image=…] [net=bridge|none] [user=me|root] [mem=2g] [pids=512] [wsro=0|1] [agent=auto|none|имя] [mount=…] [nocfg=0|1] — поднять\nагенты хоста (agy/claude/…) пробрасываются внутрь автоматически (ro) — без сборки образа\n",
            ));
        }
    }
    // v0.26.0: runner — контур исполнения MCP-брокера
    let rn = runner_name(ws_root);
    let rstate: String = match runner {
        Some(r) => match box_running(&r.name) {
            Some(true) => "работает".into(),
            Some(false) => "остановлен (box runner on — стартовать)".into(),
            None => "не найден (box runner on — поднять)".into(),
        },
        None => match box_running(&rn) {
            Some(true) => "работает (box runner on — принять)".into(),
            Some(false) => "остановлен".into(),
            None => "не создан".into(),
        },
    };
    s.push_str(&format!(
        "runner: контур исполнения брокера (MCP poler_box_exec) · контейнер {rn}: {rstate} · net none · только {WS_MOUNT}\nbox runner on|off|status — управление · box off разбирает и runner\n",
    ));
    s
}

// ---------------------------------------------------------------------------
// Runner — изолированный контур исполнения (v0.26.0, двухконтурный брокер)
// ---------------------------------------------------------------------------

/// Конфигурация runner-контейнера (`box runner on [k=v…]`).
/// Отличия от box: net=none по умолчанию (скриптам сеть не нужна), НЕТ
/// /home/poler и НЕТ агентов — сюда брокер отправляет ИСПОЛНЕНИЕ,
/// а не мозг агента (контур 3 схемы двухконтурного брокера).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerConfig {
    pub image: String,
    /// Только `none` (по умолчанию) | `bridge` — явный opt-in.
    pub net: String,
    pub mem: String,
    pub pids: u32,
    pub ws_readonly: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            image: DEFAULT_IMAGE.into(),
            net: "none".into(),
            mem: "1g".into(),
            pids: 256,
            ws_readonly: false,
        }
    }
}

impl RunnerConfig {
    /// Строка юзера для docker run: uid:gid владельца (файлы в /workspace
    /// остаются его собственными; root в runner не предусмотрен).
    pub fn user_arg(&self) -> String {
        let (uid, gid) = uid_gid();
        format!("{uid}:{gid}")
    }
}

/// Активный runner (сессионное состояние gateway).
#[derive(Debug, Clone)]
pub struct RunnerState {
    pub name: String,
    pub cfg: RunnerConfig,
    pub ws_root: PathBuf,
}

/// Имя runner-контейнера: `poler-runner-<fnv1a-8>` (тот же хеш ws, что у box).
pub fn runner_name(ws_root: &Path) -> String {
    format!("poler-runner-{:08x}", ws_hash(ws_root))
}

/// Разбор аргументов `box runner on` (k=v: image/net/mem/pids/wsro).
pub fn parse_runner_args(args: &[String]) -> Result<RunnerConfig, String> {
    let mut cfg = RunnerConfig::default();
    for a in args {
        if a.is_empty() {
            continue;
        }
        if !a.contains('=') {
            if !a.starts_with('-') && cfg.image == DEFAULT_IMAGE {
                cfg.image = a.clone();
                continue;
            }
            return Err(format!(
                "box runner on: {a}? (k=v: image=… net=none|bridge mem=1g pids=256 wsro=0|1)"
            ));
        }
        let (k, v) = a.split_once('=').ok_or("box runner on: пустой ключ")?;
        match k {
            "image" => {
                if v.is_empty() || v.contains(char::is_whitespace) {
                    return Err("box runner on: image= не может быть пустым или с пробелами".into());
                }
                cfg.image = v.into();
            }
            "net" => match v {
                "none" | "bridge" => cfg.net = v.into(),
                "host" => {
                    return Err(
                        "box runner on: net=host запрещён (контур исполнения без сети хоста)".into(),
                    )
                }
                other => return Err(format!("box runner on: net={other}? (none|bridge)")),
            },
            "mem" => {
                if !valid_mem(v) {
                    return Err(format!("box runner on: mem={v}? (примеры: 512m, 1g)"));
                }
                cfg.mem = v.into();
            }
            "pids" => {
                let n: u32 = v
                    .parse()
                    .map_err(|_| format!("box runner on: pids={v}? (число 16..=8192)"))?;
                if !(16..=8192).contains(&n) {
                    return Err("box runner on: pids вне диапазона 16..=8192".into());
                }
                cfg.pids = n;
            }
            "wsro" | "readonly" => match v {
                "1" | "true" | "on" | "yes" => cfg.ws_readonly = true,
                "0" | "false" | "off" | "no" => cfg.ws_readonly = false,
                other => return Err(format!("box runner on: {k}={other}? (0|1)")),
            },
            other => {
                return Err(format!(
                    "box runner on: {other}=? (ключи: image net mem pids wsro)"
                ))
            }
        }
    }
    Ok(cfg)
}

/// argv `docker run` для runner: как box, но БЕЗ /home/poler и агентов,
/// net=none по умолчанию, HOME=/tmp — только /workspace.
pub fn runner_run_argv(name: &str, cfg: &RunnerConfig, ws_root: &Path) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.into(),
        "--hostname".into(),
        "poler-runner".into(),
        "--init".into(),
        "--user".into(),
        cfg.user_arg(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--memory".into(),
        cfg.mem.clone(),
        "--memory-swap".into(),
        cfg.mem.clone(),
        "--pids-limit".into(),
        cfg.pids.to_string(),
        "--network".into(),
        cfg.net.clone(),
        "--stop-timeout".into(),
        "2".into(),
    ];
    let ro = if cfg.ws_readonly { ":ro" } else { "" };
    v.push("-v".into());
    v.push(format!("{}:{WS_MOUNT}{ro}", ws_root.display()));
    v.push("-w".into());
    v.push(WS_MOUNT.into());
    v.push("-e".into());
    v.push(format!("HOME={RUNNER_HOME}"));
    v.push("-e".into());
    v.push(format!("POLER_WORKSPACE={WS_MOUNT}"));
    v.push("-e".into());
    v.push("POLER_RUNNER=1".into());
    v.push("--label".into());
    v.push("poler.runner=1".into());
    v.push("--label".into());
    v.push(format!("poler.runner.image={}", cfg.image));
    v.push(cfg.image.clone());
    v.extend(["sleep", "infinity"].map(Into::into));
    v
}

/// Поднять/принять runner для корня workspace (идемпотентно, как box_on).
pub fn runner_on(ws_root: &Path, cfg: &RunnerConfig) -> Result<(RunnerState, String), String> {
    docker_probe().map_err(|e| format!("docker недоступен: {e}"))?;
    let canon = ws_root
        .canonicalize()
        .map_err(|e| format!("workspace {}: {e}", ws_root.display()))?;
    let name = runner_name(&canon);
    if let Some(running) = box_running(&name) {
        if !running {
            docker_cmd(&["start", &name], Duration::from_secs(30))
                .map_err(|e| format!("docker start {name}: {e}"))?;
        }
        let image = inspect_label(&name, "poler.runner.image").unwrap_or_else(|| cfg.image.clone());
        let st = RunnerState {
            name: name.clone(),
            cfg: RunnerConfig {
                image: image.clone(),
                ..cfg.clone()
            },
            ws_root: canon.clone(),
        };
        let verb = if running { "принят работающий" } else { "стартован остановленный" };
        return Ok((
            st,
            format!(
                "🏃 runner ВКЛ — {verb} контейнер {name} (образ {image})\nконтур исполнения MCP-брокера; конфигурация неизменна до box runner off/on\n"
            ),
        ));
    }
    let run_args = runner_run_argv(&name, cfg, &canon);
    let refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();
    docker_cmd(&refs, Duration::from_secs(600))
        .map_err(|e| format!("docker run: {e} (docker pull {}?)", cfg.image))?;
    if box_running(&name) != Some(true) {
        let _ = docker_cmd(&["rm", "-f", &name], Duration::from_secs(30));
        return Err(format!(
            "runner {name} не пережил запуск — образ {} без coreutils-sleep?",
            cfg.image
        ));
    }
    let ro = if cfg.ws_readonly { "ro" } else { "rw" };
    let report = format!(
        "🏃 runner ВКЛ — изолированный контур исполнения (двухконтурный брокер)\n\
         контейнер: {name} · образ {image} · net {net} · mem {mem} · pids {pids}\n\
         /workspace ← {ws} ({ro}) · БЕЗ /home/poler · БЕЗ агентов · БЕЗ сети по умолчанию\n\
         назначение: MCP-инструмент poler_box_exec исполняет сюда скрипты агентов;\n\
         судья sandbox.rs выносит вердикт ДО исполнения (деструктив — Block)\n\
         box runner off — разобрать (данные в workspace остаются)\n",
        name = name,
        image = cfg.image,
        net = cfg.net,
        mem = cfg.mem,
        pids = cfg.pids,
        ws = canon.display(),
        ro = ro,
    );
    let st = RunnerState {
        name: name.clone(),
        cfg: cfg.clone(),
        ws_root: canon.clone(),
    };
    Ok((st, report))
}

/// Разобрать runner.
pub fn runner_off(name: &str) -> Result<String, String> {
    docker_probe().map_err(|e| format!("docker недоступен: {e}"))?;
    if box_running(name).is_none() {
        return Ok(format!("runner-контейнер {name} не найден — убирать нечего\n"));
    }
    docker_cmd(&["rm", "-f", name], Duration::from_secs(60))
        .map_err(|e| format!("docker rm {name}: {e}"))?;
    Ok(format!(
        "🏃 runner ВЫКЛ — контейнер {name} удалён (workspace не тронут)\n"
    ))
}

/// Обёртка команды для runner: `docker exec -i …` (пайповый режим — брокер
/// читает stdout/stderr, TTY не нужен). cwd маппится как в box.
pub fn wrap_runner_exec(runner: &RunnerState, tokens: &[String], host_cwd: &Path) -> Vec<String> {
    // маппинг путей тот же, что у box (ws→/workspace); вне ws — якорь /workspace
    let jail_like = BoxState {
        name: runner.name.clone(),
        cfg: BoxConfig::default(),
        ws_root: runner.ws_root.clone(),
        home_dir: box_home_base().join(&runner.name), // не монтирован, но маппинг консистентен
    };
    let cwd_in = in_container_path(&jail_like, host_cwd);
    let mut v: Vec<String> = vec![
        docker_bin(),
        "exec".into(),
        "-i".into(),
        "-w".into(),
        cwd_in,
        "-e".into(),
        format!("HOME={RUNNER_HOME}"),
        "-e".into(),
        format!("POLER_WORKSPACE={WS_MOUNT}"),
        "-e".into(),
        "POLER_RUNNER=1".into(),
        runner.name.clone(),
    ];
    v.extend(tokens.iter().cloned());
    v
}

/// Собрать BoxState по имени ws-корня для контейнера box (cross-process
/// discovery для MCP-брокера: сервис mcp не разделяет память с gateway).
pub fn box_state_for_ws(ws_root: &Path) -> Option<BoxState> {
    let canon = ws_root.canonicalize().ok()?;
    let name = container_name(&canon);
    if box_running(&name) != Some(true) {
        return None;
    }
    let image = inspect_label(&name, "poler.box.image").unwrap_or_else(|| DEFAULT_IMAGE.into());
    let agent_names: Vec<String> = inspect_label(&name, "poler.box.agents")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some(BoxState {
        name,
        cfg: BoxConfig {
            image,
            agent_names,
            ..BoxConfig::default()
        },
        ws_root: canon.clone(),
        home_dir: box_home_base().join(container_name(&canon)),
    })
}

/// Собрать RunnerState по ws-корню (cross-process discovery для MCP).
pub fn runner_state_for_ws(ws_root: &Path) -> Option<RunnerState> {
    let canon = ws_root.canonicalize().ok()?;
    let name = runner_name(&canon);
    if box_running(&name) != Some(true) {
        return None;
    }
    let image = inspect_label(&name, "poler.runner.image").unwrap_or_else(|| DEFAULT_IMAGE.into());
    Some(RunnerState {
        name,
        cfg: RunnerConfig {
            image,
            ..RunnerConfig::default()
        },
        ws_root: canon,
    })
}

/// Тестовая сериализация мутаций POLER_BOX_DOCKER: env — процесс-глобал,
/// cargo test гоняет тесты параллельно, а с v0.26.0 wrap_* тоже читают
/// env. ОБЩИЙ лок для containers/dispatch/mcp-тестов.
#[cfg(test)]
pub(crate) fn docker_env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_on_args_defaults() {
        let c = parse_on_args(&[]).unwrap();
        assert_eq!(c, BoxConfig::default());
        assert_eq!(c.image, DEFAULT_IMAGE);
        assert_eq!(c.net, "bridge");
        assert!(!c.user_root);
        assert_eq!(c.mem, "2g");
        assert_eq!(c.pids, 512);
        assert!(!c.ws_readonly);
    }

    #[test]
    fn parse_on_args_positional_image_shortcut() {
        let c = parse_on_args(&["alpine:3.20".into()]).unwrap();
        assert_eq!(c.image, "alpine:3.20");
        // k=v после шортката
        let c = parse_on_args(&["node:22-slim".into(), "net=none".into()]).unwrap();
        assert_eq!(c.image, "node:22-slim");
        assert_eq!(c.net, "none");
    }

    #[test]
    fn parse_on_args_overrides() {
        let c = parse_on_args(&[
            "image=alpine:3.20".into(),
            "net=none".into(),
            "user=root".into(),
            "mem=8g".into(),
            "pids=1024".into(),
            "wsro=1".into(),
        ])
        .unwrap();
        assert_eq!(c.image, "alpine:3.20");
        assert_eq!(c.net, "none");
        assert!(c.user_root);
        assert_eq!(c.mem, "8g");
        assert_eq!(c.pids, 1024);
        assert!(c.ws_readonly);
        assert_eq!(c.user_arg(), "0:0");
    }

    #[test]
    fn parse_on_args_rejects_bad() {
        assert!(parse_on_args(&["net=host".into()]).is_err(), "host-сеть запрещена");
        assert!(parse_on_args(&["net=x".into()]).is_err());
        assert!(parse_on_args(&["user=both".into()]).is_err());
        assert!(parse_on_args(&["mem=2x".into()]).is_err());
        assert!(parse_on_args(&["mem=".into()]).is_err());
        assert!(parse_on_args(&["pids=abc".into()]).is_err());
        assert!(parse_on_args(&["pids=1".into()]).is_err(), "ниже 16");
        assert!(parse_on_args(&["pids=99999".into()]).is_err(), "выше 8192");
        assert!(parse_on_args(&["zzz=1".into()]).is_err(), "неизвестный ключ");
        assert!(parse_on_args(&["image=with space".into()]).is_err());
    }

    #[test]
    fn container_name_stable_and_distinct() {
        let a = container_name(Path::new("/home/u/proj"));
        let a2 = container_name(Path::new("/home/u/proj/")); // canonicalize поправит
        assert_eq!(a, container_name(Path::new("/home/u/proj")));
        assert!(a.starts_with("poler-box-"), "префикс: {a}");
        assert_eq!(a.len(), "poler-box-".len() + 8, "8 hex-символов: {a}");
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if let Ok(canon) = Path::new("/home/u/proj").canonicalize() {
            assert_eq!(a, container_name(&canon));
        }
        let _ = a2; // может не существовать — не важно
    }

    fn fake_jail() -> BoxState {
        BoxState {
            name: "poler-box-deadbeef".into(),
            cfg: BoxConfig::default(),
            ws_root: PathBuf::from("/tmp/polertest-ws"),
            home_dir: PathBuf::from("/tmp/polertest-home"),
        }
    }

    #[test]
    fn in_container_path_mapping() {
        let j = fake_jail();
        assert_eq!(in_container_path(&j, Path::new("/tmp/polertest-ws")), "/workspace");
        assert_eq!(
            in_container_path(&j, Path::new("/tmp/polertest-ws/src/main.rs")),
            "/workspace/src/main.rs"
        );
        assert_eq!(in_container_path(&j, Path::new("/tmp/polertest-home")), "/home/poler");
        assert_eq!(
            in_container_path(&j, Path::new("/tmp/polertest-home/.gemini")),
            "/home/poler/.gemini"
        );
        // вне монтировок — якорь /workspace (exec-плоскость живёт в jail)
        assert_eq!(in_container_path(&j, Path::new("/etc")), "/workspace");
    }

    #[test]
    fn wrap_host_exec_shape() {
        let _g = docker_env_test_lock();
        let j = fake_jail();
        let w = wrap_host_exec(&j, &["ls".into(), "-la".into()], Path::new("/tmp/polertest-ws"));
        assert_eq!(&w[1..3], &["exec".to_string(), "-i".into()]);
        assert_eq!(w[0], "docker", "бинарник по умолчанию: {w:?}");
        assert!(!w.contains(&"-it".to_string()), "пайповый режим без -t: {w:?}");
        assert!(w.contains(&"-w".to_string()));
        assert!(w.contains(&"/workspace".to_string()));
        assert!(w.contains(&"HOME=/home/poler".to_string()));
        assert!(w.contains(&"POLER_BOX=1".to_string()), "брокер-контекст в exec: {w:?}");
        assert!(w.contains(&j.name), "имя контейнера: {w:?}");
        // хвост = исходные токены насквозь
        assert_eq!(&w[w.len() - 2..], &["ls".to_string(), "-la".to_string()]);
        // POLER_BOX_DOCKER-override действует и на exec-плоскость
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let w2 = wrap_host_exec(&j, &["ls".into()], Path::new("/tmp/polertest-ws"));
        std::env::remove_var("POLER_BOX_DOCKER");
        assert_eq!(w2[0], "/bin/false", "override бинарника exec: {w2:?}");
    }

    #[test]
    fn wrap_pty_exec_shape() {
        let _g = docker_env_test_lock();
        let j = fake_jail();
        let w = wrap_pty_exec(&j, &["vim".into(), "main.rs".into()], Path::new("/tmp/polertest-ws"));
        assert_eq!(&w[1..3], &["exec".to_string(), "-it".to_string()]);
        assert_eq!(w[0], "docker");
        assert_eq!(w.last().unwrap(), "main.rs");
    }

    #[test]
    fn docker_run_argv_hardening() {
        let cfg = BoxConfig {
            image: "alpine:3.20".into(),
            net: "none".into(),
            user_root: false,
            mem: "512m".into(),
            pids: 256,
            ws_readonly: true,
            ..BoxConfig::default()
        };
        let v = docker_run_argv("poler-box-x", &cfg, Path::new("/ws"), Path::new("/home"));
        let joined = v.join("\u{1}");
        for must in [
            "--cap-drop\u{1}ALL",
            "--security-opt\u{1}no-new-privileges",
            "--memory\u{1}512m",
            "--pids-limit\u{1}256",
            "--network\u{1}none",
            "--init",
            "--stop-timeout\u{1}2",
            "/ws:/workspace:ro",
            "/home:/home/poler",
            "--label\u{1}poler.box.image=alpine:3.20",
            "POLER_WORKSPACE=/workspace",
            "POLER_BOX=1",
        ] {
            assert!(joined.contains(must), "docker run без {must}: {v:?}");
        }
        // хвост: образ + sleep infinity (keepalive)
        assert_eq!(&v[v.len() - 3..], &["alpine:3.20".to_string(), "sleep".into(), "infinity".into()]);
        assert!(v.contains(&"-w".to_string()) && v.contains(&"/workspace".to_string()));
    }

    #[test]
    fn is_daemon_ctl_vectors() {
        assert!(is_daemon_ctl(&["docker".into(), "ps".into()]));
        assert!(is_daemon_ctl(&["/usr/bin/docker".into(), "run".into(), "-v".into(), "/:/x".into()]));
        assert!(is_daemon_ctl(&["podman".into()]));
        assert!(is_daemon_ctl(&["docker-compose".into(), "up".into()]));
        assert!(is_daemon_ctl(&["nerdctl".into()]));
        assert!(is_daemon_ctl(&["colima".into()]));
        assert!(!is_daemon_ctl(&["ls".into()]));
        assert!(!is_daemon_ctl(&["dockerfile-lint".into()]), "базовое имя, не подстрока");
        assert!(!is_daemon_ctl(&[]));
    }

    #[test]
    fn box_shell_tokens_constant() {
        let t = box_shell_tokens();
        assert_eq!(t[0], "sh");
        assert_eq!(t[1], "-c");
        // константа без пользовательского ввода — границей является контейнер
        assert_eq!(t[2], "exec bash 2>/dev/null || exec sh");
    }

    // -----------------------------------------------------------------
    // v0.27.0: рут-брокер — PATH шимов + root-exec обёртка
    // -----------------------------------------------------------------

    #[test]
    fn docker_run_argv_puts_polbin_first_in_path() {
        let cfg = BoxConfig::default();
        let v = docker_run_argv("poler-box-x", &cfg, Path::new("/ws"), Path::new("/home"));
        let path_entry = v.iter().find(|s| s.starts_with("PATH=")).expect("PATH= в env");
        assert!(
            path_entry.starts_with(&format!("PATH={}", crate::gateway::rootbroker::POLER_BIN_MOUNT)),
            "шим-каталог первым в PATH: {path_entry}"
        );
        assert!(path_entry.contains("/usr/local/bin"), "системный PATH сохранён: {path_entry}");
    }

    #[test]
    fn wrap_root_pty_exec_shape() {
        let _g = docker_env_test_lock();
        let j = fake_jail();
        let tokens = box_root_tokens();
        let w = wrap_root_pty_exec(&j, &tokens, Path::new("/tmp/polertest-ws"));
        assert_eq!(&w[1..3], &["exec".to_string(), "-it".into()]);
        // рут-флаги контейнера
        assert!(w.windows(2).any(|p| p == ["-u".to_string(), "0:0".into()]), "-u 0:0: {w:?}");
        assert!(w.windows(2).any(|p| p == ["-w".to_string(), "/".into()]), "cwd /: {w:?}");
        // хвост = константные токены насквозь
        assert_eq!(&w[w.len() - 3..], &["sh".to_string(), "-c".into(), "exec bash -l 2>/dev/null || exec sh".to_string()]);
        // POLER_BOX_DOCKER-override действует и на рут-обёртку
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let w2 = wrap_root_pty_exec(&j, &tokens, Path::new("/tmp/polertest-ws"));
        std::env::remove_var("POLER_BOX_DOCKER");
        assert_eq!(w2[0], "/bin/false", "override рут-обёртки: {w2:?}");
    }

    #[test]
    fn box_root_tokens_constant() {
        let t = box_root_tokens();
        assert_eq!(t[0], "sh");
        assert_eq!(t[1], "-c");
        assert!(t[2].contains("bash"), "bash при наличии: {t:?}");
        assert!(t[2].contains("|| exec sh"), "фолбэк на sh: {t:?}");
    }

    #[test]
    fn docker_probe_without_docker_honest_error() {
        let _g = docker_env_test_lock();
        // подменяем бинарник на заведомо нерабочий — проба обязана честно упасть
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let r = docker_probe();
        std::env::remove_var("POLER_BOX_DOCKER");
        assert!(r.is_err(), "проба с /bin/false обязана провалиться: {r:?}");
        assert!(r.unwrap_err().contains("docker"), "ошибка упоминает docker");
    }

    // -----------------------------------------------------------------
    // v0.26.0: bind-mounting агентов + runner
    // -----------------------------------------------------------------

    /// Временный каталог с фейковыми агентами: ELF (магия), скрипт (shebang),
    /// не-исполняемый файл. Возвращает путь каталога.
    fn fake_agent_dir(tag: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("poler-agents-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // ELF-агент
        let elf = d.join("agy");
        std::fs::write(&elf, [0x7fu8, b'E', b'L', b'F', 2, 1, 0, 0]).unwrap();
        std::fs::set_permissions(&elf, std::fs::Permissions::from_mode(0o755)).unwrap();
        // скрипт-агент (shebang на node)
        let sh = d.join("claude");
        std::fs::write(&sh, "#!/usr/bin/env node\nconsole.log(1)\n").unwrap();
        std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
        // не-исполняемый (должен быть проигнорирован)
        let noexec = d.join("codex");
        std::fs::write(&noexec, [0x7fu8, b'E', b'L', b'F', 2]).unwrap();
        std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o644)).unwrap();
        d
    }

    #[test]
    fn discover_host_agents_classifies() {
        let d = fake_agent_dir("disc");
        let found = discover_host_agents(&[d.clone()]);
        let agy = found.iter().find(|a| a.name == "agy").expect("agy найден");
        assert_eq!(agy.kind, AgentKind::Elf);
        assert!(agy.host_path.ends_with("agy"));
        let claude = found.iter().find(|a| a.name == "claude").expect("claude найден");
        assert_eq!(claude.kind, AgentKind::Script);
        assert_eq!(claude.interpreter.as_deref(), Some("node"));
        assert!(!found.iter().any(|a| a.name == "codex"), "не-исполняемый пропущен");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn plan_agent_mounts_shapes() {
        let d = fake_agent_dir("plan");
        let found = discover_host_agents(&[d.clone()]);
        let cfg_dir = d.join(".gemini");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let (mounts, notes) = plan_agent_mounts(&found, true, &[cfg_dir.clone()]);
        let agy_m = mounts
            .iter()
            .find(|m| m.container == "/usr/local/bin/agy")
            .expect("монтировка agy");
        assert!(agy_m.ro, "бинарник агента — только ro");
        let cfg_m = mounts
            .iter()
            .find(|m| m.container == "/home/poler/.gemini")
            .expect("монтировка конфига");
        assert!(!cfg_m.ro, "конфиг — rw (авторизация обновляется)");
        assert!(cfg_m.host.ends_with(".gemini"));
        // заметка про интерпретатор для скрипт-агента
        assert!(notes.iter().any(|n| n.contains("claude") && n.contains("node")));
        // docker-аргументы
        assert_eq!(agy_m.docker_arg(), format!("{}:/usr/local/bin/agy:ro", agy_m.host.display()));
        assert_eq!(cfg_m.docker_arg(), format!("{}:/home/poler/.gemini", cfg_m.host.display()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn agent_config_dir_known_and_missing() {
        let home = Path::new("/home/tester");
        // каталог не существует → None (честность: не монтируем фантомы)
        assert!(agent_config_dir("agy", home).is_none());
        // неизвестный агент → None
        assert!(agent_config_dir("vim", home).is_none());
        // существующий → путь (живая проверка с реальным ~/.gemini — только если он есть)
        if let Some(h) = std::env::var("HOME").ok().map(PathBuf::from) {
            let gemini = h.join(".gemini");
            let got = agent_config_dir("agy", &h);
            if gemini.is_dir() {
                assert_eq!(got, Some(gemini));
            } else {
                assert_eq!(got, None);
            }
        }
    }

    #[test]
    fn parse_mount_spec_security_vectors() {
        let d = fake_agent_dir("mnt");
        let good = d.join("agy");
        // валидные формы
        let m = parse_mount_spec(&good.display().to_string()).unwrap();
        assert_eq!(m.container, "/home/poler/agy");
        assert!(m.ro, "ручные монтировки по умолчанию ro");
        let m = parse_mount_spec(&format!("{}:/opt/poler/tool:ro", good.display())).unwrap();
        assert_eq!(m.container, "/opt/poler/tool");
        let m = parse_mount_spec(&format!("{}:/home/poler/data:rw", good.display())).unwrap();
        assert!(!m.ro);
        // docker-сокет — всегда отказ (главный вектор угона демона)
        assert!(parse_mount_spec("/var/run/docker.sock:/x/sock:ro").is_err());
        assert!(parse_mount_spec("/run/podman.sock:/x").is_err());
        // системные корни хоста
        assert!(parse_mount_spec("/:/home/poler/root").is_err());
        assert!(parse_mount_spec("/etc:/opt/poler/etc").is_err());
        assert!(parse_mount_spec("/proc:/opt/poler/proc").is_err());
        assert!(parse_mount_spec("/dev:/opt/poler/dev").is_err());
        assert!(parse_mount_spec("/var/run:/opt/poler/run").is_err(), "канонизация /var/run → /run, тоже запрет");
        // несуществующий хост-путь
        assert!(parse_mount_spec("/nonexistent-path-xyz:/opt/poler/x").is_err());
        // относительный хост-путь
        assert!(parse_mount_spec("agy:/opt/poler/agy").is_err());
        // цели вне белого списка / внутри /workspace / с ..
        assert!(parse_mount_spec(&format!("{}:/etc/evil", good.display())).is_err());
        assert!(parse_mount_spec(&format!("{}:/workspace/evil", good.display())).is_err());
        assert!(parse_mount_spec(&format!("{}:/home/poler/../..", good.display())).is_err());
        assert!(parse_mount_spec(&format!("{}:/var/x", good.display())).is_err());
        // rw под /usr/local/bin — нельзя (бинарники ro)
        assert!(parse_mount_spec(&format!("{}:/usr/local/bin/agy:rw", good.display())).is_err());
        // режим-мусор
        assert!(parse_mount_spec(&format!("{}:/opt/poler/x:xx", good.display())).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn parse_on_args_v026_keys() {
        let d = fake_agent_dir("args");
        let agy = d.join("agy");
        // agent-политика
        let c = parse_on_args(&["agent=none".into()]).unwrap();
        assert_eq!(c.agents, AgentPolicy::None);
        let c = parse_on_args(&["agent=agy,claude".into()]).unwrap();
        assert_eq!(c.agents, AgentPolicy::Only(vec!["agy".into(), "claude".into()]));
        assert!(parse_on_args(&["agent=zzz".into()]).is_err(), "неизвестный агент");
        assert!(parse_on_args(&["agent=".into()]).is_err(), "пустой список");
        // nocfg
        let c = parse_on_args(&["nocfg=1".into()]).unwrap();
        assert!(c.no_cfg);
        // mount= (повторяемый)
        let c = parse_on_args(&[
            format!("mount={}", agy.display()),
            format!("mount={}:/opt/poler/tool:rw", agy.display()),
        ])
        .unwrap();
        assert_eq!(c.mounts.len(), 2);
        assert_eq!(c.mounts[1].container, "/opt/poler/tool");
        // мусорный mount= падает на парсинге (до любого docker-вызова)
        assert!(parse_on_args(&["mount=/var/run/docker.sock:/x".into()]).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn docker_run_argv_includes_agent_mounts_and_label() {
        let d = fake_agent_dir("argv");
        let agy = d.join("agy");
        let cfg_dir = d.join(".gemini");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        let mut cfg = BoxConfig::default();
        cfg.mounts = vec![
            MountSpec {
                host: agy.clone(),
                container: "/usr/local/bin/agy".into(),
                ro: true,
            },
            MountSpec {
                host: cfg_dir.clone(),
                container: "/home/poler/.gemini".into(),
                ro: false,
            },
        ];
        cfg.agent_names = vec!["agy".into()];
        let v = docker_run_argv("poler-box-m", &cfg, Path::new("/ws"), Path::new("/home"));
        let joined = v.join("\u{1}");
        assert!(
            joined.contains(&format!("{}:/usr/local/bin/agy:ro", agy.display()))
                || v.contains(&format!("{}:/usr/local/bin/agy:ro", agy.display())),
            "нет ro-проброса agy: {v:?}"
        );
        assert!(
            v.contains(&format!("{}:/home/poler/.gemini", cfg_dir.display())),
            "нет rw-проброса ~/.gemini: {v:?}"
        );
        assert!(joined.contains("--label\u{1}poler.box.agents=agy"), "нет label агентов");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn runner_name_and_argv_hardening() {
        let ws = Path::new("/home/u/proj");
        let bn = container_name(ws);
        let rn = runner_name(ws);
        assert!(rn.starts_with("poler-runner-"), "префикс: {rn}");
        assert_eq!(rn.len(), "poler-runner-".len() + 8);
        // тот же хеш ws, разные префиксы — согласованность discovery MCP
        assert_eq!(bn.trim_start_matches("poler-box-"), rn.trim_start_matches("poler-runner-"));

        let cfg = RunnerConfig::default();
        assert_eq!(cfg.net, "none", "runner по умолчанию без сети");
        let v = runner_run_argv(&rn, &cfg, ws);
        let joined = v.join("\u{1}");
        for must in [
            "--cap-drop\u{1}ALL",
            "--security-opt\u{1}no-new-privileges",
            "--network\u{1}none",
            "--label\u{1}poler.runner=1",
            "--label\u{1}poler.runner.image=debian:bookworm-slim",
            "POLER_RUNNER=1",
            "HOME=/tmp",
        ] {
            assert!(joined.contains(must), "runner run без {must}: {v:?}");
        }
        // только /workspace: НЕТ /home/poler и НЕТ монтировок агентов
        assert!(!joined.contains("/home/poler"), "runner без home-монтировки: {v:?}");
        assert_eq!(&v[v.len() - 3..], &["debian:bookworm-slim".to_string(), "sleep".into(), "infinity".into()]);

        // конфиг: net=host запрещён, позиционный образ
        assert!(parse_runner_args(&["net=host".into()]).is_err());
        let c = parse_runner_args(&["node:22-slim".into(), "mem=2g".into(), "pids=512".into()]).unwrap();
        assert_eq!(c.image, "node:22-slim");
        assert_eq!(c.mem, "2g");
        assert_eq!(c.pids, 512);
        assert_eq!(c.net, "none");
        assert!(parse_runner_args(&["zzz=1".into()]).is_err());
    }

    #[test]
    fn wrap_runner_exec_shape() {
        let _g = docker_env_test_lock();
        let st = RunnerState {
            name: "poler-runner-cafe".into(),
            cfg: RunnerConfig::default(),
            ws_root: PathBuf::from("/tmp/polertest-ws"),
        };
        let w = wrap_runner_exec(&st, &["python3".into(), "build.py".into()], Path::new("/tmp/polertest-ws"));
        assert_eq!(&w[1..3], &["exec".to_string(), "-i".into()]);
        assert_eq!(w[0], "docker");
        assert!(!w.contains(&"-it".to_string()), "брокер — пайповый режим: {w:?}");
        assert!(w.contains(&"POLER_RUNNER=1".to_string()));
        assert!(w.contains(&"HOME=/tmp".to_string()));
        assert!(w.contains(&st.name), "имя runner: {w:?}");
        assert_eq!(&w[w.len() - 2..], &["python3".to_string(), "build.py".to_string()]);
        assert!(w.contains(&"-w".to_string()) && w.contains(&"/workspace".to_string()));
    }

    #[test]
    fn box_status_mentions_runner_and_agents() {
        let _g = docker_env_test_lock();
        // без docker — статус не падает, упоминает runner-секцию
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        let s = box_status_text(None, None, Path::new("/tmp/some-ws"));
        std::env::remove_var("POLER_BOX_DOCKER");
        assert!(s.contains("runner:"), "нет секции runner: {s}");
        assert!(s.contains("poler-runner-"), "нет имени runner: {s}");
        assert!(s.contains("box runner on"), "нет подсказки: {s}");
    }
}
