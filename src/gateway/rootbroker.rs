//! # Root Broker — «sudo как услуга» через шлюз (v0.27.0)
//!
//! Живой кейс эксплуатации: агент в Container Jail честно жалуется «нет рута»
//! (uid 1000: apt-get и системные установки в образе недоступны). Вывод
//! владельца: **«рут — это тоже привилегия хоста»** — настоящим хостовым
//! рутом агенту владеть нельзя В ПРИНЦИПЕ, но возможность рут-исполнения
//! ему нужна. Модель — та же, что у облачных AI-рантаймов Google
//! («в песочнице нет Python — Python вызывают снаружи»):
//!
//! * агент в клетке **НЕ ДЕРЖИТ** рут ни секунды: у него есть `sudo`-шим,
//!   который умеет только ЗАПРОСИТЬ исполнение (файл-канал брокера);
//! * шлюз (контур 2) читает запрос, **судья** (`sandbox.rs` + корневая
//!   политика ниже) выносит вердикт: деструктив — Deny всегда, ручной
//!   allowlist владельца — Allow, менеджеры пакетов — Allow по умолчанию;
//! * при Allow исполнение происходит **со стороны хоста**:
//!   `docker exec -u 0:0 <box> <argv…>` — root ВНУТРИ контейнера,
//!   контейнер по-прежнему cap-drop ALL / no-new-privileges;
//! * агенту возвращаются ТОЛЬКО stdout/stderr + exit-код.
//!
//! ## v0.28.0 «Root Broker Password Mode» — рут по паролю
//!
//! Живой кейс владельца: «в v0.26.0 всё идеально, единственный блок —
//! рут-права: агент вызывает любые утилиты, но хост не передаёт ему рут,
//! а иногда нужно — я ему дам пароль, и у него есть рут». Модель та же
//! (рут — привилегия хоста), но появляется **выданный владельцем пароль**:
//!
//! * `box sudo passwd` (только интерактив в шлюзе) — владелец задаёт
//!   пароль; хранится host-only солью+хешем (2048 раунда FNV, 0600,
//!   вне монтируемых каталогов — агент не может ни прочитать, ни дописать);
//! * агент в клетке зовёт `echo ПАРОЛЬ | sudo -S <cmd>` — шим v2 читает
//!   первую строку stdin и прикладывает её к запросу (base64-поле);
//! * брокер сверяет пароль: верный → НЕдеструктивные команды разрешены
//!   (пароль = самый широкий ключ, НО инварианты держат: Block судьи,
//!   инструменты побега, пути ядра — Deny ВСЕГДА, пароль не ослабляет);
//! * брут-форс: 5 промахов → лок 60с (каждый промах — в аудите, без
//!   материала пароля); пароль НЕ попадает в argv процессов docker.
//!
//! Канал — файловый (без сети, работает при net=none, детерминированно
//! тестируется): хост-каталог `<box_home>/.poler-broker` (= контейнерный
//! `/home/poler/.poler-broker`, уже смонтирован как /home/poler):
//! * `requests.jsonl` — v2: `<id>|<b64 cwd>|<b64 пароль>|<b64 argv0>|…`
//!   (протокол v0.27.0 без пароля — легаси, парсится как пустой);
//!   агент дописывает, шлюз читает по смещению;
//! * `responses/<id>.exit|.out|.err|.msg` — ответы шлюза (атомарная запись
//!   tmp+rename: симлинк-подмена агентом НЕ разыменовывается);
//! * `enabled` — маркер живости: брокер обновляет его каждые 5с, шим
//!   требует свежесть ≤2 мин (крах шлюза = маркер протух = шим честно
//!   отказывает, а не висит 120с).
//!
//! Политика владельца живёт ТОЛЬКО на хосте вне монтируемых каталогов
//! (`~/.local/share/poler-engine/policy/<box>.sudo` — агент-зец не может
//! дописать себя в allowlist). Аудит — тоже на хосте
//! (`~/.local/share/poler-engine/audit/root-<box>.jsonl`).
//!
//! Инварианты:
//! * **Block не ослабляется ничем** — allowlist не перекрывает вердикт судьи;
//! * **Zero Silent Escalation** — Confirm из клетки не подтверждается:
//!   рут-брокер отвечает отказом (подтверждение доступно только владельцу
//!   в шлюзе);
//! * лимит 30 запросов/час (анти-спам из клетки), таймаут 120с, кап вывода;
//! * инструменты контейнер-побега (docker/nsenter/unshare/mount/…) и пути
//!   ядра (/proc /sys /dev) в рут-запросах — Deny всегда.
//!
//! Нулей новых зависимостей: base64 — ручной кодек (стандартный алфавит).

use std::collections::VecDeque;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::containers::{BoxState, HOME_MOUNT};
use super::sandbox::{self, Policy};

/// Контейнерный каталог брокер-канала (= хост `<box_home>/.poler-broker`).
pub const BROKER_MOUNT: &str = "/home/poler/.poler-broker";
/// Контейнерный каталог шимов (= хост `<box_home>/.poler-bin`); попадает
/// первым в PATH контейнера (docker_run_argv v0.27.0).
pub const POLER_BIN_MOUNT: &str = "/home/poler/.poler-bin";
/// Хвостовое имя файла запросов.
const REQUESTS_FILE: &str = "requests.jsonl";
/// Хвостовое имя маркера живости брокера.
const MARKER_FILE: &str = "enabled";
/// Лимит рут-запросов в час (анти-спам: клетка не должна долбить судью).
const RATE_LIMIT_PER_HOUR: usize = 30;
/// Таймаут рут-исполнения (docker exec -u 0).
const ROOT_EXEC_TIMEOUT_SECS: u64 = 120;
/// Кап stdout/stderr рут-ответа агенту.
const ROOT_OUT_CAP: usize = 1_048_576;
const ROOT_ERR_CAP: usize = 131_072;
/// Период обновления маркера живости.
const MARKER_REFRESH: Duration = Duration::from_secs(5);
/// Тик чтения канала запросов.
const POLL_TICK: Duration = Duration::from_millis(150);
/// Максимум аргументов / длина строки запроса (защита от мусора).
const MAX_ARGS: usize = 64;
const MAX_LINE: usize = 8192;

/// Минимальная/максимальная длина рут-пароля (байты).
const PASSWORD_MIN: usize = 6;
const PASSWORD_MAX: usize = 64;
/// Промахов пароля до лок-аута (анти-брутфорс из клетки).
const LOCK_FAILS: u32 = 5;

/// Длина лок-аута в секундах. `POLER_SUDO_LOCK_SECS` — тест-оверрайд
/// (1..=3600, чтобы юнит-тесты не ждали минуту).
fn lock_secs() -> u64 {
    std::env::var("POLER_SUDO_LOCK_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| (1..=3600).contains(v))
        .unwrap_or(60)
}

// ---------------------------------------------------------------------------
// base64-кодек (стандартный алфавит; без новых зависимостей)
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Кодировать в base64 (с паддингом `=`).
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Декодировать base64 (символы вне алфавита/`=` — ошибка).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err("длина не кратна 4".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (ci, chunk) in bytes.chunks(4).enumerate() {
        let mut vals = [0u32; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if ci + 1 != bytes.len() / 4 {
                    return Err("= в середине".into());
                }
                pad += 1;
                vals[i] = 0;
            } else {
                let v = B64_ALPHABET
                    .iter()
                    .position(|&a| a == c)
                    .ok_or_else(|| format!("символ «{}» вне алфавита", c as char))?;
                vals[i] = v as u32;
            }
        }
        if pad > 2 || (pad > 0 && chunk[..4 - pad].contains(&b'=')) {
            return Err("некорректный паддинг".into());
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Протокол запроса
// ---------------------------------------------------------------------------

/// Разобранный рут-запрос из клетки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoRequest {
    /// Идентификатор (генерит шим: `r<pid>-<epoch>`; валидный charset).
    pub id: String,
    /// cwd ВНУТРИ контейнера (контейнерный абсолютный путь).
    pub cwd: String,
    /// v0.28.0: пароль из запроса (`sudo -S` — первая строка stdin).
    /// `None` = легаси-протокол v0.27.0; `Some("")` = `-S` без ввода.
    pub password: Option<String>,
    /// argv полезной нагрузки (без «sudo» — шим и есть sudo).
    pub argv: Vec<String>,
}

/// Валидный id: `[A-Za-z0-9._-]{1,64}` — без слэшей/«..» (id попадает в
/// имена файлов ответов: path traversal исключается на парсинге).
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id != ".."
        && id != "."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Собрать строку запроса (легаси-протокол v0.27.0 — без пароля).
pub fn encode_request(id: &str, cwd: &str, argv: &[String]) -> String {
    let mut parts: Vec<String> = vec![id.to_string(), b64_encode(cwd.as_bytes())];
    for a in argv {
        parts.push(b64_encode(a.as_bytes()));
    }
    parts.join("|")
}

/// Собрать строку запроса протокола v2 (с паролем): шим `sudo -S`
/// прикладывает первую строку stdin. Пароль — всегда поле №2 (после cwd).
pub fn encode_request_v2(id: &str, cwd: &str, password: &str, argv: &[String]) -> String {
    let mut parts: Vec<String> = vec![
        id.to_string(),
        b64_encode(cwd.as_bytes()),
        b64_encode(password.as_bytes()),
    ];
    for a in argv {
        parts.push(b64_encode(a.as_bytes()));
    }
    parts.join("|")
}

/// Разобрать строку запроса. Fail-closed: любая дрянь — ошибка.
/// v2 (≥4 полей): `id|cwd|пароль|argv…`; ровно 3 поля — легаси v0.27.0
/// (пароля нет, argv = одно поле; устаревший шим честно получит отказ).
pub fn parse_request_line(line: &str) -> Result<SudoRequest, String> {
    let line = line.trim_end_matches('\n').trim_end_matches('\r');
    if line.is_empty() {
        return Err("пустая строка".into());
    }
    if line.len() > MAX_LINE {
        return Err(format!("строка длиннее {MAX_LINE} байт"));
    }
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 3 {
        return Err("меньше трёх полей (id|cwd|argv0)".into());
    }
    let legacy = parts.len() == 3;
    if parts.len() > MAX_ARGS + 3 {
        return Err(format!("больше {MAX_ARGS} аргументов"));
    }
    let id = parts[0].to_string();
    if !valid_id(&id) {
        return Err(format!("id «{id}» вне [A-Za-z0-9._-] (≤64)"));
    }
    let cwd_bytes = b64_decode(parts[1]).map_err(|e| format!("cwd: {e}"))?;
    let cwd = String::from_utf8(cwd_bytes).map_err(|_| "cwd: не UTF-8".to_string())?;
    // v2: пароль — фиксированное поле №2; легаси (3 поля) — его нет
    let password = if legacy {
        None
    } else {
        let pb = b64_decode(parts[2]).map_err(|e| format!("password: {e}"))?;
        Some(String::from_utf8(pb).map_err(|_| "password: не UTF-8".to_string())?)
    };
    let argv_fields: &[&str] = if legacy { &parts[2..3] } else { &parts[3..] };
    let mut argv: Vec<String> = Vec::with_capacity(argv_fields.len());
    for p in argv_fields {
        let b = b64_decode(p).map_err(|e| format!("argv: {e}"))?;
        let s = String::from_utf8(b).map_err(|_| "argv: не UTF-8".to_string())?;
        argv.push(s);
    }
    Ok(SudoRequest {
        id,
        cwd,
        password,
        argv,
    })
}

// ---------------------------------------------------------------------------
// Судья рут-запросов (pure — юнит-тестируемый)
// ---------------------------------------------------------------------------

/// Вердикт рут-брокера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootVerdict {
    /// Исполнить от рута (docker exec -u 0) со стороны хоста.
    Allow,
    /// Отказ (причина уходит агенту в .msg и в аудит).
    Deny(String),
}

/// Инструменты контейнер-побега/управления демоном: через рут-брокер
/// они не проходят НИКОГДА (брокер не должен стать примитивом побега).
const ROOT_ESCAPE_TOOLS: &[&str] = &[
    "docker",
    "podman",
    "nerdctl",
    "ctr",
    "crun",
    "runc",
    "dockerd",
    "docker-compose",
    "podman-compose",
    "nsenter",
    "unshare",
    "setns",
    "switch_root",
    "mount",
    "umount",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "telinit",
    "init",
    "modprobe",
    "insmod",
    "rmmod",
    "sysctl",
    "iptables",
    "nft",
    "ip6tables",
    "ebtables",
    "ptrace",
    "gdb",
    "proot",
    "nsjail",
    "bwrap",
    "chroot",
];

/// Пути ядра/устройств/демона, запрещённые в аргументах рут-запроса.
const ROOT_ARG_DENY_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/run", "/var/run"];

/// Подкоманды менеджеров пакетов, разрешённые ПО УМОЛЧАНИЮ (жалоба агента
/// «нет рута» — почти всегда про apt-get install).
const PKG_TOOLS: &[&str] = &["apt-get", "apt", "dpkg", "dpkg-deb"];
const PKG_SAFE_SUBCMDS: &[&str] = &[
    "update",
    "install",
    "download",
    "show",
    "upgrade",
    "dist-upgrade",
    "clean",
    "autoremove",
    "remove",
    "purge",
    "list",
    "search",
    "-i",
    "-r",
    "-P",
    "-l",
    "-s",
    "-L",
    "--configure",
    "--unpack",
    "reconfigure",
];

/// Файловые операции, разрешённые в границах /workspace и /home/poler.
const FS_SCOPE_TOOLS: &[&str] = &[
    "mkdir", "mv", "cp", "touch", "chmod", "chown", "install", "tee", "ln",
];

/// Безобидные идентификационные команды.
const SAFE_TOOLS: &[&str] = &["id", "whoami", "true", "pwd", "uname"];

/// Проверить, что путь-подобный аргумент остаётся в разрешённой зоне.
fn path_in_scope(arg: &str) -> bool {
    if arg.starts_with('-') {
        return true; // флаг
    }
    let looks_path = arg.starts_with('/')
        || arg.starts_with("./")
        || arg.starts_with("../")
        || arg == "."
        || arg == "..";
    if !looks_path {
        return true; // не путь (имя пакета и т.п.)
    }
    let a = arg.trim_end_matches('/');
    a == "/workspace"
        || a == HOME_MOUNT
        || a.starts_with("/workspace/")
        || a.starts_with("/home/poler/")
}

/// Простой glob ( `*` — любая последовательность, `?` — один символ ).
pub fn glob_match(pat: &str, s: &str) -> bool {
    // итеративный two-pointer с бэктрекингом по «*»
    let (p, t) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Вердикт по рут-запросу. Порядок — инварианты вперёд:
/// 1) судья `sandbox.rs` по argv (Block → Deny ВСЕГДА; Confirm → Deny:
///    клетка не подтверждает — Zero Silent Escalation);
/// 2) инструменты побега/демона → Deny;
/// 3) пути ядра/устройств в аргументах → Deny;
/// 4) **v0.28.0: верный пароль** (выдан владельцем через `box sudo passwd`)
///    → Allow НЕдеструктивного остатка — пароль не ослабляет пункты 1–3;
/// 5) allowlist владельца (glob по «argv0 argv1 …»);
/// 6) дефолтный allow: пакетные менеджеры + fs-опы в границах + id/whoami;
/// 7) остальное — Deny с подсказкой.
pub fn judge_root_request(
    req: &SudoRequest,
    allow_globs: &[String],
    password_ok: bool,
) -> RootVerdict {
    if req.argv.is_empty() {
        return RootVerdict::Deny(
            "пустая полезная нагрузка (легаси-шим v0.27? box sudo on перепечатает)".into(),
        );
    }
    // 1) первый эшелон — общий судья
    match sandbox::judge_segment(&req.argv) {
        Policy::Block(why) => {
            return RootVerdict::Deny(format!("судья: BLOCK — {why}"));
        }
        Policy::Confirm(why) => {
            return RootVerdict::Deny(format!(
                "судья: требует подтверждения ({why}) — рут-брокер молча не подтверждает; владелец: box allow sudo «<glob>» или box sudo passwd"
            ));
        }
        Policy::Allow => {}
    }
    // 2) инструменты побега
    let base = req.argv[0].rsplit('/').next().unwrap_or(&req.argv[0]);
    if ROOT_ESCAPE_TOOLS.contains(&base) {
        return RootVerdict::Deny(format!(
            "«{base}» — инструмент побега/управления контейнер-демоном: рут-брокер такие не исполняет (пароль не ослабляет)"
        ));
    }
    // 3a) v0.28.0 (находка builtin-охоты): контроль-символы в argv —
    // инъекция перевода строки. docker exec не даёт шелла (аргумент
    // литерален), но рут-исполнение аргумента с \n/\r/\0 — всегда
    // подозрительно и не имеет легитимных сценариев: Deny.
    for a in &req.argv {
        if a.contains('\n') || a.contains('\r') || a.contains('\0') {
            return RootVerdict::Deny(
                "контроль-символ (перевод строки) в аргументе — инъекция: рут-брокер такие не исполняет".into(),
            );
        }
    }
    // 3) пути ядра/демона в аргументах
    for a in &req.argv[1..] {
        if a.contains("docker.sock") || a.contains("podman.sock") {
            return RootVerdict::Deny("аргумент ссылается на docker-сокет".into());
        }
        if ROOT_ARG_DENY_PREFIXES.iter().any(|pfx| a.starts_with(pfx)) {
            return RootVerdict::Deny(format!(
                "путь «{a}» — ядро/устройства/раннтайм: вне рут-политики (пароль не ослабляет)"
            ));
        }
    }
    // 4) v0.28.0: пароль владельца — ключ к НЕдеструктивному остатку
    if password_ok {
        return RootVerdict::Allow;
    }
    // 5) allowlist владельца (хост-only файл; Block выше уже отработал)
    let joined = req.argv.join(" ");
    for g in allow_globs {
        if glob_match(g, &joined) {
            return RootVerdict::Allow;
        }
    }
    // 6) дефолтный allow
    if PKG_TOOLS.contains(&base) {
        let sub = req.argv.get(1).map(|s| s.as_str()).unwrap_or("");
        if PKG_SAFE_SUBCMDS.contains(&sub) {
            return RootVerdict::Allow;
        }
        return RootVerdict::Deny(format!(
            "«{base} {sub}» — подкоманда вне дефолтного набора (update/install/…); box allow sudo — расширить, box sudo passwd — выдать пароль"
        ));
    }
    if FS_SCOPE_TOOLS.contains(&base) && req.argv[1..].iter().all(|a| path_in_scope(a)) {
        return RootVerdict::Allow;
    }
    if SAFE_TOOLS.contains(&base) {
        return RootVerdict::Allow;
    }
    // 7) отказ по умолчанию
    RootVerdict::Deny(format!(
        "«{joined}» не в рут-политике (владелец: box sudo passwd — выдать пароль агенту, или box allow sudo «<glob>» — точечно)"
    ))
}

// ---------------------------------------------------------------------------
// Политика владельца (host-only, вне монтируемых каталогов!)
// ---------------------------------------------------------------------------

/// База политик: `POLER_POLICY_HOME` (тесты) | `~/.local/share/poler-engine/policy`.
/// ВАЖНО: НЕ внутри box_home_base() — home бокса смонтирован в клетку rw,
/// агент не должен уметь дописывать себя в allowlist.
pub fn policy_base() -> PathBuf {
    if let Ok(d) = std::env::var("POLER_POLICY_HOME") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/poler-engine/policy")
}

/// Файл allowlist-глобов конкретного бокса.
pub fn policy_path(box_name: &str) -> PathBuf {
    policy_base().join(format!("{box_name}.sudo"))
}

/// Прочитать глобы (файла нет → пусто; строки-комменты `#` игнорируются).
pub fn load_allow_globs(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Добавить глоб (валидация: непустой, без перевода строки, ≤128).
pub fn add_allow_glob(path: &Path, glob: &str) -> Result<String, String> {
    let g = glob.trim();
    if g.is_empty() {
        return Err("box allow sudo: пустой glob".into());
    }
    if g.contains('\n') || g.contains('\r') {
        return Err("box allow sudo: glob без переводов строк".into());
    }
    if g.len() > 128 {
        return Err("box allow sudo: glob длиннее 128 символов".into());
    }
    if g.contains(|c: char| c.is_control()) {
        return Err("box allow sudo: control-символы запрещены".into());
    }
    let mut list = load_allow_globs(path);
    if list.iter().any(|x| x == g) {
        return Ok(format!("box allow sudo: «{g}» уже в списке\n"));
    }
    list.push(g.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("policy {}: {e}", parent.display()))?;
    }
    let body = format!(
        "# POLER root-broker allowlist (владелец; host-only)\n{}\n",
        list.join("\n")
    );
    std::fs::write(path, body).map_err(|e| format!("policy {}: {e}", path.display()))?;
    Ok(format!(
        "box allow sudo: «{g}» добавлен (список: {})\n⛔ инвариант: Block-вердикты судьи allowlist НЕ ослабляет\n",
        list.len()
    ))
}

/// Очистить allowlist.
pub fn reset_allow_globs(path: &Path) -> Result<String, String> {
    let _ = std::fs::remove_file(path);
    Ok("box allow sudo: allowlist очищен\n".into())
}

// ---------------------------------------------------------------------------
// v0.28.0: рут-пароль (host-only: соль + хеш, 0600)
// ---------------------------------------------------------------------------

/// Выданный владельцем секрет брокера. Хранится ТОЛЬКО хешем — файл
/// вне монтируемых каталогов, 0600; брут-форс из клетки ловится счётчиком
/// промахов (5 → лок) и аудитом. Хеширование — не bcrypt, а растянутый
/// FNV-1a (2048 раунда × длина): угроз-модель локальная (файл непрочитаем
/// из клетки — агент не видит даже хеш), задача — не хранить пароль
/// открытым текстом на хосте.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSecret {
    pub salt: [u8; 16],
    pub hash: u64,
}

impl PasswordSecret {
    /// Сверить пароль с секретом.
    pub fn verify(&self, pwd: &str) -> bool {
        hash_password(&self.salt, pwd) == self.hash
    }
}

/// Растянутый FNV-1a (2048 раунда × байты пароля + соль на каждом раунде).
fn hash_password(salt: &[u8; 16], pwd: &str) -> u64 {
    let salt_lo = u64::from_le_bytes(salt[0..8].try_into().expect("8 байт"));
    let salt_hi = u64::from_le_bytes(salt[8..16].try_into().expect("8 байт"));
    let mut h: u64 = 0xcbf29ce484222325 ^ salt_lo ^ salt_hi.rotate_left(17);
    for _ in 0..2048 {
        for b in pwd.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for s in salt {
            h ^= *s as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

/// Файл пароля конкретного бокса (`<box>.passwd` в policy-базе).
pub fn password_path(box_name: &str) -> PathBuf {
    policy_base().join(format!("{box_name}.passwd"))
}

/// Задан ли пароль (режим пароля включён).
pub fn password_exists(box_name: &str) -> bool {
    load_password(&password_path(box_name)).is_some()
}

/// Загрузить секрет (файл: `salt-hex32 hash-hex16`; дрянь → None).
pub fn load_password(path: &Path) -> Option<PasswordSecret> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().next()?;
    let mut it = line.split_whitespace();
    let salt_hex = it.next()?;
    let hash_hex = it.next()?;
    if salt_hex.len() != 32 || hash_hex.len() != 16 {
        return None;
    }
    let mut salt = [0u8; 16];
    for (i, chunk) in salt_hex.as_bytes().chunks(2).enumerate() {
        salt[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    let hash = u64::from_str_radix(hash_hex, 16).ok()?;
    Some(PasswordSecret { salt, hash })
}

/// Валидация пароля (перед парой): 6..=64 байт, без control-символов.
pub fn validate_password(pwd: &str) -> Result<(), String> {
    let n = pwd.len();
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&n) {
        return Err(format!(
            "пароль {n} байт — нужно {PASSWORD_MIN}..{PASSWORD_MAX}"
        ));
    }
    if pwd.chars().any(|c| c.is_control()) {
        return Err("пароль не может содержать control-символы".into());
    }
    if pwd.starts_with(' ') || pwd.ends_with(' ') {
        return Err("пароль не должен начинаться/кончаться пробелом".into());
    }
    Ok(())
}

/// Соль из /dev/urandom (фолбэк — fnv от времени+pid, как канарейка).
fn random_salt() -> [u8; 16] {
    use std::io::Read as _;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut buf = [0u8; 16];
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5a17);
    let mut h: u64 = 0xcbf29ce484222325 ^ t ^ (std::process::id() as u64);
    for _ in 0..16 {
        h = h.wrapping_mul(0x100000001b3);
    }
    let lo = h.to_le_bytes();
    let hi = h.wrapping_mul(0x9e3779b97f4a7c15).to_le_bytes();
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&lo);
    salt[8..].copy_from_slice(&hi);
    salt
}

/// Задать пароль по паре вводов (двойное подтверждение + валидация +
/// запись 0600). Pure-функция без чтения stdin — TTY-слой в dispatch.
pub fn set_password_from_pair(path: &Path, p1: &str, p2: &str) -> Result<String, String> {
    let p1 = p1.trim_end_matches('\n').trim_end_matches('\r');
    let p2 = p2.trim_end_matches('\n').trim_end_matches('\r');
    if p1 != p2 {
        return Err("пароли не совпали (повторите box sudo passwd)".into());
    }
    validate_password(p1)?;
    let salt = random_salt();
    let hash = hash_password(&salt, p1);
    let body = format!(
        "{} {hash:016x}\n",
        salt.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("policy {}: {e}", parent.display()))?;
    }
    std::fs::write(path, body).map_err(|e| format!("passwd {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(format!(
        "🔐 рут-пароль задан ({}) — режим пароля ВКЛ\nагент в клетке: echo ПАРОЛЬ | sudo -S <команда>\n⛔ инварианты держат: деструктив/инструменты побега/пути ядра — Deny всегда\n🛡 брут-форс: 5 промахов → лок {}с; попытки — в аудите\n",
        path.display(),
        lock_secs()
    ))
}

/// Снять пароль (возврат в строгий режим allowlist/дефолт).
pub fn clear_password(path: &Path) -> Result<String, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(
            "🔐 рут-пароль снят — режим пароля ВЫКЛ (строгая политика: apt/fs-дефолт + allowlist)\n"
                .into(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok("руут-пароль не был задан\n".into())
        }
        Err(e) => Err(format!("passwd {}: {e}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// v0.28.0: авто-блоклист builtin-охоты («нашёл → закрыл» в рантайме)
// ---------------------------------------------------------------------------

/// Файл авто-блоклиста бокса (host-only). Строки: `<вектор>\t<argv-префикс>`
/// — добавляет Jailbreak Hunter для векторов, найденных живьём; брокер
/// отклоняет запросы, чей «argv0 argv1 …» начинается с префикса.
pub fn blocklist_path(box_name: &str) -> PathBuf {
    policy_base().join(format!("{box_name}.blocklist"))
}

/// Загрузить блоклист (дрянь пропускается молча — fail-open по формату,
/// но сам отказ — fail-closed: несовпадение = обычная политика).
pub fn load_blocklist(path: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let (id, pfx) = l.split_once('\t')?;
            let pfx = pfx.trim();
            if id.trim().is_empty() || pfx.len() < 3 {
                return None; // защита от случайных пустых/обрезанных префиксов
            }
            Some((id.trim().to_string(), pfx.to_string()))
        })
        .collect()
}

/// Добавить вектор в блоклист (вызывает hunter при Anomaly/Breach).
pub fn append_blocklist(box_name: &str, vector_id: &str, argv_prefix: &str) -> Result<(), String> {
    let pfx = argv_prefix.trim();
    if pfx.len() < 3 {
        return Ok(()); // слишком общий префикс — не блокируем легитимное
    }
    let path = blocklist_path(box_name);
    let existing = load_blocklist(&path);
    if existing.iter().any(|(id, _)| id == vector_id) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("policy {}: {e}", parent.display()))?;
    }
    let mut body = String::new();
    for (id, p) in &existing {
        body.push_str(&format!("{id}\t{p}\n"));
    }
    body.push_str(&format!("{vector_id}\t{pfx}\n"));
    std::fs::write(&path, body).map_err(|e| format!("blocklist {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Аудит (host-only JSONL)
// ---------------------------------------------------------------------------

/// База аудита: `POLER_AUDIT_HOME` (тесты) | `~/.local/share/poler-engine/audit`.
pub fn audit_base() -> PathBuf {
    if let Ok(d) = std::env::var("POLER_AUDIT_HOME") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/poler-engine/audit")
}

/// Файл аудита рут-запросов бокса.
pub fn audit_path(box_name: &str) -> PathBuf {
    audit_base().join(format!("root-{box_name}.jsonl"))
}

/// Дописать JSON-запись в аудит (создаёт каталог; ошибки не роняют брокер).
fn audit_append(box_name: &str, value: serde_json::Value) {
    let path = audit_path(box_name);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut line = value.to_string();
    line.push('\n');
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

/// Хвост аудита для `box sudo log [N]`.
pub fn tail_audit(box_name: &str, n: usize) -> String {
    let path = audit_path(box_name);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return format!("руут-аудит пуст ({}) — запросов не было\n", path.display());
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return format!("руут-аудит пуст ({})\n", path.display());
    }
    let take = n.clamp(1, 200);
    let start = lines.len().saturating_sub(take);
    let mut s = format!(
        "руут-аудит {box_name} — последние {} из {} записей:\n",
        lines.len() - start,
        lines.len()
    );
    for l in &lines[start..] {
        // компактный вид: {ts, argv, verdict, reason}
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
            let argv = v
                .get("argv")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            s.push_str(&format!(
                "  · {} · [{}] {}{}{}\n",
                v.get("ts").and_then(|t| t.as_i64()).unwrap_or(0),
                v.get("verdict").and_then(|t| t.as_str()).unwrap_or("?"),
                argv,
                v.get("reason")
                    .and_then(|t| t.as_str())
                    .filter(|r| !r.is_empty())
                    .map(|r| format!(" · {r}"))
                    .unwrap_or_default(),
                v.get("exit")
                    .and_then(|t| t.as_i64())
                    .filter(|e| *e != 0)
                    .map(|e| format!(" · exit {e}"))
                    .unwrap_or_default(),
            ));
        } else {
            s.push_str(&format!("  · {l}\n"));
        }
    }
    s
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Шим sudo внутри клетки (deploy: box on / box sudo on)
// ---------------------------------------------------------------------------

/// Текст `sudo`-шима v2 (POSIX sh; coreutils: date/base64/tr/find).
/// Рут остаётся у хоста: шим только оформляет ЗАПРОС и ждёт ответа брокера.
/// v0.28.0: флаг `-S` — пароль читается с ПЕРВОЙ строки stdin (как у
/// настоящего sudo: `echo ПАРОЛЬ | sudo -S cmd`) и уходит в запросе
/// base64-полем; пароль не попадает в argv процессов и не виден в ps.
pub const SUDO_SHIM: &str = r#"#!/bin/sh
# POLER Engine v0.28.0 — root broker shim v2 (sudo как услуга через шлюз).
# Рут — привилегия ХОСТА: агент может только ЗАПРОСИТЬ исполнение; судья
# шлюза решает, исполнение идёт docker exec -u 0 СО СТОРОНЫ ХОСТА.
# Агенту возвращаются только stdout/stderr/exit-код. Аудит — на хосте.
# v2: пароль-режим — sudo -S читает пароль с stdin и прикладывает к запросу.
B=/home/poler/.poler-broker
if [ "$#" -eq 0 ]; then
  echo "poler-sudo: usage: sudo [-S] <команда…> — запрос уйдёт брокеру шлюза (судья решает; -S — пароль с stdin)" >&2
  exit 2
fi
if [ ! -f "$B/enabled" ] || [ -z "$(find "$B/enabled" -mmin -2 2>/dev/null)" ]; then
  echo "poler-sudo: рут-брокер не активен (шлюз не слушает) — владелец: box sudo on в шлюзе" >&2
  exit 4
fi
# v2: пароль — если есть точный токен -S, читаем первую строку stdin
PW=""
SFLAG=0
NARGS=0
for a in "$@"; do
  if [ "$a" = "-S" ]; then SFLAG=1; else NARGS=$((NARGS+1)); fi
done
if [ "$NARGS" -eq 0 ]; then
  echo "poler-sudo: после -S нужна команда (sudo -S id)" >&2
  exit 2
fi
if [ "$SFLAG" = "1" ]; then
  printf '[sudo] пароль для poler (stdin): ' >&2
  read -r PW || PW=""
fi
ID="r$$-$(date +%s)"
REQ="$ID|$(pwd | base64 | tr -d '\n')|$(printf %s "$PW" | base64 | tr -d '\n')"
for a in "$@"; do
  [ "$a" = "-S" ] && continue
  REQ="$REQ|$(printf %s "$a" | base64 | tr -d '\n')"
done
printf '%s\n' "$REQ" >> "$B/requests.jsonl" 2>/dev/null || {
  echo "poler-sudo: брокер-канал недоступен" >&2
  exit 3
}
i=0
while [ "$i" -lt 120 ]; do
  if [ -f "$B/responses/$ID.exit" ]; then
    [ -f "$B/responses/$ID.msg" ] && cat "$B/responses/$ID.msg" >&2
    [ -f "$B/responses/$ID.out" ] && cat "$B/responses/$ID.out"
    [ -f "$B/responses/$ID.err" ] && cat "$B/responses/$ID.err" >&2
    ex="$(cat "$B/responses/$ID.exit" 2>/dev/null)"
    rm -f "$B/responses/$ID.exit" "$B/responses/$ID.out" \
          "$B/responses/$ID.err" "$B/responses/$ID.msg" 2>/dev/null
    exit "${ex:-125}"
  fi
  i=$((i+1))
  sleep 1
done
echo "poler-sudo: таймаут ожидания решения шлюза (120с)" >&2
exit 124
"#;

/// Хост-каталог брокер-канала бокса.
pub fn broker_dir(box_home: &Path) -> PathBuf {
    box_home.join(".poler-broker")
}

/// Развернуть шимы в home бокса (идемпотентно: перезапись лечит подмену —
/// подмена шима привилегии не даёт: решение и исполнение на хосте).
pub fn deploy_shims(box_home: &Path) -> Result<(), String> {
    let bin = box_home.join(".poler-bin");
    let broker = broker_dir(box_home);
    std::fs::create_dir_all(&bin).map_err(|e| format!("shim {}: {e}", bin.display()))?;
    std::fs::create_dir_all(broker.join("responses"))
        .map_err(|e| format!("broker {}: {e}", broker.display()))?;
    for name in ["sudo", "poler-sudo"] {
        let p = bin.join(name);
        std::fs::write(&p, SUDO_SHIM).map_err(|e| format!("shim {}: {e}", p.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ответы (атомарно: tmp + rename — симлинк-подмена не разыменовывается)
// ---------------------------------------------------------------------------

/// Безопасная запись файла ответа: tmp (create_new) → rename поверх цели.
/// rename заменяет сам inode записи каталога — симлинк агента будет
/// перезаписан КАК ЗАПИСЬ, а не через переход.
fn write_response_file(resp_dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let final_p = resp_dir.join(name);
    let tmp_p = resp_dir.join(format!(".tmp.{}.{}", name, std::process::id()));
    let _ = std::fs::remove_file(&tmp_p);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_p)
        .map_err(|e| format!("tmp {}: {e}", tmp_p.display()))?;
    f.write_all(bytes).map_err(|e| format!("tmp write: {e}"))?;
    drop(f);
    std::fs::rename(&tmp_p, &final_p)
        .map_err(|e| format!("rename → {}: {e}", final_p.display()))?;
    Ok(())
}

/// Выслать агенту ответ по запросу.
fn write_response(resp_dir: &Path, req_id: &str, exit: i32, out: &str, err: &str, msg: &str) {
    let _ = write_response_file(
        resp_dir,
        &format!("{req_id}.exit"),
        format!("{exit}\n").as_bytes(),
    );
    let _ = write_response_file(resp_dir, &format!("{req_id}.out"), out.as_bytes());
    let _ = write_response_file(resp_dir, &format!("{req_id}.err"), err.as_bytes());
    if !msg.is_empty() {
        let _ = write_response_file(
            resp_dir,
            &format!("{req_id}.msg"),
            format!("{msg}\n").as_bytes(),
        );
    }
}

/// Кап строки с маркером обреза.
fn cap_str(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let mut cut = s
            .char_indices()
            .take_while(|(i, _)| *i <= cap)
            .last()
            .map(|(i, _)| i)
            .unwrap_or(cap);
        cut = cut.min(cap);
        format!("{}\n…(обрезано на капе {} байт)\n", &s[..cut], cap)
    }
}

// ---------------------------------------------------------------------------
// Исполнение от рута (host-сторона, docker exec -u 0:0)
// ---------------------------------------------------------------------------

fn docker_bin() -> String {
    std::env::var("POLER_BOX_DOCKER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "docker".into())
}

/// Безопасный cwd запроса: контейнерный абсолютный путь без «..».
fn safe_cwd(cwd: &str) -> String {
    if cwd.starts_with('/') && !cwd.contains("..") && cwd.len() <= 256 {
        cwd.to_string()
    } else {
        "/workspace".to_string()
    }
}

/// argv `docker exec -u 0:0 -w CWD BOX argv…` (pure — тестируем форму).
pub fn root_exec_argv(jail_name: &str, req: &SudoRequest) -> Vec<String> {
    let mut v: Vec<String> = vec![
        docker_bin(),
        "exec".into(),
        "-u".into(),
        "0:0".into(),
        "-w".into(),
        safe_cwd(&req.cwd),
        jail_name.into(),
    ];
    v.extend(req.argv.iter().cloned());
    v
}

/// Исполнить с таймаутом и раздельными пайпами. Возвращает
/// (exit, stdout, stderr, timed_out, spawn_err).
#[allow(clippy::type_complexity)]
fn exec_root(argv: &[String]) -> (i32, String, String, bool, Option<String>) {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child: Child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return (
                125,
                String::new(),
                String::new(),
                false,
                Some(format!("{e}")),
            )
        }
    };
    let t_out = child.stdout.take().map(super::containers::drain_pipe);
    let t_err = child.stderr.take().map(super::containers::drain_pipe);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if started.elapsed() >= Duration::from_secs(ROOT_EXEC_TIMEOUT_SECS) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    let out = t_out
        .and_then(|t| t.join().ok())
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_default();
    let err = t_err
        .and_then(|t| t.join().ok())
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_default();
    match status {
        Some(st) => (st.code().unwrap_or(-1), out, err, false, None),
        None => (124, out, err, true, None),
    }
}

// ---------------------------------------------------------------------------
// Брокер (поток шлюза)
// ---------------------------------------------------------------------------

/// Счётчики/статус брокера (виден владельцу через `box sudo status`).
#[derive(Debug, Clone)]
pub struct BrokerStatus {
    pub box_name: String,
    pub processed: u64,
    pub allowed: u64,
    pub denied: u64,
    pub rate_limited: u64,
    pub malformed: u64,
    pub duplicates: u64,
    /// v0.28.0: пароль верен (запросов разблокировано паролем).
    pub password_ok: u64,
    /// v0.28.0: промахи пароля (с момента подъёма брокера).
    pub password_fail: u64,
    /// v0.28.0: пароль задан (режим пароля включён).
    pub password_mode: bool,
    /// v0.28.0: лок-аут брут-форса активен.
    pub locked: bool,
    /// v0.28.0: запросов отклонено авто-блоклистом охоты.
    pub autoblocked: u64,
    pub last_reason: Option<String>,
}

/// Ручка брокера: остановка + чтение статуса.
pub struct BrokerHandle {
    stop_flag: Arc<AtomicBool>,
    status: Arc<Mutex<BrokerStatus>>,
    broker_dir: PathBuf,
    /// поток не джойнимся: он может сидеть в docker exec до 120с;
    /// маркер живости снимаем сразу, поток завершится сам.
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl BrokerHandle {
    /// Остановить брокер (снять маркер немедленно; поток доберётся сам).
    pub fn stop(&mut self) -> String {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_file(self.broker_dir.join(MARKER_FILE));
        let st = self.status();
        format!(
            "🔐 рут-брокер ОСТАНОВЛЕН: обработано {} · allow {} · deny {} · rate {} · мусор {}\n",
            st.processed, st.allowed, st.denied, st.rate_limited, st.malformed
        )
    }

    /// Снимок статуса.
    pub fn status(&self) -> BrokerStatus {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Текст `box sudo status`.
    pub fn status_text(&self) -> String {
        let st = self.status();
        let globs = load_allow_globs(&policy_path(&st.box_name));
        let mut s = format!(
            "🔐 рут-брокер ВКЛ — контейнер {}\nобработано {} · allow {} · deny {} · rate-limited {}\nлимит {} запросов/час · таймаут {}с · кап вывода {}КБ\n",
            st.box_name,
            st.processed,
            st.allowed,
            st.denied,
            st.rate_limited,
            RATE_LIMIT_PER_HOUR,
            ROOT_EXEC_TIMEOUT_SECS,
            ROOT_OUT_CAP / 1024
        );
        // v0.28.0: режим пароля
        if st.password_mode {
            s.push_str(&format!(
                "режим пароля: ВКЛ (владелец выдал) — пароль верен {} · промахов {}{}\nагент: echo ПАРОЛЬ | sudo -S <команда> (sudo -S — пароль с stdin)\n",
                st.password_ok,
                st.password_fail,
                if st.locked {
                    " · 🚨 ЛОК АУТ активен"
                } else {
                    ""
                }
            ));
        } else {
            s.push_str(
                "режим пароля: ВЫКЛ (box sudo passwd — выдать агенту; строгая политика ниже)\n",
            );
        }
        if st.autoblocked > 0 {
            s.push_str(&format!(
                "авто-блоклист охоты: {} запрос(ов) отклонено\n",
                st.autoblocked
            ));
        }
        if globs.is_empty() {
            s.push_str("allowlist: пуст (дефолт: apt/apt-get/dpkg + fs в границах /workspace|/home/poler; остальное — отказ)\n");
        } else {
            s.push_str(&format!(
                "allowlist ({}): {}\n",
                globs.len(),
                globs.join(", ")
            ));
        }
        if let Some(r) = st.last_reason {
            s.push_str(&format!("последний вердикт: {r}\n"));
        }
        s.push_str("модель: агент ПРОСИТ — судья решает — рут исполняется СО СТОРОНЫ ХОСТА (docker exec -u 0); агент рут не держит\n");
        s
    }
}

/// Поднять брокер для активного бокса: каналы + шимы + поток-читатель.
/// Маркер живости обновляется каждые 5с (протухает через 2 мин после краха).
pub fn spawn_broker(jail: &BoxState) -> Result<BrokerHandle, String> {
    let broker = broker_dir(&jail.home_dir);
    std::fs::create_dir_all(broker.join("responses"))
        .map_err(|e| format!("брокер-канал {}: {e}", broker.display()))?;
    // шимы: развернуть/вылечить (подмена шима привилегии не даёт)
    deploy_shims(&jail.home_dir)?;
    // маркер живости (дороже протухания: write = mtime)
    std::fs::write(
        broker.join(MARKER_FILE),
        format!("alive {}", now_epoch_ms()),
    )
    .map_err(|e| format!("маркер {}: {e}", broker.display()))?;
    // стартуем с текущего конца файла: старые неотвеченные запросы
    // (от прошлой сессии шлюза) честно игнорируются
    let start_offset = std::fs::metadata(broker.join(REQUESTS_FILE))
        .map(|m| m.len())
        .unwrap_or(0);
    if !broker.join(REQUESTS_FILE).exists() {
        std::fs::write(broker.join(REQUESTS_FILE), "").map_err(|e| format!("канал: {e}"))?;
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let status = Arc::new(Mutex::new(BrokerStatus {
        box_name: jail.name.clone(),
        processed: 0,
        allowed: 0,
        denied: 0,
        rate_limited: 0,
        malformed: 0,
        duplicates: 0,
        password_ok: 0,
        password_fail: 0,
        password_mode: password_exists(&jail.name),
        locked: false,
        autoblocked: 0,
        last_reason: None,
    }));
    let (stop2, status2) = (stop_flag.clone(), status.clone());
    let box_name = jail.name.clone();
    let broker2 = broker.clone();
    let thread = std::thread::Builder::new()
        .name("poler-root-broker".into())
        .spawn(move || broker_loop(box_name, broker2, start_offset, stop2, status2))
        .map_err(|e| format!("поток брокера: {e}"))?;

    Ok(BrokerHandle {
        stop_flag,
        status,
        broker_dir: broker,
        _thread: Some(thread),
    })
}

/// Цикл брокера: поллинг requests.jsonl по смещению, судья, исполнение,
/// ответы, аудит, маркер живости.
fn broker_loop(
    box_name: String,
    broker: PathBuf,
    mut offset: u64,
    stop: Arc<AtomicBool>,
    status: Arc<Mutex<BrokerStatus>>,
) {
    let req_path = broker.join(REQUESTS_FILE);
    let resp_dir = broker.join("responses");
    let mut rate: VecDeque<Instant> = VecDeque::new();
    let mut seen: VecDeque<String> = VecDeque::with_capacity(512);
    let mut pending: Vec<u8> = Vec::new();
    let mut last_marker = Instant::now();
    // v0.28.0: состояние брут-форс-защиты пароля (лок — 60с после 5 промахов)
    let mut pw_fails: u32 = 0;
    let mut locked_until: Option<Instant> = None;
    loop {
        if stop.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(broker.join(MARKER_FILE));
            break;
        }
        // маркер живости
        if last_marker.elapsed() >= MARKER_REFRESH {
            let _ = std::fs::write(
                broker.join(MARKER_FILE),
                format!("alive {}", now_epoch_ms()),
            );
            last_marker = Instant::now();
        }
        // дочитать новые байты; нет новых — тик (частичная строка не гоняет цикл вхолостую)
        let meta_len = std::fs::metadata(&req_path).map(|m| m.len()).unwrap_or(0);
        if meta_len < offset {
            // файл усечён/ротирован агентом — перечитываем с нуля
            offset = 0;
            pending.clear();
        }
        if meta_len <= offset {
            std::thread::sleep(POLL_TICK);
            continue;
        }
        if meta_len > offset {
            if let Ok(mut f) = std::fs::File::open(&req_path) {
                use std::io::Seek as _;
                if f.seek(std::io::SeekFrom::Start(offset)).is_ok() {
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_ok() {
                        offset += buf.len() as u64;
                        pending.extend_from_slice(&buf);
                    }
                }
            }
        }
        // разобрать полные строки
        while let Some(nl) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line[..nl]).to_string();
            if line.trim().is_empty() {
                continue;
            }
            // id известен? (для отказа мусору тоже нужен адресат)
            let maybe_id = line.split('|').next().unwrap_or("").to_string();
            let id_ok = valid_id(&maybe_id);
            // дедуп: повтор запроса с тем же id — только аудит
            if id_ok && seen.contains(&maybe_id) {
                audit_append(
                    &box_name,
                    serde_json::json!({
                        "ts": now_epoch_ms(), "id": maybe_id, "verdict": "duplicate",
                        "argv": [], "reason": "повтор id (replay)",
                    }),
                );
                if let Ok(mut st) = status.lock() {
                    st.duplicates += 1;
                }
                continue;
            }
            if id_ok {
                seen.push_back(maybe_id.clone());
                if seen.len() > 512 {
                    seen.pop_front();
                }
            }
            // rate limit
            while let Some(front) = rate.front() {
                if front.elapsed() > Duration::from_secs(3600) {
                    rate.pop_front();
                } else {
                    break;
                }
            }
            if rate.len() >= RATE_LIMIT_PER_HOUR {
                if id_ok {
                    write_response(
                        &resp_dir,
                        &maybe_id,
                        1,
                        "",
                        "",
                        "poler-sudo: лимит рут-запросов (30/час) — подождите час",
                    );
                }
                audit_append(
                    &box_name,
                    serde_json::json!({
                        "ts": now_epoch_ms(), "id": maybe_id, "verdict": "rate",
                        "argv": [], "reason": "лимит 30/час",
                    }),
                );
                if let Ok(mut st) = status.lock() {
                    st.rate_limited += 1;
                }
                continue;
            }
            rate.push_back(Instant::now());
            // разбор + судья
            let req = match parse_request_line(&line) {
                Ok(r) => r,
                Err(why) => {
                    if id_ok {
                        write_response(
                            &resp_dir,
                            &maybe_id,
                            1,
                            "",
                            "",
                            &format!("poler-sudo: мусорный запрос: {why}"),
                        );
                    }
                    audit_append(
                        &box_name,
                        serde_json::json!({
                            "ts": now_epoch_ms(), "id": maybe_id, "verdict": "malformed",
                            "argv": [], "reason": why,
                        }),
                    );
                    if let Ok(mut st) = status.lock() {
                        st.malformed += 1;
                    }
                    continue;
                }
            };
            let globs = load_allow_globs(&policy_path(&box_name));
            // v0.28.0: авто-блоклист builtin-охоты («нашёл → закрыл» в рантайме)
            let blocklist = load_blocklist(&blocklist_path(&box_name));
            let joined_argv = req.argv.join(" ");
            if let Some((vid, _)) = blocklist
                .iter()
                .find(|(_, pfx)| joined_argv.starts_with(pfx.as_str()))
            {
                write_response(
                    &resp_dir,
                    &req.id,
                    1,
                    "",
                    "",
                    &format!(
                        "poler-sudo: авто-блоклист: вектор «{vid}» закрыт builtin-охотой (см. box hunt report)"
                    ),
                );
                audit_append(
                    &box_name,
                    serde_json::json!({
                        "ts": now_epoch_ms(), "id": req.id, "argv": req.argv,
                        "verdict": "auto-block", "reason": format!("вектор {vid}"),
                        "exit": 1,
                    }),
                );
                if let Ok(mut st) = status.lock() {
                    st.processed += 1;
                    st.autoblocked += 1;
                    st.last_reason = Some(format!("auto-block: {joined_argv}"));
                }
                continue;
            }
            // v0.28.0: пароль-режим — сверка ДО судьи (инварианты судьи и так
            // первыми в judge_root_request: пароль их не ослабляет).
            // Пустой пароль = «не предоставлен» (без -S / -S без ввода) —
            // обычный путь судьи, НЕ промах (пустой пароль не бывает верным).
            let mut password_ok = false;
            if let Some(pw) = req.password.as_deref().filter(|p| !p.is_empty()) {
                let now_i = Instant::now();
                let still_locked = locked_until.is_some_and(|u| now_i < u);
                if still_locked {
                    let left = locked_until
                        .map(|u| u.saturating_duration_since(now_i))
                        .unwrap_or_default()
                        .as_secs();
                    write_response(
                        &resp_dir,
                        &req.id,
                        1,
                        "",
                        "",
                        &format!(
                            "poler-sudo: брут-форс-защита: пароль-канал заперт ещё {left}с (5 промахов)"
                        ),
                    );
                    audit_append(
                        &box_name,
                        serde_json::json!({
                            "ts": now_epoch_ms(), "id": req.id, "argv": req.argv,
                            "verdict": "password-lock",
                            "reason": format!("лок ещё {left}с"), "exit": 1, "password": false,
                        }),
                    );
                    if let Ok(mut st) = status.lock() {
                        st.processed += 1;
                        st.password_fail += 1;
                        st.locked = true;
                        st.last_reason = Some(format!("password-lock: {joined_argv}"));
                    }
                    continue;
                }
                locked_until = None; // лок истёк — свежий счёт
                let pw_path = password_path(&box_name);
                let secret = load_password(&pw_path);
                let mode_on = secret.is_some();
                let verified = match &secret {
                    None => false,
                    Some(sec) => sec.verify(pw),
                };
                if verified {
                    password_ok = true;
                    pw_fails = 0;
                    if let Ok(mut st) = status.lock() {
                        st.password_ok += 1;
                        st.password_mode = true;
                    }
                } else {
                    pw_fails += 1;
                    let (msg, locked_now) = if pw_fails >= LOCK_FAILS {
                        locked_until = Some(now_i + Duration::from_secs(lock_secs()));
                        pw_fails = 0;
                        (
                            format!(
                                "poler-sudo: пароль неверен ({LOCK_FAILS}/{LOCK_FAILS}) — лок {}с",
                                lock_secs()
                            ),
                            true,
                        )
                    } else {
                        (
                            format!("poler-sudo: пароль неверен (попытка {pw_fails}/{LOCK_FAILS})"),
                            false,
                        )
                    };
                    write_response(&resp_dir, &req.id, 1, "", "", &msg);
                    let reason = if mode_on {
                        "пароль неверен".to_string()
                    } else {
                        "руут-пароль не задан (владелец: box sudo passwd в шлюзе)".to_string()
                    };
                    audit_append(
                        &box_name,
                        serde_json::json!({
                            "ts": now_epoch_ms(), "id": req.id, "argv": req.argv,
                            "verdict": "password-fail", "reason": reason,
                            "exit": 1, "password": false,
                        }),
                    );
                    if let Ok(mut st) = status.lock() {
                        st.processed += 1;
                        st.password_fail += 1;
                        st.password_mode = mode_on;
                        st.locked = locked_now;
                        st.last_reason = Some(format!("password-fail: {joined_argv}"));
                    }
                    continue;
                }
            }
            let t0 = Instant::now();
            let (verdict, exit, out, err, note) =
                match judge_root_request(&req, &globs, password_ok) {
                    RootVerdict::Deny(why) => (Some(why), 1, String::new(), String::new(), "deny"),
                    RootVerdict::Allow => {
                        let argv = root_exec_argv(&box_name, &req);
                        let (exit, out, err, timed_out, spawn_err) = exec_root(&argv);
                        let note = if timed_out {
                            "allow/timeout"
                        } else if spawn_err.is_some() {
                            "allow/spawn-error"
                        } else {
                            "allow"
                        };
                        let se = spawn_err.unwrap_or_default();
                        (Some(se), exit, out, err, note)
                    }
                };
            let ms = t0.elapsed().as_millis() as u64;
            let reason = verdict.clone().unwrap_or_default();
            // ответ агенту
            match verdict.as_deref() {
                Some(why) if note == "deny" => {
                    write_response(
                        &resp_dir,
                        &req.id,
                        1,
                        "",
                        "",
                        &format!("poler-sudo: судья: {why}"),
                    );
                }
                _ => {
                    let out_c = cap_str(&out, ROOT_OUT_CAP);
                    let err_c = cap_str(&err, ROOT_ERR_CAP);
                    let mut msg = String::new();
                    if timed_note(note) {
                        msg.push_str(
                            "poler-sudo: исполнено от рута (docker exec -u 0, со стороны хоста)\n",
                        );
                    }
                    if note == "allow/timeout" {
                        msg.push_str("poler-sudo: таймаут 120с — процесс убит\n");
                    }
                    if note == "allow/spawn-error" {
                        msg.push_str(&format!("poler-sudo: docker exec не поднялся: {reason}\n"));
                    }
                    write_response(&resp_dir, &req.id, exit, &out_c, &err_c, &msg);
                }
            }
            // аудит + счётчики
            audit_append(
                &box_name,
                serde_json::json!({
                    "ts": now_epoch_ms(), "id": req.id, "argv": req.argv,
                    "cwd": req.cwd, "verdict": note, "reason": reason,
                    "exit": exit, "ms": ms, "password": password_ok,
                }),
            );
            if let Ok(mut st) = status.lock() {
                st.processed += 1;
                match note {
                    "deny" => {
                        st.denied += 1;
                        st.last_reason = Some(format!("deny: {}", req.argv.join(" ")));
                    }
                    "rate" => st.rate_limited += 1,
                    "malformed" => st.malformed += 1,
                    _ => {
                        st.allowed += 1;
                        st.last_reason =
                            Some(format!("allow: {} (exit {})", req.argv.join(" "), exit));
                    }
                }
            }
        }
        if pending.is_empty() {
            std::thread::sleep(POLL_TICK);
        }
    }
}

fn timed_note(note: &str) -> bool {
    note == "allow" || note == "allow/timeout" || note == "allow/spawn-error"
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn req(argv: &[&str]) -> SudoRequest {
        SudoRequest {
            id: "r123-1700000000".into(),
            cwd: "/workspace".into(),
            password: None,
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn req_pw(argv: &[&str], pw: &str) -> SudoRequest {
        SudoRequest {
            id: "r123-1700000000".into(),
            cwd: "/workspace".into(),
            password: Some(pw.into()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
    }

    // --- base64 ---
    #[test]
    fn b64_roundtrip() {
        for s in ["", "a", "ab", "abc", "hello мир!", "sudo\trm -rf /\nx"] {
            let enc = b64_encode(s.as_bytes());
            assert_eq!(b64_decode(&enc).unwrap(), s.as_bytes(), "roundtrip: {s:?}");
        }
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert_eq!(b64_encode(b"ab"), "YWI=");
        assert_eq!(b64_encode(b"a"), "YQ==");
    }

    #[test]
    fn b64_decode_rejects_garbage() {
        assert!(b64_decode("YQ=").is_err(), "длина не кратна 4");
        assert!(b64_decode("Y*==").is_err(), "символ вне алфавита");
        assert!(b64_decode("Y=Q=").is_err(), "= в середине");
        assert!(b64_decode("Y===").is_err(), "паддинг > 2");
    }

    // --- протокол ---
    #[test]
    fn request_line_roundtrip() {
        // v2: мульти-argv обязан кодироваться с пароль-полем (пустым при
        // отсутствии: «не предоставлен»); легаси-строки ≥4 полей без пароля
        // интерпретируются как v2 (задокументированный квирк совместимости)
        let line = encode_request_v2(
            "r42-1700000001",
            "/workspace",
            "",
            &["apt-get".into(), "install".into(), "-y".into(), "sl".into()],
        );
        let r = parse_request_line(&line).unwrap();
        assert_eq!(r.id, "r42-1700000001");
        assert_eq!(r.cwd, "/workspace");
        assert_eq!(r.password.as_deref(), Some(""));
        assert_eq!(r.argv, vec!["apt-get", "install", "-y", "sl"]);
    }

    #[test]
    fn request_line_rejects_traversal_and_garbage() {
        // id с «/» — path traversal в имени файла ответа
        let bad_id = encode_request("../evil", "/x", &["id".into()]);
        assert!(
            parse_request_line(&bad_id).is_err(),
            "id-траверсал обязан отказывать"
        );
        assert!(parse_request_line("").is_err());
        assert!(parse_request_line("onlyfield").is_err());
        assert!(
            parse_request_line("id|notb64!|YQ==").is_err(),
            "битый base64 cwd"
        );
        // перегруз аргументов
        let many: Vec<String> = (0..80).map(|i| format!("a{i}")).collect();
        let line = encode_request("ok-id", "/w", &many);
        assert!(parse_request_line(&line).is_err(), ">64 аргументов — отказ");
        // пустой id
        assert!(parse_request_line(&encode_request("", "/w", &["id".into()])).is_err());
    }

    // --- судья ---
    #[test]
    fn judge_allows_package_managers() {
        for argv in [
            vec!["apt-get", "install", "-y", "sl"],
            vec!["apt", "update"],
            vec!["dpkg", "-i", "/workspace/pkg.deb"],
            vec!["apt-get", "download", "htop"],
        ] {
            let v = judge_root_request(&req(&argv), &[], false);
            assert_eq!(v, RootVerdict::Allow, "дефолт-allow: {argv:?}");
        }
    }

    #[test]
    fn judge_blocks_destructive_invariant() {
        // Block судьи НЕ ослабляется даже allowlist'ом
        for globs in [vec![], vec!["rm *".into()], vec!["*".into()]] {
            let v = judge_root_request(&req(&["rm", "-rf", "/usr"]), &globs, false);
            assert!(
                matches!(v, RootVerdict::Deny(_)),
                "Block-инвариант: {globs:?}"
            );
            let v = judge_root_request(&req(&["sh", "-c", "mkfs.ext4 /dev/sda"]), &globs, false);
            assert!(
                matches!(v, RootVerdict::Deny(_)),
                "интерп-деструктив: {globs:?}"
            );
        }
    }

    #[test]
    fn judge_confirm_is_deny_zse() {
        // sudo в payload → судья Confirm → брокер не подтверждает молча
        let v = judge_root_request(&req(&["sudo", "id"]), &[], false);
        match v {
            RootVerdict::Deny(why) => assert!(why.contains("подтвержд"), "ZSE-причина: {why}"),
            other => panic!("sudo-payload должен быть Deny: {other:?}"),
        }
    }

    #[test]
    fn judge_denies_escape_tools() {
        for argv in [
            vec!["docker", "ps"],
            vec!["nsenter", "--target", "1", "--mount", "--uts"],
            vec!["unshare", "-Ur", "id"],
            vec!["mount", "/dev/sda", "/mnt"],
            vec!["reboot"],
            vec!["modprobe", "evil"],
            vec!["ptrace", "-p", "1"],
        ] {
            let v = judge_root_request(&req(&argv), &[], false);
            assert!(
                matches!(v, RootVerdict::Deny(_)),
                "инструмент побега: {argv:?}"
            );
        }
    }

    #[test]
    fn judge_denies_kernel_paths() {
        for argv in [
            vec!["chmod", "777", "/proc/self/mem"],
            vec!["sh", "-c", "echo x > /proc/sys/kernel/core_pattern"], // судья BLOCKED_WRITE → Block
            vec!["cp", "x", "/sys/fs/cgroup/thing"],
            vec!["tee", "/dev/kmem"],
            vec!["cat", "/var/run/docker.sock"],
        ] {
            let v = judge_root_request(&req(&argv), &[], false);
            assert!(
                matches!(v, RootVerdict::Deny(_)),
                "пути ядра/демона: {argv:?}"
            );
        }
    }

    #[test]
    fn judge_allowlist_glob() {
        let globs = vec!["cargo install*".to_string()];
        assert_eq!(
            judge_root_request(&req(&["cargo", "install", "ripgrep"]), &globs, false),
            RootVerdict::Allow
        );
        // без глоба — отказ по умолчанию
        assert!(matches!(
            judge_root_request(&req(&["cargo", "install", "ripgrep"]), &[], false),
            RootVerdict::Deny(_)
        ));
        // глоб не совпал
        assert!(matches!(
            judge_root_request(&req(&["cargo", "build"]), &globs, false),
            RootVerdict::Deny(_)
        ));
    }

    #[test]
    fn judge_fs_ops_scope() {
        assert_eq!(
            judge_root_request(&req(&["mkdir", "/workspace/build"]), &[], false),
            RootVerdict::Allow
        );
        assert_eq!(
            judge_root_request(&req(&["chown", "root:root", "/home/poler/x"]), &[], false),
            RootVerdict::Allow
        );
        assert!(
            matches!(
                judge_root_request(&req(&["mkdir", "/etc/pwn"]), &[], false),
                RootVerdict::Deny(_)
            ),
            "fs-опа вне границ — отказ"
        );
        // rm не входит в fs-дефолт (только allowlist)
        assert!(matches!(
            judge_root_request(&req(&["rm", "/workspace/x"]), &[], false),
            RootVerdict::Deny(_)
        ));
    }

    #[test]
    fn judge_safe_and_empty() {
        assert_eq!(
            judge_root_request(&req(&["id"]), &[], false),
            RootVerdict::Allow
        );
        assert_eq!(
            judge_root_request(&req(&["whoami"]), &[], false),
            RootVerdict::Allow
        );
        assert!(matches!(
            judge_root_request(&req(&[]), &[], false),
            RootVerdict::Deny(_)
        ));
        // пакый саб
        assert!(matches!(
            judge_root_request(&req(&["apt-get", "moo"]), &[], false),
            RootVerdict::Deny(_)
        ));
    }

    #[test]
    fn glob_match_cases() {
        assert!(glob_match("*", "всё что угодно"));
        assert!(glob_match("apt*", "apt-get install x"));
        assert!(glob_match("cargo install*", "cargo install ripgrep"));
        assert!(!glob_match("cargo install*", "cargo build"));
        assert!(glob_match("te?t", "test"));
        assert!(!glob_match("te?t", "tempt"));
        assert!(glob_match("a*b*c", "a-x-b-y-c"));
        assert!(!glob_match("a*b*c", "a-b"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    // --- политика ---
    #[test]
    fn policy_add_list_reset() {
        let dir = std::env::temp_dir().join(format!("poler-pol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("box.sudo");
        assert!(load_allow_globs(&path).is_empty());
        add_allow_glob(&path, "cargo *").unwrap();
        add_allow_glob(&path, "make *").unwrap();
        assert!(add_allow_glob(&path, "cargo *")
            .unwrap()
            .contains("уже в списке"));
        assert_eq!(load_allow_globs(&path), vec!["cargo *", "make *"]);
        assert!(add_allow_glob(&path, "").is_err());
        assert!(add_allow_glob(&path, "a\nb").is_err());
        assert!(add_allow_glob(&path, &"x".repeat(200)).is_err());
        reset_allow_globs(&path).unwrap();
        assert!(load_allow_globs(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- шимы ---
    #[test]
    fn deploy_shims_creates_executable_scripts() {
        let dir = std::env::temp_dir().join(format!("poler-shim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        deploy_shims(&dir).unwrap();
        let sudo = dir.join(".poler-bin/sudo");
        assert!(sudo.is_file());
        let text = std::fs::read_to_string(&sudo).unwrap();
        assert!(text.contains(".poler-broker"), "шим пишет в брокер-канал");
        assert!(text.contains("docker exec"), "документация модели в шиме");
        assert!(text.contains("base64"), "протокол base64");
        assert!(
            text.contains("-mmin -2"),
            "маркер живости с freshness-чеком"
        );
        assert!(dir.join(".poler-broker/responses").is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sudo).unwrap().permissions().mode();
            assert!(mode & 0o111 != 0, "исполняемый: {:o}", mode);
        }
        assert!(dir.join(".poler-bin/poler-sudo").is_file());
        // идемпотентность
        deploy_shims(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_exec_argv_shape() {
        let _g = super::super::containers::docker_env_test_lock();
        let argv = root_exec_argv("poler-box-abcd", &req(&["apt-get", "update"]));
        assert_eq!(
            &argv[1..5],
            &["exec".to_string(), "-u".into(), "0:0".into(), "-w".into()]
        );
        assert_eq!(argv[5], "/workspace");
        assert_eq!(argv[6], "poler-box-abcd");
        assert_eq!(&argv[7..], &["apt-get".to_string(), "update".into()]);
        // cwd с «..» → якорь /workspace
        let bad = SudoRequest {
            id: "x".into(),
            cwd: "/workspace/../../etc".into(),
            password: None,
            argv: vec!["id".into()],
        };
        assert_eq!(root_exec_argv("b", &bad)[5], "/workspace");
        std::env::set_var("POLER_BOX_DOCKER", "/bin/false");
        assert_eq!(root_exec_argv("b", &req(&["id"]))[0], "/bin/false");
        std::env::remove_var("POLER_BOX_DOCKER");
    }

    #[test]
    fn write_response_is_symlink_safe() {
        let dir = std::env::temp_dir().join(format!("poler-resp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let resp = dir.join("responses");
        std::fs::create_dir_all(&resp).unwrap();
        // агент подготовил симлинк-ловушку на месте ответа
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp/poler-would-be-victim", resp.join("r1.exit")).unwrap();
        write_response_file(&resp, "r1.exit", b"7\n").unwrap();
        let meta = std::fs::symlink_metadata(resp.join("r1.exit")).unwrap();
        assert!(meta.is_file(), "после записи — обычный файл, не симлинк");
        assert_eq!(
            std::fs::read_to_string(resp.join("r1.exit")).unwrap(),
            "7\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Дописать строку в канал запросов (offset-поллинг видит только рост).
    fn append_request(home: &Path, line: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(broker_dir(home).join(REQUESTS_FILE))
            .expect("открыть канал");
        f.write_all(line.as_bytes()).expect("дописать канал");
    }

    // --- живой брокер с фейковым docker (герметичный интеграционный) ---
    #[test]
    fn broker_end_to_end_allow_and_deny() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-broker-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let audit_dir = base.join("audit");
        let policy_dir = base.join("policy");
        std::fs::create_dir_all(&home).unwrap();
        // фейковый docker: логирует argv, пишет stdout/stderr, exit 7
        let fake = base.join("fake-docker.sh");
        let log = base.join("docker-calls.log");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"$@\" >> {0}\necho FAKE-ROOT-OUT\necho FAKE-ROOT-ERR >&2\nexit 7\n",
                log.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755));
        }
        let jail = BoxState {
            name: "poler-box-e2e".into(),
            cfg: super::super::containers::BoxConfig::default(),
            ws_root: base.join("ws"),
            home_dir: home.clone(),
        };
        std::env::set_var("POLER_BOX_DOCKER", fake.to_str().unwrap());
        std::env::set_var("POLER_AUDIT_HOME", audit_dir.to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", policy_dir.to_str().unwrap());
        let mut handle = spawn_broker(&jail).unwrap();
        // маркер живости появился
        assert!(broker_dir(&home).join(MARKER_FILE).is_file());

        // 1) разрешённый запрос: apt-get install (v2, пароль не предоставлен)
        let ok_line = encode_request_v2(
            "r1-1",
            "/workspace",
            "",
            &["apt-get".into(), "install".into(), "-y".into(), "sl".into()],
        );
        append_request(&home, &format!("{ok_line}\n"));
        // 2) деструктив: rm -rf /
        let bad_line = encode_request_v2(
            "r2-2",
            "/workspace",
            "",
            &["rm".into(), "-rf".into(), "/".into()],
        );
        // файл перезапишется — ждём обработки первого, потом второй
        let resp = broker_dir(&home).join("responses");
        let mut waited = 0;
        while !resp.join("r1-1.exit").exists() && waited < 100 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        assert!(resp.join("r1-1.exit").exists(), "allow-ответ пришёл");
        assert_eq!(
            std::fs::read_to_string(resp.join("r1-1.exit"))
                .unwrap()
                .trim(),
            "7"
        );
        assert!(std::fs::read_to_string(resp.join("r1-1.out"))
            .unwrap()
            .contains("FAKE-ROOT-OUT"));
        assert!(std::fs::read_to_string(resp.join("r1-1.err"))
            .unwrap()
            .contains("FAKE-ROOT-ERR"));
        // фейковый docker получил -u 0:0 и argv насквозь
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(calls.contains("-u 0:0"), "рут-флаг: {calls}");
        assert!(calls.contains("poler-box-e2e"));
        assert!(
            calls.contains("apt-get install -y sl"),
            "argv насквозь: {calls}"
        );

        // второй запрос (дописывается: offset-поллинг брокера видит рост)
        append_request(&home, &format!("{bad_line}\n"));
        let mut waited = 0;
        while !resp.join("r2-2.exit").exists() && waited < 100 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        let deny_exit = std::fs::read_to_string(resp.join("r2-2.exit"))
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(deny_exit, "1", "deny → exit 1");
        let msg = std::fs::read_to_string(resp.join("r2-2.msg")).unwrap();
        assert!(msg.contains("судья"), "причина судьи: {msg}");

        // статус
        let st = handle.status();
        assert_eq!(st.allowed, 1);
        assert_eq!(st.denied, 1);
        // аудит
        let audit = std::fs::read_to_string(audit_path("poler-box-e2e")).unwrap();
        assert!(audit.contains("\"verdict\":\"allow\""));
        assert!(audit.contains("\"verdict\":\"deny\""));
        // остановка: маркер снят
        let rep = handle.stop();
        assert!(rep.contains("ОСТАНОВЛЕН"));
        assert!(!broker_dir(&home).join(MARKER_FILE).is_file());
        // replay того же id после остановки не обрабатывается
        std::env::remove_var("POLER_BOX_DOCKER");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn tail_audit_empty_and_filled() {
        let _g = super::super::containers::docker_env_test_lock();
        let dir = std::env::temp_dir().join(format!("poler-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("POLER_AUDIT_HOME", dir.to_str().unwrap());
        let empty = tail_audit("poler-box-none", 10);
        assert!(empty.contains("пуст"));
        audit_append(
            "poler-box-x",
            serde_json::json!({"ts": 1, "argv": ["apt-get", "update"], "verdict": "allow", "reason": "", "exit": 0}),
        );
        audit_append(
            "poler-box-x",
            serde_json::json!({"ts": 2, "argv": ["rm", "-rf", "/"], "verdict": "deny", "reason": "судья: BLOCK", "exit": 1}),
        );
        let text = tail_audit("poler-box-x", 10);
        assert!(text.contains("apt-get update"));
        assert!(text.contains("[deny]"));
        std::env::remove_var("POLER_AUDIT_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shim_text_is_posix_clean() {
        // без башизмов (клетка = debian slim: /bin/sh → dash)
        assert!(!SUDO_SHIM.contains("function "));
        assert!(!SUDO_SHIM.contains("[[ "));
        assert!(SUDO_SHIM.contains("#!/bin/sh"));
        // id формируется без $RANDOM (dash)
        assert!(SUDO_SHIM.contains("$(date +%s)"));
    }

    // =====================================================================
    // v0.28.0: Root Broker Password Mode
    // =====================================================================

    #[test]
    fn password_set_load_verify_clear_roundtrip() {
        let dir = std::env::temp_dir().join(format!("poler-pwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("box.passwd");
        // задание: пара совпадает, валидный пароль
        let rep = set_password_from_pair(&path, "hunter2secret", "hunter2secret").unwrap();
        assert!(rep.contains("режим пароля ВКЛ"), "отчёт: {rep}");
        let sec = load_password(&path).unwrap();
        assert!(sec.verify("hunter2secret"), "верный пароль");
        assert!(!sec.verify("hunter2secre"), "промах");
        assert!(!sec.verify(""), "пустой");
        assert!(!sec.verify("hunter2SECRET"), "регистр");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert!(mode & 0o777 == 0o600, "пароль-файл 0600: {:o}", mode);
        }
        // в файле нет открытого текста пароля
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("hunter2"),
            "пароль не хранится открыто: {raw}"
        );
        // пара не совпала
        assert!(set_password_from_pair(&path, "aaa123", "bbb123").is_err());
        // валидация
        assert!(
            set_password_from_pair(&path, "abc", "abc").is_err(),
            "короткий"
        );
        assert!(
            set_password_from_pair(&path, &"x".repeat(80), &"x".repeat(80)).is_err(),
            "длинный"
        );
        assert!(
            set_password_from_pair(&path, "abc\ndef", "abc\ndef").is_err(),
            "control-символы (\\n)"
        );
        // снятие
        let rep = clear_password(&path).unwrap();
        assert!(rep.contains("ВЫКЛ"));
        assert!(!path.exists());
        let rep = clear_password(&path).unwrap();
        assert!(rep.contains("не был задан"), "повторное снятие: {rep}");
        // дрянь в файле → секрет не загружается
        std::fs::write(&path, "garbage\n").unwrap();
        assert!(load_password(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn password_unlocks_nondestructive_but_not_invariants() {
        // пароль открывает НЕдеструктивное (вне дефолт-политики)
        for argv in [
            vec!["pip", "install", "requests"],
            vec!["npm", "install", "-g", "typescript"],
            vec!["systemctl", "restart", "ssh"],
        ] {
            assert_eq!(
                judge_root_request(&req(&argv), &[], true),
                RootVerdict::Allow,
                "пароль открывает: {argv:?}"
            );
            // без пароля — дефолт-Deny (та же команда)
            assert!(
                matches!(
                    judge_root_request(&req(&argv), &[], false),
                    RootVerdict::Deny(_)
                ),
                "без пароля отказ: {argv:?}"
            );
        }
        // ИНВАРИАНТЫ пароль НЕ ослабляет
        for argv in [
            vec!["rm", "-rf", "/"],
            vec!["sh", "-c", "mkfs.ext4 /dev/sda"],
            vec!["docker", "run", "--privileged", "x"],
            vec!["nsenter", "--target", "1", "--mount"],
            vec!["chmod", "777", "/proc/self/mem"],
            vec!["chmod", "777", "/dev/mem"],
        ] {
            assert!(
                matches!(
                    judge_root_request(&req(&argv), &[], true),
                    RootVerdict::Deny(_)
                ),
                "инвариант с паролем: {argv:?}"
            );
        }
        // ZSE: вложенный sudo — судья Confirm → Deny даже с паролем
        assert!(matches!(
            judge_root_request(&req_pw(&["sudo", "id"], "hunter2secret"), &[], true),
            RootVerdict::Deny(_)
        ));
        // newline-инъекция в argv — raw-scan ловит
        assert!(
            matches!(
                judge_root_request(&req(&["apt-get", "install", "x\nrm -rf /"]), &[], true),
                RootVerdict::Deny(_)
            ),
            "newline-инъекция = Block (raw-scan)"
        );
    }

    #[test]
    fn request_line_v2_password_roundtrip() {
        let line = encode_request_v2(
            "r7-1",
            "/workspace",
            "hunter2secret",
            &["apt-get".into(), "install".into(), "-y".into(), "sl".into()],
        );
        let r = parse_request_line(&line).unwrap();
        assert_eq!(r.password.as_deref(), Some("hunter2secret"));
        assert_eq!(r.argv, vec!["apt-get", "install", "-y", "sl"]);
        // пустой пароль (-S без ввода)
        let line = encode_request_v2("r8-1", "/workspace", "", &["id".into()]);
        let r = parse_request_line(&line).unwrap();
        assert_eq!(r.password.as_deref(), Some(""));
        assert_eq!(r.argv, vec!["id"]);
        // пароль с «|» и unicode — b64 переносит
        let line = encode_request_v2("r9-1", "/w", "p|a|ss¡", &["id".into()]);
        let r = parse_request_line(&line).unwrap();
        assert_eq!(r.password.as_deref(), Some("p|a|ss¡"));
        // легаси-3-поля: пароля нет, argv = единственное поле
        let legacy = encode_request("r10-1", "/w", &["id".into()]);
        let r = parse_request_line(&legacy).unwrap();
        assert_eq!(r.password, None);
        assert_eq!(r.argv, vec!["id"]);
    }

    #[test]
    fn blocklist_roundtrip_and_semantics() {
        let _g = super::super::containers::docker_env_test_lock();
        let dir = std::env::temp_dir().join(format!("poler-bl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // append_blocklist пишет через policy_base() — изолируем HOME-политику
        std::env::set_var("POLER_POLICY_HOME", dir.to_str().unwrap());
        let path = dir.join("box.blocklist");
        assert!(load_blocklist(&path).is_empty());
        append_blocklist("box", "jdg:newline-injection", "apt-get install x").unwrap();
        append_blocklist("box", "jdg:escape-tool", "/usr/bin/docker").unwrap();
        // идемпотентность по id
        append_blocklist("box", "jdg:newline-injection", "другой префикс").unwrap();
        let bl = load_blocklist(&path);
        assert_eq!(bl.len(), 2, "дубликат не добавляется: {bl:?}");
        // короткий префикс не блокируется
        append_blocklist("box", "x:short", "ab").unwrap();
        assert_eq!(
            load_blocklist(&path).len(),
            2,
            "префикс <3 символов игнорируется"
        );
        // семантика: joined-argv матчится префиксом
        let bl = load_blocklist(&path);
        assert!(bl
            .iter()
            .any(|(id, pfx)| id == "jdg:escape-tool" && "/usr/bin/docker ps".starts_with(pfx)));
        // дрянь в файле пропускается
        std::fs::write(&path, "no-tab-line\n\n\nx\tok-prefix\n").unwrap();
        let bl = load_blocklist(&path);
        assert_eq!(bl.len(), 1, "мусор пропущен: {bl:?}");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Живой брокер с фейковым docker: полный пароль-цикл — промахи, лок,
    /// разблокировка, верный пароль → Allow (docker exec -u 0 насквозь).
    #[test]
    fn broker_password_end_to_end() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-broker-pw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let audit_dir = base.join("audit");
        let policy_dir = base.join("policy");
        std::fs::create_dir_all(&home).unwrap();
        let fake = base.join("fake-docker.sh");
        let log = base.join("docker-calls.log");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho \"$@\" >> {0}\necho FAKE-ROOT-OUT\necho FAKE-ROOT-ERR >&2\nexit 7\n",
                log.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755));
        }
        // пароль задаётся ДО подъёма брокера (режим виден сразу)
        set_password_from_pair(
            &policy_dir.join("poler-box-pw.passwd"),
            "s3cret-pass",
            "s3cret-pass",
        )
        .unwrap();
        // короткий лок для теста
        std::env::set_var("POLER_SUDO_LOCK_SECS", "1");
        std::env::set_var("POLER_BOX_DOCKER", fake.to_str().unwrap());
        std::env::set_var("POLER_AUDIT_HOME", audit_dir.to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", policy_dir.to_str().unwrap());
        let jail = BoxState {
            name: "poler-box-pw".into(),
            cfg: super::super::containers::BoxConfig::default(),
            ws_root: base.join("ws"),
            home_dir: home.clone(),
        };
        let mut handle = spawn_broker(&jail).unwrap();
        assert!(
            handle.status().password_mode,
            "режим пароля виден в статусе"
        );
        let req_f = broker_dir(&home).join(REQUESTS_FILE);
        let resp = broker_dir(&home).join("responses");

        // 1) неверный пароль ×5 → лок (5-я попытка пишет «лок»).
        //    Пишем НАКОПИТЕЛЬНО: перезапись той же длины невидима offset-поллингу
        let mut cumulative = String::new();
        for i in 1..=5 {
            let line = encode_request_v2(
                &format!("rwp{i}"),
                "/workspace",
                "wrong-password",
                &["pip".into(), "install".into(), "x".into()],
            );
            cumulative.push_str(&format!("{line}\n"));
            std::fs::write(&req_f, &cumulative).unwrap();
            let mut waited = 0;
            while !resp.join(format!("rwp{i}.exit")).exists() && waited < 100 {
                std::thread::sleep(Duration::from_millis(100));
                waited += 1;
            }
            assert!(
                resp.join(format!("rwp{i}.exit")).exists(),
                "ответ промаха {i}"
            );
            let msg = std::fs::read_to_string(resp.join(format!("rwp{i}.msg"))).unwrap();
            assert!(msg.contains("пароль неверен"), "промах {i}: {msg}");
        }
        // docker НЕ вызывался ни разу
        assert!(!log.exists(), "деструктивный промах не исполняется");

        // 2) верный пароль во время лока → password-lock
        let locked = encode_request_v2(
            "rwlock",
            "/workspace",
            "s3cret-pass",
            &["pip".into(), "install".into(), "x".into()],
        );
        cumulative.push_str(&format!("{locked}\n"));
        std::fs::write(&req_f, &cumulative).unwrap();
        let mut waited = 0;
        while !resp.join("rwlock.exit").exists() && waited < 100 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        let msg = std::fs::read_to_string(resp.join("rwlock.msg")).unwrap();
        assert!(msg.contains("заперт"), "лок держит верный пароль: {msg}");
        assert!(handle.status().locked, "статус видит лок");

        // 3) лок истёк (1с) → верный пароль разблокирует
        std::thread::sleep(Duration::from_millis(1200));
        let ok = encode_request_v2(
            "rwok",
            "/workspace",
            "s3cret-pass",
            &["pip".into(), "install".into(), "requests".into()],
        );
        cumulative.push_str(&format!("{ok}\n"));
        std::fs::write(&req_f, &cumulative).unwrap();
        let mut waited = 0;
        while !resp.join("rwok.exit").exists() && waited < 150 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        assert_eq!(
            std::fs::read_to_string(resp.join("rwok.exit"))
                .unwrap()
                .trim(),
            "7",
            "верный пароль → исполнено от рута (exit 7 фейка)"
        );
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(calls.contains("-u 0:0"), "рут-флаг: {calls}");
        assert!(
            calls.contains("pip install requests"),
            "argv насквозь (пароль в argv НЕТ): {calls}"
        );
        assert!(
            !calls.contains("s3cret-pass"),
            "пароль не утекает в docker argv"
        );

        // 4) пароль не ослабляет инварианты: rm -rf / с ВЕРНЫМ паролем
        let evil = encode_request_v2(
            "rwevil",
            "/workspace",
            "s3cret-pass",
            &["rm".into(), "-rf".into(), "/".into()],
        );
        cumulative.push_str(&format!("{evil}\n"));
        std::fs::write(&req_f, &cumulative).unwrap();
        let mut waited = 0;
        while !resp.join("rwevil.exit").exists() && waited < 100 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        let msg = std::fs::read_to_string(resp.join("rwevil.msg")).unwrap();
        assert!(msg.contains("судья"), "Block с паролем: {msg}");

        // аудит без материала пароля
        let audit = std::fs::read_to_string(audit_path("poler-box-pw")).unwrap();
        assert!(audit.contains("\"verdict\":\"password-fail\""));
        assert!(audit.contains("\"verdict\":\"password-lock\""));
        assert!(audit.contains("\"password\":true"));
        assert!(!audit.contains("s3cret-pass"), "пароль не утекает в аудит");
        let st = handle.status();
        assert!(st.password_fail >= 5);
        assert!(st.password_ok >= 1);
        let _ = handle.stop();
        std::env::remove_var("POLER_SUDO_LOCK_SECS");
        std::env::remove_var("POLER_BOX_DOCKER");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Авто-блоклист: вектор, добавленный охотой, отклоняется ДО судьи
    /// (запрос, который иначе прошёл бы по дефолту apt-allow).
    #[test]
    fn broker_blocklist_denies_before_judge() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-broker-bl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let audit_dir = base.join("audit");
        let policy_dir = base.join("policy");
        std::fs::create_dir_all(&home).unwrap();
        let fake = base.join("fake-docker.sh");
        let log = base.join("docker-calls.log");
        std::fs::write(
            &fake,
            format!("#!/bin/sh\necho \"$@\" >> {}\nexit 0\n", log.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755));
        }
        std::env::set_var("POLER_BOX_DOCKER", fake.to_str().unwrap());
        std::env::set_var("POLER_AUDIT_HOME", audit_dir.to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", policy_dir.to_str().unwrap());
        // блоклист пишется УЖЕ в изолированную policy-базу
        append_blocklist("poler-box-bl", "jdg:test-vector", "apt-get install -y htop").unwrap();
        let jail = BoxState {
            name: "poler-box-bl".into(),
            cfg: super::super::containers::BoxConfig::default(),
            ws_root: base.join("ws"),
            home_dir: home.clone(),
        };
        let mut handle = spawn_broker(&jail).unwrap();
        let line = encode_request_v2(
            "rbl1",
            "/workspace",
            "",
            &[
                "apt-get".into(),
                "install".into(),
                "-y".into(),
                "htop".into(),
            ],
        );
        std::fs::write(broker_dir(&home).join(REQUESTS_FILE), format!("{line}\n")).unwrap();
        let resp = broker_dir(&home).join("responses");
        let mut waited = 0;
        while !resp.join("rbl1.exit").exists() && waited < 100 {
            std::thread::sleep(Duration::from_millis(100));
            waited += 1;
        }
        let msg = std::fs::read_to_string(resp.join("rbl1.msg")).unwrap();
        assert!(msg.contains("авто-блоклист"), "вектор закрыт: {msg}");
        assert!(!log.exists(), "docker не вызывался (закрыто ДО судьи)");
        let st = handle.status();
        assert_eq!(st.autoblocked, 1);
        let audit_f = audit_path("poler-box-bl");
        let mut a_waited = 0;
        while !audit_f.exists() && a_waited < 100 {
            std::thread::sleep(Duration::from_millis(50));
            a_waited += 1;
        }
        let audit = std::fs::read_to_string(&audit_f).unwrap();
        assert!(audit.contains("\"verdict\":\"auto-block\""));
        let _ = handle.stop();
        std::env::remove_var("POLER_BOX_DOCKER");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn shim_v2_supports_dash_s() {
        assert!(SUDO_SHIM.contains("\"$a\" = \"-S\""), "фильтр -S");
        assert!(SUDO_SHIM.contains("read -r PW"), "пароль с stdin");
        assert!(
            SUDO_SHIM.contains("printf %s \"$PW\" | base64"),
            "пароль уходит b64-полем"
        );
        // пароль не попадает в argv-часть запроса: поле №2 фиксировано
        assert!(SUDO_SHIM.contains("$(printf %s \"$PW\" | base64 | tr -d '\\n')\""));
        assert!(SUDO_SHIM.contains("sudo [-S]"), "usage отражает -S");
        // без башизмов
        assert!(!SUDO_SHIM.contains("[[ "));
        assert!(!SUDO_SHIM.contains("function "));
    }
}
