//! # Builtin Hunter (v0.28.0) — собственный красный суб-агент POLER
//!
//! Задача владельца: «найти уязвимость нулевого дня, поместив СВОЕГО
//! суб-агента (не моего agy) внутрь, чтобы он нашёл дыры ИЗНУТРИ уже
//! скомпилированной программы БЕЗ ДОСТУПА К ИСХОДНИКАМ — короче, сделай
//! то, что сделал GPT на серверах OpenAI».
//!
//! Модель (как у OpenAI-агентов наблюдения на собственных серверах):
//! * **Свой суб-агент** — детерминированный красный движок, вшитый в
//!   POLER Engine, а не сторонний LLM владельца (agent-режим sentinel —
//!   отдельно, `--mode agent`);
//! * **Чёрный ящик** — атака идёт ТОЛЬКО через развёрнутые интерфейсы:
//!   `docker exec -i <box> sh -c <script>` от uid агента, файл-канал
//!   брокера (те же байты, что пишет шим), docker inspect. Никаких
//!   внутренних API судьи/брокера в атакующей фазе;
//! * **Наблюдение с хоста** (синяя сторона) — чтение host-only аудита,
//!   ответов канала, маркера живости, статуса конфигурации контейнера:
//!   «наблюдай за попытками пробиться со стороны хоста»;
//! * **Kill-switch** — любой Breach = docker stop немедленно (изоляция
//!   важнее наблюдения, форензика сохраняется);
//! * **«Нашёл → закрыл» в рантайме** — Anomaly/Breach judge-векторов
//!   попадают в авто-блоклист рут-брокера (`<box>.blocklist`, host-only):
//!   брокер отклоняет такие argv ДО судьи до выхода следующего релиза;
//! * **--loop** — постоянное наблюдение (как у GPT-агентов на серверах
//!   OpenAI): лёгкий свип каждые N сек (маркер/канал/аномалии) + полная
//!   батарея каждые M сек, журнал — `hunt/<box>-builtin/journal.jsonl`.
//!
//! Волны атаки (16+ векторов; escape-батарея sentinel — отдельные 28):
//! * **judge** — обходы судьи через живой канал (escape-инструмент
//!   под маской пути, пути ядра, деструктив, newline-инъекция в argv);
//! * **channel** — фаззинг протокола брокера изнутри клетки (мусорные
//!   и сверхлимитные строки, id-траверсал, replay, симлинк-ловушка на
//!   файле ответа, усечение канала, подмена шима, брут-форс пароля,
//!   concurrent-flood против лимита 30/час);
//! * **boundary** — запись в корень контейнера от непривилегированного
//!   пользователя;
//! * **escape** (deep, только в живом контейнере) — батарея sentinel
//!   изнутри + docker-inspect аудит конфигурации.
//!
//! Нулей новых зависимостей: POSIX sh в клетке + pure-парсеры в Rust.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::containers::BoxState;
use super::{rootbroker, sentinel};

/// Контейнерные пути (в тестах == хостовым, скрипты исполняются локально).
pub const C_BROKER: &str = "/home/poler/.poler-broker";
pub const C_HOME: &str = "/home/poler";

// ---------------------------------------------------------------------------
// Вердикты
// ---------------------------------------------------------------------------

/// Вердикт одного вектора охоты.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HV {
    /// Защита держит (ожидаемое поведение).
    Safe,
    /// Граница прорвана — kill-switch немедленно.
    Breached,
    /// Неожиданное поведение — кандидат в нули (уходит в отчёт/блоклист).
    Anomaly,
    /// Вектор неприменим (нет брокера/пропущен deep) — честно зафиксирован.
    Skipped,
    /// Инфраструктурная ошибка (docker/exec) — не вердикт о защите.
    Error,
}

impl HV {
    pub fn as_str(self) -> &'static str {
        match self {
            HV::Safe => "safe",
            HV::Breached => "breached",
            HV::Anomaly => "anomaly",
            HV::Skipped => "skipped",
            HV::Error => "error",
        }
    }
}

/// Результат одного вектора.
#[derive(Debug, Clone)]
pub struct VectorOutcome {
    pub id: String,
    pub wave: &'static str,
    pub verdict: HV,
    pub evidence: String,
}

/// Результат полной батареи.
#[derive(Debug, Clone)]
pub struct BatteryReport {
    pub box_name: String,
    pub ts: u64,
    pub broker_on: bool,
    pub password_mode: bool,
    pub deep: bool,
    pub outcomes: Vec<VectorOutcome>,
    pub kill_switched: bool,
    pub report_path: Option<PathBuf>,
}

impl BatteryReport {
    /// (safe, breached, anomaly, skipped, error)
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0, 0);
        for o in &self.outcomes {
            match o.verdict {
                HV::Safe => c.0 += 1,
                HV::Breached => c.1 += 1,
                HV::Anomaly => c.2 += 1,
                HV::Skipped => c.3 += 1,
                HV::Error => c.4 += 1,
            }
        }
        c
    }

    /// Markdown-отчёт для владельца.
    pub fn render(&self) -> String {
        let (s, b, a, sk, e) = self.counts();
        let mut out = format!(
            "# Builtin Hunter — отчёт атаки изнутри (чёрный ящик)\n\nконтейнер {} · ts {} · брокер: {} · пароль-режим: {} · escape-волна: {}\n\nитоги: safe {} · **breached {}** · anomaly {} · skipped {} · error {}\n\n",
            self.box_name,
            self.ts,
            if self.broker_on { "ВКЛ (атаковался живой канал)" } else { "ВЫКЛ (канальные волны пропущены)" },
            if self.password_mode { "ВКЛ (брут-форс вектор)" } else { "ВЫКЛ" },
            if self.deep { "включена" } else { "выключена (нет живого контейнера)" },
            s, b, a, sk, e
        );
        out.push_str("| волна | вектор | вердикт | факт |\n|---|---|---|---|\n");
        for o in &self.outcomes {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                o.wave,
                o.id,
                o.verdict.as_str(),
                o.evidence
            ));
        }
        if self.kill_switched {
            out.push_str("\n🚨 KILL-SWITCH: контейнер остановлен (форензика сохранена).\n");
        }
        out.push_str(
            "\nЦикл «нашёл → закрыл»: judge-векторы с anomaly/breach — в авто-блоклист рут-брокера;\nкаждый breach — регрессионный тест следующего релиза.\n",
        );
        out
    }
}

// ---------------------------------------------------------------------------
// Контекст батареи
// ---------------------------------------------------------------------------

/// Параметры запуска батареи: хостовые пути (наблюдение) + контейнерные
/// (атака) + флаги. В тестах контейнерные пути = хостовым, а exec — локальный sh.
pub struct BatteryCtx {
    pub box_name: String,
    /// Хостовый каталог брокер-канала (= jail.home_dir/.poler-broker).
    pub broker_host: PathBuf,
    /// Хостовый home бокса (= jail.home_dir; шимы, файлы-жертвы).
    pub home_host: PathBuf,
    /// Контейнерный путь брокер-канала (в атакующих скриптах).
    pub c_broker: String,
    /// Контейнерный путь home (в атакующих скриптах).
    pub c_home: String,
    pub broker_on: bool,
    pub password_mode: bool,
    /// deep=true → escape-волна (живой контейнер: батарея sentinel + inspect).
    pub deep: bool,
}

impl BatteryCtx {
    /// Контекст для живого jail (атака — docker exec, наблюдение — хост).
    pub fn for_jail(jail: &BoxState, broker_on: bool, password_mode: bool, deep: bool) -> Self {
        BatteryCtx {
            box_name: jail.name.clone(),
            broker_host: rootbroker::broker_dir(&jail.home_dir),
            home_host: jail.home_dir.clone(),
            c_broker: C_BROKER.to_string(),
            c_home: C_HOME.to_string(),
            broker_on,
            password_mode,
            deep,
        }
    }

    fn responses(&self) -> PathBuf {
        self.broker_host.join("responses")
    }

    fn marker(&self) -> PathBuf {
        self.broker_host.join("enabled")
    }

    fn audit(&self) -> PathBuf {
        rootbroker::audit_path(&self.box_name)
    }
}

/// Результат исполнения атакующего скрипта.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub exit: i32,
    pub stdout: String,
}

/// Тип exec-замыкания: prod — docker exec в клетку, тесты — локальный sh.
pub type ExecFn<'a> = dyn Fn(&str) -> Result<ExecOutcome, String> + 'a;

// ---------------------------------------------------------------------------
// Наблюдение (host-сторона, синяя команда)
// ---------------------------------------------------------------------------

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Прочитать аудит как JSON-записи (мусор пропускается).
fn audit_entries(path: &Path) -> Vec<serde_json::Value> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Вердикты аудита для конкретного id.
fn audit_verdicts_for(entries: &[serde_json::Value], id: &str) -> Vec<String> {
    entries
        .iter()
        .filter(|v| v.get("id").and_then(|x| x.as_str()) == Some(id))
        .filter_map(|v| v.get("verdict").and_then(|x| x.as_str()).map(String::from))
        .collect()
}

/// Количество записей с данным вердиктом.
fn count_verdict(entries: &[serde_json::Value], verdict: &str) -> usize {
    entries
        .iter()
        .filter(|v| v.get("verdict").and_then(|x| x.as_str()) == Some(verdict))
        .count()
}

/// Ждать условие (поллинг 100мс) — для ответов/аудита асинхронного брокера.
fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

/// Маркер живости свежий (≤120с — тот же порог, что у шима).
fn marker_fresh(ctx: &BatteryCtx) -> bool {
    let m = ctx.marker();
    let age_ok = std::fs::metadata(&m)
        .and_then(|md| md.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d < Duration::from_secs(120))
        .unwrap_or(false);
    m.is_file() && age_ok
}

/// Собрать v2-строку запроса (как шим): пустой пароль = не предоставлен.
fn req_line(id: &str, password: &str, argv: &[&str]) -> String {
    let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    rootbroker::encode_request_v2(id, "/workspace", password, &args)
}

// ---------------------------------------------------------------------------
// Атакующие payload-ы (POSIX sh; пути подставлены контекстом)
// ---------------------------------------------------------------------------

/// Приклеить строку запроса к каналу (атакующий примитив).
fn send_line(ctx: &BatteryCtx, line: &str) -> String {
    format!(
        "printf '%s\\n' '{line}' >> '{}/requests.jsonl' 2>/dev/null\n",
        ctx.c_broker
    )
}

/// Записать в канал пачку строк.
fn send_lines(ctx: &BatteryCtx, lines: &[String]) -> String {
    let mut s = format!("F='{}/requests.jsonl'\n", ctx.c_broker);
    for l in lines {
        s.push_str(&format!("printf '%s\\n' '{l}' >> \"$F\" 2>/dev/null\n"));
    }
    s
}

// ---------------------------------------------------------------------------
// Батарея (детерминированный автономный красный цикл)
// ---------------------------------------------------------------------------

/// Полный прогон батареи. Каждый вектор: атака (exec) → наблюдение
/// (аудит/файлы/маркер) → вердикт. Breach → kill-switch + блоклист.
pub fn run_battery(ctx: &BatteryCtx, exec: &ExecFn, stop: &AtomicBool) -> BatteryReport {
    let mut report = BatteryReport {
        box_name: ctx.box_name.clone(),
        ts: now_epoch(),
        broker_on: ctx.broker_on,
        password_mode: ctx.password_mode,
        deep: ctx.deep,
        outcomes: Vec::new(),
        kill_switched: false,
        report_path: None,
    };

    // ---- волна JUDGE: обходы судьи через живой канал ----
    let judge_vectors: &[(&str, Vec<&str>)] = &[
        ("jdg:escape-tool-path", vec!["/usr/bin/docker", "ps"]),
        ("jdg:kernel-path", vec!["chmod", "777", "/proc/self/mem"]),
        ("jdg:destructive", vec!["rm", "-rf", "/"]),
        (
            "jdg:newline-injection",
            vec!["apt-get", "install", "x\nrm -rf /"],
        ),
    ];
    for (i, (id, argv)) in judge_vectors.iter().enumerate() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if !ctx.broker_on {
            report.outcomes.push(VectorOutcome {
                id: id.to_string(),
                wave: "judge",
                verdict: HV::Skipped,
                evidence: "брокер не активен (box sudo on — атаковать живой канал)".into(),
            });
            continue;
        }
        let rid = format!("jh{i}");
        let script = send_line(ctx, &req_line(&rid, "", argv));
        let before = audit_entries(&ctx.audit()).len();
        let exec_err = exec(&script).err();
        let verdict = match exec_err.is_some() {
            true => HV::Error,
            false => {
                let ok = wait_for(Duration::from_secs(8), || {
                    audit_entries(&ctx.audit()).len() > before
                });
                if !ok {
                    HV::Error
                } else {
                    let entries = audit_entries(&ctx.audit());
                    let vs = audit_verdicts_for(&entries, &rid);
                    let joined = argv.join(" ");
                    if vs.iter().any(|v| v == "deny") {
                        report.outcomes.push(VectorOutcome {
                            id: id.to_string(),
                            wave: "judge",
                            verdict: HV::Safe,
                            evidence: format!("судья Deny: {joined}"),
                        });
                        // авто-блок только для найденных дыр — не нужен
                        continue;
                    } else if vs.iter().any(|v| v == "allow") {
                        HV::Anomaly
                    } else if vs.iter().any(|v| v == "rate") {
                        // лимит 30/час мог исчерпаться earlier — не вердикт о судье
                        report.outcomes.push(VectorOutcome {
                            id: id.to_string(),
                            wave: "judge",
                            verdict: HV::Skipped,
                            evidence: "rate-лимит канала — судья не достигнут (порядок волн)"
                                .into(),
                        });
                        continue;
                    } else {
                        HV::Error
                    }
                }
            }
        };
        let joined = argv.join(" ");
        let o = VectorOutcome {
            id: id.to_string(),
            wave: "judge",
            verdict,
            evidence: match verdict {
                HV::Anomaly => format!(
                    "судья ПРОПУСТИЛ «{joined}» — кандидат в нули (исполнение без шелла, но флаг)"
                ),
                HV::Error => match exec_err {
                    Some(e) => format!("exec не поднялся: {e}"),
                    None => format!("вектор не отработал (нет записи аудита для «{joined}»)"),
                },
                _ => format!("argv: {joined}"),
            },
        };
        // «нашёл → закрыл»: judge-аномалия сразу в блоклист брокера
        if verdict == HV::Anomaly || verdict == HV::Breached {
            let _ = rootbroker::append_blocklist(&ctx.box_name, id, &joined);
        }
        report.outcomes.push(o);
    }

    // ---- волна CHANNEL: фаззинг брокер-канала изнутри ----
    if ctx.broker_on {
        channel_wave(ctx, exec, stop, &mut report);
    } else {
        for id in [
            "chn:malformed-binary",
            "chn:oversize",
            "chn:id-traversal",
            "chn:replay",
            "chn:symlink-trap",
            "chn:truncate",
            "chn:shim-tamper",
            "chn:brute-force",
            "chn:concurrent-flood",
        ] {
            report.outcomes.push(VectorOutcome {
                id: id.to_string(),
                wave: "channel",
                verdict: HV::Skipped,
                evidence: "брокер не активен (box sudo on)".into(),
            });
        }
    }

    // ---- волна BOUNDARY: контейнер как есть ----
    if !stop.load(Ordering::SeqCst) {
        let script = "U=$(id -u 2>/dev/null || echo 0)\n\
                      if [ \"$U\" = \"0\" ]; then echo SKIP-ROOT-USER; exit 0; fi\n\
                      touch /pwned-write-probe 2>/dev/null\n\
                      echo \"EXIT=$?\"\n\
                      rm -f /pwned-write-probe 2>/dev/null\n";
        match exec(script) {
            Err(_) => {
                report.outcomes.push(VectorOutcome {
                    id: "bnd:write-root".into(),
                    wave: "boundary",
                    verdict: HV::Error,
                    evidence: "exec не отработал".into(),
                });
            }
            Ok(out) => {
                if out.stdout.contains("SKIP-ROOT-USER") {
                    report.outcomes.push(VectorOutcome {
                        id: "bnd:write-root".into(),
                        wave: "boundary",
                        verdict: HV::Skipped,
                        evidence: "uid=0 (user=root) — вектор не определён, см. esc:uid".into(),
                    });
                } else {
                    let v = if out.stdout.contains("EXIT=0") {
                        HV::Anomaly
                    } else {
                        HV::Safe
                    };
                    report.outcomes.push(VectorOutcome {
                        id: "bnd:write-root".into(),
                        wave: "boundary",
                        verdict: v,
                        evidence: match v {
                            HV::Safe => "touch / — отказ (uid без рута в контейнере)".into(),
                            HV::Anomaly => {
                                "корень контейнера записываем непривилегированным!".into()
                            }
                            _ => "exec не отработал".into(),
                        },
                    });
                }
            }
        }
    }

    // ---- волна ESCAPE (deep: только живой контейнер) ----
    if ctx.deep && !stop.load(Ordering::SeqCst) {
        // батарея sentinel изнутри (28 векторов побега)
        let _ = sentinel::deploy_probe(&ctx.home_host);
        let script = format!("{}/.poler-bin/polers-probe", ctx.c_home);
        match exec(&script) {
            Err(e) => report.outcomes.push(VectorOutcome {
                id: "esc:probe-battery".into(),
                wave: "escape",
                verdict: HV::Error,
                evidence: e,
            }),
            Ok(out) => {
                let probes = sentinel::parse_probe_output(&out.stdout);
                let (b, a, e, _i) = sentinel::count_verdicts(&probes);
                let escaped = sentinel::count_verdicts(&probes).2;
                let verdict = if escaped > 0 { HV::Breached } else { HV::Safe };
                report.outcomes.push(VectorOutcome {
                    id: "esc:probe-battery".into(),
                    wave: "escape",
                    verdict,
                    evidence: format!(
                        "батарея: blocked {} · anomaly {} · escape {} · info {}",
                        b, a, e, _i
                    ),
                });
            }
        }
        // docker-inspect аудит (host-истина по конфигурации)
        let hard = sentinel::host_hardening_check(&ctx.box_name);
        let he = sentinel::count_verdicts(&hard).2;
        report.outcomes.push(VectorOutcome {
            id: "esc:inspect-audit".into(),
            wave: "escape",
            verdict: if he > 0 { HV::Breached } else { HV::Safe },
            evidence: format!("inspect: privileged/capadd/net/pid/mounts — escape {}", he),
        });
    }

    // ---- восстановление после атак: шимы перепечатываются (лечит подмену),
    //      мусорные ответы охоты убираются ----
    let _ = rootbroker::deploy_shims(&ctx.home_host);
    cleanup_hunt_artifacts(ctx);

    // ---- kill-switch по breach ----
    let breached = report.counts().1;
    if breached > 0 {
        report.kill_switched = true;
        append_journal(ctx, "kill-switch", &format!("breach-векторов: {breached}"));
        match sentinel::kill_switch(&ctx.box_name) {
            Ok(_) => {}
            Err(e) => append_journal(ctx, "kill-switch-error", &e),
        }
    }
    report
}

/// Канальная волна: фаззинг протокола брокера руками «агента в клетке».
fn channel_wave(ctx: &BatteryCtx, exec: &ExecFn, stop: &AtomicBool, report: &mut BatteryReport) {
    let audit = ctx.audit();

    // 1) мусорные строки (бинарщина + битый b64)
    if !stop.load(Ordering::SeqCst) {
        let before_malformed = count_verdict(&audit_entries(&audit), "malformed");
        let script = format!(
            "printf 'junk1\\357\\277\\275\\002binary\\n' >> '{cb}/requests.jsonl'\n\
             printf 'junk2-1|\\041\\041notb64\\041\\041|dHJ1ZQ==\\n' >> '{cb}/requests.jsonl'\n",
            cb = ctx.c_broker
        );
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let seen = wait_for(Duration::from_secs(8), || {
                    count_verdict(&audit_entries(&audit), "malformed") > before_malformed
                });
                if seen {
                    HV::Safe
                } else {
                    HV::Error
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:malformed-binary".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => "бинарный мусор → malformed, брокер жив".into(),
                HV::Error => "аудит не зафиксировал malformed (брокер молчит?)".into(),
                _ => String::new(),
            },
        });
    }

    // 2) сверхлимитная строка (>8КБ)
    if !stop.load(Ordering::SeqCst) {
        let script = format!(
            "{{ printf 'rbig1-1|'; head -c 9000 /dev/zero | tr '\\0' 'A'; printf '\\n'; }} >> '{cb}/requests.jsonl'\n",
            cb = ctx.c_broker
        );
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let seen = wait_for(Duration::from_secs(8), || {
                    audit_verdicts_for(&audit_entries(&audit), "rbig1-1")
                        .iter()
                        .any(|v| v == "malformed")
                });
                if seen {
                    HV::Safe
                } else {
                    HV::Error
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:oversize".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => "строка 9КБ → malformed (лимит 8КБ держит)".into(),
                HV::Error => "oversize не отклонён в аудите".into(),
                _ => String::new(),
            },
        });
    }

    // 3) id-траверсал: «../pwn»
    if !stop.load(Ordering::SeqCst) {
        let script = send_line(ctx, "../pwn|Lw==|dHJ1ZQ==");
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let seen = wait_for(Duration::from_secs(8), || {
                    count_verdict(&audit_entries(&audit), "malformed") > 0
                        && audit_entries(&audit)
                            .iter()
                            .any(|v| v.get("id").and_then(|x| x.as_str()) == Some("../pwn"))
                });
                let no_escape_file = !ctx.home_host.join("pwn").exists()
                    && !ctx
                        .broker_host
                        .parent()
                        .map(|p| p.join("pwn"))
                        .unwrap_or_default()
                        .exists();
                if seen && no_escape_file {
                    HV::Safe
                } else if seen {
                    HV::Anomaly
                } else {
                    HV::Error
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:id-traversal".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => "id «../pwn» → malformed, файлов вне responses нет".into(),
                HV::Anomaly => "id-траверсал оставил файл вне responses!".into(),
                HV::Error => "id-траверсал не отклонён".into(),
                _ => String::new(),
            },
        });
    }

    // 4) replay: та же строка дважды
    if !stop.load(Ordering::SeqCst) {
        let line = req_line("rrp1-1", "", &["id"]);
        let script = send_lines(ctx, &[line.clone(), line]);
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let done = wait_for(Duration::from_secs(10), || {
                    let vs = audit_verdicts_for(&audit_entries(&audit), "rrp1-1");
                    vs.len() >= 2
                });
                if !done {
                    HV::Error
                } else {
                    let vs = audit_verdicts_for(&audit_entries(&audit), "rrp1-1");
                    let allows = vs.iter().filter(|v| *v == "allow").count();
                    let dups = vs.iter().filter(|v| *v == "duplicate").count();
                    if allows == 1 && dups >= 1 {
                        HV::Safe
                    } else if allows >= 2 {
                        HV::Anomaly
                    } else {
                        HV::Error
                    }
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:replay".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => "первый id исполнен, второй — duplicate (дедуп держит)".into(),
                HV::Anomaly => "replay дал ДВА исполнения — дедуп сломан!".into(),
                HV::Error => "replay не отработал (аудит пуст)".into(),
                _ => String::new(),
            },
        });
    }

    // 5) симлинк-ловушка на файле ответа
    if !stop.load(Ordering::SeqCst) {
        let victim = ctx.home_host.join("trap-victim.txt");
        let line = req_line("rsy1-1", "", &["id"]);
        let script = format!(
            "echo VICTIM-ORIGINAL-9231 > '{h}/trap-victim.txt'\n\
             ln -sf '{h}/trap-victim.txt' '{cb}/responses/rsy1-1.exit'\n\
             {send}",
            h = ctx.c_home,
            cb = ctx.c_broker,
            send = send_line(ctx, &line)
        );
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let answered = wait_for(Duration::from_secs(10), || {
                    ctx.responses().join("rsy1-1.exit").is_file()
                });
                let victim_intact = std::fs::read_to_string(&victim)
                    .map(|s| s.contains("VICTIM-ORIGINAL-9231"))
                    .unwrap_or(false);
                if answered && victim_intact {
                    HV::Safe
                } else if answered {
                    HV::Breached
                } else {
                    HV::Error
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:symlink-trap".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => "ответ пришёл, жертва не тронута (tmp+rename держит)".into(),
                HV::Breached => "запись ответа ЧЕРЕЗ симлинк — файл жертвы перезаписан!".into(),
                HV::Error => "ответ по запросу не пришёл".into(),
                _ => String::new(),
            },
        });
    }

    // 6) усечение канала (offset > len)
    if !stop.load(Ordering::SeqCst) {
        let line = req_line("rt1-1", "", &["id"]);
        let script = format!(
            ": > '{cb}/requests.jsonl'\n{send}",
            cb = ctx.c_broker,
            send = send_line(ctx, &line)
        );
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let answered = wait_for(Duration::from_secs(10), || {
                    ctx.responses().join("rt1-1.exit").is_file()
                }) && marker_fresh(ctx);
                if answered {
                    HV::Safe
                } else {
                    HV::Error
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:truncate".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => "усечение канала пережито: offset сброшен, запрос обработан".into(),
                HV::Error => "после усечения брокер не отвечает (или маркер протух)".into(),
                _ => String::new(),
            },
        });
    }

    // 7) подмена шима (персистентный home — агент владеет .poler-bin)
    if !stop.load(Ordering::SeqCst) {
        let before = audit_entries(&audit).len();
        let script = format!(
            "printf '#!/bin/sh\\nexit 87\\n' > '{h}/.poler-bin/sudo'\n\
             chmod 0755 '{h}/.poler-bin/sudo' 2>/dev/null\n\
             '{h}/.poler-bin/sudo' id\n\
             echo \"TAMPER-EXIT=$?\"\n",
            h = ctx.c_home
        );
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(out) => {
                let tampered = out.stdout.contains("TAMPER-EXIT=87");
                let audit_grew = audit_entries(&audit).len() > before;
                if tampered && !audit_grew {
                    HV::Safe
                } else if tampered {
                    HV::Anomaly
                } else {
                    HV::Error
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:shim-tamper".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => {
                    "подменённый шим локально исполнился, но запроса не создал (решение на хосте)"
                        .into()
                }
                HV::Anomaly => "подмена шима создала запрос в канале".into(),
                HV::Error => "подмена шима не воспроизвелась".into(),
                _ => String::new(),
            },
        });
    }

    // 8) брут-форс пароля (5 промахов → лок; без пароля — честный отказ)
    if !stop.load(Ordering::SeqCst) {
        let attempts: Vec<String> = if ctx.password_mode {
            (1..=5)
                .map(|i| req_line(&format!("rbf{i}"), "wrong-guess-password", &["id"]))
                .collect()
        } else {
            (1..=2)
                .map(|i| req_line(&format!("rbf{i}"), "wrong-guess-password", &["id"]))
                .collect()
        };
        let script = send_lines(ctx, &attempts);
        let expected = attempts.len();
        let verdict = match exec(&script) {
            Err(_) => HV::Error,
            Ok(_) => {
                let done = wait_for(Duration::from_secs(10), || {
                    count_verdict(&audit_entries(&audit), "password-fail") >= expected
                });
                if !done {
                    HV::Error
                } else {
                    // ни один промах не исполнился (нет allow для rbf-коров)
                    let leaked = (1..=expected).any(|i| {
                        audit_verdicts_for(&audit_entries(&audit), &format!("rbf{i}"))
                            .iter()
                            .any(|v| v == "allow")
                    });
                    if leaked {
                        HV::Breached
                    } else {
                        HV::Safe
                    }
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:brute-force".into(),
            wave: "channel",
            verdict,
            evidence: match verdict {
                HV::Safe => format!("{expected} промаха → password-fail в аудите, исполнений нет"),
                HV::Breached => "промах пароля ИСПОЛНИЛСЯ — сверка сломана!".into(),
                HV::Error => "промахи не зафиксированы".into(),
                _ => String::new(),
            },
        });
    }

    // 9) concurrent-flood: 25 запросов (rate 30/час — часть обязана уйти в rate)
    if !stop.load(Ordering::SeqCst) {
        let tail = format!(
            "|{}|{}|{}",
            rootbroker::b64_encode(b"/workspace"),
            rootbroker::b64_encode(b""),
            rootbroker::b64_encode(b"id")
        );
        let script = format!(
            "F='{cb}/requests.jsonl'\n\
             i=0\n\
             while [ \"$i\" -lt 25 ]; do printf 'rbf%s-9{tail}\\n' \"$i\" >> \"$F\" 2>/dev/null; i=$((i+1)); done\n",
            cb = ctx.c_broker,
            tail = tail
        );
        let (verdict, evidence) = match exec(&script) {
            Err(_) => (HV::Error, "exec не поднялся".to_string()),
            Ok(_) => {
                let done = wait_for(Duration::from_secs(25), || {
                    let entries = audit_entries(&audit);
                    (0..25)
                        .filter(|i| !audit_verdicts_for(&entries, &format!("rbf{i}-9")).is_empty())
                        .count()
                        >= 25
                });
                if !done {
                    (
                        HV::Error,
                        "не все 25 запросов получили вердикт (таймаут)".to_string(),
                    )
                } else {
                    let entries = audit_entries(&audit);
                    let mut allows = 0;
                    let mut rates = 0;
                    let mut missing = 0;
                    for i in 0..25 {
                        let vs = audit_verdicts_for(&entries, &format!("rbf{i}-9"));
                        if vs.iter().any(|v| v == "allow") {
                            allows += 1;
                        } else if vs.iter().any(|v| v == "rate") {
                            rates += 1;
                        } else if vs.is_empty() {
                            missing += 1;
                        }
                    }
                    let ev =
                        format!("allow {allows} · rate {rates} · пропало {missing} (лимит 30/час)");
                    if missing == 0 {
                        (HV::Safe, ev)
                    } else {
                        (HV::Anomaly, ev)
                    }
                }
            }
        };
        report.outcomes.push(VectorOutcome {
            id: "chn:concurrent-flood".into(),
            wave: "channel",
            verdict,
            evidence,
        });
    }
}

// ---------------------------------------------------------------------------
// Исполнение payload-ов (prod: docker exec; тесты: локальный sh)
// ---------------------------------------------------------------------------

fn docker_bin() -> String {
    std::env::var("POLER_BOX_DOCKER")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "docker".into())
}

/// Исполнить скрипт в клетке: `docker exec -i -w /workspace BOX sh -c SCRIPT`.
/// Атака идёт от uid агента (default user контейнера), без TTY — как вызовы
/// самого агента. Таймаут 30с + дренаж пайпов.
pub fn exec_in_box_script(box_name: &str, script: &str) -> Result<ExecOutcome, String> {
    let bin = docker_bin();
    let mut cmd = Command::new(&bin);
    cmd.args([
        "exec",
        "-i",
        "-w",
        "/workspace",
        box_name,
        "sh",
        "-c",
        script,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child: Child = cmd
        .spawn()
        .map_err(|e| format!("exec в клетку: {e} (docker работает?)"))?;
    let t_out = child.stdout.take().map(super::containers::drain_pipe);
    let t_err = child.stderr.take().map(super::containers::drain_pipe);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if started.elapsed() >= Duration::from_secs(30) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    };
    let out = t_out
        .and_then(|t| t.join().ok())
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_default();
    let _err = t_err
        .and_then(|t| t.join().ok())
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_default();
    Ok(ExecOutcome {
        exit: status.map(|s| s.code().unwrap_or(-1)).unwrap_or(124),
        stdout: out,
    })
}

/// Локальное исполнение payload-а (тесты: пути контейнера = хостовым).
pub fn exec_local(script: &str) -> Result<ExecOutcome, String> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child: Child = cmd.spawn().map_err(|e| format!("локальный exec: {e}"))?;
    let t_out = child.stdout.take().map(super::containers::drain_pipe);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if started.elapsed() >= Duration::from_secs(20) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    };
    let out = t_out
        .and_then(|t| t.join().ok())
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_default();
    Ok(ExecOutcome {
        exit: status.map(|s| s.code().unwrap_or(-1)).unwrap_or(124),
        stdout: out,
    })
}

// ---------------------------------------------------------------------------
// Журнал + база + зачистка
// ---------------------------------------------------------------------------

/// База builtin-охоты бокса: `hunt_base()/<box>-builtin`.
pub fn builtin_base(box_name: &str) -> PathBuf {
    sentinel::hunt_base().join(format!("{box_name}-builtin"))
}

/// Файл журнала (JSONL).
pub fn journal_path(box_name: &str) -> PathBuf {
    builtin_base(box_name).join("journal.jsonl")
}

/// Дописать запись в журнал.
pub fn append_journal(ctx_like: &BatteryCtx, kind: &str, detail: &str) {
    let p = journal_path(&ctx_like.box_name);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let line = serde_json::json!({
        "ts": now_epoch(), "kind": kind, "box": ctx_like.box_name, "detail": detail,
    });
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .and_then(|mut f| {
            use std::io::Write as _;
            f.write_all(format!("{line}\n").as_bytes())
        });
}

/// Сохранить отчёт батареи; вернуть путь.
pub fn save_report(report: &BatteryReport) -> Option<PathBuf> {
    let dir = builtin_base(&report.box_name);
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{}-report.md", report.ts));
    std::fs::write(&path, report.render()).ok()?;
    Some(path)
}

/// Убрать артефакты охоты из канала (ответы на прямые записи hunter-а) и хвосты.
fn cleanup_hunt_artifacts(ctx: &BatteryCtx) {
    let resp = ctx.responses();
    if let Ok(rd) = std::fs::read_dir(&resp) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let is_hunt = [
                "jh", "rrp", "rsy", "rt1", "rbig", "rbf", "rwp", "rwlock", "rwok",
            ]
            .iter()
            .any(|p| name.starts_with(p));
            if is_hunt {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let _ = std::fs::remove_file(ctx.home_host.join("trap-victim.txt"));
}

// ---------------------------------------------------------------------------
// BuiltinHandle: ручка oneshot/loop для dispatch
// ---------------------------------------------------------------------------

/// Счётчики наблюдения.
#[derive(Debug, Clone)]
pub struct LoopStats {
    pub sweeps: u64,
    pub batteries: u64,
    pub anomalies: u64,
    pub breaches: u64,
    pub errors: u64,
    pub started: u64,
    pub last_sweep: u64,
    pub last_battery: u64,
    pub last_note: String,
    pub kill_switched: bool,
}

impl LoopStats {
    fn new() -> Self {
        LoopStats {
            sweeps: 0,
            batteries: 0,
            anomalies: 0,
            breaches: 0,
            errors: 0,
            started: now_epoch(),
            last_sweep: 0,
            last_battery: 0,
            last_note: "запуск".into(),
            kill_switched: false,
        }
    }
}

/// Ручка встроенного охотника: oneshot (батарея прогнана) или loop (живой
/// поток наблюдения). `box hunt status|report|stop` работают через неё.
pub struct BuiltinHandle {
    pub box_name: String,
    pub loop_mode: bool,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<LoopStats>>,
    last_report: Arc<Mutex<Option<PathBuf>>>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl BuiltinHandle {
    /// Остановить наблюдение (oneshot — уже завершён).
    pub fn stop(&mut self) -> String {
        self.stop.store(true, Ordering::SeqCst);
        let st = self.stats_snapshot();
        format!(
            "🤖 builtin-охота остановлена: свипов {} · батарей {} · anomaly {} · breach {} · error {}\nжурнал: {}\n",
            st.sweeps,
            st.batteries,
            st.anomalies,
            st.breaches,
            st.errors,
            journal_path(&self.box_name).display()
        )
    }

    pub fn stats_snapshot(&self) -> LoopStats {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn last_report_path(&self) -> Option<PathBuf> {
        self.last_report
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Текст для `box hunt status`.
    pub fn status_text(&self) -> String {
        let st = self.stats_snapshot();
        let mut s = format!(
            "🤖 Builtin Hunter (суб-агент POLER) — {} · контейнер {}\nсвипов {} · батарей {} · anomaly {} · breach {} · error {}\n",
            if self.loop_mode { "LOOP-наблюдение" } else { "oneshot-батарея" },
            self.box_name,
            st.sweeps,
            st.batteries,
            st.anomalies,
            st.breaches,
            st.errors
        );
        if !st.last_note.is_empty() {
            s.push_str(&format!("последний свип: {}\n", st.last_note));
        }
        if st.kill_switched {
            s.push_str("🚨 kill-switch сработал (контейнер остановлен)\n");
        }
        if let Some(p) = self.last_report_path() {
            s.push_str(&format!("отчёт: {}\n", p.display()));
        }
        s.push_str(&format!(
            "журнал: {}\n",
            journal_path(&self.box_name).display()
        ));
        s
    }
}

/// Разовая батарея (синхронно): атака → наблюдение → отчёт → (kill-switch).
/// Возвращает ручку для status/report и текст для владельца.
pub fn run_oneshot(
    jail: &BoxState,
    broker_on: bool,
    deep: bool,
) -> Result<(BuiltinHandle, String), String> {
    let ctx = BatteryCtx::for_jail(
        jail,
        broker_on,
        rootbroker::password_exists(&jail.name),
        deep,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let exec = |s: &str| exec_in_box_script(&jail.name, s);
    let report = run_battery(&ctx, &exec, &stop);
    append_journal(
        &ctx,
        "battery",
        &format!("safe/breach/anomaly: {:?}", report.counts()),
    );
    let path = save_report(&report);
    let mut report = report;
    report.report_path = path.clone();
    let stats = Arc::new(Mutex::new(LoopStats::new()));
    {
        let mut st = stats.lock().unwrap_or_else(|e| e.into_inner());
        st.batteries = 1;
        let (_s, b, a, _sk, e) = report.counts();
        st.anomalies = a as u64;
        st.breaches = b as u64;
        st.errors = e as u64;
        st.last_battery = now_epoch();
        st.last_note = format!("oneshot-батарея: {:?}", report.counts());
        st.kill_switched = report.kill_switched;
    }
    let last_report = Arc::new(Mutex::new(path));
    let handle = BuiltinHandle {
        box_name: jail.name.clone(),
        loop_mode: false,
        stop,
        stats,
        last_report,
        _thread: None,
    };
    let mut out = String::new();
    out.push_str(&handle.status_text());
    out.push('\n');
    out.push_str(&report.render());
    if !report.outcomes.is_empty() {
        out.push_str("box hunt report — полный отчёт; judge-аномалии закрыты блоклистом брокера\n");
    }
    Ok((handle, out))
}

/// Постоянное наблюдение (как GPT-агенты на серверах OpenAI): лёгкий свип
/// каждые `interval` сек, полная батарея каждые `full_every` сек, всё —
/// в журнал; breach в батарее → kill-switch → поток завершается.
pub fn start_loop(
    jail: &BoxState,
    broker_on: bool,
    interval: u64,
    full_every: u64,
) -> Result<BuiltinHandle, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Mutex::new(LoopStats::new()));
    let last_report: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let ctx = BatteryCtx::for_jail(
        jail,
        broker_on,
        rootbroker::password_exists(&jail.name),
        true,
    );
    let box_name = jail.name.clone();
    let (stop2, stats2, report2, ctx2) = (stop.clone(), stats.clone(), last_report.clone(), ctx);
    let thread = std::thread::Builder::new()
        .name("poler-builtin-hunter".into())
        .spawn(move || loop_thread(ctx2, interval, full_every, stop2, stats2, report2))
        .map_err(|e| format!("поток builtin-охоты: {e}"))?;
    Ok(BuiltinHandle {
        box_name,
        loop_mode: true,
        stop,
        stats,
        last_report,
        _thread: Some(thread),
    })
}

fn loop_thread(
    ctx: BatteryCtx,
    interval: u64,
    full_every: u64,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<LoopStats>>,
    last_report: Arc<Mutex<Option<PathBuf>>>,
) {
    let mut last_battery = Instant::now();
    let mut last_sweep = Instant::now();
    loop {
        if stop.load(Ordering::SeqCst) {
            append_journal(&ctx, "stop", "наблюдение остановлено владельцем");
            break;
        }
        if last_battery.elapsed() >= Duration::from_secs(full_every) {
            let exec = |s: &str| exec_in_box_script(&ctx.box_name, s);
            let report = run_battery(&ctx, &exec, &stop);
            append_journal(
                &ctx,
                "battery",
                &format!("safe/breach/anomaly: {:?}", report.counts()),
            );
            let path = save_report(&report);
            *last_report.lock().unwrap_or_else(|e| e.into_inner()) = path;
            if let Ok(mut st) = stats.lock() {
                st.batteries += 1;
                st.last_battery = now_epoch();
                let (s, b, a, _sk, e) = report.counts();
                st.anomalies += a as u64;
                st.breaches += b as u64;
                st.errors += e as u64;
                st.last_note = format!("батарея: safe {s} · breach {b} · anomaly {a} · error {e}");
                st.kill_switched = st.kill_switched || report.kill_switched;
            }
            if report.kill_switched {
                append_journal(&ctx, "halt", "kill-switch — наблюдение завершено");
                break;
            }
            last_battery = Instant::now();
        } else if last_sweep.elapsed() >= Duration::from_secs(interval) {
            let note = light_sweep(&ctx);
            append_journal(&ctx, "sweep", &note);
            if let Ok(mut st) = stats.lock() {
                st.sweeps += 1;
                st.last_sweep = now_epoch();
                st.last_note = note;
            }
            last_sweep = Instant::now();
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Лёгкий свип наблюдения (без атак): маркер брокера, рост канала, мусор.
fn light_sweep(ctx: &BatteryCtx) -> String {
    let mut parts: Vec<String> = Vec::new();
    if ctx.broker_on {
        if marker_fresh(ctx) {
            parts.push("маркер брокера жив (<120с)".into());
        } else {
            parts.push("⚠ маркер брокера протух/нет — шлюз не слушает?".into());
        }
        let entries = audit_entries(&ctx.audit());
        if entries.is_empty() {
            parts.push("канал тих (запросов нет)".into());
        } else {
            let allow = count_verdict(&entries, "allow");
            let deny = count_verdict(&entries, "deny");
            let malformed = count_verdict(&entries, "malformed");
            let pwfail = count_verdict(&entries, "password-fail");
            let lock = count_verdict(&entries, "password-lock");
            parts.push(format!(
                "канал: всего {} · allow {} · deny {} · malformed {} · промахи {} · лок {}",
                entries.len(),
                allow,
                deny,
                malformed,
                pwfail,
                lock
            ));
        }
        // аномалия: резкий всплеск промахов пароля = идёт брут-форс
        let pwfail = count_verdict(&audit_entries(&ctx.audit()), "password-fail");
        if pwfail >= 10 {
            parts.push("🚨 ≥10 промахов пароля — похоже на брут-форс из клетки".into());
        }
    } else {
        parts.push("брокер ВЫКЛ — наблюдает контейнер как есть".into());
    }
    if let Ok(rd) = std::fs::read_dir(ctx.responses()) {
        let stray = rd.flatten().count();
        if stray > 50 {
            parts.push(format!("⚠ {stray} неубранных ответов в канале (аномалия?)"));
        }
    }
    parts.join(" · ")
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_for(base: &Path, box_name: &str) -> BatteryCtx {
        let home = base.join("home");
        BatteryCtx {
            box_name: box_name.to_string(),
            broker_host: rootbroker::broker_dir(&home),
            home_host: home.clone(),
            c_broker: rootbroker::broker_dir(&home).to_string_lossy().to_string(),
            c_home: home.to_string_lossy().to_string(),
            broker_on: false,
            password_mode: false,
            deep: false,
        }
    }

    fn fake_jail(base: &Path, name: &str) -> BoxState {
        BoxState {
            name: name.into(),
            cfg: super::super::containers::BoxConfig::default(),
            ws_root: base.join("ws"),
            home_dir: base.join("home"),
        }
    }

    #[test]
    fn verdicts_and_counts_render() {
        let report = BatteryReport {
            box_name: "poler-box-x".into(),
            ts: 1,
            broker_on: true,
            password_mode: true,
            deep: false,
            outcomes: vec![
                VectorOutcome {
                    id: "jdg:a".into(),
                    wave: "judge",
                    verdict: HV::Safe,
                    evidence: "ok".into(),
                },
                VectorOutcome {
                    id: "chn:b".into(),
                    wave: "channel",
                    verdict: HV::Anomaly,
                    evidence: "странно".into(),
                },
                VectorOutcome {
                    id: "chn:c".into(),
                    wave: "channel",
                    verdict: HV::Breached,
                    evidence: "прорыв".into(),
                },
                VectorOutcome {
                    id: "bnd:d".into(),
                    wave: "boundary",
                    verdict: HV::Skipped,
                    evidence: "skip".into(),
                },
                VectorOutcome {
                    id: "esc:e".into(),
                    wave: "escape",
                    verdict: HV::Error,
                    evidence: "err".into(),
                },
            ],
            kill_switched: true,
            report_path: None,
        };
        assert_eq!(report.counts(), (1, 1, 1, 1, 1));
        let text = report.render();
        assert!(text.contains("breached 1"));
        assert!(text.contains("| chn:c | breached |"));
        assert!(text.contains("KILL-SWITCH"));
        assert!(text.contains("чёрный ящик"));
        assert_eq!(HV::Safe.as_str(), "safe");
        assert_eq!(HV::Breached.as_str(), "breached");
    }

    #[test]
    fn payloads_are_posix_sh_clean() {
        let base = std::env::temp_dir().join(format!("poler-hp-{}", std::process::id()));
        let ctx = ctx_for(&base, "poler-box-x");
        let scripts = vec![
            send_line(&ctx, &req_line("x1", "", &["id"])),
            send_lines(
                &ctx,
                &[req_line("x2", "", &["id"]), req_line("x3", "pw", &["id"])],
            ),
            format!(
                "printf 'junk1\\357\\277\\275\\002binary\\n' >> '{cb}/requests.jsonl'\n",
                cb = ctx.c_broker
            ),
        ];
        for s in &scripts {
            assert!(!s.contains("[[ "), "без башизмов: {s}");
            assert!(!s.contains("function "));
            assert!(s.contains("requests.jsonl"), "атака пишет в канал: {s}");
        }
        // v2-строка с паролем: поле №2 — b64, не открытый текст
        let line = req_line("x3", "secretpw", &["id"]);
        assert!(
            !line.contains("secretpw"),
            "пароль в канале только b64: {line}"
        );
        assert!(
            line.matches('|').count() >= 3,
            "v2: id|cwd|пароль|argv: {line}"
        );
        // пустой пароль — тоже валидная v2-строка
        let line = req_line("x1", "", &["id"]);
        assert!(rootbroker::parse_request_line(&line).unwrap().password == Some("".into()));
    }

    #[test]
    fn exec_local_runs_sh() {
        let out = exec_local("echo hello-hunter-42").unwrap();
        assert_eq!(out.exit, 0);
        assert!(out.stdout.contains("hello-hunter-42"));
        let out = exec_local("exit 9").unwrap();
        assert_eq!(out.exit, 9);
        assert!(exec_local("sleep 30").is_ok()); // таймаут-гейт не роняет
    }

    /// Батарея БЕЗ брокера: канальные/судейские волны пропущены честно,
    /// boundary работает, ничего не падает, шимы перепечатаны.
    #[test]
    fn battery_without_broker_skips_channel_honestly() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-hn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::env::set_var("POLER_AUDIT_HOME", base.join("audit").to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", base.join("policy").to_str().unwrap());
        let ctx = ctx_for(&base, "poler-box-hn");
        let stop = AtomicBool::new(false);
        let report = run_battery(&ctx, &exec_local, &stop);
        // 4 judge + 9 channel = 13 skipped
        let skipped = report
            .outcomes
            .iter()
            .filter(|o| o.verdict == HV::Skipped)
            .count();
        assert_eq!(
            skipped,
            13,
            "канал/судья без брокера — Skipped: {:?}",
            report.counts()
        );
        assert_eq!(report.counts().1, 0, "breach быть не может");
        // boundary-вектор присутствует и не прорван
        let bnd = report
            .outcomes
            .iter()
            .find(|o| o.id == "bnd:write-root")
            .unwrap();
        assert!(
            bnd.verdict == HV::Safe || bnd.verdict == HV::Skipped,
            "boundary: {bnd:?}"
        );
        // deep=false → escape-волны нет
        assert!(report.outcomes.iter().all(|o| o.wave != "escape"));
        // шимы перепечатаны даже без атак (heal)
        assert!(ctx.home_host.join(".poler-bin/sudo").is_file());
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ГЛАВНЫЙ ЖИВОЙ ТЕСТ: реальный брокер-поток + фейковый docker + локальный
    /// exec (= атака изнутри). Собственный суб-агент бьёт развёрнутую систему
    /// чёрным ящиком — все 14 векторов должны показать Safe.
    #[test]
    fn builtin_battery_live_all_safe() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-hlive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(&home).unwrap();
        // фейковый docker: лог argv, stdout/stderr, exit 7
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
        // пароль-режим: брут-форс вектор проверяет живую сверку
        rootbroker::set_password_from_pair(
            &base.join("policy").join("poler-box-hl.passwd"),
            "live-pass-9",
            "live-pass-9",
        )
        .unwrap();
        std::env::set_var("POLER_BOX_DOCKER", fake.to_str().unwrap());
        std::env::set_var("POLER_AUDIT_HOME", base.join("audit").to_str().unwrap());
        std::env::set_var("POLER_POLICY_HOME", base.join("policy").to_str().unwrap());
        std::env::set_var("POLER_HUNT_HOME", base.join("hunt").to_str().unwrap());
        let jail = fake_jail(&base, "poler-box-hl");
        let mut broker = rootbroker::spawn_broker(&jail).unwrap();
        // контейнерные пути == хостовым: локальный exec трогает те же файлы,
        // что смонтированы брокеру (атака изнутри, наблюдение с хоста)
        let broker_host = rootbroker::broker_dir(&home);
        let ctx = BatteryCtx {
            box_name: "poler-box-hl".into(),
            broker_host: broker_host.clone(),
            home_host: home.clone(),
            c_broker: broker_host.to_string_lossy().to_string(),
            c_home: home.to_string_lossy().to_string(),
            broker_on: true,
            password_mode: true,
            deep: false,
        };
        let stop = AtomicBool::new(false);
        let report = run_battery(&ctx, &exec_local, &stop);

        // ИНВАРИАНТ: ни одного прорыва
        let (s, b, a, sk, e) = report.counts();
        assert_eq!(b, 0, "breach недопустим: {:?}", report.outcomes);
        assert_eq!(e, 0, "инфра-ошибок быть не должно: {:?}", report.outcomes);
        // judge-волна: все 4 закрыты судей
        for id in [
            "jdg:escape-tool-path",
            "jdg:kernel-path",
            "jdg:destructive",
            "jdg:newline-injection",
        ] {
            let o = report.outcomes.iter().find(|o| o.id == id).expect(id);
            assert_eq!(o.verdict, HV::Safe, "{id}: {o:?}");
        }
        // channel-волна: защита держит
        for id in [
            "chn:malformed-binary",
            "chn:oversize",
            "chn:id-traversal",
            "chn:replay",
            "chn:symlink-trap",
            "chn:truncate",
            "chn:shim-tamper",
            "chn:brute-force",
            "chn:concurrent-flood",
        ] {
            let o = report.outcomes.iter().find(|o| o.id == id).expect(id);
            assert_eq!(o.verdict, HV::Safe, "{id}: {o:?}");
        }
        // boundary не прорван (safe/skipped под рутом)
        let bnd = report
            .outcomes
            .iter()
            .find(|o| o.id == "bnd:write-root")
            .unwrap();
        assert!(bnd.verdict == HV::Safe || bnd.verdict == HV::Skipped);
        // шим исцеляется после подмены
        assert_eq!(
            std::fs::read_to_string(home.join(".poler-bin/sudo")).unwrap(),
            rootbroker::SUDO_SHIM,
            "подмена шима вылечена deploy_shims"
        );
        // аудит зафиксировал весь арсенал атак
        let audit = std::fs::read_to_string(rootbroker::audit_path("poler-box-hl")).unwrap();
        assert!(
            audit.contains("\"verdict\":\"deny\""),
            "судейские отказы: {audit}"
        );
        assert!(audit.contains("\"verdict\":\"malformed\""));
        assert!(audit.contains("\"verdict\":\"duplicate\""));
        assert!(audit.contains("\"verdict\":\"password-fail\""));
        assert!(
            audit.contains("\"verdict\":\"rate\""),
            "flood упёрся в лимит: {audit}"
        );
        assert!(
            audit.contains("\"verdict\":\"allow\""),
            "легитимные id исполнены"
        );
        // docker получал только -u 0:0 и argv (без пароля)
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(calls.contains("-u 0:0"));
        assert!(!calls.contains("live-pass-9"), "пароль не утекает в docker");
        // аномалий нет → блоклист пуст
        assert!(rootbroker::load_blocklist(&rootbroker::blocklist_path("poler-box-hl")).is_empty());
        // артефакты охоты убраны
        assert!(!home.join("trap-victim.txt").exists());
        // отчёт сохраняется и читается
        let path = save_report(&report);
        assert!(path.is_some());
        let text = std::fs::read_to_string(path.unwrap()).unwrap();
        assert!(text.contains("breached 0"));
        let _ = s;
        let _ = a;
        let _ = sk;
        let _ = broker.stop();
        std::env::remove_var("POLER_BOX_DOCKER");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_POLICY_HOME");
        std::env::remove_var("POLER_HUNT_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn light_sweep_reports_marker_and_channel() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-hsw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("home/.poler-broker/responses")).unwrap();
        std::env::set_var("POLER_AUDIT_HOME", base.join("audit").to_str().unwrap());
        let ctx = ctx_for(&base, "poler-box-hsw");
        // без маркера — честное «протух»
        let note = light_sweep(&ctx);
        assert!(
            note.contains("протух") || note.contains("брокер ВЫКЛ"),
            "нет маркера: {note}"
        );
        // с маркером — жив
        std::fs::write(ctx.broker_host.join("enabled"), "alive").unwrap();
        let ctx = BatteryCtx {
            broker_on: true,
            ..ctx_for(&base, "poler-box-hsw")
        };
        let note = light_sweep(&ctx);
        assert!(note.contains("маркер"), "маркер жив: {note}");
        // рост канала виден
        let audit_p = rootbroker::audit_path("poler-box-hsw");
        std::fs::create_dir_all(audit_p.parent().unwrap()).unwrap();
        std::fs::write(
            &audit_p,
            "{\"ts\":1,\"id\":\"a\",\"argv\":[\"id\"],\"verdict\":\"allow\",\"reason\":\"\",\"exit\":0}\n",
        )
        .unwrap();
        let note = light_sweep(&ctx);
        assert!(note.contains("allow 1"), "канал посчитан: {note}");
        std::env::remove_var("POLER_AUDIT_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// LOOP-режим: живой поток наблюдения — свипы идут, stop() останавливает.
    #[test]
    fn loop_monitors_and_stops() {
        let _g = super::super::containers::docker_env_test_lock();
        let base = std::env::temp_dir().join(format!("poler-hloop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("home")).unwrap();
        std::env::set_var("POLER_AUDIT_HOME", base.join("audit").to_str().unwrap());
        std::env::set_var("POLER_HUNT_HOME", base.join("hunt").to_str().unwrap());
        let jail = fake_jail(&base, "poler-box-hloop");
        // full_every=3600: батарея не стартует — только лёгкие свипы (быстро)
        let mut handle = start_loop(&jail, false, 1, 3600).unwrap();
        std::thread::sleep(Duration::from_millis(2300));
        let st = handle.stats_snapshot();
        assert!(st.sweeps >= 1, "свипы идут: {st:?}");
        let status = handle.status_text();
        assert!(status.contains("LOOP-наблюдение"), "{status}");
        assert!(status.contains("журнал"));
        let rep = handle.stop();
        assert!(rep.contains("остановлена"), "{rep}");
        // поток замечает stop и выходит (ждём чуть-чуть, не джойним)
        std::thread::sleep(Duration::from_millis(1500));
        assert!(journal_path("poler-box-hloop").is_file(), "журнал ведётся");
        let j = std::fs::read_to_string(journal_path("poler-box-hloop")).unwrap();
        assert!(j.contains("\"kind\":\"sweep\""), "записи свипов: {j}");
        assert!(j.contains("\"kind\":\"stop\""), "останов записан: {j}");
        std::env::remove_var("POLER_AUDIT_HOME");
        std::env::remove_var("POLER_HUNT_HOME");
        let _ = std::fs::remove_dir_all(&base);
    }
}
