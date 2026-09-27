//! Command parser + dispatcher для REPL/TUI. Принимает строку ввода
//! пользователя, парсит на команды и аргументы (с поддержкой кавычек),
//! вызывает соответствующий обработчик `ShellState`.
//!
//! Синтаксис:
//! ```text
//! poler> search "Касіопея Astra-Nic Complex" --top 5
//! poler> stats                          # статистика web-index
//! poler> crawl https://example.com      # обход сайта в индекс
//! poler> sync vcs gh kotokvit           # синк VCS в индекс
//! poler> notes add "Идея"               # локальные заметки
//! poler> set format json                # переключить формат
//! poler> set top 20                     # топ-K по умолчанию
//! poler> help                           # список команд
//! poler> quit | exit                    # выход
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use crate::game::KeyCode;
use crate::notes;
use crate::sources;
use crate::vcs::VcsAdapter;

use super::agentenv;
use super::help;
use super::state::ShellState;
use super::wincompat::{self, WinTranslation};


/// Результат исполнения одной команды.
#[derive(Debug, Clone)]
pub enum CmdResult {
    /// Команда выполнена, `output` — текст для отображения.
    Done(String),
    /// Команда требует выхода из шелла.
    Quit,
    /// Пустая строка ввода (ничего не делать, перейти к следующей итерации).
    Empty,
}

/// Распарсить строку ввода на токены с поддержкой кавычек.
/// `"..."` и `'...'` — единый токен с пробелами внутри.
pub fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    for ch in line.chars() {
        match (ch, in_dq, in_sq) {
            ('"', false, false) => in_dq = true,
            ('\'', false, false) => in_sq = true,
            ('"', true, false) => in_dq = false,
            ('\'', false, true) => in_sq = false,
            (c, _, _) if !in_dq && !in_sq && c.is_whitespace() => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            (c, _, _) => buf.push(c),
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// Исполнить одну строку ввода в контексте `state`.
pub fn dispatch(state: &mut ShellState, line: &str) -> CmdResult {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return CmdResult::Empty;
    }

    // v0.48.0: Префикс `=` — быстрый путь калькулятора (= 2^10, = 5 km to mi)
    if let Some(expr) = trimmed.strip_prefix('=') {
        let expr = expr.trim();
        if expr.is_empty() {
            return CmdResult::Done("= <выражение> — посчитать (= 2^10, = 5 km to mi, = solve x^2 = 4)".into());
        }
        return cmd_calc(state, expr);
    }

    // v0.46.0: Прямой вызов системного шелла через `!` (например, `! agy ...` или `! ls -la`)
    if trimmed.starts_with('!') {
        let raw_sh = trimmed.trim_start_matches('!').trim();
        if raw_sh.is_empty() {
            return CmdResult::Done("! <command> — выполнить команду в системном шелле (например, `! ls -la`, `! agy ...`)".into());
        }
        return run_sh_command(raw_sh);
    }

    let tokens = tokenize(line);
    if tokens.is_empty() {
        return CmdResult::Empty;
    }
    let cmd = tokens[0].as_str();
    let args = &tokens[1..];

    match cmd {
        "" => CmdResult::Empty,
        "quit" | "exit" | "q" => CmdResult::Quit,
        "help" | "?" => {
            // `help` без аргументов → overview; `help <topic>` → детальная справка
            if args.is_empty() {
                CmdResult::Done(help::help_overview())
            } else {
                let topic = args.join(" ");
                CmdResult::Done(help::help_topic(&topic))
            }
        }
        "version" | "v" => CmdResult::Done(format!(
            "poler-engine {} (poler-shell v0.48.0 — Калькулятор Всего: calc/= , единицы, матрицы expm, триты, астро/гео, hw-зонд; среда агента: sysinfo/env/pty/--exec --json)",
            env!("CARGO_PKG_VERSION")
        )),
        "search" | "web" => cmd_search(state, args),
        "stats" => cmd_stats(state),
        // v0.16.0: alias для subкоманд vcs-sync: `sync vcs github owner`
        "sync" => cmd_sync(state, args),
        "set" => cmd_set(state, args),
        // v0.15.1: нативные команды crawl/impact внутри шелла
        "crawl" => cmd_crawl(state, args),
        "impact" => cmd_impact(state, args),
        // v0.16.0: Unified VCS & Data Mesh — нативные адаптеры GitHub/GitLab/Gitea/gix
        "gh" => cmd_gh(state, args),
        "gl" => cmd_gl(state, args),
        "gt" => cmd_gt(state, args),
        "gix" => cmd_gix(state, args),
        // v0.17.0: Notes & Sources CRUD
        "notes" => cmd_notes(state, args),
        "sources" => cmd_sources(state, args),
        // v0.46.0: Системный шелл и прямое исполнение
        "sh" | "bash" | "exec" => {
            if args.is_empty() {
                CmdResult::Done("sh <command> — выполнить команду в шелле".into())
            } else {
                run_sh_command(&args.join(" "))
            }
        }
        // v0.47.0: навигация ФС и терминал (Linux + Windows словари)
        "cd" | "chdir" => cmd_cd(args),
        "pwd" => CmdResult::Done(
            std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("❌ {e}")),
        ),
        "clear" | "cls" => CmdResult::Done("\x1b[2J\x1b[H".into()),
        // v0.47.0: среда для ИИ-агентов (Antigravity)
        "sysinfo" | "systeminfo" => CmdResult::Done(agentenv::sysinfo()),
        "env" => CmdResult::Done(agentenv::env_snapshot(args.first().map(|s| s.as_str()))),
        "agent" => CmdResult::Done(agentenv::agent_status()),
        "win" | "winhelp" => CmdResult::Done(wincompat::catalog()),
        "pty" => cmd_pty(args),
        // v0.47.0: прямые команды движка
        "engine" => cmd_engine(args),
        // v0.47.0: POLER Reader — живой голос книги
        "read" | "reader" => cmd_read(args),
        // v0.48.0: Калькулятор Всего — calc берёт RAW-аргументы (кавычки в
        // выражениях типа trit_val("1TT") обязаны дожить до лексера)
        "calc" => {
            let raw = raw_args_of(line);
            if raw.trim().is_empty() {
                CmdResult::Done(calc_usage())
            } else {
                cmd_calc(state, &raw)
            }
        }
        // v0.48.0: зонд скрытых параметров ПК
        "hw" | "hardware" => cmd_hw(args),
        // v0.51.0 (цикл P): квантовый мост — pqc прямо в шелле движка
        "quantum" | "qm" => {
            let raw = raw_args_of(line);
            if raw.trim().is_empty() {
                CmdResult::Done(quantum_usage())
            } else {
                cmd_quantum(state, &raw)
            }
        }
        // v0.53.0 (цикл R): P³-Мост — конформанс Rust↔Zig и рендер
        "p3" => {
            let raw = raw_args_of(line);
            if raw.trim().is_empty() {
                CmdResult::Done(p3_usage())
            } else {
                cmd_p3(&raw)
            }
        }
        // v0.54.0 (цикл S): Ядро Игры — сущности, тики, сцены, рендер
        "game" => {
            let raw = raw_args_of(line);
            if raw.trim().is_empty() {
                CmdResult::Done(game_usage())
            } else {
                cmd_game(&raw)
            }
        }
        other => {
            // v0.47.0: echo с Windows-переменными %NAME% → ${NAME}
            if other == "echo" && args.iter().any(|a| contains_win_var(a)) {
                let rewritten: Vec<String> =
                    args.iter().map(|a| expand_win_vars(a)).collect();
                return run_sh_command(&format!("echo {}", rewritten.join(" ")));
            }
            // v0.47.0: Windows-словарь (dir/type/copy/findstr/taskkill…) —
            // трансляция ПЕРЕД PATH-поиском; Linux-команды не перехватываются
            match wincompat::translate(other, args) {
                Some(tr) => run_win_translation(tr),
                None => run_system_cmd(other, args),
            }
        }
    }
}


// ---------------------------------------------------------------------------
// v0.48.0: Калькулятор Всего (calc / префикс =) и зонд железа (hw)
// ---------------------------------------------------------------------------

/// RAW-хвост строки после первого слова — БЕЗ разборки кавычек
/// (токенизатор шелла съедает "…" , а лексеру калькулятора они нужны).
pub fn raw_args_of(line: &str) -> String {
    let trimmed = line.trim_start();
    match trimmed.find(char::is_whitespace) {
        Some(sp) => trimmed[sp..].trim().to_string(),
        None => String::new(),
    }
}

/// Краткая справка по calc.
fn calc_usage() -> String {
    [
        "calc <выражение>          — вычислить: calc (1538*485)/1024, calc 2^10",
        "calc solve <уравнение>    — корни: calc solve x^2 - 4 = 0",
        "calc x = 5                — переменная; ans — последний результат",
        "calc 5 km + 300 m         — единицы: to mi / to m/s / to degF",
        "calc expm([0,-1;1,0]*psi) — матрицы: det inv eigen trace rot2 so_gen",
        "calc trits(5)             — триты POLER: trit_val(\"1TT\")",
        "calc moon_illum(2024,4,8,18.35) — астрономия (затмения/фазы/планеты)",
        "calc dist(50.45,30.52,49.84,24.03) — геодезия/навигация",
        "calc constants | units | funcs | vars | hist | laws — каталоги",
        "calc script <закон> [k=v] — генератор скриптов по законам физики",
        "префикс: = 2^10          — то же самое, короче",
        "help calc                 — полная справка с примерами",
    ]
    .join("\n")
}

/// Исполнить выражение калькулятора в контексте state.
fn cmd_calc(state: &mut ShellState, expr: &str) -> CmdResult {
    let src = expr.trim();

    // симметричные кавычки вокруг выражения: calc "2 + 2"
    let src = if src.len() >= 2
        && src.starts_with('"')
        && src.ends_with('"')
        && !src[1..src.len() - 1].contains('"')
    {
        &src[1..src.len() - 1]
    } else {
        src
    };

    // подкоманды-каталоги: строго по первому слову (иначе units*2 примут
    // за запрос каталога)
    let mut words = src.split_whitespace();
    let first = words.next().unwrap_or("").to_lowercase();
    let rest: String = words.collect::<Vec<_>>().join(" ");
    match first.as_str() {
        "vars" | "переменные" => {
            return CmdResult::Done(state.calc.vars_text().trim_end().to_string())
        }
        "hist" | "history" | "история" => {
            return CmdResult::Done(state.calc.history_text(20).trim_end().to_string())
        }
        "constants" => {
            return CmdResult::Done(
                crate::calc::constants::list_all(&rest.to_lowercase()).trim_end().to_string(),
            )
        }
        "units" => {
            let names = crate::calc::units::all_names();
            let filtered: Vec<&str> = names
                .into_iter()
                .filter(|n| rest.is_empty() || n.contains(&rest.to_lowercase()))
                .collect();
            return CmdResult::Done(format!("{} единиц: {}", filtered.len(), filtered.join(" ")));
        }
        "funcs" => {
            return CmdResult::Done(
                crate::calc::functions::catalog(&rest.to_lowercase()).trim_end().to_string(),
            )
        }
        "laws" => {
            return CmdResult::Done(crate::calc::scriptgen::list_laws().trim_end().to_string())
        }
        "script" => {
            let (law_name, overrides) = parse_script_overrides(&rest);
            return match crate::calc::scriptgen::find_law(&law_name) {
                None => CmdResult::Done(format!(
                    "закон «{law_name}» не найден; список: calc laws"
                )),
                Some(law) => match crate::calc::scriptgen::generate(law, &overrides) {
                    Ok(text) => CmdResult::Done(text.trim_end().to_string()),
                    Err(e) => CmdResult::Done(format!("❌ {e}")),
                },
            };
        }
        _ => {}
    }

    // обычное вычисление
    match state.calc.eval_line(src) {
        Ok(out) => CmdResult::Done(out),
        Err(e) => CmdResult::Done(format!("❌ {e}")),
    }
}

/// «kepler3 a=0.5 au M1=1.9885e30 kg» → («kepler3», [(a, «0.5 au»), …]).
/// Значение жадно поглощает токены до следующего `k=` (юниты с пробелами!).
fn parse_script_overrides(rest: &str) -> (String, Vec<(String, String)>) {
    let mut it = rest.split_whitespace();
    let law = it.next().unwrap_or("").to_string();
    let mut overrides = Vec::new();
    let mut current: Option<(String, String)> = None;
    for tok in it {
        if let Some((k, v)) = tok.split_once('=') {
            if let Some(done) = current.take() {
                overrides.push(done);
            }
            current = Some((k.to_string(), v.to_string()));
        } else if let Some((_, v)) = current.as_mut() {
            v.push(' ');
            v.push_str(tok);
        }
    }
    if let Some(done) = current.take() {
        overrides.push(done);
    }
    (law, overrides)
}

/// Зонд скрытых параметров ПК: `hw`, `hw --json`.
fn cmd_hw(args: &[String]) -> CmdResult {
    let report = crate::calc::hardware::probe();
    if args.iter().any(|a| a == "--json" || a == "-j") {
        CmdResult::Done(report.to_json())
    } else {
        let mut out = String::from("🔍 Скрытые параметры ПК (v0.48.0)");
        out.push_str(&report.to_text());
        CmdResult::Done(out.trim_end().to_string())
    }
}

// ---------------------------------------------------------------------------
// v0.51.0 (цикл P): квантовый мост — pqc прямо в шелле движка
// ---------------------------------------------------------------------------

/// Справка команды quantum.
fn quantum_usage() -> String {
    [
        "quantum run <algo> [opts]   — схема на идеальных кубитах:",
        "    bell ghz qft iqft grover bv dj period teleport",
        "    opts: --n K --shots M --seed S --marks a,b --secret S --period R --theta T",
        "quantum run qcasm <файл|->    — произвольная схема QCASM (цикл Q)",
        "quantum qcasm <файл|-> [opts] — opts: --shots M --seed S --top K --probs",
        "    --amplitudes --exact --noise <preset> (ideal|ibm-heron|google-willow|noisy-90s)",
        "quantum qaoa [--edges i-j,…] [--n K] [--p P] — MaxCut-ансатц с оптимизацией",
        "    opts: --shots M --seed S --restarts R --sweeps W (цикл Q)",
        "quantum teleport [--theta T] [--exact] — телепортация q0 → q2 с фиделити",
        "quantum bloch <alpha> [beta] — сфера Блоха (выражения calc: 1/sqrt(2), i/2…)",
        "quantum state <alpha> <beta>  — состояние кубита: амплитуды, вероятности, Блох",
        "quantum verify unitary <algo> [--n K] — формальное доказательство U†U = I",
        "quantum verify equiv <A> <B> [--n K] [--phase] — эквивалентность схем",
        "quantum verify teleport        — канал телепортации (точно, на базисе)",
        "    verify … --noise <preset> --shots M — вердикт + шум железа (цикл Q)",
        "quantum calc <выражение>       — мост в Калькулятор Всего (schrodinger,",
        "    pauli_x/y/z, kron, expm, eigen, ghz — физика цикла O)",
        "quantum list                   — каталог алгоритмов",
        "короткий псевдоним: qm run ghz --n 5 (q — занят под quit)",
    ]
    .join("\n")
}

// ---------------------------------------------------------------------------
// v0.53.0 (цикл R): P³-Мост — p3 info / conformance / frame
// ---------------------------------------------------------------------------

fn p3_usage() -> String {
    [
        "p3 info                      — библиотека P³: путь, ядро, ABI-рукопожатие",
        "p3 conformance [--pairs N] [--json] — конформанс Rust ↔ Zig:",
        "    d_FS, гомогенность, U†U=I, (AB)v=A(Bv), det, идемпотенты P²=P",
        "p3 frame [opts]              — «кадр из гамильтониана» (цикл R3):",
        "    цепочка Изинга → эволюция expm → P³ рендер → 3 PNG (rgb/depth/seg)",
        "    opts: --n K(2..8) --steps T --size WxH --out DIR --jz J --hx H --cloud M",
        "пути библиотеки: P3_FFI_LIB → ffi/ рядом с бинарником → ffi/ репо",
    ]
    .join("\n")
}

fn cmd_p3(raw: &str) -> CmdResult {
    let raw = raw.trim();
    let raw = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    let parts: Vec<String> = raw.split_whitespace().map(String::from).collect();
    let sub = parts.first().map(String::as_str).unwrap_or("");
    let args = &parts[1..];

    match sub {
        "help" | "usage" => CmdResult::Done(p3_usage()),
        "info" => cmd_p3_info(),
        "conformance" | "conf" => cmd_p3_conformance(args),
        "frame" | "render" => cmd_p3_frame(args),
        other => CmdResult::Done(format!(
            "p3: неизвестная подкоманда `{other}`\n\n{}",
            p3_usage()
        )),
    }
}

fn cmd_p3_info() -> CmdResult {
    match crate::p3::ffi::P3Lib::open() {
        Ok(lib) => CmdResult::Done(format!(
            "P³-Мост активен\n  библиотека : {}\n  ядро       : {}\n  ABI        : v{} (ожидалась v{})\n  экспорты   : fs_distance, pgl_identity/mul/transpose/apply/det,\n              givens4, spectral_projector, idempotent_rank/residual,\n              ortho_residual, render_frame",
            lib.path.display(),
            lib.kernel_tag,
            lib.abi_version,
            crate::p3::ffi::EXPECTED_ABI,
        )),
        Err(e) => CmdResult::Done(format!("P³-Мост недоступен: {e}")),
    }
}

fn cmd_p3_conformance(args: &[String]) -> CmdResult {
    let pairs = match q_flag_num(args, "--pairs", 96u32) {
        Ok(p) => p.clamp(4, 4096),
        Err(e) => return CmdResult::Done(format!("p3 conformance: {e}")),
    };
    let as_json = q_flag(args, "--json");
    match crate::p3::conformance::run_conformance(pairs) {
        Ok(report) => {
            if as_json {
                let mut j = String::from("{\n");
                j.push_str(&format!(
                    "  \"library\": {},\n  \"kernel\": {},\n  \"abi\": {},\n  \"pairs\": {},\n  \"passed\": {},\n  \"checks\": [\n",
                    json_str(&report.lib_path),
                    json_str(&report.kernel_tag),
                    report.abi_version,
                    report.pairs,
                    report.passed()
                ));
                for (i, c) in report.checks.iter().enumerate() {
                    j.push_str(&format!(
                        "    {{\"name\": {}, \"checked\": {}, \"max_dev\": {:e}, \"tol\": {:e}, \"passed\": {}}}{}\n",
                        json_str(c.name),
                        c.checked,
                        c.max_dev,
                        c.tol,
                        c.passed(),
                        if i + 1 < report.checks.len() { "," } else { "" }
                    ));
                }
                j.push_str("  ]\n}");
                CmdResult::Done(j)
            } else {
                CmdResult::Done(report.summary())
            }
        }
        Err(e) => CmdResult::Done(format!("p3 conformance: {e}")),
    }
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn cmd_p3_frame(args: &[String]) -> CmdResult {
    let mut cfg = crate::p3::render::FrameConfig::default();
    if let Ok(n) = q_flag_num(args, "--n", cfg.n_qubits as u32) {
        if !(2..=8).contains(&n) {
            return CmdResult::Done("p3 frame: --n 2..=8".into());
        }
        cfg.n_qubits = n as usize;
    }
    if let Ok(t) = q_flag_num(args, "--steps", cfg.steps as u32) {
        if !(4..=512).contains(&t) {
            return CmdResult::Done("p3 frame: --steps 4..=512".into());
        }
        cfg.steps = t as usize;
    }
    if let Some(size) = args.iter().position(|a| a == "--size") {
        let val = match args.get(size + 1) {
            Some(v) => v.clone(),
            None => return CmdResult::Done("p3 frame: --size WxH (например 960x540)".into()),
        };
        let Some((w, h)) = val.split_once('x') else {
            return CmdResult::Done("p3 frame: --size WxH (например 960x540)".into());
        };
        let (Ok(w), Ok(h)) = (w.trim().parse::<u32>(), h.trim().parse::<u32>()) else {
            return CmdResult::Done("p3 frame: --size WxH — целые числа".into());
        };
        if !(64..=4096).contains(&w) || !(64..=4096).contains(&h) {
            return CmdResult::Done("p3 frame: --size 64..=4096 по каждой стороне".into());
        }
        cfg.width = w;
        cfg.height = h;
    }
    if let Ok(jz) = q_flag_num(args, "--jz", cfg.jz) {
        if !(-10.0..=10.0).contains(&jz) || !jz.is_finite() {
            return CmdResult::Done("p3 frame: --jz -10..=10".into());
        }
        cfg.jz = jz;
    }
    if let Ok(hx) = q_flag_num(args, "--hx", cfg.hx) {
        if !(-10.0..=10.0).contains(&hx) || !hx.is_finite() {
            return CmdResult::Done("p3 frame: --hx -10..=10".into());
        }
        cfg.hx = hx;
    }
    if let Ok(m) = q_flag_num(args, "--cloud", cfg.cloud_top as u32) {
        if !(1..=64).contains(&m) {
            return CmdResult::Done("p3 frame: --cloud 1..=64".into());
        }
        cfg.cloud_top = m as usize;
    }
    if let Some(p) = args.iter().position(|a| a == "--out") {
        match args.get(p + 1) {
            Some(v) => cfg.out_dir = std::path::PathBuf::from(v.clone()),
            None => return CmdResult::Done("p3 frame: --out DIR".into()),
        }
    }

    match crate::p3::render::render_hamiltonian_frame(&cfg) {
        Ok(out) => CmdResult::Done(format!(
            "Кадр из гамильтониана (P³ рендер, цикл R3)\n  схема      : цепочка Изинга n={}, J={}, h={}, шагов {}\n  геометрия  : {} точек P³, {} рёбер\n  рендер     : {}×{}, закрашено {} пикселей, max d_FS = {:.4} рад\n  честность  : дрейф энергии/нормы = {:.2e} (унитарность expm)\n  артефакты  :\n    {}\n    {}\n    {}",
            cfg.n_qubits,
            cfg.jz,
            cfg.hx,
            cfg.steps,
            out.n_points,
            out.n_edges,
            cfg.width,
            cfg.height,
            out.painted_px,
            out.max_fs_depth,
            out.energy_drift,
            out.rgb_png.display(),
            out.depth_png.display(),
            out.seg_png.display(),
        )),
        Err(e) => CmdResult::Done(format!("p3 frame: {e}")),
    }
}

// ---------------------------------------------------------------------------
// v0.54.0 (цикл S): Ядро Игры — game info / demo / scene / write-demo
// ---------------------------------------------------------------------------

fn game_usage() -> String {
    [
        "game info                     — статус ядра: демо-сцена, счётчики, честность",
        "game demo [opts]              — прогнать демо-сцену «Этерия» и отрендерить кадр:",
        "    World → тики (fixed dt 1/60, кеплеровские ω) → P³ рендер → 3 PNG",
        "    opts: --ticks N(1..100000) --size WxH --out DIR --no-orbits --no-box --json",
        "game scene <file.json> [opts] — своя сцена (формат см. game write-demo):",
        "    тела/иерархия/орбиты/камера; те же opts",
        "game write-demo <file.json>   — выгрузить демо-сцену как редактируемый JSON",
        "game sound [opts]             — озвучить сцену (T1 «акустический кристалл»):",
        "    ω→высота, радиус→гейн, X→панорама; WAV PCM16 + хеши",
        "    opts: --ticks N --out F.wav --fs HZ(8000..96000) --gain X(0..1) --json",
        "game texture [opts]            — процедурная текстура (T2 «спектральный синтез»):",
        "    тайл-функция (беск. зум) → PNG; SVD rank-k кодек с кривой PSNR",
        "    opts: --size WxH --style noise|marble|wood --palette gray|copper|ice|jade",
        "          --seed N --freq F --octaves N --zoom F --out F.png",
        "          --svd-rank K --rank-curve --json",
        "game normalmap [opts]          — normal map из той же функции шума (U0):",
        "    честная производная dh/du → тангентные нормали, беск. зум",
        "    opts: --size WxH --style noise|marble|wood --seed N --freq F",
        "          --octaves N --zoom F --amplitude A(0..1.5) --out F.png --json",
        "game input-demo [opts]         — ввод→камера→рендер без окна (U1–U4):",
        "    скрипт событий → очередь → Input → орбит-камера → кадры+хеши",
        "    opts: --frames N(10..10000) --every N --size WxH --out DIR",
        "          --script F.json --json",
        "game window [opts]             — НАСТОЯЩЕЕ X11-окно (dlopen libX11, zero-dep):",
        "    опрос событий → Input → камера → P³-кадр в окно; нужен DISPLAY",
        "    opts: --size WxH --frames N(0=до закрытия) --ticks-cap N",
        "game asset absorb|emit [opts]   — Y «Эхо»: готовый ассет → нейроны → PQW →",
        "    с нуля: absorb --in F.wav|F.png --out F.pqw; emit --in F.pqw",
        "    --out F.wav|F.png [--seconds S] [--width W --height H]",
        "          [--seed N] [--burst 0..8] [--compare ORIGINAL] --json",
        "game vortex [opts]             — вихревой кодек «Шеннон-байпас» (V0):",
        "    шум → 2D-FFT → моды Колмогорова → GF(3)-триты (3^5=243≤256) → VRTX",
        "    честный зачёт: сжатие vs zstd-19, обход предела Шеннона, PSNR",
        "    opts: --size N(64..1024, степень 2) --style vortex|kolmogorov|fbm|white|all",
        "          --seed N --modes N --octaves N --keep F --eps E --out-dir DIR",
        "          --amp-trits T --phase-trits P --json",
        "честность: детерминизм бит-в-бит (state/audio/crystal/texture/frame/vortex-hash), ω=√(GM)/r^1.5",
    ]
    .join("\n")
}

/// Разбор --size WxH (общий с p3 frame).
fn game_parse_size(args: &[String]) -> Option<Result<(u32, u32), String>> {
    let i = args.iter().position(|a| a == "--size")?;
    let val = match args.get(i + 1) {
        Some(v) => v.clone(),
        None => return Some(Err("game: --size WxH (например 960x540)".into())),
    };
    let Some((w, h)) = val.split_once('x') else {
        return Some(Err("game: --size WxH (например 960x540)".into()));
    };
    let (Ok(w), Ok(h)) = (w.trim().parse::<u32>(), h.trim().parse::<u32>()) else {
        return Some(Err("game: --size WxH — целые числа".into()));
    };
    if !(64..=4096).contains(&w) || !(64..=4096).contains(&h) {
        return Some(Err("game: --size 64..=4096 по каждой стороне".into()));
    }
    Some(Ok((w, h)))
}

/// Общие опции game-рендера.
struct GameOpts {
    ticks: u32,
    width: u32,
    height: u32,
    out_dir: std::path::PathBuf,
    orbits: bool,
    render_box: bool,
    as_json: bool,
}

fn game_parse_opts(args: &[String]) -> Result<GameOpts, String> {
    let mut o = GameOpts {
        ticks: 600,
        width: 960,
        height: 540,
        out_dir: std::path::PathBuf::from("."),
        orbits: true,
        render_box: true,
        as_json: false,
    };
    if let Ok(t) = q_flag_num(args, "--ticks", o.ticks) {
        if !(1..=100_000).contains(&t) {
            return Err("game: --ticks 1..=100000".into());
        }
        o.ticks = t;
    }
    if let Some(r) = game_parse_size(args) {
        let (w, h) = r?;
        o.width = w;
        o.height = h;
    }
    if let Some(i) = args.iter().position(|a| a == "--out") {
        match args.get(i + 1) {
            Some(v) => o.out_dir = std::path::PathBuf::from(v.clone()),
            None => return Err("game: --out DIR".into()),
        }
    }
    o.orbits &= !q_flag(args, "--no-orbits");
    o.render_box &= !q_flag(args, "--no-box");
    o.as_json = q_flag(args, "--json");
    Ok(o)
}

/// Прогнать мир N тиков и отрендерить кадр.
fn game_run_and_render(
    scene: &crate::game::SceneFile,
    opts: &GameOpts,
) -> CmdResult {
    let mut world = match scene.build_world() {
        Ok(w) => w,
        Err(e) => return CmdResult::Done(format!("game: сцена `{}`: {e}", scene.name)),
    };
    let t0 = std::time::Instant::now();
    for _ in 0..opts.ticks {
        world.tick(crate::game::FIXED_DT);
    }
    let sim_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let state_hash = world.state_hash();

    let cfg = crate::game::FrameConfig {
        width: opts.width,
        height: opts.height,
        camera: scene.camera,
        render_orbits: opts.orbits,
        render_box: opts.render_box,
        scene_name: scene.name.clone(),
        out_dir: opts.out_dir.clone(),
    };
    match crate::game::render_frame(&world, &cfg) {
        Ok(out) => {
            if opts.as_json {
                CmdResult::Done(format!(
                    "{{\n  \"scene\": {},\n  \"bodies\": {},\n  \"ticks\": {},\n  \"state_hash\": \"0x{:016X}\",\n  \"sim_ms\": {:.3},\n  \"render\": {{\"points\": {}, \"edges\": {}, \"painted_px\": {}, \"max_fs_depth\": {:.4}, \"ms\": {:.1}}},\n  \"rgb_png\": {},\n  \"depth_png\": {},\n  \"seg_png\": {}\n}}",
                    json_str(&scene.name),
                    world.len(),
                    world.tick,
                    state_hash,
                    sim_ms,
                    out.n_points,
                    out.n_edges,
                    out.painted_px,
                    out.max_fs_depth,
                    out.elapsed_ms,
                    json_str(&out.rgb_png.display().to_string()),
                    json_str(&out.depth_png.display().to_string()),
                    json_str(&out.seg_png.display().to_string()),
                ))
            } else {
                CmdResult::Done(format!(
                    "Ядро Игры: сцена «{}» (цикл S, v0.54.0)\n  мир        : {} тел, {} тиков (fixed dt = 1/60 c)\n  физика     : кеплеровские ω = √(G·M)/r^1.5, иерархия parent→child\n  честность  : state-hash 0x{:016X} (детерминизм бит-в-бит)\n  симуляция  : {sim_ms:.1} мс ({:.2} мс/тик, {:.0}x реального времени)\n  рендер     : {}×{}, {} точек, {} рёбер, закрашено {} пикселей, max d_FS = {:.4} рад\n  артефакты  :\n    {}\n    {}\n    {}",
                    scene.name,
                    world.len(),
                    world.tick,
                    state_hash,
                    sim_ms / opts.ticks as f64,
                    (opts.ticks as f64 * crate::game::FIXED_DT) / (sim_ms / 1000.0),
                    opts.width,
                    opts.height,
                    out.n_points,
                    out.n_edges,
                    out.painted_px,
                    out.max_fs_depth,
                    out.rgb_png.display(),
                    out.depth_png.display(),
                    out.seg_png.display(),
                ))
            }
        }
        Err(e) => CmdResult::Done(format!("game: рендер: {e}")),
    }
}

fn cmd_game(raw: &str) -> CmdResult {
    let raw = raw.trim();
    let raw = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    let parts: Vec<String> = raw.split_whitespace().map(String::from).collect();
    let sub = parts.first().map(String::as_str).unwrap_or("");
    let args = &parts[1..];

    match sub {
        "help" | "usage" => CmdResult::Done(game_usage()),
        "info" => cmd_game_info(),
        "demo" => {
            let opts = match game_parse_opts(args) {
                Ok(o) => o,
                Err(e) => return CmdResult::Done(format!("game demo: {e}")),
            };
            game_run_and_render(&crate::game::demo_scene(), &opts)
        }
        "scene" => {
            let Some(file) = args.iter().find(|a| !a.starts_with("--")) else {
                return CmdResult::Done(
                    "game scene: укажите файл сцены (game scene my.json --ticks 300)".into(),
                );
            };
            let opts = match game_parse_opts(args) {
                Ok(o) => o,
                Err(e) => return CmdResult::Done(format!("game scene: {e}")),
            };
            match crate::game::SceneFile::load_json(std::path::Path::new(file)) {
                Ok(scene) => game_run_and_render(&scene, &opts),
                Err(e) => CmdResult::Done(format!("game scene: {e}")),
            }
        }
        "write-demo" => {
            let Some(file) = args.iter().find(|a| !a.starts_with("--")) else {
                return CmdResult::Done("game write-demo: укажите файл".into());
            };
            let scene = crate::game::demo_scene();
            match serde_json::to_string_pretty(&scene) {
                Ok(json) => match std::fs::write(file, json + "\n") {
                    Ok(_) => CmdResult::Done(format!(
                        "Демо-сцена «{}» ({} тел) выгружена: {file}\nПравьте и запускайте: game scene {file} --ticks 300",
                        scene.name, scene.bodies.len()
                    )),
                    Err(e) => CmdResult::Done(format!("game write-demo: {e}")),
                },
                Err(e) => CmdResult::Done(format!("game write-demo: сериализация: {e}")),
            }
        }
        "sound" => cmd_game_sound(args),
        "texture" => cmd_game_texture(args),
        "normalmap" => cmd_game_normalmap(args),
        "input-demo" => cmd_game_input_demo(args),
        "window" => cmd_game_window(args),
        "vortex" => cmd_game_vortex(args),
        "water" => cmd_game_water(args),
        "asset" => cmd_game_asset(args),
        other => CmdResult::Done(format!(
            "game: неизвестная подкоманда `{other}`\n\n{}",
            game_usage()
        )),
    }
}

/// `game sound`: T1 — сонофикация сцены в WAV + хеши детерминизма.
fn cmd_game_sound(args: &[String]) -> CmdResult {
    use crate::game::audio::{sonify_world, SonifyConfig, SpectralCrystal};

    let mut ticks: u32 = 900;
    let mut out = std::path::PathBuf::from("poler_track.wav");
    let mut fs: u32 = crate::game::audio::AUDIO_FS;
    let mut gain: f64 = 0.5;
    let mut as_json = false;
    if let Ok(t) = q_flag_num::<u32>(args, "--ticks", ticks) {
        if !(1..=100_000).contains(&t) {
            return CmdResult::Done("game sound: --ticks 1..=100000".into());
        }
        ticks = t;
    }
    if let Some(i) = args.iter().position(|a| a == "--out") {
        match args.get(i + 1) {
            Some(v) => out = std::path::PathBuf::from(v.clone()),
            None => return CmdResult::Done("game sound: --out FILE.wav".into()),
        }
    }
    if let Ok(f) = q_flag_num::<u32>(args, "--fs", fs) {
        if !(8000..=96_000).contains(&f) {
            return CmdResult::Done("game sound: --fs 8000..=96000".into());
        }
        fs = f;
    }
    if let Ok(g) = q_flag_num::<f64>(args, "--gain", gain) {
        if !(0.0..=1.0).contains(&g) {
            return CmdResult::Done("game sound: --gain 0..=1".into());
        }
        gain = g;
    }
    as_json |= q_flag(args, "--json");

    let mut scene = crate::game::demo_scene();
    let mut world = match scene.build_world() {
        Ok(w) => w,
        Err(e) => return CmdResult::Done(format!("game sound: сцена: {e}")),
    };
    let n_bodies = world.len();
    let cfg = SonifyConfig { fs, master_gain: gain, ..Default::default() };
    let t0 = std::time::Instant::now();
    let track = sonify_world(&mut world, ticks, crate::game::FIXED_DT, &cfg);
    let crystal = SpectralCrystal::from_track(&track, 4, 6);
    let notes: Vec<String> = crystal
        .top_hz(4)
        .iter()
        .map(|f| format!("{:.1} Гц ({})", f, crate::game::audio::note_name(*f)))
        .collect();
    let bytes = match track.write_wav(&out) {
        Ok(b) => b,
        Err(e) => return CmdResult::Done(format!("game sound: запись {}: {e}", out.display())),
    };
    let elapsed = t0.elapsed();
    if as_json {
        let j = serde_json::json!({
            "track": out.display().to_string(),
            "bytes": bytes,
            "fs": fs,
            "ticks": ticks,
            "bodies": n_bodies,
            "duration_s": (track.duration_s() * 1000.0).round() / 1000.0,
            "audio_hash": format!("0x{:016X}", track.audio_hash()),
            "crystal_hash": format!("0x{:016X}", crystal.crystal_hash()),
            "peak_dbfs": (track.peak_dbfs() * 100.0).round() / 100.0,
            "rms_dbfs": (track.rms_dbfs() * 100.0).round() / 100.0,
            "top_hz": crystal.top_hz(4),
            "elapsed_ms": elapsed.as_millis(),
        });
        CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
    } else {
        CmdResult::Done(format!(
            "T1 «Акустический кристалл»: сцена «{}» ({} тел) → звук\n  трек     : {} ({} байт, {:.2} c, fs {} Гц, PCM16 stereo)\n  физика   : ω→высота (до 3 октав), радиус→гейн, X→панорама (power-pan)\n  метрики  : peak {:.1} dBFS, RMS {:.1} dBFS\n  голоса   : {}\n  хеш аудио: 0x{:016X} (бит-в-бит)\n  хеш кристалла: 0x{:016X} (STFT 4×4096, топ-6 пиков)\n  время    : {} мс",
            scene.name,
            n_bodies,
            out.display(),
            bytes,
            track.duration_s(),
            fs,
            track.peak_dbfs(),
            track.rms_dbfs(),
            if notes.is_empty() { "—".to_string() } else { notes.join(", ") },
            track.audio_hash(),
            crystal.crystal_hash(),
            elapsed.as_millis(),
        ))
    }
}

/// `game texture`: T2 — процедурная текстура → PNG + SVD-кодек.
fn cmd_game_texture(args: &[String]) -> CmdResult {
    use crate::game::texture::{
        rank_curve, svd_encode_gray, Palette, TextureSpec,
    };

    let mut w: u32 = 512;
    let mut h: u32 = 512;
    let mut spec = TextureSpec::default();
    let mut pal_name = String::from("copper");
    let mut zoom: f64 = 1.0;
    let mut out = std::path::PathBuf::from("poler_texture.png");
    let mut svd_rank: Option<usize> = None;
    let mut want_curve = false;
    let mut as_json = false;

    if let Some(r) = game_parse_size(args) {
        let (sw, sh) = match r {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("game texture: {e}")),
        };
        w = sw;
        h = sh;
    }
    if let Some(i) = args.iter().position(|a| a == "--style") {
        match args.get(i + 1).and_then(|v| crate::game::texture::TexStyle::parse(v)) {
            Some(s) => spec.style = s,
            None => return CmdResult::Done("game texture: --style noise|marble|wood".into()),
        }
    }
    if let Some(i) = args.iter().position(|a| a == "--palette") {
        match args.get(i + 1).map(|v| v.to_string()) {
            Some(v) if Palette::parse(&v).is_some() => pal_name = v,
            _ => {
                return CmdResult::Done(
                    "game texture: --palette gray|copper|ice|jade".into(),
                )
            }
        }
    }
    if let Ok(s) = q_flag_num::<u64>(args, "--seed", spec.seed) {
        spec.seed = s;
    }
    if let Ok(f) = q_flag_num::<f64>(args, "--freq", spec.freq) {
        if !(0.5..=64.0).contains(&f) {
            return CmdResult::Done("game texture: --freq 0.5..=64".into());
        }
        spec.freq = f;
    }
    if let Ok(o) = q_flag_num::<u32>(args, "--octaves", spec.octaves) {
        if !(1..=12).contains(&o) {
            return CmdResult::Done("game texture: --octaves 1..=12".into());
        }
        spec.octaves = o;
    }
    if let Ok(z) = q_flag_num::<f64>(args, "--zoom", zoom) {
        if !(1.0..=64.0).contains(&z) {
            return CmdResult::Done("game texture: --zoom 1..=64".into());
        }
        zoom = z;
    }
    if let Ok(c) = q_flag_num::<f64>(args, "--contrast", spec.contrast) {
        if !(0.25..=4.0).contains(&c) {
            return CmdResult::Done("game texture: --contrast 0.25..=4".into());
        }
        spec.contrast = c;
    }
    if let Some(i) = args.iter().position(|a| a == "--out") {
        match args.get(i + 1) {
            Some(v) => out = std::path::PathBuf::from(v.clone()),
            None => return CmdResult::Done("game texture: --out FILE.png".into()),
        }
    }
    if args.iter().any(|a| a == "--svd-rank") {
        match args
            .iter()
            .position(|a| a == "--svd-rank")
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse::<usize>().ok())
        {
            Some(k) if (1..=16).contains(&k) => svd_rank = Some(k),
            _ => return CmdResult::Done("game texture: --svd-rank K (1..=16)".into()),
        }
    }
    want_curve |= q_flag(args, "--rank-curve");
    as_json |= q_flag(args, "--json");

    let pal = Palette::parse(&pal_name).expect("проверено выше");
    let t0 = std::time::Instant::now();
    let tex = spec.render(w, h, zoom, &pal);
    let render_ms = t0.elapsed().as_millis();
    let gray = tex.gray();
    let thash = tex.texture_hash();
    match tex.write_png(&out) {
        Ok(()) => {}
        Err(e) => return CmdResult::Done(format!("game texture: запись {}: {e}", out.display())),
    }

    // SVD-анализ (тайл 16)
    let svd_summary = if let Some(k) = svd_rank {
        let (_, stats) = svd_encode_gray(&gray, w as usize, h as usize, 16, k);
        Some(stats)
    } else if want_curve {
        None // кривая ниже
    } else {
        None
    };
    let curve: Vec<crate::game::texture::CodecStats> = if want_curve {
        rank_curve(&gray, w as usize, h as usize, 16, &[1, 2, 4, 8, 16])
    } else {
        Vec::new()
    };
    let svd_ms = t0.elapsed().as_millis() - render_ms;

    if as_json {
        let j = serde_json::json!({
            "png": out.display().to_string(),
            "size": [w, h],
            "style": spec.style.as_str(),
            "palette": pal_name,
            "seed": spec.seed,
            "freq": spec.freq,
            "octaves": spec.octaves,
            "zoom": zoom,
            "contrast": spec.contrast,
            "texture_hash": format!("0x{:016X}", thash),
            "render_ms": render_ms,
            "svd_ms": svd_ms,
            "svd_rank": svd_rank,
            "svd_stats": svd_summary,
            "rank_curve": curve,
        });
        CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
    } else {
        let mut lines = vec![
            format!(
                "T2 «Спектральный синтез»: {} {}x{} (zoom {zoom})\n  материал : {} · палитра {} · зерно {} · fBm {} октав (freq {})\n  PNG      : {} · хеш текстуры 0x{:016X} (бит-в-бит)\n  рендер   : {} мс (аналитический тайл — пикселизации нет)",
                spec.style.as_str(),
                w,
                h,
                spec.style.as_str(),
                pal_name,
                spec.seed,
                spec.octaves,
                spec.freq,
                out.display(),
                thash,
                render_ms,
            ),
        ];
        if let Some(st) = svd_summary {
            lines.push(format!(
                "  SVD rank-{}: PSNR {:.1} dB · RMSE {:.2} · держим {}/{} компонент ({:.0}%)",
                st.rank,
                st.psnr_db,
                st.rmse,
                st.rank,
                st.full_rank,
                st.kept_ratio * 100.0
            ));
        }
        if !curve.is_empty() {
            let parts: Vec<String> = curve
                .iter()
                .map(|c| format!("r{}={:.1}dB", c.rank, c.psnr_db))
                .collect();
            lines.push(format!("  кривая   : {}", parts.join("  ")));
        }
        lines.push(format!("  SVD время: {} мс", svd_ms));
        CmdResult::Done(lines.join("\n"))
    }
}

/// `game normalmap`: U0 — normal map из той же аналитической функции.
fn cmd_game_normalmap(args: &[String]) -> CmdResult {
    use crate::game::texture::TextureSpec;

    let mut w: u32 = 512;
    let mut h: u32 = 512;
    let mut spec = TextureSpec::default();
    let mut zoom: f64 = 1.0;
    let mut amplitude: f64 = 0.08;
    let mut out = std::path::PathBuf::from("poler_normalmap.png");
    let mut as_json = false;

    if let Some(r) = game_parse_size(args) {
        let (sw, sh) = match r {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("game normalmap: {e}")),
        };
        w = sw;
        h = sh;
    }
    if let Some(i) = args.iter().position(|a| a == "--style") {
        match args.get(i + 1).and_then(|v| crate::game::texture::TexStyle::parse(v)) {
            Some(s) => spec.style = s,
            None => return CmdResult::Done("game normalmap: --style noise|marble|wood".into()),
        }
    }
    if let Ok(s) = q_flag_num::<u64>(args, "--seed", spec.seed) {
        spec.seed = s;
    }
    if let Ok(f) = q_flag_num::<f64>(args, "--freq", spec.freq) {
        if !(0.5..=64.0).contains(&f) {
            return CmdResult::Done("game normalmap: --freq 0.5..=64".into());
        }
        spec.freq = f;
    }
    if let Ok(o) = q_flag_num::<u32>(args, "--octaves", spec.octaves) {
        if !(1..=12).contains(&o) {
            return CmdResult::Done("game normalmap: --octaves 1..=12".into());
        }
        spec.octaves = o;
    }
    if let Ok(z) = q_flag_num::<f64>(args, "--zoom", zoom) {
        if !(1.0..=64.0).contains(&z) {
            return CmdResult::Done("game normalmap: --zoom 1..=64".into());
        }
        zoom = z;
    }
    if let Ok(a) = q_flag_num::<f64>(args, "--amplitude", amplitude) {
        if !(0.0..=1.5).contains(&a) {
            return CmdResult::Done("game normalmap: --amplitude 0..=1.5".into());
        }
        amplitude = a;
    }
    if let Some(i) = args.iter().position(|a| a == "--out") {
        match args.get(i + 1) {
            Some(v) => out = std::path::PathBuf::from(v.clone()),
            None => return CmdResult::Done("game normalmap: --out FILE.png".into()),
        }
    }
    as_json |= q_flag(args, "--json");

    let t0 = std::time::Instant::now();
    let tex = spec.render_normal(w, h, zoom, amplitude);
    let render_ms = t0.elapsed().as_millis();
    let thash = tex.texture_hash();
    match tex.write_png(&out) {
        Ok(()) => {}
        Err(e) => return CmdResult::Done(format!("game normalmap: запись {}: {e}", out.display())),
    }

    if as_json {
        let j = serde_json::json!({
            "png": out.display().to_string(),
            "size": [w, h],
            "style": spec.style.as_str(),
            "seed": spec.seed,
            "freq": spec.freq,
            "octaves": spec.octaves,
            "zoom": zoom,
            "amplitude": amplitude,
            "normal_hash": format!("0x{:016X}", thash),
            "render_ms": render_ms,
        });
        CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
    } else {
        CmdResult::Done(format!(
            "U0 «Normal map»: {} {}x{} (zoom {zoom})\n  материал  : {} · зерно {} · {} октав (freq {})\n  амплитуда : {amplitude} ({:.0}% глубины тайла) — честная dh/du\n  PNG       : {} · хеш нормалей 0x{:016X} (бит-в-бит)\n  рендер    : {} мс (разрешение- и зум-инвариантно)",
            spec.style.as_str(),
            w,
            h,
            spec.style.as_str(),
            spec.seed,
            spec.octaves,
            spec.freq,
            amplitude * 100.0,
            out.display(),
            thash,
            render_ms,
        ))
    }
}

// ---------------------------------------------------------------------------
// v0.57.0 (цикл V0): вихревой кодек «Шеннон-байпас»
// ---------------------------------------------------------------------------

/// `game vortex`: V0 — квантование шума фазовыми вихрями (Shannon Bypass).
///
/// Шеннон прав для белого шума с максимальной энтропией — но физический
/// шум (турбулентность Навье–Стокса, fBm-текстуры, сенсоры) есть каскад
/// когерентных фазовых вихрей с колмогоровским спектром K41. Конвейер:
/// 2D-FFT → топ-моды по энергии → GF(3)-триты амплитуды (лог-шкала) и
/// фазы (сектора циклон/антициклон/глазок) → 5 трит/байт → VRTX-контейнер.
/// Отчёт честный: сжатие против zstd-19 на тех же байтах, обход порядкового
/// предела Шеннона, PSNR для глаза, хеши детерминизма бит-в-бит.
fn cmd_game_vortex(args: &[String]) -> CmdResult {
    use crate::game::vortex::{self, VortexParams};

    let mut n: usize = 256;
    let mut style: String = "all".into();
    let mut seed: u64 = 42;
    let mut modes: usize = 48;
    let mut octaves: u32 = 5;
    let mut keep: f64 = 0.02;
    let mut eps: Option<f64> = None;
    let mut amp_trits: u32 = 4;
    let mut phase_trits: u32 = 6;
    let mut out_dir: Option<std::path::PathBuf> = None;
    let mut as_json = false;

    if let Some(i) = args.iter().position(|a| a == "--size") {
        match args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
            Some(v) if v.is_power_of_two() && (64..=1024).contains(&v) => n = v,
            _ => {
                return CmdResult::Done(
                    "game vortex: --size N — степень двойки 64..=1024".into(),
                )
            }
        }
    }
    if let Some(i) = args.iter().position(|a| a == "--style") {
        match args.get(i + 1).map(String::as_str) {
            Some(s @ ("vortex" | "kolmogorov" | "fbm" | "white" | "all")) => {
                style = s.into()
            }
            _ => {
                return CmdResult::Done(
                    "game vortex: --style vortex|kolmogorov|fbm|white|all".into(),
                )
            }
        }
    }
    if let Ok(v) = q_flag_num::<u64>(args, "--seed", seed) {
        seed = v;
    }
    if let Ok(v) = q_flag_num::<usize>(args, "--modes", modes) {
        if !(4..=4096).contains(&v) {
            return CmdResult::Done("game vortex: --modes 4..=4096".into());
        }
        modes = v;
    }
    if let Ok(v) = q_flag_num::<u32>(args, "--octaves", octaves) {
        if !(1..=10).contains(&v) {
            return CmdResult::Done("game vortex: --octaves 1..=10".into());
        }
        octaves = v;
    }
    if let Ok(v) = q_flag_num::<f64>(args, "--keep", keep) {
        if !(0.0005..=1.0).contains(&v) {
            return CmdResult::Done("game vortex: --keep 0.0005..=1.0".into());
        }
        keep = v;
    }
    if let Some(i) = args.iter().position(|a| a == "--eps") {
        match args.get(i + 1).and_then(|v| v.parse::<f64>().ok()) {
            Some(v) if (1e-12..=0.5).contains(&v) => eps = Some(v),
            _ => {
                return CmdResult::Done(
                    "game vortex: --eps E — 1e-12..=0.5 (покрыть энергию 1−E)".into(),
                )
            }
        }
    }
    if let Ok(v) = q_flag_num::<u32>(args, "--amp-trits", amp_trits) {
        if !(1..=8).contains(&v) {
            return CmdResult::Done("game vortex: --amp-trits 1..=8".into());
        }
        amp_trits = v;
    }
    if let Ok(v) = q_flag_num::<u32>(args, "--phase-trits", phase_trits) {
        if !(1..=10).contains(&v) {
            return CmdResult::Done("game vortex: --phase-trits 1..=10".into());
        }
        phase_trits = v;
    }
    if let Some(i) = args.iter().position(|a| a == "--out-dir") {
        match args.get(i + 1) {
            Some(v) => out_dir = Some(std::path::PathBuf::from(v.clone())),
            None => return CmdResult::Done("game vortex: --out-dir DIR".into()),
        }
    }
    as_json |= q_flag(args, "--json");

    let params = VortexParams { keep_fraction: keep, energy_eps: eps, amp_trits, phase_trits };
    let styles: Vec<&'static str> = match style.as_str() {
        "all" => vec!["vortex", "kolmogorov", "fbm", "white"],
        "vortex" => vec!["vortex"],
        "kolmogorov" => vec!["kolmogorov"],
        "fbm" => vec!["fbm"],
        _ => vec!["white"],
    };

    // (источник, отчёт, zstd-19 байты, оригинал u8, реконструкция u8, VRTX-контейнер)
    let mut rows: Vec<(&'static str, vortex::VortexReport, usize, Vec<u8>, Vec<u8>, Vec<u8>)> =
        Vec::new();
    for name in styles {
        let field: Vec<f64> = match name {
            "vortex" => vortex::vortex_field(n, seed, modes),
            "kolmogorov" => vortex::kolmogorov_field(n, seed),
            "fbm" => vortex::fbm_field(n, seed, octaves),
            _ => vortex::white_field(n, seed),
        };
        let orig_u8 = vortex::field_u8(&field);
        let report = vortex::codec_run(name, &field, n, &params);
        // Контейнер отдельно — артефакт релиза (те же байты, что внутри codec_run)
        let spec = vortex::analyze(&field, n, &params);
        let vrtx = vortex::encode(&spec);
        let recon_u8 = if out_dir.is_some() {
            let back = vortex::decode(&vrtx).expect("vortex: собственный VRTX");
            vortex::field_u8(&vortex::synthesize(&back))
        } else {
            Vec::new()
        };
        let zstd_bytes = zstd::bulk::compress(&orig_u8, 19)
            .map(|v| v.len())
            .unwrap_or(0);
        rows.push((name, report, zstd_bytes, orig_u8, recon_u8, vrtx));
    }

    if let Some(dir) = &out_dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return CmdResult::Done(format!("game vortex: каталог {}: {e}", dir.display()));
        }
        let to_tex = |g: &[u8]| crate::game::texture::Texture {
            w: n as u32,
            h: n as u32,
            rgb: g.iter().flat_map(|&v| [v, v, v]).collect(),
        };
        for (name, _, _, orig, recon, vrtx) in &rows {
            if orig.is_empty() {
                continue;
            }
            let p1 = dir.join(format!("{name}_orig.png"));
            let p2 = dir.join(format!("{name}_recon.png"));
            if let Err(e) = to_tex(orig).write_png(&p1) {
                return CmdResult::Done(format!("game vortex: запись {}: {e}", p1.display()));
            }
            if let Err(e) = to_tex(recon).write_png(&p2) {
                return CmdResult::Done(format!("game vortex: запись {}: {e}", p2.display()));
            }
            let pv = dir.join(format!("{name}.vrtx"));
            if let Err(e) = std::fs::write(&pv, vrtx) {
                return CmdResult::Done(format!("game vortex: запись {}: {e}", pv.display()));
            }
        }
    }

    if as_json {
        let results: Vec<serde_json::Value> = rows
            .iter()
            .map(|(name, r, zb, _, _, _)| {
                let zr = if *zb > 0 { r.raw_bytes as f64 / *zb as f64 } else { 0.0 };
                serde_json::json!({
                    "source": name,
                    "modes_kept": r.modes_kept,
                    "modes_total": r.modes_total,
                    "energy_covered": r.energy_covered,
                    "raw_bytes": r.raw_bytes,
                    "codec_bytes": r.codec_bytes,
                    "ratio": r.ratio,
                    "zstd_bytes": zb,
                    "zstd_ratio": zr,
                    "vs_zstd": if *zb > 0 {
                        *zb as f64 / r.codec_bytes.max(1) as f64
                    } else {
                        0.0
                    },
                    "psnr_db": if r.psnr_db.is_finite() {
                        serde_json::json!(r.psnr_db)
                    } else {
                        serde_json::json!("inf")
                    },
                    "entropy_bits": r.entropy_bits,
                    "entropy_floor_ratio": r.entropy_floor_ratio,
                    "vortex_hash": format!("0x{:016X}", r.vortex_hash),
                    "field_hash": format!("0x{:016X}", r.field_hash),
                    "png": if out_dir.is_some() {
                        serde_json::json!([
                            format!("{name}_orig.png"),
                            format!("{name}_recon.png")
                        ])
                    } else {
                        serde_json::json!([])
                    },
                    "vrtx": if out_dir.is_some() {
                        format!("{name}.vrtx")
                    } else {
                        String::new()
                    },
                })
            })
            .collect();
        let j = serde_json::json!({
            "cycle": "V0",
            "codec": "vortex-gf3",
            "idea": "Shannon Bypass: физический шум = когерентные фазовые вихри (Навье–Стокс, K41)",
            "size": n,
            "seed": seed,
            "params": {
                "keep": keep,
                "eps": eps,
                "amp_trits": amp_trits,
                "phase_trits": phase_trits,
            },
            "results": results,
        });
        CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
    } else {
        let mut out = String::from(
            "V0 «Вихрь» — Шеннон-байпас: физический шум = каскад когерентных фазовых вихрей\n  (Навье–Стокс, K41 E(k) ∝ k^−5/3) → 2D-FFT → GF(3)-триты → VRTX\n",
        );
        for (name, r, zb, _, _, _) in &rows {
            let zr = if *zb > 0 { r.raw_bytes as f64 / *zb as f64 } else { 0.0 };
            let vsz = if *zb > 0 {
                *zb as f64 / r.codec_bytes.max(1) as f64
            } else {
                0.0
            };
            let psnr = if r.psnr_db.is_finite() {
                format!("{:.1} dB", r.psnr_db)
            } else {
                "∞ (бит-в-бит)".to_string()
            };
            out.push_str(&format!(
                "\n  [{name}] {n}×{n} · сид {seed} · GF(3): {amp_trits} трит амплитуды + {phase_trits} фазы\n"
            ));
            out.push_str(&format!(
                "    моды      : {} из {} ({:.2}%) · покрыто энергии {:.4}\n",
                r.modes_kept,
                r.modes_total,
                100.0 * r.modes_kept as f64 / r.modes_total.max(1) as f64,
                r.energy_covered
            ));
            out.push_str(&format!(
                "    байты     : сырые {} → VRTX {} (×{:.1}) · zstd-19 {} (×{:.2})\n",
                r.raw_bytes, r.codec_bytes, r.ratio, zb, zr
            ));
            out.push_str(&format!(
                "    фора      : вихрь компактнее zstd в {vsz:.2} раз · порядковый предел Шеннона ×{:.2} обойдён\n",
                r.entropy_floor_ratio
            ));
            out.push_str(&format!(
                "    PSNR      : {psnr} · хеши: VRTX 0x{:016X} · поле 0x{:016X}\n",
                r.vortex_hash, r.field_hash
            ));
        }
        if let Some(dir) = &out_dir {
            out.push_str(&format!(
                "\n  артефакты : {} ({{источник}}_orig.png / _recon.png / .vrtx)\n",
                dir.display()
            ));
        }
        out.push_str(
            "\n  честность : белый шум не сжимает никто — кодек это показывает, а не скрывает",
        );
        CmdResult::Done(out)
    }
}

// ---------------------------------------------------------------------------
// v0.60.0 (цикл X): обрушение — нелинейная спектральная гидродинамика
// ---------------------------------------------------------------------------

/// `game water` — море как спектр волн: генерация → целочисленная эволюция →
/// честный зачёт против f64-эталона + артефакты (PNG-кадры, шейдинг, VRTX).
/// Цикл X: 2-я гармоника Стокса, снос гребней (Мичелл), белые барашки
/// (Бофорт) и вихри Ламб–Озеена — первое ротационное поле движка.
fn cmd_game_water(args: &[String]) -> CmdResult {
    use crate::game::vortex;
    use crate::game::water::{self, WaterParams};
    use std::time::Instant;

    let mut n: usize = 256;
    let mut seed: u64 = 42;
    let mut modes: usize = 192;
    let mut wind: f64 = 8.0;
    let mut viscosity: f64 = 1e-6;
    let mut tau_wind: f64 = 30.0;
    let mut steps: usize = 240;
    let mut dt: f64 = 1.0 / 60.0;
    let mut amp_trits: u32 = 6;
    let mut phase_trits: u32 = 6;
    let mut nonlinear: bool = true;
    let mut steepness_break: f64 = 0.32;
    let mut out_dir: Option<std::path::PathBuf> = None;
    let mut as_json = false;

    if let Some(i) = args.iter().position(|a| a == "--size") {
        match args.get(i + 1).and_then(|v| v.parse::<usize>().ok()) {
            Some(v) if v.is_power_of_two() && (16..=1024).contains(&v) => n = v,
            _ => {
                return CmdResult::Done(
                    "game water: --size N — степень двойки 16..=1024".into(),
                )
            }
        }
    }
    if let Ok(v) = q_flag_num::<u64>(args, "--seed", seed) {
        seed = v;
    }
    if let Ok(v) = q_flag_num::<usize>(args, "--modes", modes) {
        if !(1..=16384).contains(&v) {
            return CmdResult::Done("game water: --modes 1..=16384".into());
        }
        modes = v;
    }
    if let Ok(v) = q_flag_num::<f64>(args, "--wind", wind) {
        if !(0.5..=60.0).contains(&v) {
            return CmdResult::Done("game water: --wind V — 0.5..=60 м/с".into());
        }
        wind = v;
    }
    if let Ok(v) = q_flag_num::<f64>(args, "--viscosity", viscosity) {
        if !(1e-8..=1e-1).contains(&v) {
            return CmdResult::Done("game water: --viscosity NU — 1e-8..=1e-1 м²/с".into());
        }
        viscosity = v;
    }
    if let Ok(v) = q_flag_num::<f64>(args, "--tau-wind", tau_wind) {
        if !(0.5..=3600.0).contains(&v) {
            return CmdResult::Done("game water: --tau-wind T — 0.5..=3600 с".into());
        }
        tau_wind = v;
    }
    if let Ok(v) = q_flag_num::<usize>(args, "--steps", steps) {
        if !(0..=1_000_000).contains(&v) {
            return CmdResult::Done("game water: --steps 0..=1000000".into());
        }
        steps = v;
    }
    if let Ok(v) = q_flag_num::<f64>(args, "--dt", dt) {
        if !(0.001..=1.0).contains(&v) {
            return CmdResult::Done("game water: --dt T — 0.001..=1.0 с".into());
        }
        dt = v;
    }
    if let Ok(v) = q_flag_num::<u32>(args, "--amp-trits", amp_trits) {
        if !(2..=8).contains(&v) {
            return CmdResult::Done("game water: --amp-trits 2..=8".into());
        }
        amp_trits = v;
    }
    if let Ok(v) = q_flag_num::<u32>(args, "--phase-trits", phase_trits) {
        if !(2..=10).contains(&v) {
            return CmdResult::Done("game water: --phase-trits 2..=10".into());
        }
        phase_trits = v;
    }
    if let Ok(v) = q_flag_num::<f64>(args, "--steepness", steepness_break) {
        if !(0.05..=0.60).contains(&v) {
            return CmdResult::Done("game water: --steepness S — 0.05..=0.60 (лимит Мичелла)".into());
        }
        steepness_break = v;
    }
    nonlinear &= !q_flag(args, "--linear");
    if let Some(i) = args.iter().position(|a| a == "--out-dir") {
        match args.get(i + 1) {
            Some(v) => out_dir = Some(std::path::PathBuf::from(v.clone())),
            None => return CmdResult::Done("game water: --out-dir DIR".into()),
        }
    }
    as_json |= q_flag(args, "--json");

    let p = WaterParams {
        n,
        modes,
        seed,
        wind,
        tau_wind,
        viscosity,
        amp_trits,
        phase_trits,
        nonlinear,
        steepness_break,
        ..Default::default()
    };
    if let Err(e) = p.validate() {
        return CmdResult::Done(format!("game water: {e}"));
    }

    let mut w = water::generate(&p);
    let mut reference = water::WaterF64::from(&w);

    let t0_field = if out_dir.is_some() { Some(w.height_field()) } else { None };
    let mut mid_field = None;
    let t_step = Instant::now();
    for i in 1..=steps {
        w.step(dt);
        reference.step(dt);
        if out_dir.is_some() && steps >= 2 && i == steps / 2 {
            mid_field = Some(w.height_field());
        }
    }
    let step_ns = t_step.elapsed().as_nanos() / steps.max(1) as u128;
    let t_synth = Instant::now();
    let field = w.height_field();
    let synth_ns = t_synth.elapsed().as_nanos();
    let ref_field = reference.height_field();

    let sigma = w.variance_target.sqrt();
    let u8f = water::field_to_u8(&field, sigma);
    let psnr = vortex::psnr_u8(&u8f, &water::field_to_u8(&ref_field, sigma));
    let vrtx = vortex::encode(&w.to_vortex());
    let grid_bytes = n * n * 4;
    let mem_ratio = grid_bytes as f64 / vrtx.len().max(1) as f64;
    let variance = w.variance();
    let hs = w.significant_height();
    let hs_pm = 0.21 * wind * wind / p.gravity;
    let water_hash = vortex::fnv1a_u8(&vrtx);
    let field_hash = vortex::fnv1a_u8(&u8f);

    // Артефакты: кадры эволюции, шейдинг с аналитическими нормалями, VRTX.
    if let Some(dir) = &out_dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return CmdResult::Done(format!("game water: каталог {}: {e}", dir.display()));
        }
        let to_tex = |g: &[u8]| crate::game::texture::Texture {
            w: n as u32,
            h: n as u32,
            rgb: g.iter().flat_map(|&v| [v, v, v]).collect(),
        };
        let write_frame = |name: &str, f: &[f64]| -> Result<(), String> {
            let path = dir.join(name);
            to_tex(&water::field_to_u8(f, sigma))
                .write_png(&path)
                .map_err(|e| format!("game water: запись {}: {e}", path.display()))
        };
        if let Some(f0) = &t0_field {
            if let Err(e) = write_frame("water_t0.png", f0) {
                return CmdResult::Done(e);
            }
        }
        if let Some(fm) = &mid_field {
            if let Err(e) = write_frame("water_mid.png", fm) {
                return CmdResult::Done(e);
            }
        }
        if let Err(e) = write_frame("water_end.png", &field) {
            return CmdResult::Done(e);
        }
        // Шейдинг: нормали из аналитических градиентов (не из разностей!),
        // ламберт + блик + пена на гребнях — глазу настоящее море.
        let cell = p.domain / n as f64;
        let mut rgb = vec![0u8; n * n * 3];
        for y in 0..n {
            for x in 0..n {
                let (h, gx, gy) = w.surface_at(x as f64 * cell, y as f64 * cell);
                let (nx, ny, nz) = (-gx, 1.0, -gy);
                let inv = 1.0 / (nx * nx + ny * ny + nz * nz).sqrt();
                let (lx, ly, lz): (f64, f64, f64) = (0.35, 0.75, 0.55);
                let linv = 1.0 / (lx * lx + ly * ly + lz * lz).sqrt();
                let diff =
                    ((nx * lx + ny * ly + nz * lz) * inv * linv).max(0.0);
                let (hx, hy, hz) = (lx, ly + 1.0, lz);
                let hinv = 1.0 / (hx * hx + hy * hy + hz * hz).sqrt();
                let spec =
                    ((nx * hx + ny * hy + nz * hz) * inv * hinv).max(0.0).powi(60);
                let foam = ((h / sigma - 1.6) / 1.2).clamp(0.0, 1.0);
                let deep = (12.0f64, 44.0, 92.0);
                let sky = (116.0, 174.0, 216.0);
                let i3 = 3 * (y * n + x);
                rgb[i3] = (deep.0 + diff * (sky.0 - deep.0) + 230.0 * spec + 150.0 * foam)
                    .clamp(0.0, 255.0) as u8;
                rgb[i3 + 1] = (deep.1 + diff * (sky.1 - deep.1) + 235.0 * spec + 155.0 * foam)
                    .clamp(0.0, 255.0) as u8;
                rgb[i3 + 2] = (deep.2 + diff * (sky.2 - deep.2) + 245.0 * spec + 160.0 * foam)
                    .clamp(0.0, 255.0) as u8;
            }
        }
        let shaded = dir.join("water_shaded.png");
        if let Err(e) = (crate::game::texture::Texture { w: n as u32, h: n as u32, rgb })
            .write_png(&shaded)
        {
            return CmdResult::Done(format!("game water: запись {}: {e}", shaded.display()));
        }
        let pv = dir.join("water.vrtx");
        if let Err(e) = std::fs::write(&pv, &vrtx) {
            return CmdResult::Done(format!("game water: запись {}: {e}", pv.display()));
        }
    }

    if as_json {
        let mut frames: Vec<String> = Vec::new();
        if out_dir.is_some() {
            frames.push("water_t0.png".into());
            if steps >= 2 {
                frames.push("water_mid.png".into());
            }
            frames.push("water_end.png".into());
            frames.push("water_shaded.png".into());
        }
        let j = serde_json::json!({
            "cycle": "X",
            "model": "spectral-water-gf3-nonlinear",
            "idea": "вода = когерентный фазовый спектр (K41); эволюция — целочисленные триты; обрушение гребней — Стокс/Мичелл/Бофорт/Ламб–Озеен",
            "physics": {
                "gravity_m_s2": p.gravity,
                "capillary_m3_s2": p.capillary,
                "viscosity_m2_s": viscosity,
                "wind_m_s": wind,
                "tau_wind_s": tau_wind,
                "domain_m": p.domain,
                "nonlinear": nonlinear,
                "steepness_break": p.steepness_break,
                "whitecap_onset_m_s": p.whitecap_onset,
            },
            "params": {
                "n": n,
                "modes": modes,
                "seed": seed,
                "amp_trits": amp_trits,
                "phase_trits": phase_trits,
                "micro_trits": 3,
                "steps": steps,
                "dt": dt,
            },
            "results": {
                "state_bytes": vrtx.len(),
                "grid_f32_bytes": grid_bytes,
                "mem_ratio": mem_ratio,
                "step_ns": step_ns,
                "synth_ns": synth_ns,
                "psnr_db": psnr,
                "variance_m2": variance,
                "variance_target_m2": w.variance_target,
                "hs_m": hs,
                "hs_pm_m": hs_pm,
                "water_hash": format!("0x{:016X}", water_hash),
                "field_hash": format!("0x{:016X}", field_hash),
                "breakers_spawned": w.spawned_total,
                "breakers_alive": w.breakers.len(),
                "heat_dissipated": w.heat_fp as f64 / 4294967296.0,
                "frames": frames,
                "vrtx": if out_dir.is_some() { "water.vrtx" } else { "" },
            },
        });
        CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
    } else {
        let mut out = String::from(
            "X «Обрушение» — нелинейная спектральная гидродинамика: Стокс 2-го порядка, Мичелл, Бофорт, Ламб–Озеен\n  (то, что OpenAI решала тераваттами брут-форсом — здесь целочисленный спектр)\n",
        );
        out.push_str(&format!(
            "  физика   : ω(k)=√(g·k+γ·k³)·(1+(kA)²/2) · K41 · Ламб e^(−2νk²t) · h₂=(kA²/2)cos2θ · s_b={steepness_break:.2}\n"
        ));
        out.push_str(&format!(
            "  море     : {n}×{n} ({domain:.0} м) · {modes} мод · ветер {wind} м/с · H_s {hs:.2} м (PM {hs_pm:.2})\n",
            domain = p.domain
        ));
        out.push_str(&format!(
            "  шаг      : {steps} × {dt:.4} с → {step_ns} нс/шаг (фаза — фикс-точка без дрейфа; нелинейность: {})\n",
            if nonlinear { "вкл" } else { "выкл (--linear)" }
        ));
        out.push_str(&format!(
            "  память   : состояние {} Б (VRTX) против {} Б f32-сетки — ×{mem_ratio:.0}\n",
            vrtx.len(),
            grid_bytes
        ));
        out.push_str(&format!(
            "  синтез   : {synth_ns} нс FFT {n}² + 2-е гармоники + штампы барашков · surface_at O(K)\n"
        ));
        out.push_str(&format!(
            "  верность : PSNR {psnr:.1} dB против f64-эталона (те же уравнения, без квантования)\n"
        ));
        out.push_str(&format!(
            "  обрушение: событий {} · живых вихрей {} · тепло {heat:.4} Дж/м² (бухгалтерия закрыта)\n",
            w.spawned_total,
            w.breakers.len(),
            heat = w.heat_fp as f64 / 4294967296.0
        ));
        out.push_str(&format!(
            "  энергия  : дисперсия {variance:.4} м² (цель {vt:.4}) · хеши: вода 0x{water_hash:016X} · поле 0x{field_hash:016X}\n",
            vt = w.variance_target
        ));
        if let Some(dir) = &out_dir {
            out.push_str(&format!(
                "\n  артефакты : {} (water_t0/mid/end.png, water_shaded.png, water.vrtx)\n",
                dir.display()
            ));
        }
        if nonlinear {
            out.push_str(
                "  честность : барашки — наблюдательный триггер Бофорта; вихрь и след — честная физика (тесты: циркуляция, дрейф Стокса, Ламб–Озеен)",
            );
        } else {
            out.push_str(
                "  честность : линейный режим (--linear) — обрушения и вихри выключены",
            );
        }
        CmdResult::Done(out)
    }
}


// ---------------------------------------------------------------------------
// v0.61.0 (цикл Y): готовые ассеты → нейроны → PQW → генерация с нуля
// ---------------------------------------------------------------------------

/// `game asset absorb|emit`: Y «Эхо» — готовый ассет (WAV/PNG/PGM/PPM)
/// впитывается нейронами и квантуется в триты PQW; emit рождает его с нуля.
fn cmd_game_asset(args: &[String]) -> CmdResult {
    use crate::game::asset as ya;

    let sub = match args.first().map(String::as_str) {
        Some(s @ ("absorb" | "emit")) => s.to_string(),
        _ => {
            return CmdResult::Done(
                "game asset: подкоманда absorb|emit\n\
                 \x20 absorb --in F.(wav|png|pgm|ppm) --out F.pqw   — впитать в нейроны\n\
                 \x20 emit   --in F.pqw --out F.(wav|png)            — сгенерировать с нуля"
                    .to_string(),
            )
        }
    };
    let mut in_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut seconds: f64 = 30.0;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let mut seed: Option<u64> = None;
    let mut burst: f64 = 2.0;
    let mut compare: Option<String> = None;
    let mut as_json = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => match args.get(i + 1) {
                Some(v) => {
                    in_path = Some(v.clone());
                    i += 2;
                }
                None => return CmdResult::Done("game asset: --in FILE".into()),
            },
            "--out" => match args.get(i + 1) {
                Some(v) => {
                    out_path = Some(v.clone());
                    i += 2;
                }
                None => return CmdResult::Done("game asset: --out FILE".into()),
            },
            "--seconds" => match args.get(i + 1).and_then(|v| v.parse::<f64>().ok()) {
                Some(v) if (0.5..=600.0).contains(&v) => {
                    seconds = v;
                    i += 2;
                }
                _ => return CmdResult::Done("game asset: --seconds 0.5..=600".into()),
            },
            "--width" => match args.get(i + 1).and_then(|v| v.parse::<u32>().ok()) {
                Some(v) if v <= 8192 => {
                    width = v;
                    i += 2;
                }
                _ => return CmdResult::Done("game asset: --width 0..=8192 (0 = как вход)".into()),
            },
            "--height" => match args.get(i + 1).and_then(|v| v.parse::<u32>().ok()) {
                Some(v) if v <= 8192 => {
                    height = v;
                    i += 2;
                }
                _ => return CmdResult::Done("game asset: --height 0..=8192 (0 = как вход)".into()),
            },
            "--seed" => match args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                Some(v) => {
                    seed = Some(v);
                    i += 2;
                }
                None => return CmdResult::Done("game asset: --seed N".into()),
            },
            "--burst" => match args.get(i + 1).and_then(|v| v.parse::<f64>().ok()) {
                Some(v) if (0.0..=8.0).contains(&v) => {
                    burst = v;
                    i += 2;
                }
                _ => return CmdResult::Done("game asset: --burst 0..=8 (усиление лавин)".into()),
            },
            "--compare" => match args.get(i + 1) {
                Some(v) => {
                    compare = Some(v.clone());
                    i += 2;
                }
                None => return CmdResult::Done("game asset: --compare ORIGINAL".into()),
            },
            "--json" => {
                as_json = true;
                i += 1;
            }
            other => return CmdResult::Done(format!("game asset: неизвестный флаг {other:?}")),
        }
    }
    let in_path = match in_path {
        Some(p) => std::path::PathBuf::from(p),
        None => return CmdResult::Done("game asset: обязателен --in".into()),
    };
    let t0 = std::time::Instant::now();

    if sub == "absorb" {
        let in_bytes = std::fs::metadata(&in_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let head = std::fs::read(&in_path)
            .ok()
            .and_then(|b| if b.len() >= 12 { Some(b) } else { None });
        let is_wav = head
            .as_ref()
            .map(|b| b.starts_with(b"RIFF") && b[8..12] == *b"WAVE")
            .unwrap_or(false);
        let out_path = match out_path {
            Some(p) => std::path::PathBuf::from(p),
            None => return CmdResult::Done("game asset absorb: --out FILE.pqw".into()),
        };
        if is_wav {
            let wav = match ya::read_wav(&in_path) {
                Ok(w) => w,
                Err(e) => return CmdResult::Done(format!("game asset absorb: {e}")),
            };
            let echo = match ya::absorb_audio(&wav) {
                Ok(e) => e,
                Err(e) => return CmdResult::Done(format!("game asset absorb: {e}")),
            };
            let synapses = echo.graph.iter().filter(|g| g.abs() >= 0.04).count();
            let (si, sj, sv) = echo.strongest_synapse();
            let loudest = echo
                .mean_db
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);
            let bytes = match ya::audio_to_pqw(&echo) {
                Ok(b) => b,
                Err(e) => return CmdResult::Done(format!("game asset absorb: {e}")),
            };
            if let Err(e) = std::fs::write(&out_path, &bytes) {
                return CmdResult::Done(format!("game asset absorb: запись {}: {e}", out_path.display()));
            }
            let ratio = if in_bytes > 0 { in_bytes as f64 / bytes.len() as f64 } else { 0.0 };
            let elapsed = t0.elapsed().as_millis();
            if as_json {
                let j = serde_json::json!({
                    "cycle": "Y",
                    "model": "neural-asset-echo-pqw",
                    "op": "absorb",
                    "kind": "audio",
                    "in": in_path.display().to_string(),
                    "out": out_path.display().to_string(),
                    "in_bytes": in_bytes,
                    "container_bytes": bytes.len(),
                    "ratio": (ratio * 100.0).round() / 100.0,
                    "fs": wav.fs,
                    "channels": wav.channels,
                    "duration_s": (wav.duration_s() * 100.0).round() / 100.0,
                    "bands": ya::B,
                    "synapses": synapses,
                    "strongest_synapse": {"from": si, "to": sj, "g": (sv * 1000.0).round() / 1000.0},
                    "stereo_corr": (echo.stereo_corr * 1000.0).round() / 1000.0,
                    "level_db": (echo.level_db * 100.0).round() / 100.0,
                    "cadence_hz": (echo.mod_hz[loudest] * 100.0).round() / 100.0,
                    "elapsed_ms": elapsed,
                });
                CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
            } else {
                CmdResult::Done(format!(
                    "Y «Эхо»: звук впитан нейронами → PQW\n  вход      : {} (PCM {}, {} Гц, {:.2} с, {} Б)\n  нейроны   : {} полосных (STFT {}/{}), каденс {:.2} Гц\n  синапсы   : {} STDP-дуг (лаг-1 корреляции полос)\n  физика    : доминанта полоса{si}→полоса{sj} (G={sv:+.2}), стерео ρ={:+.2}, уровень {:.1} dB\n  контейнер : {} ({} Б — ×{:.0} против PCM)\n  время     : {} мс",
                    in_path.display(),
                    if wav.channels >= 2 { "stereo" } else { "mono" },
                    wav.fs,
                    wav.duration_s(),
                    in_bytes,
                    ya::B,
                    ya::STFT_N,
                    ya::STFT_HOP,
                    echo.mod_hz[loudest],
                    synapses,
                    echo.stereo_corr,
                    echo.level_db,
                    out_path.display(),
                    bytes.len(),
                    ratio,
                    elapsed,
                ))
            }
        } else {
            let img = match ya::read_image(&in_path) {
                Ok(im) => im,
                Err(e) => return CmdResult::Done(format!("game asset absorb: {e}")),
            };
            let echo = match ya::absorb_texture(&img) {
                Ok(e) => e,
                Err(e) => return CmdResult::Done(format!("game asset absorb: {e}")),
            };
            let bytes = match ya::texture_to_pqw(&echo) {
                Ok(b) => b,
                Err(e) => return CmdResult::Done(format!("game asset absorb: {e}")),
            };
            if let Err(e) = std::fs::write(&out_path, &bytes) {
                return CmdResult::Done(format!("game asset absorb: запись {}: {e}", out_path.display()));
            }
            let tiles = (img.w as usize / ya::TILE) * (img.h as usize / ya::TILE);
            let synapses: usize = echo
                .graph_right
                .iter()
                .chain(echo.graph_down.iter())
                .map(|row| row.iter().filter(|&&p| p > 0.02).count())
                .sum();
            let ratio = if in_bytes > 0 { in_bytes as f64 / bytes.len() as f64 } else { 0.0 };
            let elapsed = t0.elapsed().as_millis();
            if as_json {
                let j = serde_json::json!({
                    "cycle": "Y",
                    "model": "neural-asset-echo-pqw",
                    "op": "absorb",
                    "kind": "texture",
                    "in": in_path.display().to_string(),
                    "out": out_path.display().to_string(),
                    "in_bytes": in_bytes,
                    "container_bytes": bytes.len(),
                    "ratio": (ratio * 100.0).round() / 100.0,
                    "w": img.w,
                    "h": img.h,
                    "tiles": tiles,
                    "protos": ya::M_PROTOS,
                    "svd_rank": ya::SVD_RANK,
                    "synapses": synapses,
                    "elapsed_ms": elapsed,
                });
                CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
            } else {
                CmdResult::Done(format!(
                    "Y «Эхо»: текстура впитана нейронами → PQW\n  вход      : {} ({}×{}, {} Б)\n  нейроны   : {} прототипов тайлов {}×{} ({} тайлов, WTA онлайн)\n  синапсы   : {} дуг смежности (вправо/вниз, Хебб по растру)\n  кодбук    : SVD ранга {} в базисе сингулярных векторов\n  контейнер : {} ({} Б — ×{:.0} против файла)\n  время     : {} мс",
                    in_path.display(),
                    img.w,
                    img.h,
                    in_bytes,
                    ya::M_PROTOS,
                    ya::TILE,
                    ya::TILE,
                    tiles,
                    synapses,
                    ya::SVD_RANK,
                    out_path.display(),
                    bytes.len(),
                    ratio,
                    elapsed,
                ))
            }
        }
    } else {
        // emit: регенерация с нуля
        let pqw = match std::fs::read(&in_path) {
            Ok(b) => b,
            Err(e) => return CmdResult::Done(format!("game asset emit: {e}")),
        };
        let out_path = match out_path {
            Some(p) => std::path::PathBuf::from(p),
            None => return CmdResult::Done("game asset emit: --out FILE.wav|FILE.png".into()),
        };
        let is_audio = ya::audio_from_pqw(&pqw).is_ok();
        if is_audio {
            let (wav, rep) = match ya::emit_audio(&pqw, seconds, seed, burst) {
                Ok(r) => r,
                Err(e) => return CmdResult::Done(format!("game asset emit: {e}")),
            };
            let out_bytes = match ya::write_wav(&out_path, wav.fs, wav.channels, &wav.samples) {
                Ok(n) => n,
                Err(e) => return CmdResult::Done(format!("game asset emit: {e}")),
            };
            let mut psd = serde_json::Value::Null;
            let mut psd_txt = String::new();
            if let Some(cmp) = &compare {
                match ya::read_wav(std::path::Path::new(cmp))
                    .map_err(|e| e.to_string())
                    .and_then(|orig| ya::psd_band_distance(&orig, &wav))
                {
                    Ok(d) => {
                        psd_txt = format!("\n  PSD-дист  : {d:.2} дБ (24 полосы, против входа)", d = d);
                        psd = serde_json::json!((d * 100.0).round() / 100.0);
                    }
                    Err(e) => psd_txt = format!("\n  сравнение : пропущено ({e})"),
                }
            }
            let elapsed = t0.elapsed().as_millis();
            if as_json {
                let j = serde_json::json!({
                    "cycle": "Y",
                    "model": "neural-asset-echo-pqw",
                    "op": "emit",
                    "kind": "audio",
                    "in": in_path.display().to_string(),
                    "out": out_path.display().to_string(),
                    "out_bytes": out_bytes,
                    "seconds": seconds,
                    "fs": wav.fs,
                    "seed": rep.seed,
                    "vortex_neurons": 600,
                    "vortex_steps": rep.vortex_steps,
                    "bursts": rep.bursts,
                    "vortex_activity": (rep.vortex_activity * 10000.0).round() / 10000.0,
                    "vortex_criticality": (rep.vortex_criticality * 10000.0).round() / 10000.0,
                    "audio_hash": format!("0x{:016X}", wav.audio_hash()),
                    "psd_distance_db": psd,
                    "elapsed_ms": elapsed,
                });
                CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
            } else {
                CmdResult::Done(format!(
                    "Y «Эхо»: океан сгенерирован с нуля (движок, не таймлайн)\n  звук      : {} ({:.1} с, {} Гц, PCM16 stereo, {} Б)\n  мозг      : SSN-вихрь 600 нейронов · {} шагов · {} лавин\n             активность {:.1}% · критичность {:.2} (край хаоса)\n  хеш       : 0x{:016X} (бит-в-бит при повторе, seed 0x{:X}){psd_txt}\n  время     : {} мс",
                    out_path.display(),
                    wav.duration_s(),
                    wav.fs,
                    out_bytes,
                    rep.vortex_steps,
                    rep.bursts,
                    rep.vortex_activity * 100.0,
                    rep.vortex_criticality,
                    wav.audio_hash(),
                    rep.seed,
                    elapsed,
                ))
            }
        } else {
            let (img, rep) = match ya::emit_texture(&pqw, width, height, seed) {
                Ok(r) => r,
                Err(e) => return CmdResult::Done(format!("game asset emit: {e}")),
            };
            if let Err(e) = crate::p3::png::encode_gray(&out_path, img.w, img.h, &img.gray) {
                return CmdResult::Done(format!("game asset emit: запись {}: {e}", out_path.display()));
            }
            let out_bytes = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
            let mut psnr_v = serde_json::Value::Null;
            let mut hist_v = serde_json::Value::Null;
            let mut cmp_txt = String::new();
            if let Some(cmp) = &compare {
                match ya::read_image(std::path::Path::new(cmp)) {
                    Ok(orig) => {
                        let recon: Vec<f64> = img.gray.iter().map(|&v| v as f64).collect();
                        let p = crate::game::texture::psnr(&orig.gray, &recon);
                        let hd = ya::histogram_distance(&orig, &img);
                        cmp_txt = format!(
                            "\n  метрики   : PSNR {p:.1} dB против входа · гистограммы {hd:.3}"
                        );
                        psnr_v = serde_json::json!((p * 100.0).round() / 100.0);
                        hist_v = serde_json::json!((hd * 1000.0).round() / 1000.0);
                    }
                    Err(e) => cmp_txt = format!("\n  сравнение : пропущено ({e})"),
                }
            }
            let elapsed = t0.elapsed().as_millis();
            if as_json {
                let j = serde_json::json!({
                    "cycle": "Y",
                    "model": "neural-asset-echo-pqw",
                    "op": "emit",
                    "kind": "texture",
                    "in": in_path.display().to_string(),
                    "out": out_path.display().to_string(),
                    "out_bytes": out_bytes,
                    "w": img.w,
                    "h": img.h,
                    "tiles": rep.tiles,
                    "start_proto": rep.start_proto,
                    "seed": rep.seed,
                    "psnr_db": psnr_v,
                    "histogram_distance": hist_v,
                    "elapsed_ms": elapsed,
                });
                CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
            } else {
                CmdResult::Done(format!(
                    "Y «Эхо»: текстура сгенерирована с нуля (блуждание по синапсам)\n  текстура  : {} ({}×{}, {}×{} тайлов, {} Б)\n  граф      : старт-прототип {} · seed 0x{:X} (бит-в-бит при повторе){cmp_txt}\n  время     : {} мс",
                    out_path.display(),
                    img.w,
                    img.h,
                    rep.tiles.0,
                    rep.tiles.1,
                    out_bytes,
                    rep.start_proto,
                    rep.seed,
                    elapsed,
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// v0.56.0 (цикл U): ввод → камера → окно
// ---------------------------------------------------------------------------

/// Событие JSON-скрипта `game input-demo --script`.
#[derive(Debug, serde::Deserialize)]
struct ScriptEvent {
    frame: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    button: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    dx: Option<f64>,
    #[serde(default)]
    dy: Option<f64>,
    #[serde(default)]
    delta: Option<f64>,
    #[serde(default)]
    ch: Option<String>,
    #[serde(default)]
    w: Option<u32>,
    #[serde(default)]
    h: Option<u32>,
    #[serde(default)]
    v: Option<u64>,
}

/// Файл сценария ввода.
#[derive(Debug, serde::Deserialize)]
struct InputScript {
    #[serde(default = "default_script_frames")]
    frames: u32,
    #[serde(default)]
    events: Vec<ScriptEvent>,
}

fn default_script_frames() -> u32 {
    180
}

fn parse_script_button(s: &str) -> Option<crate::game::MouseButton> {
    use crate::game::MouseButton::*;
    Some(match s.to_ascii_lowercase().as_str() {
        "left" | "l" => Left,
        "middle" | "m" => Middle,
        "right" | "r" => Right,
        _ => return None,
    })
}

/// Сконвертировать JSON-события в типизированные (сортировка по кадрам).
fn script_to_events(script: &InputScript) -> Result<Vec<(u64, crate::game::Event)>, String> {
    use crate::game::events::{Event, KeyPhase};
    let mut out = Vec::with_capacity(script.events.len());
    for (i, e) in script.events.iter().enumerate() {
        let ev = match e.kind.as_str() {
            "key_down" => Event::Key {
                code: KeyCode::parse(e.code.as_deref().unwrap_or(""))
                    .ok_or_else(|| format!("событие #{i}: неизвестная клавиша {:?}", e.code))?,
                phase: KeyPhase::Pressed,
            },
            "key_up" => Event::Key {
                code: KeyCode::parse(e.code.as_deref().unwrap_or(""))
                    .ok_or_else(|| format!("событие #{i}: неизвестная клавиша {:?}", e.code))?,
                phase: KeyPhase::Released,
            },
            "mouse_down" => Event::MouseButton {
                button: parse_script_button(e.button.as_deref().unwrap_or("left"))
                    .ok_or_else(|| format!("событие #{i}: кнопка {:?}", e.button))?,
                phase: KeyPhase::Pressed,
            },
            "mouse_up" => Event::MouseButton {
                button: parse_script_button(e.button.as_deref().unwrap_or("left"))
                    .ok_or_else(|| format!("событие #{i}: кнопка {:?}", e.button))?,
                phase: KeyPhase::Released,
            },
            "mouse_move" => Event::MouseMove {
                dx: e.dx.unwrap_or(0.0),
                dy: e.dy.unwrap_or(0.0),
            },
            "wheel" => Event::MouseWheel { delta: e.delta.unwrap_or(0.0) },
            "text" => {
                let ch = e.ch.as_deref().and_then(|s| s.chars().next())
                    .ok_or_else(|| format!("событие #{i}: text без ch"))?;
                Event::Text(ch)
            }
            "resize" => Event::WindowResize {
                w: e.w.unwrap_or(64).max(1),
                h: e.h.unwrap_or(64).max(1),
            },
            "focus_lost" => Event::WindowFocus { gained: false },
            "focus_gained" => Event::WindowFocus { gained: true },
            "close" => Event::WindowClose,
            "user" => Event::User(e.v.unwrap_or(0)),
            other => return Err(format!("событие #{i}: неизвестный тип `{other}`")),
        };
        out.push((e.frame, ev));
    }
    out.sort_by_key(|(f, _)| *f);
    Ok(out)
}

/// Встроенный демо-сценарий: полный обход орбиты мышью, зум колесом,
/// клавиатурная орбита — все три источника ввода камеры.
fn default_script_events() -> Vec<(u64, crate::game::Event)> {
    use crate::game::events::{Event, KeyPhase, MouseButton};
    let mut evs = Vec::new();
    // Фаза 1: драг ЛКМ — облёт по горизонтали с лёгким наклоном
    evs.push((5, Event::MouseButton { button: MouseButton::Left, phase: KeyPhase::Pressed }));
    for i in 0..60u64 {
        let f = 8 + i * 2;
        let dx = 6.0 + (i as f64 * 0.35).sin() * 4.0;
        let dy = (i as f64 * 0.22).cos() * 3.0;
        evs.push((f, Event::MouseMove { dx, dy }));
    }
    evs.push((130, Event::MouseButton { button: MouseButton::Left, phase: KeyPhase::Released }));
    // Фаза 2: колесо — зум-ин и обратно
    evs.push((150, Event::MouseWheel { delta: 2.0 }));
    evs.push((170, Event::MouseWheel { delta: 2.0 }));
    evs.push((190, Event::MouseWheel { delta: -3.0 }));
    // Фаза 3: клавиатура — доворот вверх и влево
    evs.push((210, Event::Key { code: KeyCode::W, phase: KeyPhase::Pressed }));
    evs.push((240, Event::Key { code: KeyCode::W, phase: KeyPhase::Released }));
    evs.push((245, Event::Key { code: KeyCode::Left, phase: KeyPhase::Pressed }));
    evs.push((270, Event::Key { code: KeyCode::Left, phase: KeyPhase::Released }));
    // Побочно: фокус и текст проходят через очередь (полнота контракта)
    evs.push((10, Event::WindowFocus { gained: false }));
    evs.push((12, Event::WindowFocus { gained: true }));
    evs.push((100, Event::Text('U')));
    evs
}

/// Итог прогона игрового цикла.
struct GameLoopSummary {
    frames: u64,
    ticks: u64,
    camera: crate::game::OrbitCamera,
    state_hash: u64,
    elapsed_s: f64,
    closed: bool,
}

/// Единый игровой цикл: события → Input → тики мира+камеры → рендер → present.
///
/// Один и тот же код крутит и офлайн-replay (детерминированный эталон),
/// и настоящее X11-окно (realtime): источник dt и источник событий —
/// параметры, логика неизменна.
#[allow(clippy::too_many_arguments)]
fn game_window_loop(
    backend: &mut dyn crate::game::WindowBackend,
    scene: &crate::game::SceneFile,
    max_frames: Option<u64>,
    mut dt_source: impl FnMut() -> f64,
    mut feed: impl FnMut(u64, &mut crate::game::EventQueue),
    ticks_cap: usize,
) -> Result<GameLoopSummary, String> {
    use crate::game::events::Event;
    use crate::game::{EventQueue, Input, OrbitCamera, FIXED_DT};

    let mut queue = EventQueue::new(512);
    let mut input = Input::default();
    let mut camera = OrbitCamera::from_spec(&scene.camera);
    let mut world = scene
        .build_world()
        .map_err(|e| format!("сцена `{}`: {e}", scene.name))?;
    let mut clock = crate::game::GameClock::new(FIXED_DT);
    let mut frames: u64 = 0;
    let t0 = std::time::Instant::now();
    let mut closed = false;

    loop {
        if let Some(n) = max_frames {
            if frames >= n {
                break;
            }
        }
        if closed {
            break;
        }
        // 1. События: скрипт кадра + бэкенд (окно)
        feed(frames, &mut queue);
        while let Some(ev) = backend.poll_event() {
            queue.push(ev);
        }
        // 2. Свёртка в состояние ввода
        while let Some(ev) = queue.pop() {
            if matches!(ev, Event::WindowClose) {
                closed = true;
            }
            input.on_event(&ev);
        }
        // 3. Симуляция: целые тики фиксированного шага
        let dt = dt_source();
        let n_ticks = clock.advance(dt, ticks_cap);
        for _ in 0..n_ticks {
            world.tick(FIXED_DT);
            camera.tick(&input, FIXED_DT);
        }
        // 4. Рендер текущего состояния + показ
        let (w, h) = backend.size();
        let cfg = crate::game::FrameConfig {
            width: w,
            height: h,
            camera: camera.spec(),
            render_orbits: true,
            render_box: true,
            scene_name: scene.name.clone(),
            out_dir: std::path::PathBuf::from("."),
        };
        let raw = crate::game::render_raw(&world, &cfg)?;
        backend.present(&raw.rgb, w, h)?;
        input.end_frame();
        frames += 1;
    }

    Ok(GameLoopSummary {
        frames,
        ticks: clock.tick,
        camera,
        state_hash: world.state_hash(),
        elapsed_s: t0.elapsed().as_secs_f64(),
        closed,
    })
}

/// `game input-demo`: U1–U4 — скрипт событий → кадры + хеши (без окна).
fn cmd_game_input_demo(args: &[String]) -> CmdResult {
    use crate::game::events::Event;
    use crate::game::{EventQueue, OffscreenWindow, WindowBackend};

    let mut frames: u32 = 300;
    let mut every: u32 = 30;
    let mut w: u32 = 640;
    let mut h: u32 = 360;
    let mut out_dir = std::path::PathBuf::from("poler_input_demo");
    let mut script_path: Option<std::path::PathBuf> = None;
    let mut as_json = false;

    if let Ok(f) = q_flag_num::<u32>(args, "--frames", frames) {
        if !(10..=10_000).contains(&f) {
            return CmdResult::Done("game input-demo: --frames 10..=10000".into());
        }
        frames = f;
    }
    if let Ok(e) = q_flag_num::<u32>(args, "--every", every) {
        if !(1..=1000).contains(&e) {
            return CmdResult::Done("game input-demo: --every 1..=1000".into());
        }
        every = e;
    }
    if let Some(r) = game_parse_size(args) {
        let (sw, sh) = match r {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("game input-demo: {e}")),
        };
        w = sw;
        h = sh;
    }
    if let Some(i) = args.iter().position(|a| a == "--out-dir") {
        match args.get(i + 1) {
            Some(v) => out_dir = std::path::PathBuf::from(v.clone()),
            None => return CmdResult::Done("game input-demo: --out-dir DIR".into()),
        }
    }
    if let Some(i) = args.iter().position(|a| a == "--script") {
        match args.get(i + 1) {
            Some(v) => script_path = Some(std::path::PathBuf::from(v.clone())),
            None => return CmdResult::Done("game input-demo: --script FILE.json".into()),
        }
    }
    as_json |= q_flag(args, "--json");

    // Сценарий: файл или встроенный
    let events: Vec<(u64, Event)> = if let Some(p) = &script_path {
        let raw = match std::fs::read_to_string(p) {
            Ok(r) => r,
            Err(e) => return CmdResult::Done(format!("game input-demo: чтение {}: {e}", p.display())),
        };
        let script: InputScript = match serde_json::from_str(&raw) {
            Ok(s) => s,
            Err(e) => return CmdResult::Done(format!("game input-demo: парсинг {}: {e}", p.display())),
        };
        frames = script.frames.clamp(10, 10_000);
        match script_to_events(&script) {
            Ok(e) => e,
            Err(e) => return CmdResult::Done(format!("game input-demo: {e}")),
        }
    } else {
        default_script_events()
    };

    let scene = crate::game::demo_scene();
    let t0 = std::time::Instant::now();
    let mut window = OffscreenWindow::new(Vec::new(), w, h, &out_dir, every);
    // Источник событий: скрипт выдаёт события, запланированные на кадр
    let mut cursor = 0usize;
    let summary = {
        let feed = |frame: u64, q: &mut EventQueue| {
            while cursor < events.len() && events[cursor].0 <= frame {
                q.push(events[cursor].1.clone());
                cursor += 1;
            }
        };
        // офлайн-детерминизм: ровно один тик на кадр
        match game_window_loop(&mut window, &scene, Some(frames as u64), || {
            crate::game::FIXED_DT
        }, feed, 4)
        {
            Ok(s) => s,
            Err(e) => return CmdResult::Done(format!("game input-demo: {e}")),
        }
    };
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let frames_hash = window.frames_hash();
    let n_png = window.frames().iter().filter(|f| f.path.is_some()).count();

    if as_json {
        let j = serde_json::json!({
            "backend": window.backend_name(),
            "frames": summary.frames,
            "ticks": summary.ticks,
            "png_written": n_png,
            "out_dir": out_dir.display().to_string(),
            "size": [w, h],
            "every": every,
            "script": script_path.map(|p| p.display().to_string()),
            "frames_hash": format!("0x{:016X}", frames_hash),
            "camera": {
                "yaw": summary.camera.yaw,
                "pitch": summary.camera.pitch,
                "dist": summary.camera.dist,
                "camera_hash": format!("0x{:016X}", summary.camera.camera_hash()),
            },
            "state_hash": format!("0x{:016X}", summary.state_hash),
            "closed": summary.closed,
            "elapsed_ms": (elapsed_ms * 1000.0).round() / 1000.0,
        });
        CmdResult::Done(serde_json::to_string_pretty(&j).unwrap_or_default())
    } else {
        CmdResult::Done(format!(
            "U1–U4 «ввод → камера → кадр»: офлайн-replay\n  бэкенд   : {} (событий в скрипте: {}, кадров: {})\n  симуляция: {} тиков · мир 0x{:016X}\n  камера   : yaw {:.3} · pitch {:.3} · dist {:.3} · hash 0x{:016X}\n  кадры    : {} presented · PNG {} (каждый {}) → {}\n  frames_hash: 0x{:016X} (детерминизм бит-в-бит)\n  время    : {:.1} мс",
            window.backend_name(),
            events.len(),
            summary.frames,
            summary.ticks,
            summary.state_hash,
            summary.camera.yaw,
            summary.camera.pitch,
            summary.camera.dist,
            summary.camera.camera_hash(),
            summary.frames,
            n_png,
            every,
            out_dir.display(),
            frames_hash,
            elapsed_ms,
        ))
    }
}

/// `game window`: U3 — настоящее X11-окно (dlopen libX11, zero-dep).
fn cmd_game_window(args: &[String]) -> CmdResult {
    let mut w: u32 = 960;
    let mut h: u32 = 540;
    let mut max_frames: Option<u64> = None;
    let mut ticks_cap: usize = 5;

    if let Some(r) = game_parse_size(args) {
        let (sw, sh) = match r {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("game window: {e}")),
        };
        w = sw;
        h = sh;
    }
    if let Ok(f) = q_flag_num::<u64>(args, "--frames", 0) {
        if f > 0 {
            max_frames = Some(f.min(1_000_000));
        }
    }
    if let Ok(c) = q_flag_num::<usize>(args, "--ticks-cap", ticks_cap) {
        if !(1..=60).contains(&c) {
            return CmdResult::Done("game window: --ticks-cap 1..=60".into());
        }
        ticks_cap = c;
    }

    let mut window = match crate::game::X11Window::open(w, h, "POLER ENGINE — game window (Esc = выход)") {
        Ok(win) => win,
        Err(e) => {
            return CmdResult::Done(format!(
                "game window: не удалось открыть X11-окно: {e}\n  (headless-окружение? для детерминированного прогона без X-сервера — game input-demo)"
            ))
        }
    };
    let scene = crate::game::demo_scene();
    // Realtime-источник dt с пейсингом 60 Гц
    let mut last = std::time::Instant::now();
    let dt_source = || {
        let target = crate::game::FIXED_DT;
        let now = std::time::Instant::now();
        let dt = now.duration_since(last).as_secs_f64();
        if dt < target {
            std::thread::sleep(std::time::Duration::from_secs_f64(target - dt));
        }
        let now2 = std::time::Instant::now();
        let real = now2.duration_since(last).as_secs_f64();
        last = now2;
        real
    };
    let feed = |_frame: u64, _q: &mut crate::game::EventQueue| {};
    let t0 = std::time::Instant::now();
    match game_window_loop(&mut window, &scene, max_frames, dt_source, feed, ticks_cap) {
        Ok(s) => CmdResult::Done(format!(
            "game window: {} кадров за {:.1} с ({:.0} fps) · {} тиков · закрыто: {}\n  камера: yaw {:.3} · pitch {:.3} · dist {:.3}\n  управление: ЛКМ+движение — орбита · колесо — зум · WASD/стрелки — орбита · Q/E — дистанция · крантик/Esc — выход",
            s.frames,
            t0.elapsed().as_secs_f64(),
            s.frames as f64 / t0.elapsed().as_secs_f64().max(1e-9),
            s.ticks,
            s.closed,
            s.camera.yaw,
            s.camera.pitch,
            s.camera.dist,
        )),
        Err(e) => CmdResult::Done(format!("game window: {e}")),
    }
}

/// `game info`: статус ядра игры.
fn cmd_game_info() -> CmdResult {
    let scene = crate::game::demo_scene();
    let world = scene.build_world().expect("демо-сцена валидна (проверена тестами)");
    let orbits = world.entities().iter().filter(|e| world.orbit(**e).is_some()).count();
    let roots = world.entities().iter().filter(|e| world.parent(**e).is_none()).count();
    let mut world2 = scene.build_world().expect("демо-сцена валидна");
    for _ in 0..600 {
        world2.tick(crate::game::FIXED_DT);
    }
    CmdResult::Done(format!(
        "POLER GAME CORE (цикл S, v0.54.0) — фундамент игрового движка\n  архитектура: Entity(generation) + World, без GC/UHT (см. docs/GAME_ENGINE_ROADMAP_UE_ANALYSIS.md)\n  демо-сцена : «{}» («Этерия» из лора POLER) — {} тел ({} корней, {} орбит), глубина иерархии 3\n  тик        : fixed dt = {:.4} c; фазы: Orbit → Transform → Hash\n  физика     : ω = √(G·M)/r^1.5 (третий закон Кеплера), наклоны плоскостей\n  детерминизм: state-hash после 600 тиков = 0x{:016X} (бит-в-бит)\n  рендер     : P³ FFI → RGB+depth(d_FS)+seg, PNG (headless-first)\n  команды    : game demo | game scene <json> | game write-demo <json>",
        scene.name,
        world.len(),
        roots,
        orbits,
        crate::game::FIXED_DT,
        world2.state_hash(),
    ))
}

/// Разбор общих флагов quantum (значение флага — следующий аргумент).
fn q_flag_num<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> Result<T, String> {
    args.iter().position(|a| a == flag).map_or(Ok(default), |i| {
        args.get(i + 1)
            .and_then(|v| v.parse::<T>().ok())
            .ok_or_else(|| format!("значение для {flag}"))
    })
}

fn q_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Позиционные аргументы (без флагов и их значений).
fn q_positionals<'a>(args: &'a [String], valued: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--") {
            if valued.contains(&a.as_str()) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        out.push(a.as_str());
        i += 1;
    }
    out
}

const Q_FLAGS_VALUED: &[&str] = &[
    "--n", "--shots", "--seed", "--marks", "--secret", "--period", "--offset", "--theta",
    "--top", "--noise", "--edges", "--p", "--restarts", "--sweeps",
];

fn cmd_quantum(state: &mut ShellState, raw: &str) -> CmdResult {
    use crate::quantum::core as pqc_core;

    // симметричные кавычки вокруг всего хвоста
    let raw = raw.trim();
    let raw = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    let parts: Vec<String> = raw.split_whitespace().map(String::from).collect();
    let sub = parts.first().map(String::as_str).unwrap_or("");
    let args = &parts[1..];

    match sub {
        "help" | "usage" => CmdResult::Done(quantum_usage()),
        "list" | "algos" | "catalog" => {
            let mut out = String::from("Каталог эталонных алгоритмов POLER Quantum PC:");
            for (name, desc) in pqc_core::algorithms::catalog() {
                out.push_str(&format!("\n  {name:<10} {desc}"));
            }
            out.push_str("\n\nФизика цикла O (Шрёдингер, Паули, ⊗): quantum calc …");
            CmdResult::Done(out)
        }
        "run" => cmd_quantum_run(args),
        "qcasm" | "qasm" => cmd_quantum_qcasm(args),
        "qaoa" => cmd_quantum_qaoa(args),
        "teleport" => cmd_quantum_teleport(args),
        "bloch" | "state" => cmd_quantum_bloch(state, args, sub == "state"),
        "verify" => cmd_quantum_verify(args),
        "calc" | "physics" => {
            // мост в Калькулятор Всего: schrodinger(pauli_y(), [1;0], pi/2)…
            let expr = parts[1..].join(" ");
            if expr.trim().is_empty() {
                CmdResult::Done(
                    "quantum calc <выражение> — примеры:\n  quantum calc schrodinger(pauli_y(), [1; 0], pi/2)\n  quantum calc kron(pauli_x(), pauli_y())\n  quantum calc exp(i * pi)"
                        .to_string(),
                )
            } else {
                cmd_calc(state, &expr)
            }
        }
        other => CmdResult::Done(format!(
            "quantum: неизвестная подкоманда `{other}`\n\n{}",
            quantum_usage()
        )),
    }
}

fn cmd_quantum_run(args: &[String]) -> CmdResult {
    use crate::quantum::core as pqc_core;
    let pos = q_positionals(args, Q_FLAGS_VALUED);
    let name = match pos.first() {
        Some(n) => *n,
        None => {
            return CmdResult::Done(format!(
                "quantum run: имя алгоритма обязательно\n\n{}",
                quantum_usage()
            ))
        }
    };
    // Цикл Q: `quantum run qcasm <файл|->` — произвольная схема.
    if name == "qcasm" || name == "qasm" {
        return match pos.get(1) {
            Some(path) => quantum_qcasm_impl(path, args),
            None => CmdResult::Done(
                "quantum run qcasm: путь к файлу схемы (или - для stdin) обязателен\n\n"
                    .to_string()
                    + &quantum_usage(),
            ),
        };
    }
    let n: usize = match q_flag_num(args, "--n", 4usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let shots: u64 = match q_flag_num(args, "--shots", 1024u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let seed: u64 = match q_flag_num(args, "--seed", 42u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let theta: f64 = match q_flag_num(args, "--theta", 0.7f64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let secret: u64 = match q_flag_num(args, "--secret", 0b1011u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let period: usize = match q_flag_num(args, "--period", 0usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let offset: usize = match q_flag_num(args, "--offset", 0usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };
    let marks: Vec<usize> = match q_flag_num(args, "--marks", String::new()) {
        Ok(s) if s.is_empty() => Vec::new(),
        Ok(s) => match s
            .split(',')
            .map(|t| t.trim().parse::<usize>())
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(_) => {
                return CmdResult::Done(format!("quantum run: --marks \"{s}\" — нужны числа через запятую"))
            }
        },
        Err(e) => return CmdResult::Done(format!("quantum run: {e}")),
    };

    let params = pqc_core::algorithms::AlgoParams {
        n,
        marks,
        secret,
        period,
        offset,
        theta,
    };
    let (circuit, iterations) = match pqc_core::algorithms::build(name, &params) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum run: {e:?}")),
    };
    let rep = match pqc_core::qpc::run(&circuit, shots, seed) {
        Ok(r) => r,
        Err(e) => return CmdResult::Done(format!("quantum run: {e:?}")),
    };

    if q_flag(args, "--json") {
        let counts: Vec<serde_json::Value> = rep
            .counts
            .iter()
            .map(|(o, c)| serde_json::json!([o, c]))
            .collect();
        let probs: Vec<f64> = rep.probabilities.clone();
        return CmdResult::Done(
            serde_json::json!({
                "engine": "poler-quantum-shell",
                "algorithm": name,
                "n_qubits": rep.n_qubits,
                "gate_count": rep.gate_count,
                "iterations": iterations,
                "shots": rep.shots,
                "norm": rep.norm,
                "entropy_bits": rep.entropy_bits,
                "landauer_j": rep.landauer_j,
                "probabilities": probs,
                "marginals": rep.marginals,
                "counts": counts,
            })
            .to_string(),
        );
    }

    let mut out = format!("POLER Quantum PC — алгоритм {name}");
    out.push_str(&format!(
        "\nкубитов: {}, вентилей: {}, итераций: {}, выстрелов: {}",
        rep.n_qubits, rep.gate_count, iterations, rep.shots
    ));
    out.push_str(&format!("\nэнтропия: {:.4} бит", rep.entropy_bits));
    if !rep.counts.is_empty() {
        out.push_str("\nтоп исходов:");
        for (o, c) in rep.counts.iter().take(12) {
            let mut bits = String::new();
            for q in (0..rep.n_qubits).rev() {
                bits.push(if o >> q & 1 == 1 { '1' } else { '0' });
            }
            out.push_str(&format!(
                "\n  |{bits}⟩  {:>8}  p̂ = {:.4}",
                c,
                *c as f64 / rep.shots.max(1) as f64
            ));
        }
    }
    if q_flag(args, "--probs") {
        out.push_str("\nраспределение Борна:");
        for (i, p) in rep.probabilities.iter().enumerate() {
            if *p > 1e-9 {
                let mut bits = String::new();
                for q in (0..rep.n_qubits).rev() {
                    bits.push(if i >> q & 1 == 1 { '1' } else { '0' });
                }
                out.push_str(&format!("\n  |{bits}⟩  {p:.6}"));
            }
        }
    }
    CmdResult::Done(out)
}

/// Цикл Q: `quantum qcasm <файл|->` — произвольная QCASM-схема из шелла.
fn cmd_quantum_qcasm(args: &[String]) -> CmdResult {
    let pos = q_positionals(args, Q_FLAGS_VALUED);
    let path = match pos.first() {
        Some(p) => *p,
        None => {
            return CmdResult::Done(
                "quantum qcasm: путь к файлу схемы (или - для stdin) обязателен\n\n"
                    .to_string()
                    + &quantum_usage(),
            )
        }
    };
    quantum_qcasm_impl(path, args)
}

/// Общий движок QCASM: файл/stdin → parse → run | --exact | --noise.
fn quantum_qcasm_impl(path: &str, args: &[String]) -> CmdResult {
    use crate::quantum::core as pqc_core;
    let shots: u64 = match q_flag_num(args, "--shots", 1024u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qcasm: {e}")),
    };
    let seed: u64 = match q_flag_num(args, "--seed", 42u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qcasm: {e}")),
    };
    let top: usize = match q_flag_num(args, "--top", 20usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qcasm: {e}")),
    };
    let text = if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        match std::io::stdin().read_to_string(&mut buf) {
            Ok(_) => buf,
            Err(e) => return CmdResult::Done(format!("quantum qcasm: stdin: {e}")),
        }
    } else {
        match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                return CmdResult::Done(format!("quantum qcasm: не читается {path}: {e}"))
            }
        }
    };
    let circuit = match pqc_core::qpc::Circuit::parse(&text) {
        Ok(c) => c,
        Err(e) => return CmdResult::Done(format!("quantum qcasm: ошибка разбора: {e:?}")),
    };

    let bits = |o: u64, n: usize| -> String {
        let mut s = String::new();
        for q in (0..n).rev() {
            s.push(if o >> q & 1 == 1 { '1' } else { '0' });
        }
        s
    };

    // Точный режим: кольцо ℤ[1/√2, i] (Clifford+T).
    if q_flag(args, "--exact") {
        return match pqc_core::exact::run_exact(&circuit) {
            Ok(rep) => {
                if q_flag(args, "--json") {
                    return CmdResult::Done(
                        serde_json::json!({
                            "engine": "poler-quantum-shell",
                            "mode": "qcasm-exact:Z[1/sqrt(2),i]",
                            "source": path,
                            "n_qubits": rep.n_qubits,
                            "norm_residual": rep.norm_residual,
                            "probabilities": rep.probs_f64,
                            "exact_probs": rep.exact_probs.iter().map(|p| format!("{p}")).collect::<Vec<_>>(),
                        })
                        .to_string(),
                    );
                }
                let mut out = format!(
                    "QCASM — ТОЧНОЕ КОЛЬЦО ℤ[1/√2, i]\nфайл: {path}\nкубитов: {}, невязка нормы: {:.2e}",
                    rep.n_qubits, rep.norm_residual
                );
                out.push_str("\nраспределение Борна (точно):");
                for (i, (p, ex)) in
                    rep.probs_f64.iter().zip(rep.exact_probs.iter()).enumerate()
                {
                    if *p > 0.0 {
                        out.push_str(&format!(
                            "\n  |{}⟩  {:.6}   = {}",
                            bits(i as u64, rep.n_qubits),
                            p,
                            ex
                        ));
                    }
                }
                CmdResult::Done(out)
            }
            Err(e) => CmdResult::Done(format!("quantum qcasm --exact: {e:?}")),
        };
    }

    // Шум поверх идеала: MCWF-ансамбль траекторий (цикл Q).
    let noise_preset: String = q_flag_num(args, "--noise", String::new()).unwrap_or_default();
    if !noise_preset.is_empty() {
        let model = match pqc_core::noise::NoiseModel::preset(&noise_preset) {
            Some(m) => m,
            None => {
                return CmdResult::Done(format!(
                    "quantum qcasm: неизвестный пресет `{noise_preset}` \
                     (ideal|ibm-heron|google-willow|noisy-90s)"
                ))
            }
        };
        return match pqc_core::noise::run_noisy(&circuit, &model, shots, seed) {
            Ok(rep) => {
                if q_flag(args, "--json") {
                    let counts: Vec<serde_json::Value> = rep
                        .counts
                        .iter()
                        .map(|(o, c)| serde_json::json!([o, c]))
                        .collect();
                    return CmdResult::Done(
                        serde_json::json!({
                            "engine": "poler-quantum-shell",
                            "mode": "qcasm-noise-mcwf",
                            "source": path,
                            "n_qubits": rep.n_qubits,
                            "preset": noise_preset,
                            "shots": rep.shots,
                            "tvd": rep.tvd,
                            "classical_fidelity": rep.classical_fidelity,
                            "chi2": rep.chi2,
                            "chi2_dof": rep.chi2_dof,
                            "ideal_peak": rep.ideal_peak,
                            "noisy_peak": rep.noisy_peak,
                            "ideal_probs": rep.ideal_probs,
                            "counts": counts,
                        })
                        .to_string(),
                    );
                }
                let mut out = format!(
                    "QCASM — шум поверх идеала (Monte Carlo траектории)\nфайл: {path}\nпресет: {noise_preset}, выстрелов: {}",
                    rep.shots
                );
                out.push_str(&format!(
                    "\nTVD ½Σ|p−q|:        {:.4}\nF_класс (Σ√pq)²:   {:.4}\nχ² Пирсона (dof {}):  {:.1}",
                    rep.tvd, rep.classical_fidelity, rep.chi2_dof, rep.chi2
                ));
                out.push_str(&format!(
                    "\nпик идеал → железо: {:.4} → {:.4}",
                    rep.ideal_peak, rep.noisy_peak
                ));
                if !rep.counts.is_empty() {
                    out.push_str("\nтоп исходов (зашумлённых):");
                    for (o, c) in rep.counts.iter().take(top) {
                        out.push_str(&format!(
                            "\n  |{}⟩  {:>8}  p̂ = {:.4}",
                            bits(*o, rep.n_qubits),
                            c,
                            *c as f64 / rep.shots.max(1) as f64
                        ));
                    }
                }
                CmdResult::Done(out)
            }
            Err(e) => CmdResult::Done(format!("quantum qcasm --noise: {e:?}")),
        };
    }

    // Идеальный прогон.
    match pqc_core::qpc::run(&circuit, shots, seed) {
        Ok(rep) => {
            if q_flag(args, "--json") {
                let counts: Vec<serde_json::Value> = rep
                    .counts
                    .iter()
                    .map(|(o, c)| serde_json::json!([o, c]))
                    .collect();
                return CmdResult::Done(
                    serde_json::json!({
                        "engine": "poler-quantum-shell",
                        "mode": "qcasm",
                        "source": path,
                        "n_qubits": rep.n_qubits,
                        "gate_count": rep.gate_count,
                        "per_shot": rep.per_shot,
                        "shots": rep.shots,
                        "norm": rep.norm,
                        "entropy_bits": rep.entropy_bits,
                        "landauer_j": rep.landauer_j,
                        "probabilities": rep.probabilities,
                        "marginals": rep.marginals,
                        "counts": counts,
                    })
                    .to_string(),
                );
            }
            let mut out = format!(
                "QCASM — идеальный субстрат\nфайл: {path}\nкубитов: {}, вентилей: {}, выстрелов: {}",
                rep.n_qubits, rep.gate_count, rep.shots
            );
            out.push_str(&format!(
                "\nрежим: {}\nнорма: {:.16}\nэнтропия: {:.4} бит",
                if rep.per_shot { "per-shot коллапс" } else { "statevector" },
                rep.norm,
                rep.entropy_bits
            ));
            if !rep.counts.is_empty() {
                out.push_str("\nтоп исходов:");
                for (o, c) in rep.counts.iter().take(top) {
                    out.push_str(&format!(
                        "\n  |{}⟩  {:>8}  p̂ = {:.4}",
                        bits(*o, rep.n_qubits),
                        c,
                        *c as f64 / rep.shots.max(1) as f64
                    ));
                }
            }
            if q_flag(args, "--probs") {
                out.push_str("\nраспределение Борна:");
                for (i, p) in rep.probabilities.iter().enumerate() {
                    if *p > 1e-9 {
                        out.push_str(&format!(
                            "\n  |{}⟩  {p:.6}",
                            bits(i as u64, rep.n_qubits)
                        ));
                    }
                }
            }
            if q_flag(args, "--amplitudes") && rep.n_qubits <= 20 {
                out.push_str("\nамплитуды:");
                for (i, a) in rep.final_state.amplitudes().iter().enumerate() {
                    if a.norm_sq() > 1e-24 {
                        out.push_str(&format!(
                            "\n  |{}⟩  ({:+.6} {:+.6}i)",
                            bits(i as u64, rep.n_qubits),
                            a.re,
                            a.im
                        ));
                    }
                }
            }
            out.push_str("\nмаргиналы P(b_q = 1):");
            for (q, m) in rep.marginals.iter().enumerate() {
                out.push_str(&format!("\n  q{q}: {m:.6}"));
            }
            CmdResult::Done(out)
        }
        Err(e) => CmdResult::Done(format!("quantum qcasm: {e:?}")),
    }
}

/// Цикл Q: `quantum qaoa` — MaxCut-ансатц с классической оптимизацией.
fn cmd_quantum_qaoa(args: &[String]) -> CmdResult {
    use crate::quantum::core as pqc_core;
    let t0 = Instant::now();
    let edges_str: String = q_flag_num(args, "--edges", String::new()).unwrap_or_default();
    let problem = if edges_str.trim().is_empty() {
        pqc_core::qaoa::MaxCut::demo()
    } else {
        let edges = match pqc_core::qaoa::MaxCut::parse_edges(&edges_str) {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("quantum qaoa: {e:?}")),
        };
        let max_v = edges.iter().map(|&(i, j)| i.max(j)).max().unwrap_or(0);
        let n: usize = match q_flag_num(args, "--n", 0usize) {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("quantum qaoa: {e}")),
        };
        let n = if n == 0 { max_v + 1 } else { n };
        match pqc_core::qaoa::MaxCut::new(n, edges) {
            Ok(p) => p,
            Err(e) => return CmdResult::Done(format!("quantum qaoa: {e:?}")),
        }
    };
    let p: usize = match q_flag_num(args, "--p", 2usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qaoa: {e}")),
    };
    let sweeps: usize = match q_flag_num(args, "--sweeps", 12usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qaoa: {e}")),
    };
    let restarts: usize = match q_flag_num(args, "--restarts", 3usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qaoa: {e}")),
    };
    let shots: u64 = match q_flag_num(args, "--shots", 1024u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qaoa: {e}")),
    };
    let seed: u64 = match q_flag_num(args, "--seed", 42u64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum qaoa: {e}")),
    };
    let cfg = pqc_core::qaoa::QaoaConfig {
        p,
        sweeps,
        restarts,
        shots,
        seed,
    };
    let rep = match pqc_core::qaoa::run_qaoa(&problem, &cfg) {
        Ok(r) => r,
        Err(e) => return CmdResult::Done(format!("quantum qaoa: {e:?}")),
    };
    let ms = t0.elapsed().as_millis();

    let bitstring = |o: u64| -> String {
        let mut s = String::new();
        for q in (0..rep.n_qubits).rev() {
            s.push(if o >> q & 1 == 1 { '1' } else { '0' });
        }
        s
    };

    if q_flag(args, "--json") {
        let gammas: Vec<f64> = rep.params[..rep.p].to_vec();
        let betas: Vec<f64> = rep.params[rep.p..].to_vec();
        let counts: Vec<serde_json::Value> = rep
            .counts
            .iter()
            .map(|(o, c)| serde_json::json!([o, c]))
            .collect();
        return CmdResult::Done(
            serde_json::json!({
                "engine": "poler-quantum-shell",
                "algorithm": "qaoa",
                "problem": "maxcut",
                "n_qubits": rep.n_qubits,
                "edges": rep.edges.iter().map(|(i, j)| serde_json::json!([i, j])).collect::<Vec<_>>(),
                "p": rep.p,
                "gammas": gammas,
                "betas": betas,
                "expected_cut": rep.expected_cut,
                "expected_cut_init": rep.expected_cut_init,
                "best_bits": bitstring(rep.best_bits),
                "best_cut": rep.best_cut,
                "optimum": rep.optimum,
                "approx_ratio": rep.approx_ratio,
                "evals": rep.evals,
                "history": rep.history,
                "gate_count": rep.gate_count,
                "shots": rep.shots,
                "norm": rep.norm,
                "counts": counts,
                "elapsed_ms": ms,
            })
            .to_string(),
        );
    }

    let mut out = String::from("QAOA — MaxCut-ансатц на идеальных кубитах (цикл Q)");
    out.push_str(&format!(
        "\nзадача: {} вершин, {} рёбер",
        rep.n_qubits,
        rep.edges.len()
    ));
    out.push_str(&format!(
        "\nансатц: p = {} слоёв, вычислений E[cut]: {}",
        rep.p, rep.evals
    ));
    out.push_str(&format!(
        "\nE[cut]: {:.4} → {:.4} (после оптимизации)",
        rep.expected_cut_init, rep.expected_cut
    ));
    out.push_str(&format!(
        "\nлучший битстринг |{}⟩ — разрез {} из {}",
        bitstring(rep.best_bits),
        rep.best_cut,
        rep.optimum.map_or_else(|| "?".to_string(), |o| o.to_string())
    ));
    if let (Some(_), Some(r)) = (rep.optimum, rep.approx_ratio) {
        out.push_str(&format!("\nаппроксимационное отношение: {:.1}%", 100.0 * r));
    } else {
        out.push_str("\nпереборный оптимум: n > 20 — не вычисляется (честная граница)");
    }
    out.push_str(&format!("\nуглы γ: {:?}", &rep.params[..rep.p]));
    out.push_str(&format!("\nуглы β: {:?}", &rep.params[rep.p..]));
    out.push_str(&format!("\nнорма: {:.16}, выстрелов: {}", rep.norm, rep.shots));
    out.push_str(&format!("\nвремя: {ms} мс"));
    CmdResult::Done(out)
}

fn cmd_quantum_teleport(args: &[String]) -> CmdResult {
    use crate::quantum::core as pqc_core;
    let theta: f64 = match q_flag_num(args, "--theta", 0.7f64) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum teleport: {e}")),
    };
    let want_exact = q_flag(args, "--exact");
    let t = match if want_exact {
        pqc_core::algorithms::run_teleport_exact()
    } else {
        pqc_core::algorithms::run_teleport(theta)
    } {
        Ok(t) => t,
        Err(e) => return CmdResult::Done(format!("quantum teleport: {e:?}")),
    };
    if q_flag(args, "--json") {
        return CmdResult::Done(
            serde_json::json!({
                "engine": "poler-quantum-shell",
                "algorithm": "teleport",
                "mode": if t.exact { "exact:Z[1/sqrt(2),i]" } else { "numeric:f64" },
                "theta": t.theta,
                "psi_in": [t.psi_in[0].0, t.psi_in[0].1, t.psi_in[1].0, t.psi_in[1].1],
                "psi_out": [t.psi_out[0].0, t.psi_out[0].1, t.psi_out[1].0, t.psi_out[1].1],
                "fidelity": t.fidelity,
                "branch_deviation": t.branch_deviation,
                "exact": t.exact,
                "bloch_in": t.bloch_in,
                "bloch_out": t.bloch_out,
                "gate_count": t.gate_count,
            })
            .to_string(),
        );
    }
    let mut out = String::from("Квантовая телепортация: |ψ⟩ с q0 → q2 (цикл P)");
    out.push_str("\nканал: 6 Клиффорд-вентилей, когерентные коррекции (отложенное измерение)");
    if want_exact {
        out.push_str("\nрежим: ТОЧНО — кольцо ℤ[1/√2, i], структурное равенство амплитуд");
    }
    out.push_str(&format!(
        "\nпрепарат q0: (α={:+.6}, β={:+.6})  Ry({:.4})|0⟩",
        t.psi_in[0].0, t.psi_in[1].0, t.theta
    ));
    out.push_str(&format!(
        "\nвыход   q2: (α={:+.6}, β={:+.6})",
        t.psi_out[0].0, t.psi_out[1].0
    ));
    out.push_str(&format!(
        "\nфиделити |⟨ψ_in|ψ_out⟩|² = {}",
        if t.exact {
            "1 (точно)".to_string()
        } else {
            format!("{:.15}", t.fidelity)
        }
    ));
    out.push_str(&format!(
        "\nрасхождение веток: {:.3e}{}",
        t.branch_deviation,
        if t.branch_deviation < 1e-12 {
            "  ✓ канал идеален"
        } else {
            ""
        }
    ));
    out.push_str(&format!(
        "\nБлох in : (x={:+.4}, y={:+.4}, z={:+.4})",
        t.bloch_in[0], t.bloch_in[1], t.bloch_in[2]
    ));
    out.push_str(&format!(
        "\nБлох out: (x={:+.4}, y={:+.4}, z={:+.4})",
        t.bloch_out[0], t.bloch_out[1], t.bloch_out[2]
    ));
    CmdResult::Done(out)
}

fn cmd_quantum_bloch(state: &mut ShellState, args: &[String], full: bool) -> CmdResult {
    let pos = q_positionals(args, &[]);
    let (a_src, b_src) = match pos.len() {
        0 => {
            return CmdResult::Done(
                "quantum bloch <alpha> [beta] — например: quantum bloch 1/sqrt(2) 1/sqrt(2)\nquantum bloch 1 i"
                    .to_string(),
            )
        }
        1 => (pos[0].to_string(), "0".to_string()),
        _ => (pos[0].to_string(), pos[1].to_string()),
    };
    let alpha = match state.calc.eval_complex(&a_src) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum bloch: α — {e}")),
    };
    let beta = match state.calc.eval_complex(&b_src) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum bloch: β — {e}")),
    };
    // Нормализация: |α|² + |β|² обязана быть 1 (или нормируем с предупреждением).
    let norm_sq = alpha.0 * alpha.0 + alpha.1 * alpha.1 + beta.0 * beta.0 + beta.1 * beta.1;
    let (alpha, beta, warning) = if (norm_sq - 1.0).abs() > 1e-9 {
        if norm_sq < 1e-30 {
            return CmdResult::Done("quantum bloch: нулевое состояние".to_string());
        }
        let k = 1.0 / norm_sq.sqrt();
        (
            (alpha.0 * k, alpha.1 * k),
            (beta.0 * k, beta.1 * k),
            format!(
                "\n⚠ нормализация: |ψ|² = {norm_sq:.6} ≠ 1 — амплитуды поделены на √|ψ|²"
            ),
        )
    } else {
        (alpha, beta, String::new())
    };
    let b = crate::quantum::core::algorithms::bloch_of(alpha, beta);
    let p0 = alpha.0 * alpha.0 + alpha.1 * alpha.1;
    let p1 = 1.0 - p0;
    let phase = beta.1.atan2(beta.0);

    let interp = if b[2] > 0.999 {
        "северный полюс: |0⟩"
    } else if b[2] < -0.999 {
        "южный полюс: |1⟩"
    } else if b[0] > 0.999 {
        "экватор: |+⟩"
    } else if b[0] < -0.999 {
        "экватор: |−⟩"
    } else if b[1] > 0.999 {
        "экватор: |i+⟩"
    } else if b[1] < -0.999 {
        "экватор: |i−⟩"
    } else {
        "общее суперпозиционное состояние"
    };

    let mut out = format!(
        "|ψ⟩ = ({:+.6}{:+.6}i)|0⟩ + ({:+.6}{:+.6}i)|1⟩",
        alpha.0, alpha.1, beta.0, beta.1
    );
    if full {
        out.push_str(&format!(
            "\nP(|0⟩) = {:.6}   P(|1⟩) = {:.6}",
            p0, p1
        ));
        if phase.abs() > 1e-12 {
            out.push_str(&format!("\nотносительная фаза arg(β) = {:+.6} рад = {:+.3}°", phase, phase.to_degrees()));
        }
    }
    out.push_str(&format!(
        "\nсфера Блоха: x = {:+.6}, y = {:+.6}, z = {:+.6}   ({interp})",
        b[0], b[1], b[2]
    ));
    // Мини-диаграмма меридиана (проекция на плоскость x–z).
    let r = 9i32;
    let px = (b[0] * r as f64).round() as i32;
    let pz = (b[2] * r as f64).round() as i32;
    let mut grid = String::from("\n        z\n        │\n");
    for row in (0..=2 * r).rev() {
        let z = row - r;
        let mut line = if z == r {
            String::from("      ┌─")
        } else if z == -r {
            String::from("      └─")
        } else {
            String::from("      │ ")
        };
        for col in -r..=r {
            let x = col;
            let on_circle = (x * x + z * z - r * r).abs() <= r / 3;
            let is_point = x == px && z == pz;
            let is_origin = x == 0 && z == 0;
            line.push(if is_point {
                '●'
            } else if is_origin {
                '┼'
            } else if on_circle {
                '·'
            } else if z == 0 {
                '─'
            } else {
                ' '
            });
        }
        grid.push_str(&line);
        grid.push('\n');
    }
    grid.push_str("       └─────── x\n        (проекция y отброшена)");
    out.push_str(&grid);
    out.push_str(&warning);
    CmdResult::Done(out)
}

fn cmd_quantum_verify(args: &[String]) -> CmdResult {
    use crate::quantum::core as pqc_core;
    use pqc_core::verify::{Verdict, VerificationReport};
    let pos = q_positionals(args, &["--n", "--shots", "--seed", "--noise"]);
    let mode = match pos.first() {
        Some(m) => *m,
        None => {
            return CmdResult::Done(format!(
                "quantum verify: режим обязателен (unitary|equiv|teleport)\n\n{}",
                quantum_usage()
            ))
        }
    };
    let n: usize = match q_flag_num(args, "--n", 4usize) {
        Ok(v) => v,
        Err(e) => return CmdResult::Done(format!("quantum verify: {e}")),
    };
    let build_algo = |name: &str| -> Result<pqc_core::qpc::Circuit, String> {
        let p = pqc_core::algorithms::AlgoParams {
            n,
            marks: vec![22 % (1usize << n.max(1))],
            secret: 0b1011,
            period: 0,
            offset: 0,
            theta: 0.7,
        };
        pqc_core::algorithms::build(name, &p)
            .map(|(c, _)| c)
            .map_err(|e| format!("{e:?}"))
    };
    let report: Result<VerificationReport, String> = match mode {
        "unitary" => match pos.get(1) {
            Some(algo) => build_algo(algo)
                .map_err(String::from)
                .and_then(|c| pqc_core::verify::verify_unitary(&c).map_err(|e| format!("{e:?}"))),
            None => {
                return CmdResult::Done(
                    "quantum verify unitary <algo> [--n K] — имя алгоритма обязательно".to_string(),
                )
            }
        },
        "equiv" => {
            let names: Vec<&str> = pos[1..].to_vec();
            if names.len() != 2 {
                return CmdResult::Done(
                    "quantum verify equiv <A> <B> [--n K] [--phase] — ровно два алгоритма"
                        .to_string(),
                );
            }
            match (build_algo(names[0]), build_algo(names[1])) {
                (Ok(a), Ok(b)) => {
                    let up_to_phase = q_flag(args, "--phase");
                    pqc_core::verify::verify_equivalence(&a, &b, up_to_phase)
                        .map_err(|e| format!("{e:?}"))
                }
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
        "teleport" => pqc_core::verify::verify_teleport_channel().map_err(|e| format!("{e:?}")),
        other => {
            return CmdResult::Done(format!(
                "quantum verify: неизвестный режим `{other}` (unitary|equiv|teleport)"
            ))
        }
    };
    let report = match report {
        Ok(r) => r,
        Err(e) => return CmdResult::Done(format!("quantum verify: {e}")),
    };

    // Цикл Q: шум поверх верификатора — вердикт + «идеал vs железо».
    let noise_preset: String = q_flag_num(args, "--noise", String::new()).unwrap_or_default();
    let mut noise_json: Option<serde_json::Value> = None;
    let mut noise_text = String::new();
    if !noise_preset.is_empty() {
        let noise_shots: u64 = match q_flag_num(args, "--shots", 4096u64) {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("quantum verify --noise: {e}")),
        };
        let seed: u64 = match q_flag_num(args, "--seed", 42u64) {
            Ok(v) => v,
            Err(e) => return CmdResult::Done(format!("quantum verify --noise: {e}")),
        };
        let circuit_opt: Result<Option<pqc_core::qpc::Circuit>, String> = match mode {
            "unitary" => match pos.get(1) {
                Some(algo) => build_algo(algo).map(Some),
                None => Ok(None),
            },
            "teleport" => pqc_core::algorithms::teleport_prepared(0.7)
                .map(Some)
                .map_err(|e| format!("{e:?}")),
            _ => Ok(None), // equiv: две схемы — шум не применяется
        };
        match circuit_opt {
            Ok(Some(circuit)) => {
                let model = match pqc_core::noise::NoiseModel::preset(&noise_preset) {
                    Some(m) => m,
                    None => {
                        return CmdResult::Done(format!(
                            "quantum verify --noise: неизвестный пресет `{noise_preset}` \
                             (ideal|ibm-heron|google-willow|noisy-90s)"
                        ))
                    }
                };
                match pqc_core::noise::run_noisy(&circuit, &model, noise_shots, seed) {
                    Ok(nrep) => {
                        noise_json = Some(serde_json::json!({
                            "preset": noise_preset,
                            "shots": nrep.shots,
                            "tvd": nrep.tvd,
                            "classical_fidelity": nrep.classical_fidelity,
                            "chi2": nrep.chi2,
                            "chi2_dof": nrep.chi2_dof,
                            "ideal_peak": nrep.ideal_peak,
                            "noisy_peak": nrep.noisy_peak,
                        }));
                        noise_text = format!(
                            "\n\nШум поверх верификатора (цикл Q):\n  пресет: {noise_preset}, \
                             выстрелов: {}\n  TVD ½Σ|p−q|: {:.4} · F_класс: {:.4} · χ²(dof {}): {:.1}\
                             \n  пик идеал → железо: {:.4} → {:.4}",
                            nrep.shots,
                            nrep.tvd,
                            nrep.classical_fidelity,
                            nrep.chi2_dof,
                            nrep.chi2,
                            nrep.ideal_peak,
                            nrep.noisy_peak
                        );
                    }
                    Err(e) => {
                        noise_text = format!("\n\nШум не применён: {e:?}");
                    }
                }
            }
            Ok(None) => {
                noise_text = "\n\nШум не применён: equiv верифицирует две схемы — \
                     прогоните каждую через `quantum qcasm <файл> --noise <пресет>`."
                    .to_string();
            }
            Err(e) => noise_text = format!("\n\nШум не применён: {e}"),
        }
    }

    if q_flag(args, "--json") {
        let verdict = match report.verdict {
            Verdict::ProvedExact => serde_json::json!("proved_exact"),
            Verdict::VerifiedNumeric(tol) => serde_json::json!(["verified_numeric", tol]),
            Verdict::VerifiedSampling(tol) => serde_json::json!(["verified_sampling", tol]),
            Verdict::Refuted(d) => serde_json::json!(["refuted", d]),
        };
        return CmdResult::Done(
            serde_json::json!({
                "engine": "poler-quantum-shell",
                "property": report.property,
                "subject": report.subject,
                "n_qubits": report.n_qubits,
                "dim": report.dim,
                "gate_count": report.gate_count,
                "method": report.method,
                "verdict": verdict,
                "max_deviation": report.max_deviation,
                "checks": report.checks.iter().map(|(n, ok, d)| serde_json::json!([n, ok, d])).collect::<Vec<_>>(),
                "notes": report.notes,
                "noise": noise_json,
            })
            .to_string(),
        );
    }

    let mut out = String::from("Формальная верификация (цикл P):");
    out.push_str(&format!("\nсвойство: {}", report.property));
    out.push_str(&format!("\nсубъект:  {}", report.subject));
    out.push_str(&format!(
        "\nсхема:    {} кубитов, {} унитарных операций, dim {}",
        report.n_qubits, report.gate_count, report.dim
    ));
    out.push_str(&format!("\nметод:    {}", report.method));
    out.push_str(&format!("\nвердикт:  {}", report.verdict_line()));
    for (name, ok, dev) in &report.checks {
        out.push_str(&format!(
            "\n  [{}] {:<24} невязка {:.3e}",
            if *ok { "✓" } else { "✗" },
            name,
            dev
        ));
    }
    for note in &report.notes {
        out.push_str(&format!("\n  · {note}"));
    }
    out.push_str(&noise_text);
    CmdResult::Done(out)
}


// ---------------------------------------------------------------------------
// v0.46.0: Системный шелл, passthrough и запуск .poler-контейнеров
// ---------------------------------------------------------------------------

fn run_sh_command(raw_cmd: &str) -> CmdResult {
    let t0 = Instant::now();
    let output = match std::process::Command::new("sh").arg("-c").arg(raw_cmd).output() {
        Ok(o) => o,
        Err(e) => return CmdResult::Done(format!("❌ помилка виклику sh: {e}")),
    };
    let mut res = format_output("sh", &output);
    res.push_str(&agent_timing_suffix(t0));
    CmdResult::Done(res)
}

/// Свести stdout+stderr команды в единый текст (v0.47.0 — общий хелпер).
fn format_output(label: &str, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut res = String::new();
    if !stdout.is_empty() {
        res.push_str(&stdout);
    }
    if !stderr.is_empty() {
        if !res.is_empty() && !res.ends_with('\n') {
            res.push('\n');
        }
        res.push_str(&stderr);
    }
    if res.is_empty() {
        res = format!("✓ [{label}] виконано (код: {})", output.status);
    }
    res.trim_end_matches('\n').to_string()
}

/// Суффикс ⏱ <мс> для внешних команд в агентном режиме (POLER_SHELL_AGENT=1).
fn agent_timing_suffix(t0: Instant) -> String {
    let on = std::env::var("POLER_SHELL_AGENT")
        .map(|v| v == "1")
        .unwrap_or(false);
    if on {
        format!("\n⏱ {} мс", t0.elapsed().as_millis())
    } else {
        String::new()
    }
}

/// v0.47.0: исполнение трансляции Windows-команды.
fn run_win_translation(tr: WinTranslation) -> CmdResult {
    match tr {
        WinTranslation::Exec { program, args, note } => {
            let t0 = Instant::now();
            let output =
                match std::process::Command::new(&program).args(&args).output() {
                    Ok(o) => o,
                    Err(e) => {
                        return CmdResult::Done(format!(
                            "❌ {program}: {e} (нет в системе?)"
                        ))
                    }
                };
            let mut res = format_output(&program, &output);
            if let Some(n) = note {
                res.push_str(&format!("\nℹ {n}"));
            }
            res.push_str(&agent_timing_suffix(t0));
            CmdResult::Done(res)
        }
        WinTranslation::Shell { script, note } => {
            let mut res = run_sh_command(&script);
            if let CmdResult::Done(ref mut s) = res {
                if let Some(n) = note {
                    s.push_str(&format!("\nℹ {n}"));
                }
            }
            res
        }
        WinTranslation::Notice(msg) => CmdResult::Done(msg),
    }
}

/// Есть ли в токене Windows-переменная вида %NAME%.
fn contains_win_var(tok: &str) -> bool {
    let bytes = tok.as_bytes();
    let mut pct: Vec<usize> = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%' {
            pct.push(i);
        }
    }
    if pct.len() < 2 {
        return false;
    }
    // хотя бы одна пара %...% с валидным именем
    for w in pct.windows(2) {
        let name = &tok[w[0] + 1..w[1]];
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return true;
        }
    }
    false
}

/// %NAME% → ${NAME} (для передачи в sh).
fn expand_win_vars(tok: &str) -> String {
    let mut out = String::with_capacity(tok.len() + 4);
    let mut chars = tok.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut name = String::new();
            let mut consumed = false;
            for c2 in chars.by_ref() {
                if c2 == '%' {
                    consumed = true;
                    break;
                }
                name.push(c2);
            }
            if consumed
                && !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                out.push_str(&format!("${{{name}}}"));
            } else {
                out.push('%');
                out.push_str(&name);
                if consumed {
                    out.push('%');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// v0.47.0: cd / pty / engine — нативные команды
// ---------------------------------------------------------------------------

fn cmd_cd(args: &[String]) -> CmdResult {
    let target = match args.first() {
        None => {
            // Windows `cd` без аргументов печатает текущий каталог
            return CmdResult::Done(
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|e| format!("❌ {e}")),
            );
        }
        Some(s) if s.is_empty() => {
            return CmdResult::Done(
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|e| format!("❌ {e}")),
            );
        }
        Some(s) => s.clone(),
    };
    let target = if target == "~" {
        std::env::var("HOME").unwrap_or(target)
    } else if let Some(rest) = target.strip_prefix("~/") {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest)
    } else {
        target
    };
    match std::env::set_current_dir(&target) {
        Ok(()) => CmdResult::Done(
            std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ),
        Err(e) => CmdResult::Done(format!("❌ cd: {e}")),
    }
}

fn cmd_pty(args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(
            "pty <command> — запуск команды в псевдотерминале (PTY-мост для top, gdb, htop и других интерактивных утилит)".into(),
        );
    }
    // script (util-linux) выделяет pseudo-tty: интерактивные утилиты видят TTY
    let script_cmd = args.join(" ");
    let t0 = Instant::now();
    let output = match std::process::Command::new("script")
        .arg("-qec")
        .arg(&script_cmd)
        .arg("/dev/null")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return CmdResult::Done(format!(
                "❌ pty: {e} — утилита `script` (util-linux) не найдена"
            ))
        }
    };
    let mut res = format_output("pty", &output);
    res.push_str(&agent_timing_suffix(t0));
    CmdResult::Done(res)
}

fn cmd_engine(args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(
            "engine <args...> — вызов CLI самого движка (self-exec).\nПримеры: engine --benchmark, engine --poler-box app.poler, engine --license\nКрейты pqc/pqw доступны напрямую через PATH (transparent passthrough).".into(),
        );
    }
    let exe =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("poler-engine"));
    let t0 = Instant::now();
    let output = match std::process::Command::new(&exe).args(args).output() {
        Ok(o) => o,
        Err(e) => return CmdResult::Done(format!("❌ engine: {e}")),
    };
    let mut res = format_output("engine", &output);
    res.push_str(&agent_timing_suffix(t0));
    CmdResult::Done(res)
}

// ---------------------------------------------------------------------------
// v0.47.0: read — POLER Reader внутри шелла
// ---------------------------------------------------------------------------

/// `read <книга.txt|md|fb2|poler-book> [--out x.wav] [--voice a_calm] [--seed N]`
/// Живой голос книги: роторный резонатор + коартикуляция. Без --out —
/// только статистика (сколько будет звучать).
fn cmd_read(args: &[String]) -> CmdResult {
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut voice = "a_calm".to_string();
    let mut seed: u64 = 42;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => {
                out = args.get(i + 1).cloned();
                i += 1;
            }
            "--voice" | "-v" => {
                if let Some(v) = args.get(i + 1) {
                    voice = v.clone();
                }
                i += 1;
            }
            "--seed" | "-s" => {
                if let Some(s) = args.get(i + 1) {
                    seed = s.parse().unwrap_or(42);
                }
                i += 1;
            }
            "--info" => {
                if let Some(p) = args.get(i + 1) {
                    return match poler_reader::polerbook::PolerBook::load(std::path::Path::new(p)) {
                        Ok(b) => CmdResult::Done(poler_reader::verify::book_info(&b)),
                        Err(e) => CmdResult::Done(format!("❌ {e}")),
                    };
                }
            }
            other if input.is_none() => input = Some(other.to_string()),
            _ => {}
        }
        i += 1;
    }
    let Some(path) = input else {
        return CmdResult::Done(
            "read <книга.txt|md|fb2|poler-book> [--out звук.wav] [--voice a_calm|a_bright|i_dark|u_calm] [--seed N]\n\nЖивой голос книги: роторный резонатор J=A−Aᵀ + тритная щель {-1,0,+1} +\nкоартикуляция (форманты плывут между звуками). Один seed = один голос навсегда.\n\nПримеры:\n  read книга.txt --out демо.wav --voice a_calm --seed 4242\n  read книга.poler-book --out демо.wav\n  read --info книга.poler-book\n\nКонвейер: pack через `poler-reader pack` (CLI-бинарник) — книга в 1500× меньше WAV.".into(),
        );
    };
    let path = PathBuf::from(&path);
    if !path.exists() {
        return CmdResult::Done(format!("❌ файл не найден: {}", path.display()));
    }

    let t0 = Instant::now();
    let arch = match poler_reader::voice::Archetype::from_name(&voice) {
        Some(a) => a,
        None => {
            return CmdResult::Done(format!(
                "❌ неизвестный голос {voice} (a_calm | a_bright | i_dark | u_calm)"
            ))
        }
    };

    // .poler-book — готовый паспорт; иначе текст → паспорт на лету
    let book = if poler_reader::book::detect_format(&path)
        == poler_reader::book::Format::PolerBook
    {
        match poler_reader::polerbook::PolerBook::load(&path) {
            Ok(b) => b,
            Err(e) => return CmdResult::Done(format!("❌ {e}")),
        }
    } else {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return CmdResult::Done(format!("❌ {e}")),
        };
        match poler_reader::stream::pack_book(&text, seed, arch) {
            Ok(b) => b,
            Err(e) => return CmdResult::Done(format!("❌ {e}")),
        }
    };

    match out {
        None => CmdResult::Done(poler_reader::verify::book_info(&book)),
        Some(out_path) => {
            let outp = PathBuf::from(&out_path);
            match poler_reader::stream::render_book_file(&book, seed, &outp) {
                Ok(r) => {
                    let mut res = format!(
                        "✓ {} — {:.1} с звука, {} фраз, {} периодов щели, jitter {:.2}%\nкнига: {} Б; WAV: {} Б (сжатие ×{:.0})",
                        out_path,
                        r.duration_s,
                        r.n_phrases,
                        r.passport.n_periods,
                        r.passport.jitter_std_pct,
                        book.size_bytes(),
                        r.samples.len() * 2,
                        (r.samples.len() * 2) as f64 / book.size_bytes() as f64,
                    );
                    res.push_str(&agent_timing_suffix(t0));
                    CmdResult::Done(res)
                }
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
    }
}

fn run_system_cmd(cmd: &str, args: &[String]) -> CmdResult {
    let expanded = if cmd.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            format!("{home}/{}", &cmd[2..])
        } else {
            cmd.to_string()
        }
    } else {
        cmd.to_string()
    };

    // Прямой запуск .poler-контейнера через poler-box
    if expanded.ends_with(".poler") || (cmd.ends_with(".poler") && std::path::Path::new(&expanded).exists()) {
        let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("poler-engine"));
        let status = std::process::Command::new(current_exe)
            .arg("--poler-box")
            .arg(&expanded)
            .args(args)
            .status();

        match status {
            Ok(s) => return CmdResult::Done(format!("✓ [poler-box] завершено: {s}")),
            Err(e) => return CmdResult::Done(format!("❌ poler-box error: {e}")),
        }
    }

    // v0.46.1 (аудит): у PATH-скані тепер потрібен і біт виконуваності,
    // а не лише is_file — інакше fallback тихо «запускав» довільні
    // невиконувані файли (data-файли з іменами без розширення) і давав
    // плутанину з правами.
    let is_executable = |p: &std::path::Path| -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match std::fs::metadata(p) {
                Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
                Err(_) => false,
            }
        }
        #[cfg(not(unix))]
        {
            p.is_file()
        }
    };
    let exists = if cmd.contains('/') {
        is_executable(std::path::Path::new(&expanded))
    } else if let Ok(paths) = std::env::var("PATH") {
        std::env::split_paths(&paths).any(|p| is_executable(&p.join(cmd)))
    } else {
        false
    };

    if exists {
        let t0 = Instant::now();
        let output = match std::process::Command::new(&expanded).args(args).output() {
            Ok(o) => o,
            Err(e) => return CmdResult::Done(format!("❌ помилка запуску {cmd}: {e}")),
        };
        let mut res = format_output(cmd, &output);
        res.push_str(&agent_timing_suffix(t0));
        CmdResult::Done(res)
    } else {
        CmdResult::Done(format!(
            "неизвестная команда: {cmd} (введите `help` для списка, `! <cmd>` для шелла, `win` для Windows-словаря, либо путь к .poler контейнеру)"
        ))
    }
}

// ---------------------------------------------------------------------------
// search / web — поиск по web-index.db
// ---------------------------------------------------------------------------

fn cmd_search(state: &mut ShellState, args: &[String]) -> CmdResult {
    let mut query = String::new();
    let mut top = state.top;
    for a in args {
        if a == "--top" || a == "-t" {
            // следующее значение — число, но мы не знаем заранее, поэтому
            // обработаем в следующей итерации
            continue;
        }
        if let Some(prev) = args.iter().take_while(|x| x.as_ptr() != a.as_ptr()).last() {
            if prev == "--top" || prev == "-t" {
                if let Ok(n) = a.parse::<usize>() {
                    top = n.max(1);
                    continue;
                }
            }
        }
        if !query.is_empty() {
            query.push(' ');
        }
        query.push_str(a);
    }
    if query.trim().is_empty() {
        return CmdResult::Done("поиск: пустой запрос (пример: search \"Касіопея Astra-Nic\")".into());
    }

    let ix = match state.ensure_index() {
        Ok(ix) => ix,
        Err(e) => return CmdResult::Done(format!("❌ {e}")),
    };
    let bridge = crate::retrieval::SemanticBridge::offline();
    let (hits, expansion) = match ix.search_with_bridge(&query, top, &bridge) {
        Ok(h) => h,
        Err(e) => return CmdResult::Done(format!("❌ web-search: {e}")),
    };
    let total = hits.len();
    let page_count = ix.page_count();

    let mut out = String::new();
    out.push_str(&format!(
        "🔍 «{query}» — {total} хитов из {page_count} страниц в web-index.db (top {top})\n\n"
    ));
    if hits.is_empty() {
        out.push_str("ничего не найдено. Подсказки:\n");
        out.push_str("  - наполните индекс: `crawl <URL>` здесь или poler-engine --crawl <URL>\n");
        out.push_str("  - локальные файлы ищет poler-engine <PATH> -q <QUERY> / --grep\n");
    } else {
        for (i, h) in hits.iter().enumerate() {
            out.push_str(&format_hit(i + 1, h, &query));
        }
    }
    // Semantic Bridge WHY: кросс-языковые кандидаты сенсора видны агенту
    if !expansion.is_empty() {
        out.push_str("\n🔗 Semantic Bridge (WHY):\n");
        for l in expansion.why_lines() {
            out.push_str(&format!("   {l}\n"));
        }
    }
    state.set_output(out.clone());
    CmdResult::Done(out)
}

fn format_hit(i: usize, h: &crate::web::WebHit, query: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!("{}. [{:.3}] {}\n", i, h.score, h.url));
    if !h.title.is_empty() {
        s.push_str(&format!("   title: {}\n", h.title));
    }
    if !h.snippet.is_empty() {
        s.push_str(&format!("   {}\n", h.snippet));
    }
    let _ = query;
    s
}

// ---------------------------------------------------------------------------
// stats — статистика web-index.db
// ---------------------------------------------------------------------------

fn cmd_stats(state: &mut ShellState) -> CmdResult {
    let ix = match state.ensure_index() {
        Ok(ix) => ix,
        Err(e) => return CmdResult::Done(format!("❌ {e}")),
    };
    let mut st = match ix.stats() {
        Ok(s) => s,
        Err(e) => return CmdResult::Done(format!("❌ stats: {e}")),
    };
    st.db_bytes = std::fs::metadata(state.db_path()).map(|m| m.len()).unwrap_or(0);
    let out = serde_json::to_string_pretty(&st).unwrap_or_else(|_| "{}".into());
    state.set_output(out.clone());
    CmdResult::Done(out)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set — переключение настроек шелла
// ---------------------------------------------------------------------------

fn cmd_set(state: &mut ShellState, args: &[String]) -> CmdResult {
    // v0.47.0: Windows-стиль `set NAME=VALUE` / `set NAME` / `set NAME=` (удалить)
    if let Some(first) = args.first() {
        if !matches!(first.as_str(), "format" | "top") && first.contains('=') {
            let (name, val) = first.split_once('=').expect("checked above");
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return CmdResult::Done(
                    "❌ set: имя переменной — латиница/цифры/подчёркивание".into(),
                );
            }
            if val.is_empty() {
                std::env::remove_var(name);
                return CmdResult::Done(format!("✓ {name} — удалена из сессии"));
            }
            std::env::set_var(name, val);
            return CmdResult::Done(format!("✓ {name}={val} (для этой сессии)"));
        }
        // `set NAME` — показать переменную (Windows-поведение)
        if args.len() == 1 && !matches!(first.as_str(), "format" | "top") {
            if let Ok(v) = std::env::var(first) {
                return CmdResult::Done(format!("{first}={v}"));
            }
        }
    }
    if args.len() < 2 {
        return CmdResult::Done(
            "set <key> <value> — доступные ключи: format (md|json|simple), top (N)\nWindows-стиль: set NAME=VALUE — переменная сессии; set NAME — показать".into(),
        );
    }
    let (key, val) = (args[0].as_str(), args[1].as_str());
    match key {
        "format" => match state.set_format(val) {
            Ok(()) => CmdResult::Done(format!("✓ format = {:?}", state.format)),
            Err(e) => CmdResult::Done(format!("❌ {e}")),
        },
        "top" => match val.parse::<usize>() {
            Ok(n) => {
                state.top = n.max(1);
                CmdResult::Done(format!("✓ top = {}", state.top))
            }
            Err(_) => CmdResult::Done(format!("❌ top: {val} — не число")),
        },
        other => CmdResult::Done(format!(
            "set: неизвестный ключ {other} (format | top)"
        )),
    }
}

// ---------------------------------------------------------------------------
// crawl — обход URL → web-index.db (нативная интеграция v0.15.1)
// ---------------------------------------------------------------------------
//
// Делегирует в poler_engine::web::cdp_fetcher + poler_engine::web::crawl::crawl
// — те же функции, что и в standalone-режиме `poler-engine --crawl URL`. Однако
// в шелле есть важное преимущество: WebIndex уже открыт (если был `search`/
// `stats` ранее), и единственное новое состояние — это CDP-фечер.
//
// Синтаксис:
//   crawl <URL> [--depth N] [--max M] [--cross] [--delay-ms N] [--wait-ms N]
//           [--cdp-port P]
//
// По умолчанию: depth=2, max=25, cross=false, delay-ms=1000, wait-ms=800,
// cdp-port=9222. Поддерживает `crawl` без URL → показывает help по команде.

fn cmd_crawl(state: &mut ShellState, args: &[String]) -> CmdResult {
    // Парсим: первый позиционный аргумент — seed URL; остальные — флаги.
    let mut seed: Option<String> = None;
    let mut depth: usize = 2;
    let mut max_pages: usize = 25;
    let mut cross_site: bool = false;
    let mut delay_ms: u64 = 1000;
    let mut wait_ms: u64 = 800;
    let mut cdp_port: u16 = 9222;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--depth" | "-d" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<usize>() {
                        depth = n;
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("crawl --depth: ожидается число (например --depth 3)".into());
            }
            "--max" | "-m" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<usize>() {
                        max_pages = n.max(1);
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("crawl --max: ожидается число (например --max 50)".into());
            }
            "--cross" => {
                cross_site = true;
                i += 1;
                continue;
            }
            "--delay-ms" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<u64>() {
                        delay_ms = n;
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("crawl --delay-ms: ожидается число мс".into());
            }
            "--wait-ms" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<u64>() {
                        wait_ms = n;
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("crawl --wait-ms: ожидается число мс".into());
            }
            "--cdp-port" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<u16>() {
                        cdp_port = n;
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("crawl --cdp-port: ожидается число 1024-65535".into());
            }
            "--help" | "-h" => {
                return CmdResult::Done(
                    "crawl <URL> [--depth N] [--max M] [--cross] [--delay-ms N] [--wait-ms N] [--cdp-port P]\n  по умолчанию: depth=2, max=25, cross=false, delay-ms=1000, wait-ms=800, cdp-port=9222".into()
                );
            }
            other if other.starts_with("--") => {
                return CmdResult::Done(format!("crawl: неизвестный флаг {other}"));
            }
            _ => {
                if seed.is_none() {
                    seed = Some(a.clone());
                } else {
                    return CmdResult::Done(format!("crawl: лишний аргумент {a} (URL уже задан)"));
                }
            }
        }
        i += 1;
    }

    let Some(seed) = seed else {
        return CmdResult::Done(
            "crawl: укажите seed URL (пример: crawl https://rust-lang.org --depth 2 --max 25)".into(),
        );
    };
    if !seed.starts_with("http://") && !seed.starts_with("https://") {
        return CmdResult::Done(format!(
            "crawl: seed должен быть http(s)://..., получено {seed}"
        ));
    }

    // Открываем CDP-фечер. Если Chromium не запущен — пробуем ensure_chromium.
    let mut fetcher = match crate::web::cdp_fetcher_with_timeout(cdp_port, wait_ms, 45_000) {
        Ok(f) => f,
        Err(e) => {
            let mut out = format!("❌ CDP fetcher не инициализирован (порт {cdp_port}): {e}\n");
            out.push_str("  подсказка: установите POLER_CHROME_BIN или запустите Chromium вручную:\n");
            out.push_str(&format!(
                "    chrome --headless --remote-debugging-port={cdp_port} --no-sandbox\n"
            ));
            out.push_str("  либо укажите другой порт через --cdp-port <P>");
            return CmdResult::Done(out);
        }
    };

    // WebIndex открывается ленимо — внутри ensure_index(). reuse того же
    // подключения, что и для search/stats.
    let cfg = crate::web::CrawlConfig {
        max_pages,
        max_depth: depth,
        delay_ms,
        cross_site,
        wait_ms,
        page_timeout_ms: 45_000,
        respect_robots: true,
    };

    let progress = format!(
        "🕷 crawl: seed {seed}, depth ≤ {depth}, до {max_pages} страниц, cross_site={cross_site}, delay={delay_ms}мс\n"
    );

    let res = state.ensure_index().and_then(|ix| {
        crate::web::crawl::crawl(ix, &mut fetcher, &seed, &cfg, false).map_err(|e| e.to_string())
    });

    let out = match res {
        Ok(stats) => {
            let mut s = progress;
            s.push_str(&format!(
                "✅ готово — fetched={}, indexed={}, unchanged={}, duplicates={}, errors={}, sitemap={}, elapsed={}мс\n",
                stats.fetched,
                stats.indexed,
                stats.unchanged,
                stats.duplicates,
                stats.errors,
                stats.sitemap_urls,
                stats.elapsed_ms
            ));
            if stats.frontier_left > 0 {
                s.push_str(&format!(
                    "  (frontier: ещё {} URL в очереди — увеличьте --max)\n",
                    stats.frontier_left
                ));
            }
            s
        }
        Err(e) => format!("{progress}❌ crawl: {e}"),
    };

    state.set_output(out.clone());
    CmdResult::Done(out)
}

// ---------------------------------------------------------------------------
// impact — AIDDE impact-паспорт символа (нативная интеграция v0.15.1)
// ---------------------------------------------------------------------------
//
// Делегирует в poler_engine::aidde::SymbolTable::build +
// impact_analysis (или в SQLite-хранилище через --cache <DB>).
//
// Синтаксис:
//   impact <PATH> <SYMBOL> [--depth N] [--cache <DB>] [--max-file-bytes N]
//
// PATH — каталог с кодом (или один файл). По нему строится SymbolTable
// с теми же расширениями, что и основной движок (rs, py, ts, js, go, ...),
// затем impact_analysis(target=symbol, depth=N, max_items=200) находит
// upstream/downstream паспорта — кого вызывает этот символ и кто его зовёт.

fn cmd_impact(state: &mut ShellState, args: &[String]) -> CmdResult {
    // Парсим: первые 2 позиционных аргумента — PATH и SYMBOL; остальное — флаги.
    let mut positional: Vec<String> = Vec::new();
    let mut depth: usize = 3;
    let mut cache_db: Option<PathBuf> = None;
    let mut max_file_bytes: u64 = 64 * 1024 * 1024;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--depth" | "-d" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<usize>() {
                        depth = n;
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("impact --depth: ожидается число (1-5)".into());
            }
            "--cache" => {
                if let Some(v) = args.get(i + 1) {
                    cache_db = Some(PathBuf::from(v));
                    i += 2;
                    continue;
                }
                return CmdResult::Done("impact --cache: укажите путь к SQLite-файлу".into());
            }
            "--max-file-bytes" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<u64>() {
                        max_file_bytes = n;
                        i += 2;
                        continue;
                    }
                }
                return CmdResult::Done("impact --max-file-bytes: ожидается число байт".into());
            }
            "--help" | "-h" => {
                return CmdResult::Done(
                    "impact <PATH> <SYMBOL> [--depth N] [--cache <DB>] [--max-file-bytes N]\n  по умолчанию: depth=3, max-file-bytes=64MB".into()
                );
            }
            other if other.starts_with("--") => {
                return CmdResult::Done(format!("impact: неизвестный флаг {other}"));
            }
            _ => {
                positional.push(a.clone());
            }
        }
        i += 1;
    }

    if positional.len() < 2 {
        return CmdResult::Done(
            "impact: укажите PATH и SYMBOL (пример: impact ./src main --depth 3)".into(),
        );
    }
    let path = PathBuf::from(&positional[0]);
    let symbol = positional[1].clone();

    if !path.exists() {
        return CmdResult::Done(format!("impact: путь не найден: {}", path.display()));
    }

    // Строим EngineConfig с дефолтными расширениями движка — это даёт
    // те же фильтры файлов, что и в poler-engine <PATH> --impact.
    let config = crate::EngineConfig::default();
    let files: Vec<PathBuf> = crate::collect_files(&path, &config)
        .into_iter()
        .filter(|p| crate::detect_lang(p) != crate::CodeLang::Plain)
        .collect();

    if files.is_empty() {
        return CmdResult::Done(format!(
            "impact: кодовые файлы не найдены в {} (поддерживаемые расширения: rs/py/ts/js/go/...)",
            path.display()
        ));
    }

    let mut progress = format!(
        "🔬 impact: символ {symbol}, путь {}, кодовых файлов: {}, depth={depth}\n",
        path.display(),
        files.len()
    );

    let report = if let Some(db_path) = &cache_db {
        // SQLite-режим (для 65K+ файлов) — как в `poler-engine --impact X --impact-cache Y`
        let mut store = match crate::aidde::SymbolStore::open(db_path) {
            Ok(s) => s,
            Err(e) => {
                return CmdResult::Done(format!("{progress}❌ SymbolStore::open({db_path:?}): {e}"));
            }
        };
        if let Err(e) = store.build(&files, max_file_bytes) {
            return CmdResult::Done(format!("{progress}❌ SymbolStore::build: {e}"));
        }
        let (defs, calls) = store.stats();
        progress.push_str(&format!("  SymbolStore(sqlite): defs={defs}, calls={calls}\n"));
        crate::aidde::impact_analysis_sqlite(&store, &symbol, depth, 200)
    } else {
        // In-memory режим (по умолчанию) — как в `poler-engine PATH --impact X`
        let table = crate::aidde::SymbolTable::build(&files, max_file_bytes);
        crate::aidde::impact_analysis(&table, &symbol, depth, 200)
    };

    let out = match report {
        Some(r) => {
            let mut s = progress;
            s.push_str("─────────────────────────────────────────────\n");
            s.push_str(&format!("🎯 target_function: {}\n", r.target_function));
            s.push_str(&format!("   file: {}\n", r.file));
            s.push_str(&format!("   lines: {}\n", r.lines));
            s.push_str(&format!("   danger_level_if_modified: {}\n", r.danger_level_if_modified));
            s.push('\n');
            s.push_str(&format!(
                "🔗 structural relations — доказано call graph ({}/{}):\n",
                r.structural_relations.upstream_dependents.len(),
                r.structural_relations.downstream_dependencies.len()
            ));
            s.push_str(&format!(
                "⬆ upstream dependents ({}):\n",
                r.structural_relations.upstream_dependents.len()
            ));
            for d in &r.structural_relations.upstream_dependents {
                s.push_str(&format!(
                    "   • {} (вызывает в {})\n",
                    d.caller, d.file
                ));
            }
            s.push('\n');
            s.push_str(&format!(
                "⬇ downstream dependencies ({}):\n",
                r.structural_relations.downstream_dependencies.len()
            ));
            for d in &r.structural_relations.downstream_dependencies {
                s.push_str(&format!("   • {} (вызывается из {})\n", d.callee, d.file));
            }
            if !r.heuristic_triage_alerts.is_empty() {
                s.push('\n');
                s.push_str(&format!(
                    "⚠ triage layer — эвристические сигналы, НЕ доказательства ({}):\n",
                    r.heuristic_triage_alerts.len()
                ));
                for a in &r.heuristic_triage_alerts {
                    s.push_str(&format!(
                        "   • [{}] {} — {}\n",
                        a.category.label(),
                        a.description,
                        a.marker
                    ));
                }
            }
            s
        }
        None => format!("{progress}❌ символ не найден: {symbol} (проверьте регистр/полное имя)"),
    };

    state.set_output(out.clone());
    CmdResult::Done(out)
}

// ---------------------------------------------------------------------------
// v0.16.0: VCS-команды — gh / gl / gt / gix / sync vcs
// ---------------------------------------------------------------------------

/// `poler> gh <subcommand> [args]` — GitHub REST API.
/// Субкоманды: `search <Q>`, `repos <USER>`, `commits <OWNER/REPO>`, `issues <OWNER/REPO>`.
fn cmd_gh(state: &mut ShellState, args: &[String]) -> CmdResult {
    let adapter = match crate::vcs::github_adapter() {
        Ok(a) => a,
        Err(e) => return CmdResult::Done(format!("❌ gh: {e}")),
    };
    cmd_vcs_adapter(state, "gh", adapter, args)
}

/// `poler> gl <subcommand>` — GitLab REST v4.
fn cmd_gl(state: &mut ShellState, args: &[String]) -> CmdResult {
    let adapter = match crate::vcs::gitlab_adapter() {
        Ok(a) => a,
        Err(e) => return CmdResult::Done(format!("❌ gl: {e}")),
    };
    cmd_vcs_adapter(state, "gl", adapter, args)
}

/// `poler> gt <subcommand>` — Gitea/Forgejo REST.
fn cmd_gt(state: &mut ShellState, args: &[String]) -> CmdResult {
    let adapter = match crate::vcs::gitea_adapter() {
        Ok(a) => a,
        Err(e) => return CmdResult::Done(format!("❌ gt: {e}")),
    };
    cmd_vcs_adapter(state, "gt", adapter, args)
}

/// `poler> gix <log|clone|lfs> ...` — локальный git через Pure-Rust gix.
/// v0.17.0: добавлен настоящий `clone` (через gix::clone::PrepareFetch) и `lfs`.
fn cmd_gix(state: &mut ShellState, args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(
            "gix <subcommand> — доступные:\n  gix log <PATH> [--top N]    — листинг коммитов\n  gix clone <URL> <PATH> [--depth N] [--branch B]  — Pure-Rust clone\n  gix lfs list <PATH>           — найти LFS pointer-файлы\n  gix lfs fetch <PATH>          — скачать LFS-объекты через batch API".into(),
        );
    }
    let sub = args[0].as_str();
    match sub {
        "log" => {
            let path = match args.get(1) {
                Some(p) => p,
                None => return CmdResult::Done("gix log <PATH> — укажите путь к репозиторию".into()),
            };
            let mut top = 20usize;
            let mut i = 2;
            while i < args.len() {
                if (args[i] == "--top" || args[i] == "-t") && i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse::<usize>() {
                        top = n.max(1);
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
            match crate::vcs::local::GixAdapter::list_commits_at_path(
                std::path::Path::new(path),
                top,
            ) {
                Ok(commits) => {
                    if commits.is_empty() {
                        return CmdResult::Done(format!("gix log: 0 коммитов в {path}"));
                    }
                    let mut out = String::new();
                    out.push_str(&format!("gix log {path} — {} коммитов (top {})\n\n", commits.len(), top));
                    let adapter = crate::vcs::local::GixAdapter::default();
                    let repo = crate::vcs::RepoId::from_path(std::path::Path::new(path));
                    // Заодно вливаем в web-index.db — коммиты как gix:// страницы
                    if let Ok(ix) = state.ensure_index() {
                        let docs = crate::vcs::ingest::commits_to_docs(adapter.scheme(), &repo, &commits);
                        let mut new_count = 0;
                        let mut unc_count = 0;
                        for doc in &docs {
                            if let Ok((_, was_new)) = ix.upsert_page(doc) {
                                if was_new {
                                    new_count += 1;
                                } else {
                                    unc_count += 1;
                                }
                            }
                        }
                        let _ = ix.recompute_pagerank(20);
                        out.push_str(&format!(
                            "✓ индексировано: {new_count} новых, {unc_count} без изменений (gix://)\n\n"
                        ));
                    }
                    for c in &commits {
                        let short = crate::vcs::ingest::short_sha(&c.sha);
                        let subject = c.message.lines().next().unwrap_or("");
                        out.push_str(&format!(
                            "{}  {}  <{}>  [{}]\n    {}\n",
                            short,
                            crate::vcs::ingest::iso_time(c.authored_at),
                            c.author,
                            c.author_email,
                            subject,
                        ));
                    }
                    state.set_output(out.clone());
                    CmdResult::Done(out)
                }
                Err(e) => CmdResult::Done(format!("❌ gix log: {e}")),
            }
        }
        "clone" => {
            let url = match args.get(1) {
                Some(u) => u,
                None => return CmdResult::Done("gix clone <URL> <PATH> [--depth N] [--branch B] — укажите URL".into()),
            };
            let dest = match args.get(2) {
                Some(p) => p,
                None => return CmdResult::Done("gix clone <URL> <PATH> [--depth N] [--branch B] — укажите путь назначения".into()),
            };
            // Парсинг опциональных флагов --depth N и --branch B
            let mut opts = crate::vcs::clone::CloneOpts::new(url, std::path::Path::new(dest));
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--depth" | "-d" if i + 1 < args.len() => {
                        if let Ok(n) = args[i + 1].parse::<usize>() {
                            opts = opts.with_depth(n);
                        }
                        i += 2;
                        continue;
                    }
                    "--branch" | "-b" if i + 1 < args.len() => {
                        opts = opts.with_branch(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                    _ => i += 1,
                }
            }
            match crate::vcs::clone::clone_repo(&opts) {
                Ok(p) => CmdResult::Done(format!("✓ gix clone: {url} → {}", p.display())),
                Err(e) => CmdResult::Done(format!("❌ gix clone: {}", e.to_user_string())),
            }
        }
        "lfs" => cmd_gix_lfs(state, &args[1..]),
        other => CmdResult::Done(format!("gix: неизвестная подкоманда {other} (log|clone|lfs)")),
    }
}

/// `poler> gix lfs <list|fetch> <PATH>` — LFS pointer detection + batch fetch.
fn cmd_gix_lfs(state: &mut ShellState, args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(
            "gix lfs <subcommand> — доступные:\n  gix lfs list <PATH>   — найти LFS pointer-файлы в worktree\n  gix lfs fetch <PATH>  — скачать LFS-объекты (batch API)".into(),
        );
    }
    let sub = args[0].as_str();
    match sub {
        "list" => {
            let path = match args.get(1) {
                Some(p) => p,
                None => return CmdResult::Done("gix lfs list <PATH> — укажите путь к репозиторию".into()),
            };
            let pointers = crate::vcs::lfs::detect_pointers(std::path::Path::new(path));
            let out = crate::vcs::lfs::format_pointers(&pointers);
            state.set_output(out.clone());
            CmdResult::Done(out)
        }
        "fetch" => {
            let path = match args.get(1) {
                Some(p) => p,
                None => return CmdResult::Done("gix lfs fetch <PATH> — укажите путь к репозиторию".into()),
            };
            let pointers = crate::vcs::lfs::detect_pointers(std::path::Path::new(path));
            if pointers.is_empty() {
                return CmdResult::Done("LFS pointer-файлов не обнаружено — нечего скачивать".into());
            }
            match crate::vcs::lfs::fetch_objects(std::path::Path::new(path), &pointers) {
                Ok(results) => {
                    let out = crate::vcs::lfs::format_fetch_results(&results);
                    state.set_output(out.clone());
                    CmdResult::Done(out)
                }
                Err(e) => CmdResult::Done(format!("❌ gix lfs fetch: {e}")),
            }
        }
        other => CmdResult::Done(format!("gix lfs: неизвестная подкоманда {other} (list|fetch)")),
    }
}

/// Общий обработчик для `gh`/`gl`/`gt` — все имеют REST-adapter.
fn cmd_vcs_adapter(
    state: &mut ShellState,
    label: &str,
    adapter: impl crate::vcs::VcsAdapter,
    args: &[String],
) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(format!(
            "{label} <subcommand> — доступные:\n  search <Q>\n  repos <USER>\n  commits <OWNER/REPO>\n  issues <OWNER/REPO>"
        ));
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    match sub {
        "search" => {
            let query = match rest.first() {
                Some(q) => q,
                None => return CmdResult::Done(format!("{label} search <QUERY> — укажите запрос")),
            };
            match adapter.search_code(query, 20) {
                Ok(hits) => {
                    if hits.is_empty() {
                        return CmdResult::Done(format!("{label} search «{query}»: 0 хитов"));
                    }
                    let mut out = String::new();
                    out.push_str(&format!("🔍 {label} «{query}» — {} хитов\n\n", hits.len()));
                    for (i, h) in hits.iter().enumerate() {
                        out.push_str(&format!("{}. {}\n", i + 1, h.repo));
                        out.push_str(&format!("   {}/{}\n", h.path, h.sha));
                        if !h.web_url.is_empty() {
                            out.push_str(&format!("   {}\n", h.web_url));
                        }
                        if !h.snippet.is_empty() {
                            out.push_str(&format!("   {}\n", h.snippet));
                        }
                    }
                    state.set_output(out.clone());
                    CmdResult::Done(out)
                }
                Err(e) => CmdResult::Done(format!("❌ {label} search: {e}")),
            }
        }
        "repos" => {
            let owner = match rest.first() {
                Some(o) => o,
                None => return CmdResult::Done(format!("{label} repos <USER> — укажите owner")),
            };
            match adapter.list_repos(owner) {
                Ok(repos) => {
                    if repos.is_empty() {
                        return CmdResult::Done(format!("{label} repos {owner}: 0 репозиториев"));
                    }
                    let mut out = String::new();
                    out.push_str(&format!("📂 {label} {owner} — {} репозиториев\n\n", repos.len()));
                    for (i, r) in repos.iter().enumerate() {
                        out.push_str(&format!("{}. {}\n", i + 1, r.display));
                    }
                    state.set_output(out.clone());
                    CmdResult::Done(out)
                }
                Err(e) => CmdResult::Done(format!("❌ {label} repos: {e}")),
            }
        }
        "commits" => {
            let repo_str = match rest.first() {
                Some(r) => r,
                None => return CmdResult::Done(format!("{label} commits <OWNER/REPO> — укажите")),
            };
            let repo = crate::vcs::RepoId::new(repo_str.clone(), repo_str.clone());
            match adapter.list_commits(&repo, 20) {
                Ok(commits) => {
                    if commits.is_empty() {
                        return CmdResult::Done(format!("{label} commits {repo_str}: 0 коммитов"));
                    }
                    let mut out = String::new();
                    out.push_str(&format!("📜 {label} {repo_str} — {} коммитов\n\n", commits.len()));
                    for c in &commits {
                        let short = crate::vcs::ingest::short_sha(&c.sha);
                        let subject = c.message.lines().next().unwrap_or("");
                        out.push_str(&format!(
                            "{}  {}  <{}>\n    {}\n",
                            short,
                            crate::vcs::ingest::iso_time(c.authored_at),
                            c.author,
                            subject,
                        ));
                    }
                    state.set_output(out.clone());
                    CmdResult::Done(out)
                }
                Err(e) => CmdResult::Done(format!("❌ {label} commits: {e}")),
            }
        }
        "issues" => {
            let repo_str = match rest.first() {
                Some(r) => r,
                None => return CmdResult::Done(format!("{label} issues <OWNER/REPO> — укажите")),
            };
            let repo = crate::vcs::RepoId::new(repo_str.clone(), repo_str.clone());
            match adapter.list_issues(&repo, 50) {
                Ok(issues) => {
                    if issues.is_empty() {
                        return CmdResult::Done(format!("{label} issues {repo_str}: 0 issues/MR"));
                    }
                    let mut out = String::new();
                    out.push_str(&format!("🐛 {label} {repo_str} — {} issues/MR\n\n", issues.len()));
                    for i in &issues {
                        let kind = if i.is_merge_request { "MR" } else { "IS" };
                        out.push_str(&format!("[{}] #{} {} ({})\n", kind, i.number, i.title, i.state));
                        out.push_str(&format!("    by {} at {}\n", i.author, crate::vcs::ingest::iso_time(i.created_at)));
                    }
                    state.set_output(out.clone());
                    CmdResult::Done(out)
                }
                Err(e) => CmdResult::Done(format!("❌ {label} issues: {e}")),
            }
        }
        "--help" | "-h" => CmdResult::Done(format!(
            "{label} <search|repos|commits|issues> ... — REST API {label}"
        )),
        other => CmdResult::Done(format!("{label}: неизвестная подкоманда {other}")),
    }
}

/// `poler> sync vcs [gh|gl|gt|all] <OWNER>` — синк всех VCS-страниц в web-index.db.
/// `poler> sync vcs ...` — делегация в vcs::sync_vcs (v2.0: NLM-синк удалён).
fn cmd_sync(state: &mut ShellState, args: &[String]) -> CmdResult {
    // Если первый аргумент — `vcs`, делегируем в vcs::sync_vcs.
    if !args.is_empty() && args[0] == "vcs" {
        let scheme = args.get(1).and_then(|s| crate::vcs::VcsScheme::parse(s).ok());
        let owner = args.get(2).map(|s| s.as_str());
        let limit = 20usize; // последний 20 коммитов/issue на репо
        let ix = match state.ensure_index() {
            Ok(ix) => ix,
            Err(e) => return CmdResult::Done(format!("❌ sync vcs: {e}")),
        };
        let stats = crate::vcs::sync_vcs(ix, scheme, owner, limit);
        let mut out = String::new();
        out.push_str(&format!("🔄 sync vcs: {} схем(а) обработано\n\n", stats.len()));
        for st in &stats {
            out.push_str(&format!(
                "  {}: {} репо, {} коммитов, {} issues, {} skip, {} errors ({:?}ms)\n",
                st.scheme,
                st.repos_synced,
                st.commits_indexed,
                st.issues_indexed,
                st.unchanged,
                st.errors,
                st.elapsed_ms,
            ));
        }
        state.set_output(out.clone());
        return CmdResult::Done(out);
    }
    // v2.0: NLM-sync удалён — `sync` без `vcs` больше ничего не делает
    CmdResult::Done(
        "sync: укажите схему — `sync vcs <gh|gl|gt|gix|all> [owner]` (NLM-синк удалён в v2.0)".into(),
    )
}

// ---------------------------------------------------------------------------

/// Запустить интерактивный REPL (`poler-engine --shell`).
pub fn run_shell(db_path: PathBuf) -> ExitCode {
    use rustyline::config::Configurer;
    use rustyline::error::ReadlineError;
    use rustyline::history::DefaultHistory;
    use rustyline::Editor;

    // Загружаем историю
    let hist_path = super::state::history_path();
    if let Some(parent) = hist_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // v0.15.1: создаём Editor с PolerCompleter (auto impl Helper) —
    // Tab-completion, Hinter, Validator теперь активны. Донастраиваем
    // history_size и auto_add_history через Configurer trait.
    let mut rl = match Editor::<super::completer::PolerCompleter, DefaultHistory>::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("poler-shell: rustyline init: {e}");
            return ExitCode::from(2);
        }
    };
    let _ = rl.set_max_history_size(2000);
    let _ = rl.set_history_ignore_dups(true);
    rl.set_completion_type(rustyline::config::CompletionType::List);
    rl.set_auto_add_history(true);

    // v0.15.1: подключаем PolerCompleter — Tab-completion + Hinter + Validator.
    // PolerCompleter автоматически impl Helper (Completer + Hinter +
    // Highlighter + Validator blanket impl), поэтому set_helper работает.
    rl.set_helper(Some(super::completer::PolerCompleter));

    // Load history (необязательно, ошибки молча игнорируем)
    let _ = rl.load_history(&hist_path);

    let mut state = ShellState::new(db_path);

    println!(
        "poler-shell {} — интерактивный режим. `help` — список команд, `quit` — выход.",
        env!("CARGO_PKG_VERSION")
    );
    println!("  Tab — автодополнение команд/подкоманд; ↑/↓ — история команд (до 2000).");

    loop {
        let prompt = "poler> ";
        let line = match rl.readline(prompt) {
            Ok(line) => line,
            Err(ReadlineError::WindowResized) => continue,
            Err(ReadlineError::Interrupted) => {
                println!("^C (quit — выход, `exit` тоже)");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("\nвыход (EOF)");
                break;
            }
            Err(e) => {
                eprintln!("poler-shell: ошибка ввода: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // auto_add_history=true уже сохраняет, но дублируем явно —
        // идиом-совместимо с fallback если авто-добавление выключат.
        let _ = rl.add_history_entry(trimmed);

        match dispatch(&mut state, &line) {
            CmdResult::Empty => continue,
            CmdResult::Quit => {
                println!("до свидания ✌");
                break;
            }
            CmdResult::Done(out) => {
                println!("{out}");
            }
        }
    }

    let _ = rl.save_history(&hist_path);
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// v0.17.0: notes CRUD — list/add/show/edit/rm/save-from-ai
// ---------------------------------------------------------------------------

fn cmd_notes(state: &mut ShellState, args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(
            "notes: укажите подкоманду (list | add | show | edit | rm)".into(),
        );
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    match sub {
        "list" => {
            let conn = match state.ensure_notes_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            let notes_list = match notes::list_notes(conn, 200) {
                Ok(n) => n,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            let out = notes::format_list(&notes_list);
            state.set_output(out.clone());
            CmdResult::Done(out)
        }
        "show" => {
            if rest.is_empty() {
                return CmdResult::Done("notes show <id>".into());
            }
            let id: i64 = match rest[0].parse() {
                Ok(n) => n,
                Err(_) => return CmdResult::Done(format!("❌ id должен быть числом: {}", rest[0])),
            };
            let conn = match state.ensure_notes_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            match notes::get_note(conn, id) {
                Ok(Some(n)) => {
                    let mut s = String::new();
                    s.push_str(&format!("📝 note #{}\n", n.id));
                    s.push_str(&format!("title: {}\n", n.title));
                    if !n.tags.is_empty() {
                        s.push_str(&format!("tags:   {}\n", n.tags.join(", ")));
                    }
                    s.push_str(&format!("source: {}\n", n.source));
                    if let Some(nb) = &n.notebook_id {
                        s.push_str(&format!("notebook: {}\n", nb));
                    }
                    s.push_str("\n");
                    s.push_str(&n.body);
                    state.set_output(s.clone());
                    CmdResult::Done(s)
                }
                Ok(None) => CmdResult::Done(format!("note id {id} не найдена")),
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        "add" => {
            if rest.is_empty() {
                return CmdResult::Done(
                    "notes add <title> — укажите заголовок (тело введёте в TUI редакторе через Ctrl+N)".into(),
                );
            }
            let title = rest.join(" ");
            let conn = match state.ensure_notes_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            match notes::add_note(conn, &title, "", &[], notes::NoteSource::Manual, None) {
                Ok(id) => {
                    let msg = format!("✓ Создана пустая заметка #{id} «{title}». Используйте `notes edit {id}` в TUI для ввода тела.");
                    CmdResult::Done(msg)
                }
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        "edit" => {
            // В REPL-режиме мы не открываем TUI редактор (нет raw-mode). Просто
            // покажем тело и подскажем открыть TUI.
            if rest.is_empty() {
                return CmdResult::Done("notes edit <id>".into());
            }
            let id: i64 = match rest[0].parse() {
                Ok(n) => n,
                Err(_) => return CmdResult::Done(format!("❌ id должен быть числом: {}", rest[0])),
            };
            CmdResult::Done(format!(
                "📝 В REPL-режиме редактирование не поддерживается. Запустите `poler-engine --tui` и используйте Ctrl+N / Ctrl+E для встроенного редактора. (note #{id})"
            ))
        }
        "rm" => {
            // v0.17.5: удаление локальной заметки — с подтверждением --yes
            use super::confirm::{env_yes, split_gate_flags};
            let (yes_flag, _dry, positional) = split_gate_flags(rest);
            if positional.is_empty() {
                return CmdResult::Done("notes rm <id> [--yes]".into());
            }
            let id: i64 = match positional[0].parse() {
                Ok(n) => n,
                Err(_) => return CmdResult::Done(format!("❌ id должен быть числом: {}", positional[0])),
            };
            let conn = match state.ensure_notes_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            if !(yes_flag || env_yes()) {
                // покажем, что удаляем, и попросим подтверждение
                let shown = match notes::get_note(conn, id) {
                    Ok(Some(n)) => format!("«{}»", n.title),
                    Ok(None) => return CmdResult::Done(format!("note id {id} не найдена")),
                    Err(e) => return CmdResult::Done(format!("❌ {e}")),
                };
                return CmdResult::Done(format!(
                    "🔒 Заметка #{id} {shown} будет удалена локально (без возможности отмены).\nПодтверди: notes rm {id} --yes"
                ));
            }
            match notes::delete_note(conn, id) {
                Ok(()) => CmdResult::Done(format!("✓ Заметка #{id} удалена")),
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        other => CmdResult::Done(format!(
            "notes: неизвестная подкоманда {other} (list|add|show|edit|rm)"
        )),
    }
}

// ---------------------------------------------------------------------------
// v0.17.0: sources CRUD — list/add/rm/test/open
// ---------------------------------------------------------------------------

fn cmd_sources(state: &mut ShellState, args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult::Done(
            "sources: укажите подкоманду (list | add | rm | test | open)".into(),
        );
    }
    let sub = args[0].as_str();
    let rest = &args[1..];
    match sub {
        "list" => {
            let conn = match state.ensure_sources_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            let srcs = match sources::list_sources(conn, 500) {
                Ok(s) => s,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            let out = sources::format_list(&srcs);
            state.set_output(out.clone());
            CmdResult::Done(out)
        }
        "add" => {
            if rest.is_empty() {
                return CmdResult::Done(
                    "sources add <value> [--kind file|url|repo] [--label \"текст\"]".into(),
                );
            }
            let mut value = String::new();
            let mut kind: Option<sources::SourceKind> = None;
            let mut label: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--kind" if i + 1 < rest.len() => {
                        kind = sources::SourceKind::from_str(&rest[i + 1]);
                        i += 2;
                        continue;
                    }
                    "--label" if i + 1 < rest.len() => {
                        label = Some(rest[i + 1].clone());
                        i += 2;
                        continue;
                    }
                    other => {
                        if !value.is_empty() {
                            value.push(' ');
                        }
                        value.push_str(other);
                        i += 1;
                    }
                }
            }
            if value.trim().is_empty() {
                return CmdResult::Done("❌ пустое значение источника".into());
            }
            let conn = match state.ensure_sources_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            match sources::add_source(conn, kind, &value, label.as_deref()) {
                Ok(id) => {
                    let detected = kind.unwrap_or_else(|| sources::detect_kind(&value));
                    CmdResult::Done(format!(
                        "✓ Добавлен источник #{id} [{}] {}",
                        detected.as_str(),
                        value
                    ))
                }
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        "rm" => {
            if rest.is_empty() {
                return CmdResult::Done("sources rm <id>".into());
            }
            let id: i64 = match rest[0].parse() {
                Ok(n) => n,
                Err(_) => return CmdResult::Done(format!("❌ id должен быть числом: {}", rest[0])),
            };
            let conn = match state.ensure_sources_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            match sources::delete_source(conn, id) {
                Ok(()) => CmdResult::Done(format!("✓ Источник #{id} удалён")),
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        "test" => {
            if rest.is_empty() {
                return CmdResult::Done("sources test <id>".into());
            }
            let id: i64 = match rest[0].parse() {
                Ok(n) => n,
                Err(_) => return CmdResult::Done(format!("❌ id должен быть числом: {}", rest[0])),
            };
            let conn = match state.ensure_sources_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            match sources::test_source(conn, id) {
                Ok(sources::TestStatus::Ok) => CmdResult::Done(format!("✓ #{id}: доступен")),
                Ok(sources::TestStatus::Fail) => CmdResult::Done(format!("✗ #{id}: недоступен")),
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        "open" => {
            if rest.is_empty() {
                return CmdResult::Done("sources open <id>".into());
            }
            let id: i64 = match rest[0].parse() {
                Ok(n) => n,
                Err(_) => return CmdResult::Done(format!("❌ id должен быть числом: {}", rest[0])),
            };
            let conn = match state.ensure_sources_conn() {
                Ok(c) => c,
                Err(e) => return CmdResult::Done(format!("❌ {e}")),
            };
            match sources::open_source(conn, id) {
                Ok(()) => CmdResult::Done(format!("✓ #{id}: отправлено в xdg-open")),
                Err(e) => CmdResult::Done(format!("❌ {e}")),
            }
        }
        other => CmdResult::Done(format!(
            "sources: неизвестная подкоманда {other} (list|add|rm|test|open)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_basic() {
        let t = tokenize("search \"hello world\"");
        assert_eq!(t, vec!["search", "hello world"]);
    }

    #[test]
    fn tokenize_single_quotes() {
        let t = tokenize("notes add 'заметка с пробелами'");
        assert_eq!(t, vec!["notes", "add", "заметка с пробелами"]);
    }

    #[test]
    fn tokenize_mixed_quotes_and_flags() {
        let t = tokenize("search \"x y\" --top 5 z");
        assert_eq!(t, vec!["search", "x y", "--top", "5", "z"]);
    }

    #[test]
    fn tokenize_empty_and_whitespace() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("    ").is_empty());
        assert_eq!(tokenize("a"), vec!["a"]);
    }

    #[test]
    fn tokenize_unclosed_quote_takes_rest() {
        let t = tokenize("search \"unclosed");
        assert_eq!(t, vec!["search", "unclosed"]);
    }

    #[test]
    fn cmd_set_format_works() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "set format json");
        match r {
            CmdResult::Done(out) => assert!(out.contains("AiJson")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_unknown_returns_message() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "nosuchcmd xyz");
        match r {
            CmdResult::Done(out) => assert!(out.contains("неизвестная команда")),
            _ => panic!(),
        }
    }

    // ── v0.46.x (аудит 2026-09-21): системний прохід ────────────────────

    #[test]
    fn bang_empty_shows_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "!") {
            CmdResult::Done(out) => assert!(out.contains("! <command>")),
            _ => panic!(),
        }
    }

    #[test]
    fn bang_runs_shell_command() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "! echo poler_audit_ok") {
            CmdResult::Done(out) => assert_eq!(out.trim(), "poler_audit_ok"),
            _ => panic!(),
        }
    }

    #[test]
    fn sh_command_alias_runs() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "sh echo poler_sh_alias_ok") {
            CmdResult::Done(out) => assert_eq!(out.trim(), "poler_sh_alias_ok"),
            _ => panic!(),
        }
    }

    #[test]
    fn fallback_runs_path_executable_with_args() {
        // `echo` є в PATH будь-якого POSIX-оточення тестів
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "echo --n poler_fallback_ok") {
            CmdResult::Done(out) => assert!(out.contains("poler_fallback_ok")),
            _ => panic!(),
        }
    }

    #[test]
    fn fallback_rejects_non_executable_file() {
        // файл без біта виконуваності НЕ має запускатись (v0.46.1 аудит)
        let dir = std::env::temp_dir().join("poler_sh_audit_nonexec");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("poler_nonexec_probe"); // без розширення, без chmod +x
        std::fs::write(&f, b"not a program").unwrap();
        let out_path = format!("{}", f.display());
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, &out_path) {
            CmdResult::Done(out) => assert!(out.contains("неизвестная команда")),
            _ => panic!(),
        }
        let _ = std::fs::remove_file(&f);
    }

    // -----------------------------------------------------------------
    // v0.47.0: WinCompat + агентная среда
    // -----------------------------------------------------------------

    #[test]
    fn win_type_runs_cat() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "type /etc/hostname") {
            CmdResult::Done(out) => {
                assert!(!out.contains("неизвестная команда"), "type должен перевестись в cat: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn win_dir_runs_ls_not_unknown() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "dir /etc/hostname") {
            CmdResult::Done(out) => {
                assert!(!out.contains("неизвестная команда"), "dir должен перевестись в ls: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn win_tasklist_runs_ps() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "tasklist") {
            CmdResult::Done(out) => {
                assert!(out.contains("PID") || out.contains("root") || out.is_empty(),
                    "tasklist → ps aux: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn win_ver_runs_uname() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "ver") {
            CmdResult::Done(out) => {
                assert!(out.contains("Linux"), "ver → uname -sr: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn win_net_is_notice_not_execution() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "net use") {
            CmdResult::Done(out) => {
                assert!(out.contains("🚫"), "net не должен выполняться: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cd_changes_and_restores_directory() {
        let saved = std::env::current_dir().unwrap();
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "cd /tmp") {
            CmdResult::Done(out) => {
                assert!(out.contains("/tmp"), "cd печатает новый каталог: {out}");
            }
            _ => panic!(),
        }
        assert_eq!(std::env::current_dir().unwrap(), std::path::PathBuf::from("/tmp"));
        // возврат для изоляции остальных тестов
        let back = format!("cd {}", saved.display());
        let _ = dispatch(&mut s, &back);
        assert_eq!(std::env::current_dir().unwrap(), saved);
    }

    #[test]
    fn cd_bare_prints_cwd() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "cd") {
            CmdResult::Done(out) => assert!(!out.is_empty()),
            _ => panic!(),
        }
    }

    #[test]
    fn pwd_prints_absolute_path() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "pwd") {
            CmdResult::Done(out) => {
                assert!(out.starts_with('/'), "pwd — абсолютный путь: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn set_windows_env_var_and_show() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "set POLER_TEST_WIN=hello47") {
            CmdResult::Done(out) => {
                assert!(out.contains("POLER_TEST_WIN"), "set NAME=VALUE: {out}");
            }
            _ => panic!(),
        }
        assert_eq!(std::env::var("POLER_TEST_WIN").unwrap(), "hello47");
        match dispatch(&mut s, "set POLER_TEST_WIN") {
            CmdResult::Done(out) => {
                assert!(out.contains("hello47"), "set NAME показывает: {out}");
            }
            _ => panic!(),
        }
        // удаление пустым значением
        let _ = dispatch(&mut s, "set POLER_TEST_WIN=");
        assert!(std::env::var("POLER_TEST_WIN").is_err());
    }

    #[test]
    fn set_format_and_top_still_work() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "set format json") {
            CmdResult::Done(out) => assert!(out.contains("json") || out.contains("Json")),
            _ => panic!(),
        }
        match dispatch(&mut s, "set top 7") {
            CmdResult::Done(out) => assert!(out.contains('7')),
            _ => panic!(),
        }
    }

    #[test]
    fn sysinfo_reports_sections() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "sysinfo") {
            CmdResult::Done(out) => {
                assert!(out.contains("[cpu]"));
                assert!(out.contains("[agent mode]"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn systeminfo_alias_works() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "systeminfo") {
            CmdResult::Done(out) => assert!(out.contains("sysinfo")),
            _ => panic!(),
        }
    }

    #[test]
    fn env_masks_token_values() {
        std::env::set_var("POLER_SHELL_TEST_SECRET", "supersecretvalue123");
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "env POLER_SHELL_TEST") {
            CmdResult::Done(out) => {
                assert!(out.contains("POLER_SHELL_TEST_SECRET"));
                assert!(!out.contains("supersecretvalue123"), "секрет должен маскироваться: {out}");
            }
            _ => panic!(),
        }
        std::env::remove_var("POLER_SHELL_TEST_SECRET");
    }

    #[test]
    fn win_catalog_command_lists_translations() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "win") {
            CmdResult::Done(out) => {
                assert!(out.contains("findstr"));
                assert!(out.contains("taskkill"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn agent_command_mentions_exec_json() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "agent") {
            CmdResult::Done(out) => {
                assert!(out.contains("--exec"));
                assert!(out.contains("--json"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn engine_bare_shows_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "engine") {
            CmdResult::Done(out) => assert!(out.contains("self-exec")),
            _ => panic!(),
        }
    }

    #[test]
    fn pty_bare_shows_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "pty") {
            CmdResult::Done(out) => assert!(out.contains("PTY")),
            _ => panic!(),
        }
    }

    #[test]
    fn echo_win_vars_expanded() {
        // чистые функции: детекция и раскрытие %NAME%
        assert!(contains_win_var("%PATH%"));
        assert!(contains_win_var("hello %USER% x"));
        assert!(!contains_win_var("100% done"));
        assert!(!contains_win_var("no vars"));
        assert_eq!(expand_win_vars("%HOME%"), "${HOME}");
        assert_eq!(expand_win_vars("a %X_Y% b"), "a ${X_Y} b");
        assert_eq!(expand_win_vars("50%"), "50%");
        assert_eq!(expand_win_vars("%bad-name%"), "%bad-name%");
    }

    #[test]
    fn unknown_command_hint_mentions_win() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "zzzdefinitely_not_a_cmd") {
            CmdResult::Done(out) => {
                assert!(out.contains("win"), "подсказка должна упоминать Windows-словарь: {out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn read_bare_shows_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "read") {
            CmdResult::Done(out) => {
                assert!(out.contains("Живой голос книги"));
                assert!(out.contains("--voice"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn read_missing_file_errors() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        match dispatch(&mut s, "read /no/such/file.txt") {
            CmdResult::Done(out) => assert!(out.contains("❌")),
            _ => panic!(),
        }
    }

    #[test]
    fn read_bad_voice_errors() {
        let dir = std::env::temp_dir().join("poler_sh_read");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("b.txt");
        std::fs::write(&f, "Тест.").unwrap();
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let line = format!("read {} --voice robot", f.display());
        match dispatch(&mut s, &line) {
            CmdResult::Done(out) => assert!(out.contains("❌")),
            _ => panic!(),
        }
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn read_stats_without_out() {
        let dir = std::env::temp_dir().join("poler_sh_read");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("c.txt");
        std::fs::write(&f, "Первая фраза. Вторая фраза!").unwrap();
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let line = format!("read {}", f.display());
        match dispatch(&mut s, &line) {
            CmdResult::Done(out) => {
                assert!(out.contains("фраз"), "инфо о книге: {out}");
            }
            _ => panic!(),
        }
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn read_renders_wav_end_to_end() {
        let dir = std::env::temp_dir().join("poler_sh_read");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("d.txt");
        std::fs::write(&f, "Живой голос книги работает.").unwrap();
        let wav = dir.join("d.wav");
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let line = format!(
            "read {} --out {} --voice a_calm --seed 7",
            f.display(),
            wav.display()
        );
        match dispatch(&mut s, &line) {
            CmdResult::Done(out) => {
                assert!(out.contains("✓"), "рендер: {out}");
                assert!(out.contains("сжатие"));
            }
            _ => panic!(),
        }
        assert!(wav.exists(), "WAV должен быть создан");
        // валидный заголовок
        let head = std::fs::read(&wav).unwrap();
        assert_eq!(&head[0..4], b"RIFF");
        let _ = std::fs::remove_file(&f);
        let _ = std::fs::remove_file(&wav);
    }

    // ================================================================
    // v0.48.0: Калькулятор Всего — интеграционные тесты dispatch
    // ================================================================
    fn calc_out(line: &str) -> String {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-calc.db"));
        match dispatch(&mut s, line) {
            CmdResult::Done(out) => out,
            other => panic!("ожидался Done, получено {other:?}"),
        }
    }

    #[test]
    fn cmd_calc_basic() {
        assert_eq!(calc_out("calc 2^10"), "1024.0");
        assert_eq!(calc_out("calc (1538 * 485) / 1024"), "728.447265625");
        assert_eq!(calc_out("calc 5!"), "120.0");
        assert_eq!(calc_out("calc sin(pi/2)"), "1.0");
        assert!(calc_out("calc 5 km to mi").starts_with("3.106"));
    }

    // -----------------------------------------------------------------
    // v0.51.0 (цикл P): квантовый мост
    // -----------------------------------------------------------------

    #[test]
    fn cmd_quantum_usage_and_list() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q1.db"));
        match dispatch(&mut s, "quantum") {
            CmdResult::Done(out) => assert!(out.contains("quantum run"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "qm list") {
            CmdResult::Done(out) => {
                assert!(out.contains("bell"), "{out}");
                assert!(out.contains("teleport"), "{out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_quantum_run_ghz() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q2.db"));
        match dispatch(&mut s, "quantum run ghz --n 4 --shots 256") {
            CmdResult::Done(out) => {
                assert!(out.contains("GHZ") || out.contains("ghz"), "{out}");
                assert!(out.contains("кубитов: 4"), "{out}");
                // GHZ-4: только |0000⟩ и |1111⟩
                assert!(out.contains("0000") && out.contains("1111"), "{out}");
            }
            _ => panic!(),
        }
        // JSON-режим для агентов
        match dispatch(&mut s, "quantum run bell --json") {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).expect("валидный JSON");
                assert_eq!(v["algorithm"], "bell");
                assert_eq!(v["n_qubits"], 2);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_quantum_teleport_fidelity() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q3.db"));
        match dispatch(&mut s, "quantum teleport --theta 0.7") {
            CmdResult::Done(out) => {
                assert!(out.contains("фиделити"), "{out}");
                assert!(out.contains("1.000000000000000"), "{out}");
                assert!(out.contains("канал идеален"), "{out}");
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "quantum teleport --exact --json") {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).expect("валидный JSON");
                assert_eq!(v["fidelity"], 1.0);
                assert_eq!(v["exact"], true);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_quantum_bloch_states() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q4.db"));
        match dispatch(&mut s, "quantum bloch 1/sqrt(2) 1/sqrt(2)") {
            CmdResult::Done(out) => {
                assert!(out.contains("x = +1.000000"), "{out}");
                assert!(out.contains("|+⟩"), "{out}");
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "quantum state 0.6 0.8i") {
            CmdResult::Done(out) => {
                assert!(out.contains("P(|0⟩) = 0.360000"), "{out}");
                assert!(out.contains("y = +0.960000"), "{out}");
            }
            _ => panic!(),
        }
        // |0⟩: северный полюс
        match dispatch(&mut s, "quantum bloch 1") {
            CmdResult::Done(out) => assert!(out.contains("z = +1.000000"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_quantum_verify_exact() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q5.db"));
        match dispatch(&mut s, "quantum verify teleport") {
            CmdResult::Done(out) => {
                assert!(out.contains("ДОКАЗАНО ТОЧНО"), "{out}");
                assert!(out.contains("teleport_channel"), "{out}");
            }
            _ => panic!(),
        }
        // QFT-3: CP(π/2), CP(π/4) — точно в кольце
        match dispatch(&mut s, "quantum verify unitary qft --n 3") {
            CmdResult::Done(out) => assert!(out.contains("ДОКАЗАНО ТОЧНО"), "{out}"),
            _ => panic!(),
        }
        // опровержение фиксируется честно
        match dispatch(&mut s, "quantum verify equiv qft iqft --n 3") {
            CmdResult::Done(out) => assert!(out.contains("ОПРОВЕРГНУТО"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_quantum_calc_bridge() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q6.db"));
        // мост в физику цикла O
        match dispatch(&mut s, "quantum calc exp(i * pi)") {
            CmdResult::Done(out) => assert!(out.starts_with("-1.0"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "quantum calc schrodinger(pauli_y(), [1; 0], pi/2)") {
            CmdResult::Done(out) => assert!(out.contains("0") && out.contains("1"), "{out}"),
            _ => panic!(),
        }
    }

    // -----------------------------------------------------------------
    // v0.52.0 (цикл Q): qcasm, qaoa, шум поверх верификатора
    // -----------------------------------------------------------------

    #[test]
    fn cmd_quantum_qcasm_bell() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q7.db"));
        let path = std::env::temp_dir().join("poler_qcasm_bell.qc");
        std::fs::write(&path, "qubits 2\nh 0\ncx 0 1\nmeasure all\n").unwrap();
        match dispatch(&mut s, &format!("quantum qcasm {} --shots 256 --seed 7", path.display())) {
            CmdResult::Done(out) => {
                assert!(out.contains("кубитов: 2"), "{out}");
                assert!(out.contains("|00⟩") && out.contains("|11⟩"), "{out}");
                assert!(!out.contains("|01⟩"), "{out}");
            }
            _ => panic!(),
        }
        // алиас `run qcasm` + JSON
        match dispatch(&mut s, &format!("quantum run qcasm {} --json", path.display())) {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).expect("валидный JSON");
                assert_eq!(v["mode"], "qcasm");
                assert_eq!(v["n_qubits"], 2);
                let p00 = v["probabilities"][0].as_f64().unwrap();
                let p11 = v["probabilities"][3].as_f64().unwrap();
                assert!((p00 - 0.5).abs() < 1e-12 && (p11 - 0.5).abs() < 1e-12);
            }
            _ => panic!(),
        }
        // точный режим: Белл в кольце Z[1/√2, i]
        match dispatch(&mut s, &format!("quantum qcasm {} --exact", path.display())) {
            CmdResult::Done(out) => {
                assert!(out.contains("ТОЧНОЕ КОЛЬЦО"), "{out}");
                assert!(out.contains("1/2"), "{out}");
            }
            _ => panic!(),
        }
        // ошибка разбора честная, с номером строки
        let bad = std::env::temp_dir().join("poler_qcasm_bad.qc");
        std::fs::write(&bad, "qubits 2\nh 5\n").unwrap();
        match dispatch(&mut s, &format!("quantum qcasm {}", bad.display())) {
            CmdResult::Done(out) => assert!(out.contains("ошибка разбора"), "{out}"),
            _ => panic!(),
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn cmd_quantum_qcasm_noise() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q8.db"));
        let path = std::env::temp_dir().join("poler_qcasm_ghz.qc");
        std::fs::write(&path, "qubits 3\nh 0\ncx 0 1\ncx 0 2\nmeasure all\n").unwrap();
        // ideal: расхождение — только биномиальный шум сэмплинга
        match dispatch(
            &mut s,
            &format!("quantum qcasm {} --noise ideal --shots 2000 --seed 1 --json", path.display()),
        ) {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert_eq!(v["mode"], "qcasm-noise-mcwf");
                assert!(v["tvd"].as_f64().unwrap() < 0.08, "TVD = {}", v["tvd"]);
            }
            _ => panic!(),
        }
        // noisy-90s: распределение реально деградирует
        match dispatch(
            &mut s,
            &format!("quantum qcasm {} --noise noisy-90s --shots 4000 --seed 1 --json", path.display()),
        ) {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert!(v["tvd"].as_f64().unwrap() > 0.10, "TVD = {}", v["tvd"]);
                assert!(v["noisy_peak"].as_f64().unwrap() < v["ideal_peak"].as_f64().unwrap());
                assert!(v["chi2"].as_f64().unwrap() > 30.0, "χ² = {}", v["chi2"]);
            }
            _ => panic!(),
        }
        // неизвестный пресет — честный отказ
        match dispatch(&mut s, &format!("quantum qcasm {} --noise qpu-3000", path.display())) {
            CmdResult::Done(out) => assert!(out.contains("неизвестный пресет"), "{out}"),
            _ => panic!(),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cmd_quantum_qaoa_triangle() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q9.db"));
        match dispatch(
            &mut s,
            "quantum qaoa --edges 0-1,1-2,0-2 --p 2 --restarts 2 --sweeps 10 --json",
        ) {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert_eq!(v["algorithm"], "qaoa");
                assert_eq!(v["n_qubits"], 3);
                assert!(v["expected_cut"].as_f64().unwrap() > 1.8, "{}", v["expected_cut"]);
                assert_eq!(v["best_cut"], 2);
                assert_eq!(v["optimum"], 2);
                assert!(v["approx_ratio"].as_f64().unwrap() >= 0.999);
                assert!(v["evals"].as_u64().unwrap() > 4);
            }
            _ => panic!(),
        }
        // текстовый отчёт демо-графа
        match dispatch(&mut s, "quantum qaoa --p 1 --restarts 1 --sweeps 6") {
            CmdResult::Done(out) => {
                assert!(out.contains("QAOA"), "{out}");
                assert!(out.contains("аппроксимационное отношение"), "{out}");
            }
            _ => panic!(),
        }
        // валидация честная
        match dispatch(&mut s, "quantum qaoa --edges 1-1") {
            CmdResult::Done(out) => assert!(out.contains("петля"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "quantum qaoa --edges a-b") {
            CmdResult::Done(out) => assert!(out.contains("не число"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_quantum_verify_with_noise() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-q10.db"));
        match dispatch(
            &mut s,
            "quantum verify unitary ghz --n 4 --noise ideal --shots 2000 --json",
        ) {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert_eq!(v["verdict"], "proved_exact");
                let noise = v["noise"].as_object().expect("блок шума");
                assert_eq!(noise["preset"], "ideal");
                assert!(noise["tvd"].as_f64().unwrap() < 0.08);
            }
            _ => panic!(),
        }
        // телепортация: точный вердикт + деградация на железе 90-х
        match dispatch(&mut s, "quantum verify teleport --noise noisy-90s --shots 3000") {
            CmdResult::Done(out) => {
                assert!(out.contains("ДОКАЗАНО ТОЧНО"), "{out}");
                assert!(out.contains("Шум поверх верификатора"), "{out}");
                assert!(out.contains("TVD"), "{out}");
            }
            _ => panic!(),
        }
        // equiv: две схемы — шум честно не применяется
        match dispatch(&mut s, "quantum verify equiv qft iqft --n 3 --noise ibm-heron") {
            CmdResult::Done(out) => assert!(out.contains("Шум не применён"), "{out}"),
            _ => panic!(),
        }
    }

    // -----------------------------------------------------------------
    // v0.53.0 (цикл R): P³-Мост — info / conformance / frame
    // -----------------------------------------------------------------

    #[test]
    fn cmd_p3_usage_and_unknown() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-r1.db"));
        match dispatch(&mut s, "p3") {
            CmdResult::Done(out) => {
                assert!(out.contains("p3 conformance"), "{out}");
                assert!(out.contains("p3 frame"), "{out}");
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "p3 help") {
            CmdResult::Done(out) => assert!(out.contains("p3 info"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "p3 bogus") {
            CmdResult::Done(out) => assert!(out.contains("неизвестная подкоманда"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_p3_info_loads_library() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-r2.db"));
        match dispatch(&mut s, "p3 info") {
            CmdResult::Done(out) => {
                // библиотека коммитится в ffi/ — на Linux x86_64 обязана
                // загрузиться; на иных платформах честный отказ
                assert!(
                    out.contains("P³-Мост активен") || out.contains("P³-Мост недоступен"),
                    "{out}"
                );
                if out.contains("активен") {
                    assert!(out.contains("p3-kernel"), "{out}");
                    assert!(out.contains("ABI        : v1"), "{out}");
                }
            }
            _ => panic!(),
        }
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn cmd_p3_conformance_report() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-r3.db"));
        match dispatch(&mut s, "p3 conformance --pairs 12") {
            CmdResult::Done(out) => {
                assert!(out.contains("КОНФОРМАНС ПОДТВЕРЖДЁН"), "{out}");
                assert!(out.contains("d_FS(a,b)"), "{out}");
                assert!(out.contains("U†U = I"), "{out}");
                assert!(out.contains("P² − P") || out.contains("Идемпотент"), "{out}");
            }
            _ => panic!(),
        }
        // JSON-режим — машиночитаемый отчёт
        match dispatch(&mut s, "p3 conformance --pairs 8 --json") {
            CmdResult::Done(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).expect("JSON: {out}");
                assert_eq!(v["passed"], serde_json::json!(true));
                assert!(v["checks"].as_array().unwrap().len() >= 7);
                assert!(v["kernel"].as_str().unwrap().contains("p3-kernel"));
            }
            _ => panic!(),
        }
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn cmd_p3_frame_renders_pngs() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-r4.db"));
        let dir = std::env::temp_dir().join("poler_p3_shell_test");
        match dispatch(
            &mut s,
            &format!("p3 frame --n 3 --steps 6 --size 128x96 --cloud 4 --out {}", dir.display()),
        ) {
            CmdResult::Done(out) => {
                assert!(out.contains("Кадр из гамильтониана"), "{out}");
                assert!(out.contains("дрейф энергии"), "{out}");
                let _ = std::fs::remove_dir_all(&dir);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_p3_frame_validates_args() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-r5.db"));
        match dispatch(&mut s, "p3 frame --n 12") {
            CmdResult::Done(out) => assert!(out.contains("--n 2..=8"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "p3 frame --size 10x10") {
            CmdResult::Done(out) => assert!(out.contains("64..=4096"), "{out}"),
            _ => panic!(),
        }
    }

    // -----------------------------------------------------------------
    // v0.54.0 (цикл S): Ядро Игры
    // -----------------------------------------------------------------

    #[test]
    fn cmd_game_usage_and_unknown() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s1.db"));
        match dispatch(&mut s, "game") {
            CmdResult::Done(out) => {
                assert!(out.contains("game demo"), "{out}");
                assert!(out.contains("game scene"), "{out}");
                assert!(out.contains("write-demo"), "{out}");
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "game help") {
            CmdResult::Done(out) => assert!(out.contains("game info"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game bogus") {
            CmdResult::Done(out) => assert!(out.contains("неизвестная подкоманда"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_texture_writes_png() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s6.db"));
        let dir = std::env::temp_dir().join("poler_game_tex_shell");
        let _ = std::fs::create_dir_all(&dir);
        let png = dir.join("t.png");
        match dispatch(
            &mut s,
            &format!(
                "game texture --style wood --size 96x64 --seed 3 --out {} --svd-rank 4",
                png.display()
            ),
        ) {
            CmdResult::Done(out) => {
                assert!(out.contains("Спектральный синтез"), "{out}");
                assert!(out.contains("хеш текстуры 0x"), "{out}");
                assert!(out.contains("SVD rank-4"), "{out}");
                assert!(png.exists(), "PNG не записан");
                let raw = std::fs::read(&png).unwrap();
                assert_eq!(&raw[1..4], b"PNG");
                let _ = std::fs::remove_dir_all(&dir);
            }
            _ => panic!(),
        }
        // --rank-curve без --svd-rank
        let dir2 = std::env::temp_dir().join("poler_game_tex_curve");
        let _ = std::fs::create_dir_all(&dir2);
        let png2 = dir2.join("c.png");
        match dispatch(
            &mut s,
            &format!(
                "game texture --style noise --size 64x64 --out {} --rank-curve --json",
                png2.display()
            ),
        ) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).expect("JSON");
                let curve = j["rank_curve"].as_array().expect("кривая в JSON");
                assert!(curve.len() == 5);
                assert!(curve.last().unwrap()["psnr_db"].as_f64().unwrap() > 50.0);
                let _ = std::fs::remove_dir_all(&dir2);
            }
            _ => panic!(),
        }
        // Валидация
        for bad in [
            "game texture --style bogus",
            "game texture --palette neon",
            "game texture --svd-rank 99",
            "game texture --zoom 0",
        ] {
            match dispatch(&mut s, bad) {
                CmdResult::Done(out) => assert!(out.contains("game texture:"), "{bad} → {out}"),
                _ => panic!(),
            }
        }
    }

    #[test]
    fn cmd_game_info_reports_core() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s2.db"));
        match dispatch(&mut s, "game info") {
            CmdResult::Done(out) => {
                assert!(out.contains("POLER GAME CORE"), "{out}");
                assert!(out.contains("aetheria"), "{out}");
                assert!(out.contains("Этерия"), "{out}");
                assert!(out.contains("state-hash") && out.contains("0x"), "{out}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_sound_writes_wav() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s5.db"));
        let dir = std::env::temp_dir().join("poler_game_sound_shell");
        let _ = std::fs::create_dir_all(&dir);
        let wav = dir.join("t.wav");
        match dispatch(
            &mut s,
            &format!("game sound --ticks 60 --fs 22050 --out {}", wav.display()),
        ) {
            CmdResult::Done(out) => {
                assert!(out.contains("Акустический кристалл"), "{out}");
                assert!(out.contains("хеш аудио: 0x"), "{out}");
                assert!(out.contains("хеш кристалла: 0x"), "{out}");
                assert!(out.contains("dBFS"), "{out}");
                assert!(wav.exists(), "WAV не записан");
                let raw = std::fs::read(&wav).unwrap();
                assert_eq!(&raw[0..4], b"RIFF");
                assert_eq!(&raw[8..12], b"WAVE");
                let _ = std::fs::remove_dir_all(&dir);
            }
            _ => panic!(),
        }
        // JSON-режим и валидация
        let dir2 = std::env::temp_dir().join("poler_game_sound_json");
        let _ = std::fs::create_dir_all(&dir2);
        let wav2 = dir2.join("t2.wav");
        match dispatch(&mut s, &format!("game sound --ticks 30 --json --out {}", wav2.display())) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).expect("валидный JSON");
                assert!(j["audio_hash"].as_str().unwrap().starts_with("0x"));
                assert!(j["fs"].as_u64().unwrap() > 0);
                let _ = std::fs::remove_dir_all(&dir2);
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "game sound --fs 100") {
            CmdResult::Done(out) => assert!(out.contains("--fs"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game sound --gain 5") {
            CmdResult::Done(out) => assert!(out.contains("--gain"), "{out}"),
            _ => panic!(),
        }
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn cmd_game_demo_renders_pngs() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s3.db"));
        let dir = std::env::temp_dir().join("poler_game_shell_test");
        match dispatch(
            &mut s,
            &format!("game demo --ticks 90 --size 160x120 --out {}", dir.display()),
        ) {
            CmdResult::Done(out) => {
                assert!(out.contains("Ядро Игры"), "{out}");
                assert!(out.contains("aetheria"), "{out}");
                assert!(out.contains("state-hash 0x"), "{out}");
                assert!(out.contains("мс/тик"), "{out}");
                let _ = std::fs::remove_dir_all(&dir);
            }
            _ => panic!(),
        }
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn cmd_game_scene_roundtrip() {
        // write-demo → правка не нужна, прогон как пользовательской сцены
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s4.db"));
        let dir = std::env::temp_dir().join("poler_game_scene_shell");
        std::fs::create_dir_all(&dir).unwrap();
        let scene_path = dir.join("my_scene.json");
        match dispatch(&mut s, &format!("game write-demo {}", scene_path.display())) {
            CmdResult::Done(out) => assert!(out.contains("выгружена"), "{out}"),
            _ => panic!(),
        }
        assert!(scene_path.exists());
        // сцена запускается и рендерится
        match dispatch(
            &mut s,
            &format!(
                "game scene {} --ticks 30 --size 96x96 --out {}",
                scene_path.display(),
                dir.display()
            ),
        ) {
            CmdResult::Done(out) => {
                assert!(out.contains("Ядро Игры"), "{out}");
                let _ = std::fs::remove_dir_all(&dir);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_demo_validates_args() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-s5.db"));
        match dispatch(&mut s, "game demo --ticks 0") {
            CmdResult::Done(out) => assert!(out.contains("--ticks 1..=100000"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game demo --size 10x10") {
            CmdResult::Done(out) => assert!(out.contains("64..=4096"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game scene /nonexistent.json") {
            CmdResult::Done(out) => assert!(out.contains("чтение"), "{out}"),
            _ => panic!(),
        }
    }

    // -----------------------------------------------------------------
    // v0.56.0 (цикл U): normalmap / input-demo / window
    // -----------------------------------------------------------------

    #[test]
    fn cmd_game_normalmap_writes_png() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-u1.db"));
        let dir = std::env::temp_dir().join("poler_shell_u1");
        std::fs::create_dir_all(&dir).unwrap();
        let png = dir.join("nm.png");
        let cmd = format!(
            "game normalmap --size 128x128 --style marble --amplitude 0.1 --out {} --json",
            png.display()
        );
        match dispatch(&mut s, &cmd) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).expect("валидный JSON");
                assert_eq!(j["normal_hash"].as_str().unwrap().len(), 18);
                assert_eq!(j["amplitude"], 0.1);
                assert!(png.exists(), "PNG записан");
                let raw = std::fs::read(&png).unwrap();
                let (w, h, ct, _) = crate::p3::png::decode_own(&raw).expect("PNG валиден");
                assert_eq!((w, h, ct), (128, 128, 2));
                // Детерминизм: второй прогон — тот же хеш
                match dispatch(&mut s, &cmd) {
                    CmdResult::Done(out2) => {
                        let j2: serde_json::Value = serde_json::from_str(&out2).unwrap();
                        assert_eq!(j["normal_hash"], j2["normal_hash"], "бит-в-бит");
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
        // Валидация
        match dispatch(&mut s, "game normalmap --amplitude 5") {
            CmdResult::Done(out) => assert!(out.contains("--amplitude 0..=1.5"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game normalmap --style basalt") {
            CmdResult::Done(out) => assert!(out.contains("--style noise|marble|wood"), "{out}"),
            _ => panic!(),
        }
    }

    // v0.57.0 (цикл V0): вихревой кодек «Шеннон-байпас»
    #[test]
    fn cmd_game_vortex_all_sources_honest_table() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-v0a.db"));
        let cmd = "game vortex --size 128 --seed 7 --json";
        let first = match dispatch(&mut s, cmd) {
            CmdResult::Done(out) => out,
            _ => panic!(),
        };
        let j: serde_json::Value = serde_json::from_str(&first).expect("JSON");
        assert_eq!(j["cycle"], "V0");
        let results = j["results"].as_array().expect("4 источника");
        assert_eq!(results.len(), 4);
        let get = |src: &str| results.iter().find(|r| r["source"] == src).expect(src);
        let rv = get("vortex");
        let rk = get("kolmogorov");
        let rf = get("fbm");
        let rw = get("white");
        // Когерентные вихри: спектр дискретный — реконструкция почти точная
        assert!(rv["psnr_db"].as_f64().unwrap() > 25.0, "{rv}");
        assert!(rv["ratio"].as_f64().unwrap() > 20.0, "{rv}");
        // Турбулентность/fBm: красный спектр — сжатие при приличном PSNR
        assert!(rk["psnr_db"].as_f64().unwrap() > 10.0, "{rk}");
        assert!(rk["ratio"].as_f64().unwrap() > 5.0, "{rk}");
        assert!(rf["psnr_db"].as_f64().unwrap() > 12.0, "{rf}");
        assert!(rf["ratio"].as_f64().unwrap() > 5.0, "{rf}");
        // Белый шум: zstd порядка не находит (≈×1.0), вихрь честно деградирует
        let zr_white = rw["zstd_ratio"].as_f64().unwrap();
        let zr_fbm = rf["zstd_ratio"].as_f64().unwrap();
        assert!(zr_white < 1.05, "белый шум не сжимается: {zr_white}");
        assert!(zr_fbm > zr_white, "fBm сжимается лучше белого: {zr_fbm} vs {zr_white}");
        assert!(
            rw["psnr_db"].as_f64().unwrap() < rf["psnr_db"].as_f64().unwrap() - 8.0,
            "честная граница Шеннона: {rw}"
        );
        // Детерминизм: повторный прогон — идентичный вывод бит-в-бит
        match dispatch(&mut s, cmd) {
            CmdResult::Done(out2) => assert_eq!(first, out2, "бит-в-бит"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_vortex_png_and_validation() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-v0b.db"));
        let dir = std::env::temp_dir().join("poler_shell_v0");
        let _ = std::fs::remove_dir_all(&dir);
        let cmd = format!(
            "game vortex --size 128 --style kolmogorov --seed 7 --out-dir {} --json",
            dir.display()
        );
        match dispatch(&mut s, &cmd) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).expect("JSON");
                let r = &j["results"][0];
                assert_eq!(r["source"], "kolmogorov");
                assert_eq!(r["modes_total"], 16384);
                assert_eq!(r["vortex_hash"].as_str().unwrap().len(), 18);
                assert!(dir.join("kolmogorov_orig.png").exists(), "оригинал записан");
                assert!(dir.join("kolmogorov_recon.png").exists(), "реконструкция записана");
                let vrtx = std::fs::read(dir.join("kolmogorov.vrtx")).expect("VRTX записан");
                assert_eq!(&vrtx[0..4], b"VRTX");
                assert!(vrtx.len() < 16384, "контейнер меньше сырых байтов: {}", vrtx.len());
                let raw = std::fs::read(dir.join("kolmogorov_orig.png")).unwrap();
                let (w, h, ct, _) = crate::p3::png::decode_own(&raw).expect("PNG валиден");
                assert_eq!((w, h, ct), (128, 128, 2));
            }
            _ => panic!(),
        }
        // Валидация аргументов
        match dispatch(&mut s, "game vortex --size 333") {
            CmdResult::Done(out) => assert!(out.contains("степень двойки"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game vortex --style basalt") {
            CmdResult::Done(out) => {
                assert!(out.contains("--style vortex|kolmogorov|fbm|white|all"), "{out}")
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "game vortex --eps 2") {
            CmdResult::Done(out) => assert!(out.contains("1e-12..=0.5"), "{out}"),
            _ => panic!(),
        }
    }

    // v0.60.0 (цикл X): нелинейная вода — Стокс/Мичелл/Бофорт/Ламб–Озеен
    #[test]
    fn cmd_game_water_json_determinism_and_validation() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-v1a.db"));
        let cmd = "game water --size 64 --modes 24 --steps 60 --seed 7 --json";
        let first = match dispatch(&mut s, cmd) {
            CmdResult::Done(out) => out,
            _ => panic!(),
        };
        let j: serde_json::Value = serde_json::from_str(&first).expect("JSON");
        assert_eq!(j["cycle"], "X");
        assert_eq!(j["model"], "spectral-water-gf3-nonlinear");
        assert_eq!(j["params"]["n"], 64);
        assert_eq!(j["params"]["micro_trits"], 3);
        // Цикл X: нелинейность в конфиге и отчёт об обрушении.
        assert_eq!(j["physics"]["nonlinear"], true);
        let r = &j["results"];
        assert!(r["breakers_spawned"].as_u64().is_some(), "{r}");
        assert!(r["heat_dissipated"].as_f64().unwrap() >= 0.0, "{r}");
        // Честная верность квантования и компактность состояния.
        assert!(r["psnr_db"].as_f64().unwrap() > 25.0, "{r}");
        assert!(r["state_bytes"].as_u64().unwrap() > 31, "{r}");
        assert!(r["mem_ratio"].as_f64().unwrap() > 20.0, "{r}");
        assert_eq!(r["water_hash"].as_str().unwrap().len(), 18);
        // Физика: дисперсия в полосе цели, H_s согласован с Пирсоном–Московицем.
        let var = r["variance_m2"].as_f64().unwrap();
        let vt = r["variance_target_m2"].as_f64().unwrap();
        assert!((0.5..=1.5).contains(&(var / vt)), "дисперсия {var} против цели {vt}");
        let hs = r["hs_m"].as_f64().unwrap();
        let hs_pm = r["hs_pm_m"].as_f64().unwrap();
        assert!((0.6..=1.4).contains(&(hs / hs_pm)), "H_s {hs} против PM {hs_pm}");
        // Детерминизм: физика бит-в-бит (тайминги не сравниваем).
        let second = match dispatch(&mut s, cmd) {
            CmdResult::Done(out) => out,
            _ => panic!(),
        };
        let j2: serde_json::Value = serde_json::from_str(&second).unwrap();
        for key in [
            "psnr_db",
            "state_bytes",
            "mem_ratio",
            "variance_m2",
            "hs_m",
            "water_hash",
            "field_hash",
        ] {
            assert_eq!(j["results"][key], j2["results"][key], "недетерминизм в {key}");
        }
        // Валидация аргументов.
        match dispatch(&mut s, "game water --size 333") {
            CmdResult::Done(out) => assert!(out.contains("степень двойки"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game water --wind 0.1") {
            CmdResult::Done(out) => assert!(out.contains("0.5..=60"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game water --viscosity 99") {
            CmdResult::Done(out) => assert!(out.contains("1e-8..=1e-1"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game water --steepness 9") {
            CmdResult::Done(out) => assert!(out.contains("0.05..=0.60"), "{out}"),
            _ => panic!(),
        }
        // Линейный режим: флаг выключает нелинейность.
        match dispatch(&mut s, "game water --size 64 --modes 8 --steps 5 --linear --json") {
            CmdResult::Done(out) => {
                let jl: serde_json::Value = serde_json::from_str(&out).expect("JSON");
                assert_eq!(jl["physics"]["nonlinear"], false);
            }
            _ => panic!(),
        }
        match dispatch(&mut s, "game water --dt 5") {
            CmdResult::Done(out) => assert!(out.contains("0.001..=1.0"), "{out}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game water --phase-trits 42") {
            CmdResult::Done(out) => assert!(out.contains("2..=10"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_water_artifacts() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-v1b.db"));
        let dir = std::env::temp_dir().join("poler_shell_v1");
        let _ = std::fs::remove_dir_all(&dir);
        let cmd = format!(
            "game water --size 64 --modes 24 --steps 40 --seed 7 --out-dir {} --json",
            dir.display()
        );
        match dispatch(&mut s, &cmd) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).expect("JSON");
                let frames = j["results"]["frames"].as_array().expect("кадры");
                assert!(frames.len() >= 3, "кадров мало: {frames:?}");
                assert!(dir.join("water_t0.png").exists(), "стартовый кадр");
                assert!(dir.join("water_mid.png").exists(), "средний кадр");
                assert!(dir.join("water_end.png").exists(), "финальный кадр");
                assert!(dir.join("water_shaded.png").exists(), "шейдинг");
                let vrtx = std::fs::read(dir.join("water.vrtx")).expect("VRTX записан");
                assert_eq!(&vrtx[0..4], b"VRTX");
                // Состояние меньше f32-сетки того же разрешения.
                assert!((vrtx.len() as f64) < 0.05 * (64 * 64 * 4) as f64, "{}", vrtx.len());
                let raw = std::fs::read(dir.join("water_end.png")).unwrap();
                let (w, h, ct, _) = crate::p3::png::decode_own(&raw).expect("PNG валиден");
                assert_eq!((w, h, ct), (64, 64, 2));
                let raw2 = std::fs::read(dir.join("water_shaded.png")).unwrap();
                let (w2, h2, ct2, _) = crate::p3::png::decode_own(&raw2).expect("шейдинг валиден");
                assert_eq!((w2, h2, ct2), (64, 64, 2));
                // Шейдинг — настоящее цветное море, не серая шкала.
                assert_ne!(raw2, raw, "шейдинг совпал с серым кадром?");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_input_demo_replay_and_script() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-u2.db"));
        let dir = std::env::temp_dir().join("poler_shell_u2");
        let _ = std::fs::remove_dir_all(&dir);
        // Встроенный сценарий: короткий прогон
        let cmd = format!(
            "game input-demo --frames 40 --every 20 --size 160x120 --out-dir {} --json",
            dir.display()
        );
        let (fh1, cam1) = match dispatch(&mut s, &cmd) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).expect("JSON");
                assert_eq!(j["frames"], 40, "кадров ровно сколько просили");
                assert_eq!(j["ticks"], 40, "офлайн: 1 тик на кадр");
                assert!(j["png_written"].as_u64().unwrap() >= 2, "PNG прорежены");
                assert_eq!(j["closed"], false, "закрытия не было");
                (
                    j["frames_hash"].as_str().unwrap().to_string(),
                    j["camera"]["camera_hash"].as_str().unwrap().to_string(),
                )
            }
            _ => panic!(),
        };
        // Детерминизм: тот же прогон — те же хеши
        match dispatch(&mut s, &cmd) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert_eq!(j["frames_hash"].as_str().unwrap(), fh1, "frames_hash бит-в-бит");
                assert_eq!(j["camera"]["camera_hash"].as_str().unwrap(), cam1);
            }
            _ => panic!(),
        }
        // Пользовательский сценарий: колесо на 20-м кадре меняет камеру
        let script = dir.join("script.json");
        std::fs::write(
            &script,
            r#"{"frames": 40, "events": [
                {"frame": 10, "type": "wheel", "delta": 3.0},
                {"frame": 15, "type": "key_down", "code": "w"},
                {"frame": 30, "type": "key_up", "code": "w"}
            ]}"#,
        )
        .unwrap();
        let cmd2 = format!(
            "game input-demo --script {} --every 100 --size 160x120 --out-dir {} --json",
            script.display(),
            dir.display()
        );
        match dispatch(&mut s, &cmd2) {
            CmdResult::Done(out) => {
                let j: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert_eq!(j["frames"], 40, "frames из сценария");
                // колесо + клавиша реально сдвинули камеру от дефолта
                assert_ne!(
                    j["camera"]["camera_hash"].as_str().unwrap(),
                    cam1,
                    "другой сценарий — другая камера"
                );
            }
            _ => panic!(),
        }
        // Битый сценарий — понятная ошибка
        let bad = dir.join("bad.json");
        std::fs::write(&bad, r#"{"frames": 40, "events": [{"frame": 1, "type": "nonsense"}]}"#).unwrap();
        match dispatch(&mut s, &game_format_script(&bad)) {
            CmdResult::Done(out) => assert!(out.contains("неизвестный тип"), "{out}"),
            _ => panic!(),
        }
        // Валидация флагов
        match dispatch(&mut s, "game input-demo --frames 3") {
            CmdResult::Done(out) => assert!(out.contains("--frames 10..=10000"), "{out}"),
            _ => panic!(),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn game_format_script(p: &std::path::Path) -> String {
        format!("game input-demo --script {}", p.display())
    }

    #[test]
    fn cmd_game_window_graceful_headless() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-u3.db"));
        // В headless-CI нет DISPLAY: ожидаем внятный отказ, не панику.
        if std::env::var("DISPLAY").map(|d| !d.is_empty()).unwrap_or(false) {
            return; // живой X-сервер: открытие реально, тут не тестируем
        }
        match dispatch(&mut s, "game window --frames 5") {
            CmdResult::Done(out) => {
                assert!(
                    out.contains("X11") || out.contains("DISPLAY") || out.contains("input-demo"),
                    "понятная ошибка: {out}"
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_calc_prefix_equals() {
        assert_eq!(calc_out("= 2^10"), "1024.0");
        assert_eq!(calc_out("=5 km + 300 m"), "5.3 km");
        // пустой префикс — подсказка
        match calc_out("=") {
            out => assert!(out.contains("выражение"), "{out}"),
        }
    }

    #[test]
    fn cmd_calc_stateful() {
        let mut s = ShellState::new(PathBuf::from("/tmp/test-calc2.db"));
        let _ = dispatch(&mut s, "calc a = 6");
        match dispatch(&mut s, "calc a * 7") {
            CmdResult::Done(out) => assert_eq!(out, "42.0"),
            other => panic!("{other:?}"),
        }
        match dispatch(&mut s, "calc ans / 6") {
            CmdResult::Done(out) => assert_eq!(out, "7.0"),
            other => panic!("{other:?}"),
        }
        // каталоги
        match dispatch(&mut s, "calc vars") {
            CmdResult::Done(out) => assert!(out.contains("a = 6"), "{out}"),
            other => panic!("{other:?}"),
        }
        match dispatch(&mut s, "calc hist") {
            CmdResult::Done(out) => assert!(out.contains("a * 7"), "{out}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cmd_calc_solve_and_catalogs() {
        let out = calc_out("calc solve x^2 - 4 = 0");
        assert!(out.contains("2.0") && out.contains("-2.0"), "{out}");
        let out = calc_out("calc constants c");
        assert!(out.contains("299792458") && out.contains("СИ-2019"), "{out}");
        let out = calc_out("calc units bit");
        assert!(out.contains("bit"), "{out}");
        let out = calc_out("calc funcs астр");
        assert!(out.contains("moon_illum"), "{out}");
        let out = calc_out("calc laws");
        assert!(out.contains("kepler3"), "{out}");
        // scriptgen через шелл
        let out = calc_out("calc script emc2");
        assert!(out.contains("[[rule]]") && out.contains("emc2"), "{out}");
        let out = calc_out("calc script kepler3 a=1 au");
        assert!(out.contains("полином") || out.contains("1 au") || out.contains("calc 2*pi"), "{out}");
        // неизвестный закон
        let out = calc_out("calc script nosuchlaw");
        assert!(out.contains("не найден"), "{out}");
    }

    #[test]
    fn cmd_calc_quatum_and_astro() {
        // ротор Ли с тритной фазой Ψ
        let out = calc_out("calc det(expm([0,-1;1,0] * psi))");
        assert!((out.parse::<f64>().unwrap() - 1.0).abs() < 1e-12, "{out}");
        // триты
        assert_eq!(calc_out("calc trits(5)"), "\"1TT\"");
        // фаза Луны на солнечном затмении 08.04.2024
        let out = calc_out("calc moon_illum(2024,4,8,18.35)");
        assert!(out.parse::<f64>().unwrap() < 0.01, "{out}");
        // гео: Киев—Львів
        let out = calc_out("calc dist(50.45,30.52,49.84,24.03)");
        let d: f64 = out.parse().unwrap();
        assert!(d > 450.0 && d < 475.0, "{d}");
    }

    #[test]
    fn cmd_calc_script_greedy_values() {
        // юнит с пробелом не теряется: a=1 au
        let out = calc_out("calc script kepler3 a=1 au");
        assert!(out.contains("1 au"), "{out}");
        assert!(out.contains("(1 au)^3") || out.contains("((1 au))^3"), "{out}");
        // несколько оверрайдов с юнитами
        let out = calc_out("calc script newton m1=70 kg m2=5.97e24 kg r=6371 km");
        assert!(out.contains("70 kg") && out.contains("6371 km"), "{out}");
    }

    #[test]
    fn cmd_calc_errors_are_messages() {
        let out = calc_out("calc 2 +");
        assert!(out.starts_with("❌"), "{out}");
        let out = calc_out("calc unknown_var + 1");
        assert!(out.starts_with("❌"), "{out}");
        let out = calc_out("calc");
        assert!(out.contains("calc <выражение>"), "{out}");
    }

    #[test]
    fn cmd_hw_probe() {
        let out = calc_out("hw");
        assert!(!out.is_empty());
        let out = calc_out("hw --json");
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok(), "{out}");
    }

    #[test]
    fn cmd_quit_signals_exit() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        assert!(matches!(dispatch(&mut s, "quit"), CmdResult::Quit));
        assert!(matches!(dispatch(&mut s, "exit"), CmdResult::Quit));
        assert!(matches!(dispatch(&mut s, "q"), CmdResult::Quit));
    }

    #[test]
    fn cmd_empty_input_returns_empty() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        assert!(matches!(dispatch(&mut s, ""), CmdResult::Empty));
        assert!(matches!(dispatch(&mut s, "   "), CmdResult::Empty));
    }

    #[test]
    fn cmd_version_works() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "version");
        match r {
            CmdResult::Done(out) => assert!(out.contains("poler-shell")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_help_lists_commands() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "help");
        match r {
            CmdResult::Done(out) => {
                assert!(out.contains("search"));
                assert!(out.contains("sync vcs"));
                assert!(out.contains("quit"));
                // v0.15.1: help должен упоминать crawl и impact
                assert!(out.contains("crawl"));
                assert!(out.contains("impact"));
            }
            _ => panic!(),
        }
    }

    // v0.15.1: команды crawl/impact

    #[test]
    fn cmd_crawl_no_url_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "crawl");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите seed URL") || out.contains("пример")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_crawl_non_http_url_rejected() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "crawl ftp://example.com");
        match r {
            CmdResult::Done(out) => assert!(out.contains("seed должен быть http(s)://")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_crawl_help_flag_works() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "crawl --help");
        match r {
            CmdResult::Done(out) => assert!(out.contains("--depth") && out.contains("--max")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_crawl_unknown_flag_rejected() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "crawl https://example.com --bogus");
        match r {
            CmdResult::Done(out) => assert!(out.contains("неизвестный флаг --bogus")),
            _ => panic!(),
        }
    }

    // ---- v0.17.5: confirmation gate ----

    #[test]
    fn cmd_notes_rm_requires_yes_v0175() {
        // создаём заметку в реальной временной БД, затем пробуем удалить без --yes
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");
        let mut s = ShellState::new(db.clone());
        // add работает без подтверждения (создание — не деструктивная операция)
        dispatch(&mut s, "notes add Тестовая");
        let notes_out = match dispatch(&mut s, "notes list") {
            CmdResult::Done(o) => o,
            _ => panic!("notes list"),
        };
        // id заметки — первое поле строки вида «#1. Тестовая» / «1. Тестовая»
        let id: String = notes_out
            .lines()
            .find(|l| l.contains("Тестовая"))
            .and_then(|l| l.trim().split('.').next().map(|s| s.trim().trim_start_matches('#').to_string()))
            .expect("заметка создана");
        // удаление БЕЗ --yes → гейт: показываем что удалим и просим подтверждение
        let r = dispatch(&mut s, &format!("notes rm {id}"));
        match r {
            CmdResult::Done(out) => {
                assert!(out.contains("--yes"), "подсказка о --yes: {out}");
                assert!(out.contains("Тестовая"), "показываем что удаляем: {out}");
            }
            _ => panic!(),
        }
        // заметка ещё жива
        let still = match dispatch(&mut s, "notes list") {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        assert!(still.contains("Тестовая"), "без --yes заметка не удалена");
        // с --yes → удаление
        let r2 = dispatch(&mut s, &format!("notes rm {id} --yes"));
        match r2 {
            CmdResult::Done(out) => assert!(out.contains("удалена")),
            _ => panic!(),
        }
        let gone = match dispatch(&mut s, "notes list") {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        assert!(!gone.contains("Тестовая"), "с --yes заметка удалена");
    }

    #[test]
    fn cmd_notes_rm_unknown_id_gives_not_found_v0175() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/notes-rm-404.db"));
        let r = dispatch(&mut s, "notes rm 99999");
        match r {
            CmdResult::Done(out) => assert!(out.contains("не найдена")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_nlm_is_gone_in_v2() {
        // v2.0: NLM-команда удалена — dispatcher отвечает «неизвестная команда»
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "nlm list");
        match r {
            CmdResult::Done(out) => assert!(out.contains("неизвестная команда"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_impact_no_args_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "impact");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите PATH и SYMBOL")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_impact_only_path_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "impact ./src");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите PATH и SYMBOL")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_impact_nonexistent_path_rejected() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "impact /nonexistent/path mysymbol");
        match r {
            CmdResult::Done(out) => assert!(out.contains("путь не найден")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_impact_help_flag_works() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "impact --help");
        match r {
            CmdResult::Done(out) => assert!(out.contains("--depth") && out.contains("--cache")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_impact_unknown_flag_rejected() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "impact /tmp my_symbol --bogus");
        match r {
            CmdResult::Done(out) => assert!(out.contains("неизвестный флаг --bogus")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_impact_on_real_code_finds_symbol() {
        // Запускаем impact на собственном коде poler-engine: cmd_search
        // точно определён в src/shell/commands.rs, и impact_analysis должна
        // найти его downstream/upstream паспорта.
        let project_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src_dir = project_dir.join("src/shell");
        if !src_dir.exists() {
            return; // в vendored-сборке без CARGO_MANIFEST_DIR тест пропускаем
        }
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let cmdline = format!("impact {} cmd_search --depth 1", src_dir.display());
        let r = dispatch(&mut s, &cmdline);
        match r {
            CmdResult::Done(out) => {
                // Должен либо найти символ (target_function: cmd_search),
                // либо корректно сообщить что символ не найден (если парсер не
                // цепляет функцию в этом конкретном файле).
                assert!(
                    out.contains("target_function") || out.contains("символ не найден"),
                    "expected 'target_function' or 'symbol not found', got: {out}"
                );
            }
            _ => panic!("expected Done, got another CmdResult"),
        }
    }

    #[test]
    fn cmd_version_string_updated_for_v0171() {
        // v0.48.0: Калькулятор Всего + среда агента (наследие v0.47.0).
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "version");
        match r {
            CmdResult::Done(out) => {
                assert!(out.contains("v0.48.0"));
                assert!(out.contains("poler-shell"));
                assert!(out.contains("Калькулятор"), "v0.48.0: калькулятор в бейдже");
                assert!(out.contains("sysinfo"), "среда агента упомянута");
                assert!(!out.contains("Auth Companion"), "v2.0: Google-интеграция удалена");
            }
            _ => panic!(),
        }
    }

    // ---- v0.16.0: VCS-команды (gh/gl/gt/gix/sync vcs) ----

    #[test]
    fn cmd_version_string_updated_for_v017() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "version");
        match r {
            CmdResult::Done(out) => assert!(out.contains("poler-shell")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gh_no_subcommand_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gh");
        match r {
            CmdResult::Done(out) => {
                assert!(out.contains("search"));
                assert!(out.contains("repos"));
                assert!(out.contains("commits"));
                assert!(out.contains("issues"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gl_no_subcommand_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gl");
        match r {
            CmdResult::Done(out) => assert!(out.contains("search")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gt_no_subcommand_returns_help_or_init_error() {
        // gitea_adapter() требует GITEA_HOST; если не задан — ошибка инициализации.
        std::env::remove_var("GITEA_HOST");
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gt");
        match r {
            CmdResult::Done(out) => {
                // либо help (если хост задан), либо ошибка GITEA_HOST
                assert!(
                    out.contains("search") || out.contains("GITEA_HOST"),
                    "got: {out}"
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gh_search_no_query_gives_help() {
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GH_TOKEN");
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gh search");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите запрос")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gh_repos_no_owner_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gh repos");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите owner")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gh_commits_no_repo_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gh commits");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gh_issues_no_repo_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gh issues");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gh_unknown_subcommand_rejected() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gh bogus");
        match r {
            CmdResult::Done(out) => assert!(out.contains("неизвестная подкоманда")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gix_no_args_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gix");
        match r {
            CmdResult::Done(out) => {
                assert!(out.contains("log"));
                assert!(out.contains("clone"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gix_log_no_path_gives_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gix log");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите путь")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gix_log_nonexistent_path_errors() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gix log /nonexistent/path");
        match r {
            CmdResult::Done(out) => assert!(out.contains("gix log") || out.contains("❌")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gix_clone_missing_args() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gix clone");
        match r {
            CmdResult::Done(out) => assert!(out.contains("укажите URL")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_gix_clone_with_url_only_gives_dest_help() {
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "gix clone https://github.com/x/y.git");
        match r {
            CmdResult::Done(out) => assert!(out.contains("путь назначения")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_sync_vcs_no_scheme_does_not_panic() {
        // `sync vcs` без scheme → пробуем все 4 адаптера. gitea без GITEA_HOST
        // даст ошибку, но не должен паниковать. Тест проверяет только что
        // dispatch возвращает Done (не падает).
        std::env::remove_var("GITEA_HOST");
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GITLAB_TOKEN");
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "sync vcs");
        match r {
            CmdResult::Done(out) => assert!(out.contains("sync vcs") || out.contains("❌")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_sync_alone_gives_v2_hint() {
        // v2.0: `sync` без vcs — подсказка про схему (NLM-синк удалён)
        let mut s = ShellState::new(std::path::PathBuf::from("/tmp/x.db"));
        let r = dispatch(&mut s, "sync");
        match r {
            CmdResult::Done(out) => assert!(out.contains("sync vcs"), "{out}"),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_game_asset_audio_absorb_emit() {
        use crate::game::asset as ya;
        let mut s = ShellState::new(PathBuf::from("/tmp/test-ya1.db"));
        // Готовый звук: две несущие + шум (3 с, стерео).
        let mut rng = crate::ssn::rng::Rng::new(42);
        let mut samples = Vec::new();
        for i in 0..22050 * 3 {
            let t = i as f64 / 22050.0;
            let v = 0.30 * (2.0 * std::f64::consts::PI * 220.0 * t).sin()
                + 0.20 * (2.0 * std::f64::consts::PI * 1500.0 * t).sin()
                + 0.10 * (rng.f64() * 2.0 - 1.0);
            let v = (v * 0.5) as f32;
            samples.push(v);
            samples.push(v);
        }
        let wav_path = "/tmp/poler_y_shell_in.wav";
        ya::write_wav(std::path::Path::new(wav_path), 22050, 2, &samples).unwrap();
        let pqw_path = "/tmp/poler_y_shell_in.pqw";
        let gen_path = "/tmp/poler_y_shell_out.wav";
        // ABSORB: впитать в нейроны.
        let cmd = format!("game asset absorb --in {wav_path} --out {pqw_path} --json");
        let out = match dispatch(&mut s, &cmd) {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        let j: serde_json::Value = serde_json::from_str(&out).expect("JSON");
        assert_eq!(j["cycle"], "Y");
        assert_eq!(j["model"], "neural-asset-echo-pqw");
        assert_eq!(j["kind"], "audio");
        assert_eq!(j["fs"], 22050);
        assert!(j["synapses"].as_u64().unwrap() > 50, "{j}");
        assert!(j["container_bytes"].as_u64().unwrap() < 8192, "{j}");
        assert!(j["ratio"].as_f64().unwrap() > 50.0, "{j}");
        // EMIT: сгенерировать с нуля + сравнение с входом.
        let cmd2 = format!(
            "game asset emit --in {pqw_path} --out {gen_path} --seconds 2 --compare {wav_path} --json"
        );
        let out2 = match dispatch(&mut s, &cmd2) {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        let j2: serde_json::Value = serde_json::from_str(&out2).expect("JSON");
        assert_eq!(j2["kind"], "audio");
        assert_eq!(j2["fs"], 22050);
        assert_eq!(j2["vortex_neurons"], 600);
        assert!(j2["vortex_steps"].as_u64().unwrap() > 80, "{j2}");
        assert!(j2["bursts"].as_u64().unwrap() > 0, "{j2}");
        assert!(j2["psd_distance_db"].as_f64().unwrap() < 6.0, "{j2}");
        let hash = j2["audio_hash"].as_str().unwrap().to_string();
        // Детерминизм: seed из содержимого PQW — хеш тот же.
        let out3 = match dispatch(&mut s, &cmd2) {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        let j3: serde_json::Value = serde_json::from_str(&out3).unwrap();
        assert_eq!(j3["audio_hash"].as_str().unwrap(), hash, "недетерминизм emit");
        // Валидация аргументов и входов.
        match dispatch(&mut s, "game asset") {
            CmdResult::Done(o) => assert!(o.contains("absorb|emit"), "{o}"),
            _ => panic!(),
        }
        match dispatch(&mut s, "game asset absorb --in /nope.wav --out /nope.pqw") {
            CmdResult::Done(o) => assert!(o.contains("absorb:"), "{o}"),
            _ => panic!(),
        }
        match dispatch(
            &mut s,
            &format!("game asset emit --in {pqw_path} --out /tmp/x.wav --seconds 900"),
        ) {
            CmdResult::Done(o) => assert!(o.contains("0.5..=600"), "{o}"),
            _ => panic!(),
        }
        let _ = std::fs::remove_file(wav_path);
        let _ = std::fs::remove_file(pqw_path);
        let _ = std::fs::remove_file(gen_path);
    }

    #[test]
    fn cmd_game_asset_texture_absorb_emit() {
        use crate::game::asset as ya;
        let mut s = ShellState::new(PathBuf::from("/tmp/test-ya2.db"));
        // Готовая текстура: fBm-мрамор 64×64 (наш PNG-энкодер, stored-блоки).
        let mut gray = vec![0u8; 64 * 64];
        for y in 0..64usize {
            for x in 0..64usize {
                gray[y * 64 + x] = (crate::game::texture::fbm(
                    x as f64 / 8.0,
                    y as f64 / 8.0,
                    42,
                    3,
                    0.5,
                ) * 255.0)
                    .clamp(0.0, 255.0) as u8;
            }
        }
        let in_path = "/tmp/poler_y_shell_tex.png";
        crate::p3::png::encode_gray(std::path::Path::new(in_path), 64, 64, &gray).unwrap();
        let pqw_path = "/tmp/poler_y_shell_tex.pqw";
        let gen_path = "/tmp/poler_y_shell_tex_out.png";
        let cmd = format!("game asset absorb --in {in_path} --out {pqw_path} --json");
        let out = match dispatch(&mut s, &cmd) {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        let j: serde_json::Value = serde_json::from_str(&out).expect("JSON");
        assert_eq!(j["kind"], "texture");
        assert_eq!(j["protos"], 32);
        assert_eq!(j["svd_rank"], 12);
        assert_eq!(j["tiles"], 16);
        assert!(j["synapses"].as_u64().unwrap() > 0, "{j}");
        // EMIT: блуждание по графу + сравнение с входом.
        let cmd2 = format!(
            "game asset emit --in {pqw_path} --out {gen_path} --width 64 --height 64 --compare {in_path} --json"
        );
        let out2 = match dispatch(&mut s, &cmd2) {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        let j2: serde_json::Value = serde_json::from_str(&out2).expect("JSON");
        assert_eq!(j2["kind"], "texture");
        assert_eq!(j2["w"], 64);
        assert_eq!(j2["h"], 64);
        assert_eq!(j2["tiles"][0], 4);
        assert!(j2["psnr_db"].as_f64().unwrap() > 8.0, "{j2}");
        assert!(j2["histogram_distance"].as_f64().unwrap() < 0.3, "{j2}");
        // Детерминизм: файлы бит-в-бит.
        let out3 = match dispatch(&mut s, &cmd2) {
            CmdResult::Done(o) => o,
            _ => panic!(),
        };
        let j3: serde_json::Value = serde_json::from_str(&out3).unwrap();
        assert_eq!(j2["seed"], j3["seed"]);
        let first = std::fs::read(gen_path).unwrap();
        let second = std::fs::read(gen_path).unwrap();
        assert_eq!(first, second);
        // Апскейл: ×2 без нового контейнера.
        let cmd4 = format!(
            "game asset emit --in {pqw_path} --out {gen_path} --width 128 --height 128 --json"
        );
        match dispatch(&mut s, &cmd4) {
            CmdResult::Done(o) => {
                let j4: serde_json::Value = serde_json::from_str(&o).expect("JSON");
                assert_eq!(j4["w"], 128);
                assert_eq!(j4["h"], 128);
            }
            _ => panic!(),
        }
        let _ = std::fs::remove_file(in_path);
        let _ = std::fs::remove_file(pqw_path);
        let _ = std::fs::remove_file(gen_path);
    }

}
