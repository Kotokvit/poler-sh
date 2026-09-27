//! POLER-SH — Суверенная командная оболочка и терминальный шлюз (Terminal Gateway).
//!
//! Интегрирует:
//! 1. Нативный «Калькулятор Всего» (`calc::CalcState`): AST-парсер, диффуравнения `solve`,
//!    матрицы, комплексные числа, физические единицы (`units`), астрономию и константы.
//! 2. Аппаратный аудит (`calc::hardware::probe`).
//! 3. Среду ИИ-агентов (`shell::agentenv`): `sysinfo`, маскирование секретов, `json_envelope`.
//! 4. Windows-совместимый словарь (`shell::wincompat`).
//! 5. Прямой запуск процессов без форков bash.

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use poler_sh::calc::{self, CalcState};
use poler_sh::shell::{agentenv, wincompat};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args.iter().any(|a| a == "--shell" || a == "-i") {
        run_repl();
        return;
    }

    if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
        print_help();
        return;
    }

    if args[0] == "--version" || args[0] == "-V" {
        println!("poler-sh 0.1.0 (Terminal Gateway Standalone)");
        return;
    }

    if args[0] == "--exec" || args[0] == "-c" {
        if args.len() < 2 {
            eprintln!("poler-sh: требуется команда для --exec");
            std::process::exit(1);
        }
        let cmd = &args[1];
        let json_mode = args.iter().any(|a| a == "--json");
        let mut calc_state = CalcState::new();
        run_exec(cmd, &mut calc_state, json_mode);
        return;
    }

    // Обычный запуск команды
    let line = args.join(" ");
    let mut calc_state = CalcState::new();
    run_exec(&line, &mut calc_state, false);
}

fn print_help() {
    println!("\
poler-sh 0.1.0 — суверенная командная оболочка и терминальный шлюз (Terminal Gateway)

ИСПОЛЬЗОВАНИЕ:
  poler-sh                     запуск интерактивного REPL
  poler-sh --exec \"<команда>\"    выполнить команду и выйти
  poler-sh --exec \"<команда>\" --json   машиночитаемый JSON-конверт для ИИ-агентов
  poler-sh -c \"<команда>\"       совместимость с posix sh/bash

ВСТРОЕННЫЕ КОМАНДЫ (мгновенные нативные утилиты 3.3 мс):
  calc <выражение>             нативный AST-калькулятор (2^64-1, sin(pi/4), solve x^2 - 4 = 0)
  = <val> <from> to <to>       конвертер физ. единиц (= 100 km/h to m/s, = 10 GiB to MB)
  hw [--json]                  скрытые аппаратные параметры ПК (CPUID, кеши L1-L3, GPU, RAM)
  sysinfo                      карта среды исполнения, окружение, компиляторы
  win                          каталог Windows-команд (dir, type, copy, del, findstr...)
  cd [путь]                    смена текущей рабочей директории
  pwd                          текущий рабочий каталог
  help                         список команд
  exit / quit                  выход из оболочки
");
}

fn run_repl() {
    println!("poler-sh 0.1.0 — суверенный терминальный шлюз. `help` — список команд, `quit` — выход.");
    let history_path = dirs_cache_history();
    let mut calc_state = CalcState::new();

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        let cwd = env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into());
        let short_cwd = shorten_path(&cwd);

        print!("poler [{short_cwd}]> ");
        let _ = stdout.flush();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
            break; // EOF
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        append_history(&history_path, trimmed);

        if trimmed == "exit" || trimmed == "quit" || trimmed == "q" {
            break;
        }

        let (out, _, _) = execute_command(trimmed, &mut calc_state);
        if !out.is_empty() {
            println!("{}", out);
        }
    }
}

fn run_exec(cmd: &str, calc_state: &mut CalcState, json_mode: bool) {
    let t0 = Instant::now();
    let (output, ok, exit_code) = execute_command(cmd, calc_state);
    let dur = t0.elapsed().as_millis();

    if json_mode {
        let json = agentenv::json_envelope(cmd, ok, exit_code as u8, dur, &output);
        println!("{json}");
    } else {
        if !output.is_empty() {
            println!("{output}");
        }
    }
    if !ok {
        std::process::exit(exit_code);
    }
}

fn execute_command(cmd: &str, calc_state: &mut CalcState) -> (String, bool, i32) {
    let trimmed = cmd.trim();

    // 1. AST Калькулятор: calc <expr> или = <expr>
    if trimmed.starts_with("calc ") || trimmed == "calc" || trimmed.starts_with('=') {
        let expr = if let Some(rest) = trimmed.strip_prefix("calc") {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix('=') {
            rest.trim()
        } else {
            trimmed
        };
        match calc_state.eval_line(expr) {
            Ok(v) => (v, true, 0),
            Err(e) => (format!("calc: {e}"), false, 1),
        }
    } else if trimmed == "hw" || trimmed.starts_with("hw ") {
        let report = calc::hardware::probe();
        let json_mode = trimmed.contains("--json");
        let out = if json_mode {
            report.to_json()
        } else {
            report.to_text()
        };
        (out, true, 0)
    } else if trimmed == "sysinfo" {
        (agentenv::sysinfo(), true, 0)
    } else if trimmed == "win" {
        (wincompat::catalog(), true, 0)
    } else if trimmed == "cd" || trimmed.starts_with("cd ") {
        let target = trimmed.strip_prefix("cd").unwrap().trim();
        let path = if target.is_empty() {
            dirs_home()
        } else if target == "~" || target.starts_with("~/") {
            let h = dirs_home();
            h.join(target.strip_prefix("~/").unwrap_or(""))
        } else {
            PathBuf::from(target)
        };

        match env::set_current_dir(&path) {
            Ok(_) => (String::new(), true, 0),
            Err(e) => (format!("cd: {}: {e}", path.display()), false, 1),
        }
    } else if trimmed == "pwd" {
        let cwd = env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into());
        (cwd, true, 0)
    } else if trimmed == "help" {
        (
            "Встроенные команды poler-sh:\n  calc <expr>, =<expr>, hw [--json], sysinfo, win, cd, pwd, exit/quit\nWindows и Linux команды транслируются нативно.".into(),
            true,
            0,
        )
    } else {
        // 8. Прямой запуск внешней команды
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            return (String::new(), true, 0);
        }

        let program = parts[0];
        let args = &parts[1..];

        let mut command = Command::new(program);
        command.args(args);

        match command.output() {
            Ok(out) => {
                let stdout_str = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr_str = String::from_utf8_lossy(&out.stderr).to_string();
                let full = if stderr_str.is_empty() {
                    stdout_str
                } else if stdout_str.is_empty() {
                    stderr_str
                } else {
                    format!("{stdout_str}\n{stderr_str}")
                };
                let code = out.status.code().unwrap_or(if out.status.success() { 0 } else { 1 });
                (full.trim_end().to_string(), out.status.success(), code)
            }
            Err(e) => (format!("poler-sh: {program}: {e}"), false, 127),
        }
    }
}

fn dirs_home() -> PathBuf {
    env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

fn dirs_cache_history() -> PathBuf {
    let base = dirs_home().join(".cache/poler-sh");
    let _ = fs::create_dir_all(&base);
    base.join("history.txt")
}

fn append_history(path: &Path, line: &str) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", line);
    }
}

fn shorten_path(p: &str) -> String {
    let home = dirs_home().display().to_string();
    if p.starts_with(&home) {
        format!("~{}", &p[home.len()..])
    } else {
        p.to_string()
    }
}
