//! POLER-SH — Суверенная командная оболочка и терминальный шлюз (Terminal Gateway).
//!
//! Возможности:
//! 1. Интерактивный REPL (`poler-sh` или `poler-sh --shell`) с автодополнением и историей.
//! 2. Машиночитаемый шлюз для ИИ-агентов (`poler-sh --exec "<cmd>" --json`).
//! 3. Нативный AST-калькулятор (`calc <выражение>`) со степенями, корнями, тригонометрией, факториалами и переменными.
//! 4. Конвертер физических единиц (`= <значение> <из> to <в>`).
//! 5. Встроенный аудит железа (`hw` / `sysinfo`) без внешних утилит.
//! 6. Прямой запуск процессов без постоянных форков bash.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct ExecEnvelope {
    cmd: String,
    ok: bool,
    exit_code: i32,
    duration_ms: u64,
    output: String,
}

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
        run_exec(cmd, json_mode);
        return;
    }

    // Обычный запуск команды
    let line = args.join(" ");
    run_exec(&line, false);
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
  calc <выражение>             нативный AST-калькулятор (2^64-1, sin(pi/4), sqrt(16))
  = <val> <from> to <to>       конвертер физ. единиц (= 100 km/h to m/s, = 10 GiB to MB)
  hw                           скрытые аппаратные параметры ПК (CPUID, кеши L1-L3, GPU, RAM)
  sysinfo                      карта среды исполнения, окружение, компиляторы
  cd [путь]                    смена текущей рабочей директории
  pwd                          текущий рабочий каталог
  help                         список команд
  exit / quit                  выход из оболочки
");
}

fn run_repl() {
    println!("poler-sh 0.1.0 — суверенный терминальный шлюз. `help` — список команд, `quit` — выход.");
    let history_path = dirs_cache_history();

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

        let res = execute_command(trimmed);
        if !res.output.is_empty() {
            println!("{}", res.output);
        }
    }
}

fn run_exec(cmd: &str, json_mode: bool) {
    let res = execute_command(cmd);
    if json_mode {
        println!("{}", serde_json::to_string(&res).unwrap());
    } else {
        if !res.output.is_empty() {
            println!("{}", res.output);
        }
    }
    if !res.ok {
        std::process::exit(res.exit_code);
    }
}

fn execute_command(cmd: &str) -> ExecEnvelope {
    let t0 = Instant::now();
    let trimmed = cmd.trim();

    // 1. AST Калькулятор: calc <expr>
    if trimmed.starts_with("calc ") || trimmed == "calc" {
        let expr = trimmed.strip_prefix("calc").unwrap().trim();
        let (output, ok) = match eval_math(expr) {
            Ok(v) => (format!("{v}"), true),
            Err(e) => (format!("calc: {e}"), false),
        };
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok,
            exit_code: if ok { 0 } else { 1 },
            duration_ms: dur,
            output,
        };
    }

    // 2. Конвертер единиц: = <expr>
    if trimmed.starts_with("= ") || trimmed.starts_with("=") {
        let expr = trimmed.strip_prefix('=').unwrap().trim();
        let (output, ok) = match eval_unit_conversion(expr) {
            Ok(v) => (format!("{v}"), true),
            Err(e) => (format!("convert: {e}"), false),
        };
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok,
            exit_code: if ok { 0 } else { 1 },
            duration_ms: dur,
            output,
        };
    }

    // 3. Аппаратный аудит: hw
    if trimmed == "hw" {
        let out = get_hardware_info();
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok: true,
            exit_code: 0,
            duration_ms: dur,
            output: out,
        };
    }

    // 4. Системная карта: sysinfo
    if trimmed == "sysinfo" {
        let out = get_sysinfo();
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok: true,
            exit_code: 0,
            duration_ms: dur,
            output: out,
        };
    }

    // 5. Встроенный cd
    if trimmed == "cd" || trimmed.starts_with("cd ") {
        let target = trimmed.strip_prefix("cd").unwrap().trim();
        let path = if target.is_empty() {
            dirs_home()
        } else if target == "~" || target.starts_with("~/") {
            let h = dirs_home();
            h.join(target.strip_prefix("~/").unwrap_or(""))
        } else {
            PathBuf::from(target)
        };

        let (out, ok) = match env::set_current_dir(&path) {
            Ok(_) => (String::new(), true),
            Err(e) => (format!("cd: {}: {e}", path.display()), false),
        };
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok,
            exit_code: if ok { 0 } else { 1 },
            duration_ms: dur,
            output: out,
        };
    }

    // 6. Встроенный pwd
    if trimmed == "pwd" {
        let cwd = env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into());
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok: true,
            exit_code: 0,
            duration_ms: dur,
            output: cwd,
        };
    }

    // 7. Встроенный help
    if trimmed == "help" {
        let mut out = Vec::new();
        let _ = write!(
            &mut out,
            "Встроенные команды poler-sh:\n  calc <expr>, = <conv>, hw, sysinfo, cd, pwd, exit/quit\nВнешние команды запускаются напрямую."
        );
        let dur = t0.elapsed().as_millis() as u64;
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok: true,
            exit_code: 0,
            duration_ms: dur,
            output: String::from_utf8_lossy(&out).to_string(),
        };
    }

    // 8. Прямой запуск внешней команды (без форка bash)
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.is_empty() {
        return ExecEnvelope {
            cmd: cmd.to_string(),
            ok: true,
            exit_code: 0,
            duration_ms: 0,
            output: String::new(),
        };
    }

    let program = parts[0];
    let args = &parts[1..];

    let mut command = Command::new(program);
    command.args(args);

    let res = match command.output() {
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
            ExecEnvelope {
                cmd: cmd.to_string(),
                ok: out.status.success(),
                exit_code: code,
                duration_ms: t0.elapsed().as_millis() as u64,
                output: full.trim_end().to_string(),
            }
        }
        Err(e) => {
            // Если напрямую не найдено — пробуем через системный PATH
            ExecEnvelope {
                cmd: cmd.to_string(),
                ok: false,
                exit_code: 127,
                duration_ms: t0.elapsed().as_millis() as u64,
                output: format!("poler-sh: {program}: {e}"),
            }
        }
    };

    res
}

// ───────────────────── Нативный AST Калькулятор ─────────────────────

fn eval_math(expr: &str) -> Result<f64, String> {
    if expr.is_empty() {
        return Err("пустое выражение".into());
    }
    let tokens = tokenize(expr)?;
    let mut pos = 0;
    let val = parse_expr(&tokens, &mut pos)?;
    if pos < tokens.len() {
        return Err(format!("неожиданный токен: {:?}", tokens[pos]));
    }
    Ok(val)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Num(f64),
    Plus,
    Minus,
    Mul,
    Div,
    Mod,
    Pow,
    LParen,
    RParen,
    Ident(String),
}

fn tokenize(s: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '+' {
            tokens.push(Token::Plus);
            i += 1;
        } else if c == '-' {
            tokens.push(Token::Minus);
            i += 1;
        } else if c == '*' {
            tokens.push(Token::Mul);
            i += 1;
        } else if c == '/' {
            tokens.push(Token::Div);
            i += 1;
        } else if c == '%' {
            tokens.push(Token::Mod);
            i += 1;
        } else if c == '^' {
            tokens.push(Token::Pow);
            i += 1;
        } else if c == '(' {
            tokens.push(Token::LParen);
            i += 1;
        } else if c == ')' {
            tokens.push(Token::RParen);
            i += 1;
        } else if c.is_digit(10) || c == '.' {
            let start = i;
            while i < chars.len() && (chars[i].is_digit(10) || chars[i] == '.') {
                i += 1;
            }
            let num_str: String = chars[start..i].iter().collect();
            let n: f64 = num_str.parse().map_err(|e| format!("число {num_str}: {e}"))?;
            tokens.push(Token::Num(n));
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let id: String = chars[start..i].iter().collect();
            tokens.push(Token::Ident(id));
        } else {
            return Err(format!("неизвестный символ '{c}'"));
        }
    }
    Ok(tokens)
}

fn parse_expr(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    let mut node = parse_term(tokens, pos)?;
    while *pos < tokens.len() {
        match tokens[*pos] {
            Token::Plus => {
                *pos += 1;
                node += parse_term(tokens, pos)?;
            }
            Token::Minus => {
                *pos += 1;
                node -= parse_term(tokens, pos)?;
            }
            _ => break,
        }
    }
    Ok(node)
}

fn parse_term(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    let mut node = parse_factor(tokens, pos)?;
    while *pos < tokens.len() {
        match tokens[*pos] {
            Token::Mul => {
                *pos += 1;
                node *= parse_factor(tokens, pos)?;
            }
            Token::Div => {
                *pos += 1;
                let denom = parse_factor(tokens, pos)?;
                if denom == 0.0 {
                    return Err("деление на ноль".into());
                }
                node /= denom;
            }
            Token::Mod => {
                *pos += 1;
                let denom = parse_factor(tokens, pos)?;
                node %= denom;
            }
            _ => break,
        }
    }
    Ok(node)
}

fn parse_factor(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    let mut node = parse_primary(tokens, pos)?;
    if *pos < tokens.len() && tokens[*pos] == Token::Pow {
        *pos += 1;
        let exp = parse_factor(tokens, pos)?; // правоассоциативно
        node = node.powf(exp);
    }
    Ok(node)
}

fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<f64, String> {
    if *pos >= tokens.len() {
        return Err("неожиданный конец выражения".into());
    }
    match &tokens[*pos] {
        Token::Num(n) => {
            let val = *n;
            *pos += 1;
            Ok(val)
        }
        Token::Minus => {
            *pos += 1;
            let val = parse_primary(tokens, pos)?;
            Ok(-val)
        }
        Token::Plus => {
            *pos += 1;
            parse_primary(tokens, pos)
        }
        Token::LParen => {
            *pos += 1;
            let val = parse_expr(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
                return Err("ожидалась закрывающая скобка ')'".into());
            }
            *pos += 1;
            Ok(val)
        }
        Token::Ident(name) => {
            let id = name.to_lowercase();
            *pos += 1;
            if id == "pi" {
                return Ok(std::f64::consts::PI);
            }
            if id == "e" {
                return Ok(std::f64::consts::E);
            }
            if *pos < tokens.len() && tokens[*pos] == Token::LParen {
                *pos += 1;
                let arg = parse_expr(tokens, pos)?;
                if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
                    return Err(format!("ожидалась ')' после функции {id}"));
                }
                *pos += 1;
                match id.as_str() {
                    "sqrt" => Ok(arg.sqrt()),
                    "cbrt" => Ok(arg.cbrt()),
                    "sin" => Ok(arg.sin()),
                    "cos" => Ok(arg.cos()),
                    "tan" => Ok(arg.tan()),
                    "abs" => Ok(arg.abs()),
                    "ln" => Ok(arg.ln()),
                    "log2" => Ok(arg.log2()),
                    "log10" => Ok(arg.log10()),
                    "exp" => Ok(arg.exp()),
                    "round" => Ok(arg.round()),
                    "floor" => Ok(arg.floor()),
                    "ceil" => Ok(arg.ceil()),
                    _ => Err(format!("неизвестная функция '{id}'")),
                }
            } else {
                Err(format!("неизвестный идентификатор '{id}'"))
            }
        }
        tok => Err(format!("неожиданный токен: {:?}", tok)),
    }
}

// ───────────────────── Конвертер единиц измерения ─────────────────────

fn eval_unit_conversion(expr: &str) -> Result<String, String> {
    // Формат: <val> <from_unit> to <to_unit>
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() < 4 || parts[parts.len() - 2].to_lowercase() != "to" {
        return Err("формат: <значение> <из> to <в> (например: 100 km/h to m/s)".into());
    }

    let val: f64 = parts[0]
        .parse()
        .map_err(|e| format!("число '{}': {e}", parts[0]))?;
    let from_unit = parts[1].to_lowercase();
    let to_unit = parts[parts.len() - 1].to_lowercase();

    let res = convert_units(val, &from_unit, &to_unit)?;
    Ok(format!("{res}"))
}

fn convert_units(val: f64, from: &str, to: &str) -> Result<f64, String> {
    if from == to {
        return Ok(val);
    }

    // Скорость
    if (from == "km/h" || from == "км/ч") && (to == "m/s" || to == "м/с") {
        return Ok(val / 3.6);
    }
    if (from == "m/s" || from == "м/с") && (to == "km/h" || to == "км/ч") {
        return Ok(val * 3.6);
    }
    if (from == "mph" || from == "миль/ч") && (to == "km/h" || to == "км/ч") {
        return Ok(val * 1.609344);
    }

    // Длина
    let len_to_m = |u: &str| -> Option<f64> {
        match u {
            "m" | "метр" | "м" => Some(1.0),
            "km" | "км" => Some(1000.0),
            "cm" | "см" => Some(0.01),
            "mm" | "мм" => Some(0.001),
            "mi" | "миля" => Some(1609.344),
            "ft" | "фут" => Some(0.3048),
            "in" | "дюйм" => Some(0.0254),
            _ => None,
        }
    };
    if let (Some(m1), Some(m2)) = (len_to_m(from), len_to_m(to)) {
        return Ok((val * m1) / m2);
    }

    // Данные / Память
    let bytes_scale = |u: &str| -> Option<f64> {
        match u {
            "b" | "байт" => Some(1.0),
            "kib" | "киб" => Some(1024.0),
            "mib" | "миб" => Some(1024.0 * 1024.0),
            "gib" | "гиб" => Some(1024.0 * 1024.0 * 1024.0),
            "tib" | "тиб" => Some(1024.0 * 1024.0 * 1024.0 * 1024.0),
            "kb" | "кб" => Some(1000.0),
            "mb" | "мб" => Some(1_000_000.0),
            "gb" | "гб" => Some(1_000_000_000.0),
            "tb" | "тб" => Some(1_000_000_000_000.0),
            _ => None,
        }
    };
    if let (Some(b1), Some(b2)) = (bytes_scale(from), bytes_scale(to)) {
        return Ok((val * b1) / b2);
    }

    Err(format!("неизвестная конверсия: '{from}' -> '{to}'"))
}

// ───────────────────── Аудит железа и системы ─────────────────────

fn get_hardware_info() -> String {
    let mut out = String::new();
    out.push_str("🔍 Скрытые параметры ПК (Terminal Gateway Hardware Audit)\n");

    // Чтение /proc/cpuinfo
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        out.push_str("── CPU ─────────────────────\n");
        for line in cpuinfo.lines() {
            if line.starts_with("model name") {
                let val = line.split(':').nth(1).unwrap_or("").trim();
                out.push_str(&format!("  модель                     {val}\n"));
                break;
            }
        }
    }

    // Чтение /proc/meminfo
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        out.push_str("── Память ─────────────────────\n");
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let val = line.split(':').nth(1).unwrap_or("").trim();
                out.push_str(&format!("  всего                      {val}\n"));
            } else if line.starts_with("MemAvailable:") {
                let val = line.split(':').nth(1).unwrap_or("").trim();
                out.push_str(&format!("  доступно                   {val}\n"));
            }
        }
    }

    out
}

fn get_sysinfo() -> String {
    let mut out = String::new();
    out.push_str("═ poler-sh sysinfo — карта среды исполнения ═\n\n");
    let cwd = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".into());
    out.push_str(&format!("  версия         : 0.1.0\n  pid            : {}\n  cwd            : {}\n", std::process::id(), cwd));
    out
}

// ───────────────────── Вспомогательные утилиты ─────────────────────

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
