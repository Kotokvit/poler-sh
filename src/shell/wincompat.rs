//! # WinCompat — слой совместимости Windows-команд (v0.47.0)
//!
//! Задача: poler-shell принимает **оба словаря** — Linux и Windows.
//! Пользователь/агент, привыкший к cmd.exe, вводит `dir`, `type`, `copy`,
//! `del`, `findstr`, `tasklist`… — а слой транслирует это в корректный
//! Linux-вызов с переводом флагов (`/w` → `-C`, `/s` → `-R`, `-n` у ping →
//! `-c` и т.д.).
//!
//! Принципы:
//! 1. **Не перехватывать то, что существует в Linux** (`sort`, `tree`,
//!    `mkdir`, `rmdir` без `/s`) — там транслируются только Windows-флаги.
//! 2. **Честные заметки**: если семантика не переносится 1:1 (например
//!    `ping -t` — бесконечный ping), перевод сопровождается примечанием,
//!    а не молчаливым искажением поведения.
//! 3. **Безопасность**: `net`, `sc`, `reg`, `format`, `diskpart` не
//!    выполняются — выдаётся подсказка о Linux-эквиваленте.
//!
//! Используется из `commands.rs` как последний fallback перед PATH-поиском:
//! неизвестная Linux-команда сначала проверяется в таблице Windows.

/// Результат трансляции Windows-команды.
#[derive(Debug, Clone, PartialEq)]
pub enum WinTranslation {
    /// Прямой запуск program(args) — без шелла, без кавычек-склейки.
    Exec {
        program: String,
        args: Vec<String>,
        /// Примечание о семантических отличиях (печатается после вывода).
        note: Option<&'static str>,
    },
    /// Запуск через `sh -c "<script>"` (нужны пайпы/редиректы/подстановки).
    Shell {
        script: String,
        note: Option<&'static str>,
    },
    /// Ничего не выполнять — только сообщение (pause, color, ver-заглушки).
    Notice(String),
}

/// Каталог поддерживаемых Windows-команд (для `win` и help).
pub fn catalog() -> String {
    let mut s = String::new();
    s.push_str("WinCompat v0.47.0 — Windows-команды, понимаемые poler-shell (Linux-словарь тоже работает):\n");
    s.push_str("\n  Файлы и каталоги:\n");
    s.push_str("    dir [/w /b /s /a:d /o:d /o:-d /o:s] [path]  → ls (с сортировками)\n");
    s.push_str("    type <file>                                 → cat\n");
    s.push_str("    copy [/y] <src...> <dst>  | copy a+b c       → cp / cat-конкатенация\n");
    s.push_str("    xcopy [/e /y] <src> <dst>                   → cp -r\n");
    s.push_str("    del|erase [/f /q /s] <file...>              → rm\n");
    s.push_str("    rd|rmdir [/s /q] <dir>                      → rm -rf / rmdir\n");
    s.push_str("    md <dir...>                                 → mkdir -p\n");
    s.push_str("    ren|rename <old> <new>                      → mv\n");
    s.push_str("    move [/y] <src> <dst>                       → mv\n");
    s.push_str("    tree [path]                                 → tree (или find-фолбэк)\n");
    s.push_str("\n  Текст и поиск:\n");
    s.push_str("    findstr [/i /v /n /s /c:\"lit\"] <pat> [file] → grep\n");
    s.push_str("    fc [/w] <a> <b>                             → diff\n");
    s.push_str("    sort [/r] [file]                            → sort (флаги переводятся)\n");
    s.push_str("    echo %VAR%                                  → echo ${VAR} (переменные)\n");
    s.push_str("    set NAME=VALUE | set NAME                   → переменные сессии\n");
    s.push_str("\n  Система и процессы:\n");
    s.push_str("    tasklist                                    → ps aux\n");
    s.push_str("    taskkill /PID n [/F] | /IM name [/F]        → kill / pkill\n");
    s.push_str("    ipconfig [/all]                             → ip addr (+ route)\n");
    s.push_str("    systeminfo                                  → sysinfo (полный отчёт)\n");
    s.push_str("    ver                                         → uname -sr\n");
    s.push_str("    where <prog>                                → which\n");
    s.push_str("    ping -n 4 -l 64 -w 1000 host                → ping -c 4 -s 64 -W 1\n");
    s.push_str("\n  Терминал:\n");
    s.push_str("    cls | clear                                 → очистка экрана (ANSI)\n");
    s.push_str("    title <text>                                → заголовок терминала\n");
    s.push_str("    pause                                       → пауза\n");
    s.push_str("    notepad <file>                              → $EDITOR / nano\n");
    s.push_str("    start <url|file>                            → xdg-open\n");
    s.push_str("\n  Не выполняются (подсказка вместо запуска): net, sc, reg, format, diskpart,\n");
    s.push_str("  driverquery, chcp, prompt, color, doskey.\n");
    s.push_str("  Прочие команды ищутся в $PATH как обычно (transparent passthrough).");
    s
}

/// Экранирование для вставки в `sh -c '...'` (одинарные кавычки).
fn sh_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    let safe = !s.chars().any(|c| {
        c.is_whitespace() || matches!(c, '\'' | '"' | '$' | '`' | '\\' | '*' | '?' | '[' | ']' | '(' | ')' | ';' | '&' | '|' | '<' | '>' | '{' | '}' | '!' | '#' | '~')
    });
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Является ли токен Windows-флагом: `/x`, `/x:y`, `/-y` (cmd-стиль).
fn is_win_flag(tok: &str) -> bool {
    tok.len() >= 2 && tok.starts_with('/') && !tok[1..].starts_with('/')
}

/// Нижний регистр имени флага без слэша: `/A:D` → `a:d`.
fn flag_name(tok: &str) -> String {
    tok[1..].to_ascii_lowercase()
}

/// Главный вход: попытаться перевести `cmd args` в Linux-эквивалент.
/// `None` — команда не из Windows-словаря (обычный PATH-поиск).
pub fn translate(cmd: &str, args: &[String]) -> Option<WinTranslation> {
    let c = cmd.to_ascii_lowercase();
    match c.as_str() {
        // ---------------- Файлы и каталоги ----------------
        "type" => Some(WinTranslation::Exec {
            program: "cat".into(),
            args: args.to_vec(),
            note: None,
        }),
        "copy" => Some(translate_copy(args)),
        "xcopy" => Some(translate_xcopy(args)),
        "del" | "erase" => Some(translate_del(args)),
        "md" => Some(WinTranslation::Exec {
            program: "mkdir".into(),
            args: std::iter::once("-p".to_string())
                .chain(args.iter().cloned())
                .collect(),
            note: Some("md → mkdir -p (Windows создаёт промежуточные каталоги)"),
        }),
        "rmdir" => {
            // rmdir существует и в Linux; перехватываем ТОЛЬКО с /s или /q
            if args.iter().any(|a| is_win_flag(a)) {
                Some(translate_rd(args))
            } else {
                None
            }
        }
        "rd" => Some(translate_rd(args)),
        "ren" | "rename" => Some(WinTranslation::Exec {
            program: "mv".into(),
            args: args.to_vec(),
            note: None,
        }),
        "move" => {
            let rest: Vec<String> = args
                .iter()
                .filter(|a| !matches!(flag_name(a).as_str(), "y" | "-y"))
                .cloned()
                .collect();
            Some(WinTranslation::Exec {
                program: "mv".into(),
                args: rest,
                note: None,
            })
        }
        "dir" => Some(translate_dir(args)),
        "tree" => {
            // tree есть в Linux — если установлен, не перехватываем.
            if which_exists("tree") {
                None
            } else {
                let path = args
                    .iter()
                    .find(|a| !is_win_flag(a))
                    .map(|s| s.as_str())
                    .unwrap_or(".");
                Some(WinTranslation::Shell {
                    script: format!("find {} -print | sort", sh_quote(path)),
                    note: Some("tree не установлен — использован find-фолбэк"),
                })
            }
        }

        // ---------------- Текст и поиск ----------------
        "findstr" => Some(translate_findstr(args)),
        "fc" => {
            let rest: Vec<String> = args
                .iter()
                .filter(|a| !is_win_flag(a))
                .cloned()
                .collect();
            Some(WinTranslation::Exec {
                program: "diff".into(),
                args: rest,
                note: Some("fc → diff (у diff выход с кодами 0/1/2 — 1 = есть отличия)"),
            })
        }
        "sort" => {
            // sort есть в Linux — переводим только Windows-флаги
            if args.iter().any(|a| is_win_flag(a) || a.starts_with("/+")) {
                Some(translate_sort(args))
            } else {
                None
            }
        }

        // ---------------- Система и процессы ----------------
        "tasklist" => Some(WinTranslation::Exec {
            program: "ps".into(),
            args: vec!["aux".into()],
            note: None,
        }),
        "taskkill" => Some(translate_taskkill(args)),
        "ipconfig" => Some(translate_ipconfig(args)),
        "ver" => Some(WinTranslation::Exec {
            program: "uname".into(),
            args: vec!["-sr".into()],
            note: None,
        }),
        "where" => {
            // Windows `where` ищет по PATH; Linux-эквивалент which.
            // `where /r dir pattern` — рекурсивный поиск → find.
            if let Some(rpos) = args.iter().position(|a| flag_name(a) == "r") {
                let dir = args.get(rpos + 1).cloned().unwrap_or_else(|| ".".into());
                let pats: Vec<String> =
                    args.iter().skip(rpos + 2).filter(|a| !is_win_flag(a)).cloned().collect();
                let mut script = format!("find {}", sh_quote(&dir));
                for p in &pats {
                    script.push_str(&format!(" -name {}", sh_quote(p)));
                }
                return Some(WinTranslation::Shell {
                    script,
                    note: Some("where /r → find -name (рекурсивный поиск)"),
                });
            }
            Some(WinTranslation::Exec {
                program: "which".into(),
                args: args.iter().filter(|a| !is_win_flag(a)).cloned().collect(),
                note: None,
            })
        }
        "ping" => Some(translate_ping(args)),
        "systeminfo" => None, // обрабатывается нативно в commands.rs → sysinfo

        // ---------------- Терминал ----------------
        "cls" | "clear" => None, // нативно в commands.rs (ANSI)
        "pause" => Some(WinTranslation::Notice(
            "⏸ pause — в poler-shell нажмите Enter для продолжения (в агентном режиме --exec это no-op)".into(),
        )),
        "title" => {
            let t = if args.is_empty() { "poler-shell".to_string() } else { args.join(" ") };
            Some(WinTranslation::Notice(format!("\x1b]0;{t}\x07")))
        }
        "notepad" => Some(WinTranslation::Shell {
            script: format!(
                "${{EDITOR:-nano}} {}",
                args.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")
            ),
            note: Some("notepad → $EDITOR (по умолчанию nano)"),
        }),
        "start" => {
            // Windows-хитрость: `start "" "url"` — первый аргумент может быть
            // пустым заголовком окна; пропускаем его.
            let mut rest: Vec<String> = args
                .iter()
                .filter(|a| !is_win_flag(a))
                .cloned()
                .collect();
            if rest.first().map(|s| s.is_empty()).unwrap_or(false) {
                rest.remove(0);
            }
            Some(WinTranslation::Exec {
                program: "xdg-open".into(),
                args: rest,
                note: Some("start → xdg-open"),
            })
        }
        "doskey" | "prompt" | "chcp" => Some(WinTranslation::Notice(
            "ℹ Эта команда cmd.exe не переносима: в poler-shell используйте `!` для сырого sh, `help` для справки, LANG/LC_ALL для кодировки.".into(),
        )),
        "color" => Some(WinTranslation::Notice(
            "ℹ color: палитры cmd.exe нет; poler-shell уже использует ANSI-цвета терминала.".into(),
        )),
        "net" => Some(WinTranslation::Notice(
            "🚫 net не выполняется: сетевые службы — `ip addr`, `ss -tulpn`, `systemctl status <svc>`; шары — mount.cifs.".into(),
        )),
        "sc" => Some(WinTranslation::Notice(
            "🚫 sc не выполняется: Linux-эквивалент — `systemctl start|stop|status <svc>`.".into(),
        )),
        "reg" => Some(WinTranslation::Notice(
            "🚫 reg не выполняется: реестра нет; конфигурация — файлы в /etc и ~/.config.".into(),
        )),
        "format" | "diskpart" => Some(WinTranslation::Notice(
            "🚫 Разметка дисков из poler-shell запрещена: используйте mkfs/fsblk вне сессии.".into(),
        )),
        "driverquery" => Some(WinTranslation::Notice(
            "🚫 driverquery: Linux-эквивалент — `lspci -k`, `lsmod`.".into(),
        )),
        _ => None,
    }
}

fn which_exists(prog: &str) -> bool {
    if let Ok(paths) = std::env::var("PATH") {
        for p in std::env::split_paths(&paths) {
            let cand = p.join(prog);
            if cand.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(md) = std::fs::metadata(&cand) {
                        if md.permissions().mode() & 0o111 != 0 {
                            return true;
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    return true;
                }
            }
        }
    }
    false
}

/// `dir [flags] [path]` → ls с комбинацией флагов.
fn translate_dir(args: &[String]) -> WinTranslation {
    let mut ls_args: Vec<String> = vec!["-l".into(), "-h".into(), "-A".into()];
    let mut shell_fallback: Option<String> = None;
    let mut paths: Vec<String> = Vec::new();

    for a in args {
        if !is_win_flag(a) {
            paths.push(a.clone());
            continue;
        }
        let f = flag_name(a);
        match f.as_str() {
            "w" => {
                // широкий формат без деталей
                ls_args.retain(|x| x != "-l");
            }
            "b" => {
                // bare: только имена
                ls_args = vec!["-1".into(), "-A".into()];
            }
            "s" => {
                ls_args.push("-R".into());
            }
            "a" => {
                // /a, /a:h — показывать скрытые: -A уже показывает
            }
            "a:d" | "ad" => {
                // только каталоги — чистым ls не выражается
                shell_fallback = Some("ls -lhA -d */ 2>/dev/null || true".into());
            }
            "a:h" | "ah" => {
                ls_args.push("-d".into());
                ls_args.push(".*".into());
            }
            "q" => {} // владелец уже в -l
            "o:d" => {
                ls_args.push("-t".into());
            }
            "o:-d" => {
                ls_args.push("-tr".into());
            }
            "o:s" => {
                ls_args.push("-S".into());
            }
            "o:-s" => {
                ls_args.push("-Sr".into());
            }
            "o:n" | "o:e" | "o:-n" | "o:-e" => {} // алфавит — дефолт ls
            _ => {}
        }
    }

    if let Some(sf) = shell_fallback {
        let mut s = sf;
        for p in &paths {
            s.push(' ');
            s.push_str(&sh_quote(p));
        }
        return WinTranslation::Shell {
            script: s,
            note: Some("dir /a:d → только каталоги"),
        };
    }
    ls_args.extend(paths);

    WinTranslation::Exec {
        program: "ls".into(),
        args: ls_args,
        note: None,
    }
}

/// `copy [/y] src... dst` и `copy a+b c` (конкатенация).
fn translate_copy(args: &[String]) -> WinTranslation {
    let mut force = false;
    let mut rest: Vec<String> = Vec::new();
    for a in args {
        if is_win_flag(a) {
            if flag_name(a) == "y" {
                force = true;
            }
            continue;
        }
        rest.push(a.clone());
    }
    // Конкатенация: ровно один аргумент вида a+b+c и назначение
    if rest.len() == 2 && rest[0].contains('+') {
        let parts: Vec<String> =
            rest[0].split('+').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if parts.len() >= 2 {
            let mut script = String::from("cat");
            for p in &parts {
                script.push(' ');
                script.push_str(&sh_quote(p));
            }
            script.push_str(" > ");
            script.push_str(&sh_quote(&rest[1]));
            return WinTranslation::Shell {
                script,
                note: Some("copy a+b c → cat a b > c (конкатенация)"),
            };
        }
    }
    let mut cp_args: Vec<String> = Vec::new();
    if force {
        cp_args.push("-f".into());
    }
    cp_args.extend(rest);
    WinTranslation::Exec {
        program: "cp".into(),
        args: cp_args,
        note: None,
    }
}

fn translate_xcopy(args: &[String]) -> WinTranslation {
    let mut recursive = false;
    let mut rest: Vec<String> = Vec::new();
    for a in args {
        if is_win_flag(a) {
            match flag_name(a).as_str() {
                "e" | "s" => recursive = true,
                "y" | "q" | "i" | "h" | "c" | "k" | "o" | "x" => {}
                _ => {}
            }
            continue;
        }
        rest.push(a.clone());
    }
    let mut cp_args: Vec<String> = Vec::new();
    if recursive {
        cp_args.push("-r".into());
    }
    cp_args.extend(rest);
    WinTranslation::Exec {
        program: "cp".into(),
        args: cp_args,
        note: Some("xcopy → cp (для каталогов добавлен -r)"),
    }
}

fn translate_del(args: &[String]) -> WinTranslation {
    let mut rm_args: Vec<String> = Vec::new();
    let mut recursive = false;
    for a in args {
        if is_win_flag(a) {
            match flag_name(a).as_str() {
                "f" | "q" => {
                    if !rm_args.iter().any(|x| x == "-f") {
                        rm_args.push("-f".into());
                    }
                }
                "s" => recursive = true,
                _ => {}
            }
            continue;
        }
        rm_args.push(a.clone());
    }
    if recursive && !rm_args.iter().any(|x| x == "-r") {
        rm_args.push("-r".into());
    }
    WinTranslation::Exec {
        program: "rm".into(),
        args: rm_args,
        note: None,
    }
}

fn translate_rd(args: &[String]) -> WinTranslation {
    let recursive = args.iter().any(|a| {
        let f = flag_name(a);
        f == "s" || f == "q" || f == "s /q"
    });
    let rest: Vec<String> = args.iter().filter(|a| !is_win_flag(a)).cloned().collect();
    if recursive {
        WinTranslation::Exec {
            program: "rm".into(),
            args: std::iter::once("-rf".to_string()).chain(rest).collect(),
            note: Some("rd /s → rm -rf (рекурсивное удаление)"),
        }
    } else {
        WinTranslation::Exec {
            program: "rmdir".into(),
            args: rest,
            note: None,
        }
    }
}

fn translate_findstr(args: &[String]) -> WinTranslation {
    let mut grep_args: Vec<String> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if is_win_flag(a) {
            let f = flag_name(a);
            match f.as_str() {
                "i" => grep_args.push("-i".into()),
                "v" => grep_args.push("-v".into()),
                "n" => grep_args.push("-n".into()),
                "s" => grep_args.push("-r".into()),
                "x" => grep_args.push("-x".into()),
                "c" => {
                    // /c:"literal" или /c:literal — следующий токен или суффикс
                    if let Some(lit) = a.strip_prefix("/c:") {
                        if !lit.is_empty() {
                            grep_args.push("-F".into());
                            rest.push(lit.to_string());
                        }
                    } else if i + 1 < args.len() {
                        grep_args.push("-F".into());
                        rest.push(args[i + 1].clone());
                        i += 1;
                    }
                }
                "r" | "b" | "e" | "p" | "o" | "m" | "l" | "g" | "d" | "a" => {}
                _ => {}
            }
        } else {
            rest.push(a.clone());
        }
        i += 1;
    }
    // findstr: pattern, потом файлы
    let mut out = grep_args;
    out.extend(rest);
    WinTranslation::Exec {
        program: "grep".into(),
        args: out,
        note: Some("findstr → grep (некоторые флаги cmd не имеют аналога и пропущены)"),
    }
}

fn translate_sort(args: &[String]) -> WinTranslation {
    let mut out: Vec<String> = Vec::new();
    for a in args {
        if is_win_flag(a) {
            let f = flag_name(a);
            match f.as_str() {
                "r" => out.push("-r".into()),
                _ => {}
            }
        } else if let Some(k) = a.strip_prefix("/+") {
            // /+n — начать сравнение с колонки n → key от n
            if let Ok(n) = k.parse::<usize>() {
                out.push("-k".into());
                out.push(n.to_string());
            }
        } else {
            out.push(a.clone());
        }
    }
    WinTranslation::Exec {
        program: "sort".into(),
        args: out,
        note: Some("sort: Windows-флаги переведены в POSIX"),
    }
}

fn translate_taskkill(args: &[String]) -> WinTranslation {
    let force = args.iter().any(|a| flag_name(a) == "f");
    let sig = if force { "-9" } else { "-15" };
    let mut pid: Option<String> = None;
    let mut im: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if is_win_flag(a) {
            let f = flag_name(a);
            if f == "pid" {
                pid = args.get(i + 1).cloned();
                i += 1;
            } else if f == "im" {
                im = args.get(i + 1).cloned();
                // Windows-имена вроде "app.exe" → убрать .exe для pkill
                if let Some(name) = im.as_deref() {
                    if let Some(stripped) = name.strip_suffix(".exe") {
                        im = Some(stripped.to_string());
                    }
                }
                i += 1;
            }
        }
        i += 1;
    }
    if let Some(p) = pid {
        return WinTranslation::Exec {
            program: "kill".into(),
            args: vec![sig.to_string(), p],
            note: Some("taskkill /PID → kill"),
        };
    }
    if let Some(name) = im {
        return WinTranslation::Exec {
            program: "pkill".into(),
            args: vec![sig.to_string(), name],
            note: Some("taskkill /IM → pkill (.exe отброшен)"),
        };
    }
    WinTranslation::Notice(
        "taskkill: нужен /PID <n> или /IM <name> (пример: taskkill /PID 1234 /F)".into(),
    )
}

fn translate_ipconfig(args: &[String]) -> WinTranslation {
    let all = args.iter().any(|a| flag_name(a) == "all");
    if all {
        WinTranslation::Shell {
            script: "ip addr 2>/dev/null || ifconfig; echo '---'; ip route 2>/dev/null || route -n; echo '---'; cat /etc/resolv.conf 2>/dev/null".into(),
            note: Some("ipconfig /all → ip addr + route + resolv.conf"),
        }
    } else {
        WinTranslation::Shell {
            script: "ip addr 2>/dev/null || ifconfig".into(),
            note: Some("ipconfig → ip addr"),
        }
    }
}

fn translate_ping(args: &[String]) -> WinTranslation {
    let mut out: Vec<String> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut note: Option<&'static str> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        // ping принимает и /-флаги (редко) и -флаги
        let is_flag = a.starts_with('-') || is_win_flag(a);
        if is_flag {
            let f = a.trim_start_matches(['-', '/']).to_ascii_lowercase();
            match f.as_str() {
                "n" => {
                    out.push("-c".into());
                    if let Some(v) = args.get(i + 1) {
                        out.push(v.clone());
                        i += 1;
                    }
                }
                "l" => {
                    out.push("-s".into());
                    if let Some(v) = args.get(i + 1) {
                        out.push(v.clone());
                        i += 1;
                    }
                }
                "i" => {
                    out.push("-t".into());
                    if let Some(v) = args.get(i + 1) {
                        out.push(v.clone());
                        i += 1;
                    }
                }
                "w" => {
                    // Windows: -w <мс>; Linux: -W <сек>
                    out.push("-W".into());
                    if let Some(v) = args.get(i + 1) {
                        if let Ok(ms) = v.parse::<u64>() {
                            out.push((ms / 1000).max(1).to_string());
                        } else {
                            out.push(v.clone());
                        }
                        i += 1;
                    }
                    note = Some("ping: -w переведён из миллисекунд в секунды (-W)");
                }
                "t" => {
                    note = Some("ping: бесконечный -t не поддерживается — остановите по ^C; добавьте -n N");
                }
                "4" => out.push("-4".into()),
                "6" => out.push("-6".into()),
                "a" => out.push("-a".into()),
                _ => {}
            }
        } else {
            rest.push(a.clone());
        }
        i += 1;
    }
    out.extend(rest);
    WinTranslation::Exec {
        program: "ping".into(),
        args: out,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn type_becomes_cat() {
        let t = translate("type", &s(&["file.txt"])).unwrap();
        assert_eq!(
            t,
            WinTranslation::Exec { program: "cat".into(), args: s(&["file.txt"]), note: None }
        );
    }

    #[test]
    fn dir_basic_is_ls_lha() {
        let t = translate("dir", &[]).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "ls");
                assert!(args.contains(&"-l".to_string()));
                assert!(args.contains(&"-A".to_string()));
            }
            _ => panic!("ожидался Exec"),
        }
    }

    #[test]
    fn dir_w_drops_long_format() {
        let t = translate("dir", &s(&["/w"])).unwrap();
        match t {
            WinTranslation::Exec { args, .. } => assert!(!args.contains(&"-l".to_string())),
            _ => panic!(),
        }
    }

    #[test]
    fn dir_b_is_bare() {
        let t = translate("dir", &s(&["/b"])).unwrap();
        match t {
            WinTranslation::Exec { args, .. } => {
                assert!(args.contains(&"-1".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn dir_only_dirs_uses_shell() {
        let t = translate("dir", &s(&["/a:d"])).unwrap();
        match t {
            WinTranslation::Shell { script, .. } => assert!(script.contains("*/")),
            _ => panic!("ожидался Shell"),
        }
    }

    #[test]
    fn copy_simple() {
        let t = translate("copy", &s(&["a.txt", "b.txt"])).unwrap();
        assert_eq!(
            t,
            WinTranslation::Exec { program: "cp".into(), args: s(&["a.txt", "b.txt"]), note: None }
        );
    }

    #[test]
    fn copy_concat() {
        let t = translate("copy", &s(&["a.txt+b.txt", "c.txt"])).unwrap();
        match t {
            WinTranslation::Shell { script, .. } => {
                assert!(script.starts_with("cat "));
                assert!(script.contains(" > "));
            }
            _ => panic!("ожидался Shell для конкатенации"),
        }
    }

    #[test]
    fn copy_y_adds_force() {
        let t = translate("copy", &s(&["/y", "a", "b"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "cp");
                assert_eq!(args, s(&["-f", "a", "b"]));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn del_flags() {
        let t = translate("del", &s(&["/f", "/q", "x"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "rm");
                assert_eq!(args.iter().filter(|x| *x == "-f").count(), 1);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rd_s_is_rm_rf() {
        let t = translate("rd", &s(&["/s", "/q", "dir1"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "rm");
                assert!(args.contains(&"-rf".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rmdir_without_flags_not_intercepted() {
        assert!(translate("rmdir", &s(&["dir1"])).is_none());
    }

    #[test]
    fn md_is_mkdir_p() {
        let t = translate("md", &s(&["a/b/c"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "mkdir");
                assert_eq!(args, s(&["-p", "a/b/c"]));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn findstr_flags() {
        let t = translate("findstr", &s(&["/i", "/n", "hello", "f.txt"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "grep");
                assert!(args.contains(&"-i".to_string()));
                assert!(args.contains(&"-n".to_string()));
                assert!(args.contains(&"hello".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ping_n_to_c() {
        let t = translate("ping", &s(&["-n", "4", "example.com"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "ping");
                // -c 4 идёт перед хостом
                let pos_c = args.iter().position(|x| x == "-c").unwrap();
                assert_eq!(args[pos_c + 1], "4");
                assert_eq!(*args.last().unwrap(), "example.com".to_string());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ping_w_ms_to_s() {
        let t = translate("ping", &s(&["-w", "3000", "h"])).unwrap();
        match t {
            WinTranslation::Exec { args, note, .. } => {
                let pos = args.iter().position(|x| x == "-W").unwrap();
                assert_eq!(args[pos + 1], "3");
                assert!(note.is_some());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn taskkill_pid() {
        let t = translate("taskkill", &s(&["/PID", "42", "/F"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "kill");
                assert!(args.contains(&"-9".to_string()));
                assert!(args.contains(&"42".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn taskkill_im_strips_exe() {
        let t = translate("taskkill", &s(&["/IM", "app.exe", "/F"])).unwrap();
        match t {
            WinTranslation::Exec { program, args, .. } => {
                assert_eq!(program, "pkill");
                assert!(args.contains(&"app".to_string()));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn dangerous_commands_are_not_executed() {
        assert!(matches!(
            translate("net", &s(&["use"])),
            Some(WinTranslation::Notice(_))
        ));
        assert!(matches!(
            translate("reg", &s(&["query", "HKLM"])),
            Some(WinTranslation::Notice(_))
        ));
        assert!(matches!(
            translate("format", &s(&["C:"])),
            Some(WinTranslation::Notice(_))
        ));
    }

    #[test]
    fn linux_commands_not_intercepted() {
        assert!(translate("ls", &[]).is_none());
        assert!(translate("cargo", &s(&["build"])).is_none());
        assert!(translate("grep", &s(&["x"])).is_none());
        assert!(translate("python3", &[]).is_none());
    }

    #[test]
    fn title_is_notice_with_ansi() {
        let t = translate("title", &s(&["My Session"])).unwrap();
        match t {
            WinTranslation::Notice(s) => assert!(s.starts_with("\x1b]0;")),
            _ => panic!(),
        }
    }

    #[test]
    fn where_r_is_find() {
        let t = translate("where", &s(&["/r", ".", "*.rs"])).unwrap();
        match t {
            WinTranslation::Shell { script, .. } => {
                assert!(script.starts_with("find "));
                assert!(script.contains("-name"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn sh_quote_escapes() {
        assert_eq!(sh_quote("simple"), "simple");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn catalog_lists_key_commands() {
        let c = catalog();
        assert!(c.contains("dir"));
        assert!(c.contains("taskkill"));
        assert!(c.contains("findstr"));
    }
}
