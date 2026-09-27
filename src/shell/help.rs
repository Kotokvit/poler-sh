//! # Help + ? palette (v2.0 sovereign stack)
//!
//! Полная man-подобная справка по всем командам poler-shell + интерактивная
//! палитра готовых сценариев (вызывается `?` в TUI или REPL).
//!
//! ## Структура
//! - `help_overview()` — общий список команд по группам (как `help` без аргументов)
//! - `help_topic(name)` — детальная справка по одной команде/группе:
//!   `help gh`, `help sources add` и т.д.
//! - `palette_scenarios()` — готовые пресеты для `?` palette
//!
//! v2.0: группа NLM удалена вместе с Google/NotebookLM-интеграциями.

use std::fmt::Write;

/// Группа команд (для фильтрации в `help`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpGroup {
    Search,
    Crawl,
    Impact,
    Vcs,
    Gix,
    Sync,
    Set,
    Notes,
    Sources,
    // v0.47.0
    System,
    Agent,
    Meta,
    // v0.48.0
    Calc,
    // v0.51.0 (цикл P)
    Quantum,
    // v0.53.0 (цикл R)
    P3,
    // v0.54.0 (цикл S)
    Game,
}

impl HelpGroup {
    pub fn as_str(self) -> &'static str {
        match self {
            HelpGroup::Search => "Пошук",
            HelpGroup::Crawl => "Crawl",
            HelpGroup::Impact => "AIDDE",
            HelpGroup::Vcs => "GitHub/GitLab/Gitea",
            HelpGroup::Gix => "gix (local)",
            HelpGroup::Sync => "Sync VCS",
            HelpGroup::Set => "Налаштування",
            HelpGroup::Notes => "Notes (CRUD)",
            HelpGroup::Sources => "Sources (CRUD)",
            // v0.47.0
            HelpGroup::System => "Система/Win+Linux (v0.47.0)",
            HelpGroup::Agent => "Середа агента (v0.47.0)",
            HelpGroup::Meta => "Мета",
            HelpGroup::Calc => "Калькулятор Всего (v0.48.0)",
            HelpGroup::Quantum => "Квантовый мост (v0.51.0)",
            HelpGroup::P3 => "P³-Мост Rust↔Zig (v0.53.0)",
            HelpGroup::Game => "Ядро Игры (v0.54.0)",
        }
    }
}

/// Одна строка в спрaвке.
#[derive(Debug, Clone)]
pub struct HelpEntry {
    pub group: HelpGroup,
    pub cmd: &'static str,
    pub short: &'static str,
}

/// Все команды poler-shell (полный реестр для `help`). v2.0: NLM удалены.
pub fn all_entries() -> Vec<HelpEntry> {
    vec![
        HelpEntry { group: HelpGroup::Search, cmd: "search \"<query>\" [--top N]", short: "Пошук по web-index.db (веб+локал)" },
        HelpEntry { group: HelpGroup::Search, cmd: "web \"<query>\"", short: "Аліас для search" },
        HelpEntry { group: HelpGroup::Search, cmd: "stats", short: "Статистика web-index.db: сторінки, байти, PageRank" },

        HelpEntry { group: HelpGroup::Crawl, cmd: "crawl <URL> [--depth N] [--max M] [--cross] [--delay-ms N]", short: "Обхід URL → web-index.db (CDP+Chromium)" },
        HelpEntry { group: HelpGroup::Impact, cmd: "impact <PATH> <SYMBOL> [--depth N] [--cache <DB>]", short: "AIDDE impact-паспорт символу в кодовій базі" },

        HelpEntry { group: HelpGroup::Vcs, cmd: "gh search <Q> [--top N]", short: "Пошук по коду GitHub (треба $GITHUB_TOKEN)" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gh repos <USER>", short: "Список репозиторіїв користувача GitHub" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gh commits <OWNER/REPO>", short: "Останні 20 комітів репо" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gh issues <OWNER/REPO>", short: "issues+PR репозиторію" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gl search <Q>", short: "Пошук по GitLab (REST v4)" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gl commits <GROUP/PROJ>", short: "Коміти GitLab проєкту" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gl issues <GROUP/PROJ>", short: "issues+MR GitLab" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gt search <Q>", short: "Пошук по Gitea/Forgejo ($GITEA_HOST)" },
        HelpEntry { group: HelpGroup::Vcs, cmd: "gt commits <OWNER/REPO>", short: "Коміти Gitea" },

        HelpEntry { group: HelpGroup::Gix, cmd: "gix log <PATH> [--top N]", short: "git log локального репо через Pure-Rust gix" },
        HelpEntry { group: HelpGroup::Gix, cmd: "gix clone <URL> <PATH> [--depth N] [--branch B]", short: "Pure-Rust git clone через gix::clone::PrepareFetch" },
        HelpEntry { group: HelpGroup::Gix, cmd: "gix lfs list <PATH>", short: "Знайти LFS pointer-файли у worktree" },
        HelpEntry { group: HelpGroup::Gix, cmd: "gix lfs fetch <PATH>", short: "Завантажити LFS-об'єкти через batch API" },

        HelpEntry { group: HelpGroup::Sync, cmd: "sync vcs [gh|gl|gt] <OWNER>", short: "Синк VCS-сторінок у web-index.db" },

        HelpEntry { group: HelpGroup::Set, cmd: "set format md|json|simple", short: "Перемикнути формат виводу" },
        HelpEntry { group: HelpGroup::Set, cmd: "set top N", short: "Топ-K за замовчуванням для search" },

        HelpEntry { group: HelpGroup::Notes, cmd: "notes list", short: "Усі замітки (новіші зверху)" },
        HelpEntry { group: HelpGroup::Notes, cmd: "notes add <title>", short: "Створити порожню замітку (тіло введете у TUI редакторі)" },
        HelpEntry { group: HelpGroup::Notes, cmd: "notes show <id>", short: "Показати повну замітку" },
        HelpEntry { group: HelpGroup::Notes, cmd: "notes edit <id>", short: "Редагувати замітку (TUI редактор)" },
        HelpEntry { group: HelpGroup::Notes, cmd: "notes rm <id>", short: "Видалити замітку" },
        HelpEntry { group: HelpGroup::Notes, cmd: "F3 (Transcript)", short: "Лента локальної історії питань у TUI: пари питання→відповідь, копіювання" },

        HelpEntry { group: HelpGroup::Sources, cmd: "sources list", short: "Усі джерела" },
        HelpEntry { group: HelpGroup::Sources, cmd: "sources add <value> [--kind file|url|repo] [--label \"...\"]", short: "Додати джерело (kind авто-детектується)" },
        HelpEntry { group: HelpGroup::Sources, cmd: "sources rm <id>", short: "Видалити джерело" },
        HelpEntry { group: HelpGroup::Sources, cmd: "sources test <id>", short: "Перевірити доступність" },
        HelpEntry { group: HelpGroup::Sources, cmd: "sources open <id>", short: "Відкрити в системі через xdg-open" },

        // v0.47.0: система — Win+Linux словарь + прямой шелл
        HelpEntry { group: HelpGroup::System, cmd: "cd <path> | cd", short: "Змінити каталог (без аргументів — показати поточний, як у cmd.exe)" },
        HelpEntry { group: HelpGroup::System, cmd: "pwd", short: "Показати поточний каталог" },
        HelpEntry { group: HelpGroup::System, cmd: "clear | cls", short: "Очистити екран (ANSI; cls — Windows-словарь)" },
        HelpEntry { group: HelpGroup::System, cmd: "engine <args...>", short: "Виклик CLI самого движка (self-exec): engine --benchmark, engine --poler-box ..." },
        HelpEntry { group: HelpGroup::System, cmd: "! <command>", short: "Прямий виклик системного шелла (sh -c)" },
        HelpEntry { group: HelpGroup::System, cmd: "sh | bash | exec <command>", short: "Виконати команду в системному шеллі" },
        HelpEntry { group: HelpGroup::System, cmd: "<path>.poler [args]", short: "Автозапуск .poler-контейнера в ізольованому poler-box" },
        HelpEntry { group: HelpGroup::System, cmd: "<системна команда>", short: "Transparent PATH passthrough: ls, cargo, python3, git..." },
        HelpEntry { group: HelpGroup::System, cmd: "dir | type | copy | del | md | ren | move", short: "Windows-словарь → ls/cat/cp/rm/mkdir/mv (деталі: `win`)" },
        HelpEntry { group: HelpGroup::System, cmd: "findstr | tasklist | taskkill | ipconfig | ping", short: "Windows-словарь → grep/ps/kill/ip addr (флаги переводяться)" },
        HelpEntry { group: HelpGroup::System, cmd: "win", short: "Повний каталог Windows-команд і їх трансляцій" },

        // v0.48.0: Калькулятор Всего
        HelpEntry { group: HelpGroup::Calc, cmd: "calc <expr> | = <expr>", short: "Вычислить всё: арифметика, единицы (to), матрицы expm/eigen, триты, законы" },
        HelpEntry { group: HelpGroup::Calc, cmd: "calc solve <eq>", short: "Корни уравнения: полиномы (Дюран–Кернер) и трансцендентные (Ньютон+бисекция)" },
        HelpEntry { group: HelpGroup::Calc, cmd: "calc constants|units|funcs|laws", short: "Каталоги: константы CODATA/IAU, единицы, функции, законы физики" },
        HelpEntry { group: HelpGroup::Calc, cmd: "calc script <law> [k=v]", short: "Сгенерировать скрипт/.poler-правило по закону физики (Kepler, Циолковский…)" },
        HelpEntry { group: HelpGroup::Calc, cmd: "hw [--json]", short: "Скрытые параметры ПК: кеши L1-L3, ISA-флаги, NUMA, GPU, топология" },
        // v0.51.0 (цикл P): квантовый мост
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum run <algo> [--n K --shots M]", short: "Схемы на идеальных кубитах: bell ghz qft iqft grover bv dj period teleport" },
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum qcasm <файл|-> [opts]", short: "Произвольная QCASM-схема; --exact — кольцо ℤ[1/√2, i]; --noise — шум железа (цикл Q)" },
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum qaoa [--edges i-j,…] [--p P]", short: "QAOA MaxCut: анзац + оптимизация углов, аппроксимационное отношение (цикл Q)" },
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum teleport [--theta T --exact]", short: "Телепортация q0 → q2: фиделити 1, когерентные коррекции (отложенное измерение)" },
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum bloch <alpha> [beta]", short: "Сфера Блоха с ASCII-диаграммой; амплитуды — выражения calc (1/sqrt(2), i…)" },
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum verify unitary|equiv|teleport", short: "Формальная верификация: U†U = I, эквивалентность — точно в ℤ[1/√2, i]; --noise — шум поверх вердикта" },
        HelpEntry { group: HelpGroup::Quantum, cmd: "quantum calc <физика>", short: "Мост в цикл O: schrodinger, pauli_x/y/z, kron, expm, eigen" },

        // v0.53.0 (цикл R): P³-Мост — живое соединение с Zig-движком
        HelpEntry { group: HelpGroup::P3, cmd: "p3 info", short: "Библиотека P³: путь, тег ядра Zig, ABI-рукопожатие" },
        HelpEntry { group: HelpGroup::P3, cmd: "p3 conformance [--pairs N --json]", short: "Конформанс Rust ↔ Zig: d_FS, U†U=I, det, идемпотенты P²=P" },
        HelpEntry { group: HelpGroup::P3, cmd: "p3 frame [opts]", short: "Кадр из гамильтониана: Изинг → expm → P³ рендер → 3 PNG (rgb/depth/seg)" },
        HelpEntry { group: HelpGroup::Game, cmd: "game info", short: "Статус ядра: демо-сцена, физика, детерминизм" },
        HelpEntry { group: HelpGroup::Game, cmd: "game demo [opts]", short: "Демо-сцена «Этерия»: тики → P³ рендер → 3 PNG" },
        HelpEntry { group: HelpGroup::Game, cmd: "game scene <json> [opts]", short: "Своя сцена: тела, иерархия, орбиты, камера" },
        HelpEntry { group: HelpGroup::Game, cmd: "game write-demo <json>", short: "Выгрузить демо-сцену как редактируемый JSON" },

        // v0.47.0: середа для ІІ-агентів (Antigravity)
        HelpEntry { group: HelpGroup::Agent, cmd: "sysinfo | systeminfo", short: "Карта середовища: CPU/RAM/GPU/диск/тулчейни/локаль/TTY — звіт для агента" },
        HelpEntry { group: HelpGroup::Agent, cmd: "env [PREFIX]", short: "Знімок змінних сесії (токени маскуються)" },
        HelpEntry { group: HelpGroup::Agent, cmd: "set NAME=VALUE", short: "Змінна сесії (Windows-стиль); set NAME — показати" },
        HelpEntry { group: HelpGroup::Agent, cmd: "pty <command>", short: "PTY-міст: запуск інтерактивних утиліт (top, gdb) через pseudo-tty" },
        HelpEntry { group: HelpGroup::Agent, cmd: "agent", short: "Статус і поради агенту: --exec, --json, MCP, таймінги" },
        HelpEntry { group: HelpGroup::Agent, cmd: "--exec '<cmd>' [--json]", short: "CLI: одноразове виконання без банера; --json — машиночитаний конверт" },

        // v0.47.0: POLER Reader — приложение живого голоса
        HelpEntry { group: HelpGroup::Agent, cmd: "read <книга> [--out x.wav] [--voice V] [--seed N]", short: "ЖИВОЙ ГОЛОС книги: роторный резонатор + коартикуляция (txt/md/fb2/poler-book)" },

        HelpEntry { group: HelpGroup::Meta, cmd: "version | v", short: "Версія poler-engine + poler-shell" },
        HelpEntry { group: HelpGroup::Meta, cmd: "quit | exit | q", short: "Вийти з шелу" },
        HelpEntry { group: HelpGroup::Meta, cmd: "help | ?", short: "Ця справка" },
        HelpEntry { group: HelpGroup::Meta, cmd: "? (palette)", short: "Інтерактивна палітра 10 сценаріїв" },
    ]
}

/// Общая справка (без аргументов): список всех команд по группам.
pub fn help_overview() -> String {
    let mut s = String::new();
    let entries = all_entries();
    let groups = [
        HelpGroup::Search,
        HelpGroup::Crawl,
        HelpGroup::Impact,
        HelpGroup::Vcs,
        HelpGroup::Gix,
        HelpGroup::Sync,
        HelpGroup::Set,
        HelpGroup::Notes,
        HelpGroup::Sources,
        HelpGroup::System,
        HelpGroup::Agent,
        HelpGroup::Meta,
    ];
    let _ = writeln!(s, "poler-shell v2.0 — sovereign stack: без Google/NotebookLM, локальный поиск без лимитов");
    let _ = writeln!(s, "Доступні команди ({}):\n", entries.len());
    for g in groups {
        let g_entries: Vec<&HelpEntry> = entries.iter().filter(|e| e.group == g).collect();
        if g_entries.is_empty() {
            continue;
        }
        let _ = writeln!(s, "[ {} ]", g.as_str());
        for e in g_entries {
            let _ = writeln!(s, "  {:<46} — {}", e.cmd, e.short);
        }
        s.push('\n');
    }
    s.push_str("Керування TUI:\n");
    s.push_str("  Tab/BackTab — зміна фокусу між панелями\n");
    s.push_str("  ↑/↓ — навігація у списках / історія у вводі\n");
    s.push_str("  PgUp/PgDn — прокрутка Chat panel\n");
    s.push_str("  Enter — виконати команду\n");
    s.push_str("  клік/Enter на джерелі (Sources) — список документів джерела (Doc Browser)\n");
    s.push_str("  клік/Enter на документі — вікно з документом у тому ж терміналі (Doc Viewer)\n");
    s.push_str("  o — відкрити джерело/документ зовні ($EDITOR / браузер)\n");
    s.push_str("  Ctrl+N — нова замітка (вбудований редактор)\n");
    s.push_str("  Ctrl+E — редагувати вибрану замітку\n");
    s.push_str("  F3 — Transcript: лента локальної історії питань\n");
    s.push_str("       переживають перезапуски; Enter — повна відповідь, y — копіювати)\n");
    s.push_str("  Ctrl+Y — копіювати виділення мишею в буфер (OSC 52 + системний)\n");
    s.push_str("  Ctrl+Shift+V / Ctrl+V — вставка з буфера (bracketed paste)\n");
    s.push_str("  ? — палітра сценаріїв\n");
    s.push_str("  Esc / Ctrl+C — вихід\n");
    s.push('\n');
    s.push_str("Деталі: `help <topic>` (напр., `help sources add`, `help gix clone`)\n");
    s
}

/// Детальная справка по одной команде/группе.
pub fn help_topic(name: &str) -> String {
    let entries = all_entries();
    let name_lower = name.trim().to_lowercase();
    // 1) Точное совпадение по полному cmd (например `?` или полный текст)
    for e in &entries {
        if e.cmd.to_lowercase() == name_lower {
            return format_entry_detail(e);
        }
    }
    // 2) Совпадение по группе (single-word name, например `gh`, `notes`)
    //    Если name — это одна "команда-родитель" (gh/gl/gt/gix/sources/notes/...),
    //    покажем все её подкоманды.
    let parent_cmds = [
        "search", "web", "stats", "sync", "set", "crawl", "impact",
        "gh", "gl", "gt", "gix", "notes", "sources", "version", "quit", "help",
        "calc", "hw", "quantum", "qm", "p3", "game",
    ];
    if parent_cmds.contains(&name_lower.as_str()) {
        let matching: Vec<&HelpEntry> = entries
            .iter()
            .filter(|e| e.cmd.split_whitespace().next() == Some(name_lower.as_str()))
            .collect();
        if !matching.is_empty() {
            // Если ровно одна команда в группе → её детальный вид
            if matching.len() == 1 {
                return format_entry_detail(matching[0]);
            }
            // Иначе — групповой вид
            let g = matching[0].group;
            return format_group_detail(g, &entries);
        }
    }
    // 3) Совпадение по группе как строка
    for g in [
        HelpGroup::Search,
        HelpGroup::Crawl,
        HelpGroup::Impact,
        HelpGroup::Vcs,
        HelpGroup::Gix,
        HelpGroup::Sync,
        HelpGroup::Set,
        HelpGroup::Notes,
        HelpGroup::Sources,
        HelpGroup::Meta,
        HelpGroup::Calc,
    ] {
        if name_lower == g.as_str().to_lowercase()
            || name_lower
                == g
                    .as_str()
                    .split(|c: char| c == '/' || c == ' ')
                    .next()
                    .unwrap_or("")
                    .to_lowercase()
        {
            return format_group_detail(g, &entries);
        }
    }
    // 4) "sources add", "gix clone" и т.п. — частичное совпадение по prefix
    for e in &entries {
        if e.cmd.starts_with(&name_lower) {
            return format_entry_detail(e);
        }
    }
    // 5) v0.48.0: развёрнутая тема калькулятора — полный каталог возможностей
    if name_lower == "calc" || name_lower == "калькулятор" || name_lower == "=" {
        return calc_help_topic();
    }
    if name_lower == "hw" || name_lower == "hardware" {
        return format!(
            "─── {} — hw [—json] ───\n\n{}\n\nСкрытые от глаз параметры ПК: кеши L1d/L1i/L2/L3 \
по индексам sysfs, ISA-флаги (AVX/AVX2/AVX-512/AES…), топология сокетов/ядер/потоков, \
NUMA-узлы, bogomips, размеры страниц, диски (HDD/SSD), GPU (nvidia-smi или PCI IDs sysfs), \
гипервизор.\n\nПримеры:\n  poler> hw\n  poler> hw --json\n  poler-engine --exec \"hw --json\" --json\n",
            HelpGroup::Calc.as_str(),
            "Зонд железа: то, что не видно в htop"
        );
    }
    // v0.51.0: развёрнутая тема квантового моста
    if name_lower == "quantum" || name_lower == "qm" || name_lower == "квант" {
        return quantum_help_topic();
    }
    // v0.53.0: развёрнутая тема P³-Моста
    if name_lower == "p3" || name_lower == "мост" || name_lower == "проектив" {
        return p3_help_topic();
    }
    // v0.54.0: развёрнутая тема Ядра Игры
    if name_lower == "game" || name_lower == "игра" || name_lower == "движок" {
        return game_help_topic();
    }
    format!("тема не знайдена: {name} (введіть `help` для повного списку)")
}

/// v0.52.0 (цикл Q): полная справка квантового моста.
fn quantum_help_topic() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "─── Квантовый мост (v0.52.0, циклы P+Q) ───");
    let _ = writeln!(s);
    let _ = writeln!(s, "pqc встроен в шелл движка: идеальные кубиты без декогеренции.");
    let _ = writeln!(s, "Три входа: poler> quantum … · алиас qm · --exec \"quantum …\" --json");
    let _ = writeln!(s, "MCP-инструмент: poler_quantum (действия run/qcasm/qaoa/teleport/bloch/verify/list).");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Схемы (quantum run) ──");
    let _ = writeln!(s, "  quantum run bell                       пара Белла (|00⟩+|11⟩)/√2");
    let _ = writeln!(s, "  quantum run ghz --n 5 --shots 512      GHZ: только |00000⟩ и |11111⟩");
    let _ = writeln!(s, "  quantum run qft --n 4                  преобразование Фурье");
    let _ = writeln!(s, "  quantum run grover --n 6 --marks 22    поиск: пики на помеченных");
    let _ = writeln!(s, "  quantum run bv --secret 0b1011         Бернштейн–Вазирани");
    let _ = writeln!(s, "  quantum run period --n 6 --period 5    ядро Шора (поиск периода)");
    let _ = writeln!(s, "  … --json                               отчёт для ИИ-агента");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Произвольные схемы QCASM (цикл Q) ──");
    let _ = writeln!(s, "  quantum qcasm scheme.qc --shots 512    любая схема из файла (- = stdin)");
    let _ = writeln!(s, "  quantum qcasm scheme.qc --exact        точно в ℤ[1/√2, i] (Clifford+T)");
    let _ = writeln!(s, "  quantum qcasm scheme.qc --noise ibm-heron   шум железа поверх идеала");
    let _ = writeln!(s, "  инструкции: qubits N, h/x/y/z/s/t…, cx/cz/swap/ccx/cp, ry/rx/rz,");
    let _ = writeln!(s, "  flipphase/flipzero/prep, measure; комментарии #");
    let _ = writeln!(s);
    let _ = writeln!(s, "── QAOA: MaxCut-оптимизация (цикл Q) ──");
    let _ = writeln!(s, "  quantum qaoa --edges 0-1,1-2,0-2 --p 2  анзац + координатный спуск");
    let _ = writeln!(s, "  отчёт: E[cut], лучший битстринг, аппроксимационное отношение");
    let _ = writeln!(s, "  пресеты железа: ideal | ibm-heron | google-willow | noisy-90s");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Телепортация (цикл P) ──");
    let _ = writeln!(s, "  quantum teleport --theta 0.7           препарат Ry(0.7)|0⟩, фиделити = 1");
    let _ = writeln!(s, "  quantum teleport --exact               точно в ℤ[1/√2, i]: структурное равенство");
    let _ = writeln!(s, "  канал: 6 Клиффорд-вентилей, когерентные коррекции — классический");
    let _ = writeln!(s, "  канал связи не нужен (принцип отложенного измерения)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Сфера Блоха ──");
    let _ = writeln!(s, "  quantum bloch 1/sqrt(2) 1/sqrt(2)      |+⟩: x = +1, экватор");
    let _ = writeln!(s, "  quantum state 0.6 0.8i                 P(|0⟩), P(|1⟩), фаза, вектор");
    let _ = writeln!(s, "  амплитуды — любые выражения calc (константы, i, sqrt…)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Формальная верификация (SMT-стиль) ──");
    let _ = writeln!(s, "  quantum verify unitary qft --n 3        U†U = I — ДОКАЗАНО ТОЧНО");
    let _ = writeln!(s, "  quantum verify equiv qft iqft --n 3    две схемы (до фазы: --phase)");
    let _ = writeln!(s, "  quantum verify teleport                 канал на базисе {{|0⟩,|1⟩}}");
    let _ = writeln!(s, "  quantum verify unitary qft --n 3 --noise ibm-heron --shots 4096");
    let _ = writeln!(s, "                                         вердикт + шум железа: TVD, χ², пик");
    let _ = writeln!(s, "  вердикты: ДОКАЗАНО ТОЧНО (кольцо) / ЧИСЛЕННО / ВЕРОЯТНОСТНО /");
    let _ = writeln!(s, "  ОПРОВЕРГНУТО (контрпример найден)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Мост в физику цикла O ──");
    let _ = writeln!(s, "  quantum calc schrodinger(pauli_y(), [1; 0], pi/2)   спин-флип");
    let _ = writeln!(s, "  quantum calc eigen(tridiag(289, -144.5, 16))        квантовая яма");
    let _ = writeln!(s, "  quantum calc exp(i * pi)                             = -1.0");
    s
}

/// v0.48.0: полная справка «Калькулятора Всего» с примерами.
fn calc_help_topic() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "─── Калькулятор Всего (v0.48.0) ───");
    let _ = writeln!(s);
    let _ = writeln!(s, "Три входа: poler> calc <expr> · префикс = <expr> · --exec \"calc …\" --json");
    let _ = writeln!(s, "В TUI: клавиша = в Normal-режиме открывает виджет с живым preview.");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Арифметика и алгебра ──");
    let _ = writeln!(s, "  calc (1538 * 485) / 1024        = 728.447265625");
    let _ = writeln!(s, "  calc 2^3^2                      = 512 (правоассоц.), -2^2 = -4, 5! = 120");
    let _ = writeln!(s, "  calc 0.5!                       = 0.8862… (Γ(1.5) = √π/2)");
    let _ = writeln!(s, "  calc x = 5; calc x^2 + 1        переменные; ans — последний результат");
    let _ = writeln!(s, "  calc solve x^2 - 4 = 0          x ∈ 2.0, -2.0 (Дюран–Кернер)");
    let _ = writeln!(s, "  calc solve x^2 + 1 = 0          комплексные: x ∈ i, -i");
    let _ = writeln!(s, "  calc solve sin(x) = 0.5         численно: Ньютон + бисекция (±100)");
    let _ = writeln!(s, "  calc gcd(1071, 462) | next_prime(1e6) | factorize(360) | fib(70)");
    let _ = writeln!(s, "  calc binomial(52, 5)            = 2598960 (покерные руки)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Единицы измерения (to) ──");
    let _ = writeln!(s, "  calc 5 km + 300 m               = 5.3 km (размерности строго)");
    let _ = writeln!(s, "  calc 100 km/h to m/s            = 27.777…");
    let _ = writeln!(s, "  calc degC(100) to degF          = 212.0 (аффинные температуры)");
    let _ = writeln!(s, "  calc asin(0.5) to deg           = 30.0 (радианы по умолчанию)");
    let _ = writeln!(s, "  calc c to km/h                  = 1.079…e9 (c — и константа, и единица)");
    let _ = writeln!(s, "  calc 1 TiB to byte              = 1099511627776.0 (IEC префиксы)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Специальная математика ──");
    let _ = writeln!(s, "  calc gamma(0.5)                 = 1.7724… (√π), Ланцрош g=7");
    let _ = writeln!(s, "  calc erf(1)                     = 0.8427008 (A&S 7.1.26)");
    let _ = writeln!(s, "  calc zeta(2)                    = 1.6449… (π²/6, Эйлер–Маклорен)");
    let _ = writeln!(s, "  calc zeta(-1)                   = -0.08333… (−1/12)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── POLER Matrix Calc (квант) ──");
    let _ = writeln!(s, "  calc [1,2;3,4] * [5;6]          матрицы: det inv trace transpose");
    let _ = writeln!(s, "  calc expm([0,-1;1,0] * psi)     вращение Ли: expm(J·Ψ), Паде [6/6]");
    let _ = writeln!(s, "  calc eigen(rot2(pi/2))          = [i, -i] — чисто мнимые");
    let _ = writeln!(s, "  calc charpoly([1,2;3,4])        = [1, -5, -2] (Фаддеев–Леврерье)");
    let _ = writeln!(s, "  calc so_gen(3,0,2) * 1.0        генератор so(3); A^(-1) — обратная");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Цикл O: уравнение Шрёдингера (кремний вместо QPU) ──");
    let _ = writeln!(s, "  calc schrodinger(pauli_y(), [1; 0], pi/2)   спин-флип |↑⟩ → |↓⟩");
    let _ = writeln!(s, "  calc eigen(tridiag(289, -144.5, 16))        яма: уровни ≈ (πk)²/2");
    let _ = writeln!(s, "  calc exp(i * pi)                 тождество Эйлера = -1.0");
    let _ = writeln!(s, "  calc kron(hadamard(), eye(2))    тензорное произведение H⊗I");
    let _ = writeln!(s, "  calc dagger([0, -i; i, 0])       эрмитово сопряжение σ_y†");
    let _ = writeln!(s, "  calc pinv([1, 2; 2, 4])          Мур–Пенроуз (Гревилль)");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Триты POLER (сбалансированная троичная) ──");
    let _ = writeln!(s, "  calc trits(5)                   = \"1TT\"; trit_val(\"1TT\") = 5");
    let _ = writeln!(s, "  calc trit_and(\"1TT\", \"10T\")   вентили Клини: min/max/инверсия");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Астрономия (Шлhyter + NOAA; якоря — реальные затмения) ──");
    let _ = writeln!(s, "  calc moon_illum(2024,4,8,18.35) ≈ 0 (солнечное затмение 08.04.2024)");
    let _ = writeln!(s, "  calc moon_phase(2025,3,14,6.9)  ≈ 180 (полнолуние-затмение)");
    let _ = writeln!(s, "  calc sun_lon(2024,3,20,3.1)     ≈ 0 (равноденствие)");
    let _ = writeln!(s, "  calc planet_lon(\"mars\",2024,6,1)  геоцентрическая долгота");
    let _ = writeln!(s, "  calc sunrise(50.45,30.52,2024,6,21)  восход в Киеве, часы UTC");
    let _ = writeln!(s, "  calc moon_dist(2024,1,1,12)     расстояние до Луны, км");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Геодезия и навигация ──");
    let _ = writeln!(s, "  calc dist(50.45,30.52,49.84,24.03)   Киев—Львов, км (большой круг)");
    let _ = writeln!(s, "  calc bearing(50.45,30.52,49.84,24.03) азимут, град");
    let _ = writeln!(s, "  calc dest(50.45,30.52,45,500)   точка в 500 км на северо-восток");
    let _ = writeln!(s, "  calc earth_radius(55.75)        радиус кривизны WGS84, км");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Генератор скриптов по законам ──");
    let _ = writeln!(s, "  calc laws                      19+ законов: Кеплер, Циолковский, Шварцшильд…");
    let _ = writeln!(s, "  calc script kepler3             готовая команда calc + .poler-правило");
    let _ = writeln!(s, "  calc script emc2 m=2 kg         со своими значениями");
    let _ = writeln!(s);
    let _ = writeln!(s, "── Каталоги ──");
    let _ = writeln!(s, "  calc constants [фильтр]         CODATA 2022 / IAU / СИ-2019 (с источниками)");
    let _ = writeln!(s, "  calc units | calc funcs         единицы и функции");
    let _ = writeln!(s, "  calc vars | calc hist           переменные и история");
    let _ = writeln!(s, "  hw | hw --json                 скрытые параметры ПК");
    s
}

fn format_entry_detail(e: &HelpEntry) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "─── {} — {} ───\n", e.group.as_str(), e.cmd);
    let _ = writeln!(s, "{}\n", e.short);
    // Примеры для конкретных команд
    match e.cmd {
        "search \"<query>\" [--top N]" => {
            s.push_str("ПРИКЛАДИ:\n");
            s.push_str("  search \"Касіопея Astra-Nic\" --top 5\n");
            s.push_str("  search \"POLER cycle\"\n\n");
            s.push_str("ВИВІД:\n");
            s.push_str("  Гібридний пошук по веб+локал: PageRank + lexical + temporal.\n");
            s.push_str("  Текст можна виділити мишею → Ctrl+Y → буфер\n");
            s.push_str("  (OSC 52 — працює і через SSH/tmux). Вставка — Ctrl+Shift+V.\n");
        }
        "sources add <value> [--kind file|url|repo] [--label \"...\"]" => {
            s.push_str("ПРИКЛАДИ:\n");
            s.push_str("  sources add https://doc.rust-lang.org/std/\n");
            s.push_str("  sources add /home/z/my-project/poler-engine/src --label \"poler src\"\n");
            s.push_str("  sources add rust-lang/rust --kind repo\n\n");
            s.push_str("АВТО-ДЕТЕКТ kind:\n");
            s.push_str("  http:// | https://         → url\n");
            s.push_str("  owner/repo (1 слеш, без шляху) → repo\n");
            s.push_str("  інше                       → file\n");
        }
        "notes add <title>" => {
            s.push_str("ПРИКЛАД:\n");
            s.push_str("  notes add \"Ідея архітектури v0.18\"\n");
            s.push_str("  → Відкриється TUI редактор для вводу тіла\n");
            s.push_str("  → Ctrl+S зберегти, Esc скасувати\n\n");
            s.push_str("Альтернатива: Ctrl+N прямо з TUI — те саме без команди.\n");
        }
        "gix clone <URL> <PATH> [--depth N] [--branch B]" => {
            s.push_str("ПРИКЛАДИ:\n");
            s.push_str("  gix clone https://github.com/rust-lang/rust ./rust\n");
            s.push_str("  gix clone https://github.com/user/repo ./r --depth 1   # shallow\n");
            s.push_str("  gix clone https://github.com/user/repo ./r --branch dev\n\n");
            s.push_str("ВАЖЛИВО:\n");
            s.push_str("  • Pure-Rust clone через gix::clone::PrepareFetch (без системного git).\n");
            s.push_str("  • PATH має бути порожнім каталогом (gix вимагає destination_must_be_empty).\n");
            s.push_str("  • Для приватних репо: встановіть POLER_GIT_TOKEN або ~/.git-credentials.\n");
            s.push_str("  • LFS-об'єкти НЕ завантажуються автоматично — використовуйте `gix lfs fetch <PATH>`.\n");
            s.push_str("  • Після clone: `gix log <PATH>` покаже коміти, `gix lfs list <PATH>` — LFS-файли.\n");
        }
        "gix lfs list <PATH>" => {
            s.push_str("ПРИКЛАД:\n");
            s.push_str("  gix lfs list ./my-repo\n\n");
            s.push_str("ВАЖЛИВО:\n");
            s.push_str("  • Обходить worktree (не .git/, не hidden-файли).\n");
            s.push_str("  • Шукає файли, що починаються з `version https://git-lfs.github.com/spec/v1`.\n");
            s.push_str("  • Виводить: шлях + oid sha256 (первые 12 хеша) + розмір у байтах.\n");
        }
        "gix lfs fetch <PATH>" => {
            s.push_str("ПРИКЛАД:\n");
            s.push_str("  gix lfs fetch ./my-repo\n\n");
            s.push_str("ЯК ПРАЦЮЄ:\n");
            s.push_str("  1. detect_pointers знаходить усі LFS pointer-файли у worktree.\n");
            s.push_str("  2. Визначає LFS-server URL з .git/config (remote.origin.url + /info/lfs).\n");
            s.push_str("  3. POST /objects/batch з JSON-тілом {operation: download, objects: [...]}\n");
            s.push_str("  4. Для кожного об'єкту завантажує blob у .git/lfs/objects/<oid[:2]>/<oid[2:]>/.\n");
            s.push_str("  5. Звіт: ✓/✗ на кожен об'єкт + підсумок кількості та байтів.\n\n");
            s.push_str("АВТОРИЗАЦІЯ:\n");
            s.push_str("  • Публічні репо: нічого не потрібно.\n");
            s.push_str("  • Приватні: POLER_GIT_TOKEN=<github_pat> передає як Bearer.\n");
            s.push_str("  • Альтернатива: ~/.git-credentials + GIT_TERMINAL_PROMPT=false.\n");
        }
        "? (palette)" => {
            s.push_str("Інтерактивна палітра сценаріїв:\n");
            for (i, sc) in palette_scenarios().iter().enumerate() {
                s.push_str(&format!("  {}. {}\n", i + 1, sc.title));
            }
            s.push_str("\nENTER — виконати, Esc — закрити, ↑↓/миша — вибір.\n");
        }
        _ => {}
    }
    s
}

fn format_group_detail(g: HelpGroup, entries: &[HelpEntry]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "─── {} ───\n", g.as_str());
    let g_entries: Vec<&HelpEntry> = entries.iter().filter(|e| e.group == g).collect();
    for e in g_entries {
        let _ = writeln!(s, "  {:<46} — {}", e.cmd, e.short);
    }
    s
}

/// Готовый сценарий для `?` palette.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub title: &'static str,
    pub cmd: &'static str,
    pub help: &'static str,
}

/// Готовые сценарии для `?` palette (v2.0: без NLM).
pub fn palette_scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            title: "1. Пошук по corpus: \"POLER cycle\"",
            cmd: "search \"POLER cycle\" --top 10",
            help: "Гібридний пошук по веб+локал: PageRank + lexical + temporal.",
        },
        Scenario {
            title: "2. Статистика web-index.db",
            cmd: "stats",
            help: "JSON: pages, terms, postings, links, db_bytes, duplicates.",
        },
        Scenario {
            title: "3. AIDDE impact-аналіз символу",
            cmd: "impact ./src run",
            help: "Impact-паспорт символу: call graph + upstream/downstream.",
        },
        Scenario {
            title: "4. Останні коміти GitHub: rust-lang/rust",
            cmd: "gh commits rust-lang/rust",
            help: "Покаже 20 останніх комітів (потрібен $GITHUB_TOKEN в .env).",
        },
        Scenario {
            title: "5. Пошук коду по GitHub: \"PageRank\"",
            cmd: "gh search PageRank --top 20",
            help: "Знайде 20 кодових хітів по всьому GitHub. Метадані: file, repo, score.",
        },
        Scenario {
            title: "6. gix log локального репо poler-engine",
            cmd: "gix log /home/z/my-project/poler-engine --top 10",
            help: "Pure-Rust gix: git log без зовнішнього git. Топ-10 коммітів.",
        },
        Scenario {
            title: "7. Створити нову замітку",
            cmd: "notes add \"Нова ідея\"",
            help: "Відкриє вбудований TUI редактор (tui-textarea). Ctrl+S зберегти.",
        },
        Scenario {
            title: "8. Додати джерело: посилання на Rust docs",
            cmd: "sources add https://doc.rust-lang.org/std/ --label \"Rust std\"",
            help: "Авто-детект url; з'явиться в правій панелі Sources TUI.",
        },
        Scenario {
            title: "9. Pure-Rust git clone + LFS",
            cmd: "gix clone https://github.com/user/large-repo ./lr",
            help: "Без системного git! Shallow + branch: --depth 1 --branch main. Потім: gix lfs fetch ./lr.",
        },
        Scenario {
            title: "10. Синк VCS → web-index.db",
            cmd: "sync vcs gh",
            help: "Індексує коміти/issues відслідковуваних GitHub-репо у web-index.",
        },
    ]
}

/// v0.53.0 (цикл R): полная справка P³-Моста.
fn p3_help_topic() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "─── P³-Мост: POLER ENGINE (Rust) ↔ P³ ENGINE (Zig) ───");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Живое соединение ядра и движка через C-ABI (libp3ffi.so). Ядро P³\n(проективная геометрия: метрика Фубини–Штуди, PGL(4), идемпотенты)\nсобрано Zig 0.14.0 в разделяемую библиотеку; POLER вызывает её\nнапрямую и сверяет со своей Rust-реализацией той же математики."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Команды:");
    let _ = writeln!(s, "  p3 info                    — библиотека, тег ядра, ABI-рукопожатие");
    let _ = writeln!(s, "  p3 conformance [--pairs N] — конформанс Rust ↔ Zig (--json — машиночитаемо):");
    let _ = writeln!(s, "    d_FS(a,b), гомогенность λ·μ, U†U = I (Гивенс), (A·B)v = A(Bv),");
    let _ = writeln!(s, "    det(PGL4), идемпотенты P² = P (спектральные проекторы)");
    let _ = writeln!(s, "  p3 frame [opts]            — «кадр из гамильтониана» (первый публичный");
    let _ = writeln!(s, "    артефакт «изображение, просчитанное математически»):");
    let _ = writeln!(s, "    цепочка Изинга −J·ΣZᵢZᵢ₊₁ − h·ΣXᵢ → эволюция expm → worldlines ⟨Zᵢ⟩(t)");
    let _ = writeln!(s, "    + облако |⟨b|Ψ⟩|² → P³ рендер в тройной буфер (RGB+depth+seg) → 3 PNG");
    let _ = writeln!(s, "    opts: --n K(2..8) --steps T --size WxH --out DIR --jz J --hx H --cloud M");
    let _ = writeln!(s);
    let _ = writeln!(s, "Поиск библиотеки: $P3_FFI_LIB → ffi/ рядом с бинарником →");
    let _ = writeln!(s, "ffi/ репозитория (коммитится) → P3_Engine/zig-out/lib.");
    let _ = writeln!(s, "Пересборка: ffi/build.sh (Zig 0.14.0, ReleaseFast).");
    let _ = writeln!(s);
    let _ = writeln!(s, "Примеры:");
    let _ = writeln!(s, "  poler> p3 conformance --pairs 256");
    let _ = writeln!(s, "  poler> p3 frame --n 6 --steps 64 --size 960x540 --out ./demo");
    let _ = writeln!(s, "  poler-engine --exec \"p3 frame --json\" --json");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_entries_nonempty() {
        let e = all_entries();
        assert!(!e.is_empty());
        assert!(!e.iter().any(|x| x.cmd.starts_with("nlm")), "v2.0: nlm удалён");
        assert!(e.iter().any(|x| x.cmd.starts_with("gh")));
        assert!(e.iter().any(|x| x.cmd.starts_with("notes")));
        assert!(e.iter().any(|x| x.cmd.starts_with("sources")));
    }

    #[test]
    fn overview_lists_every_group() {
        let s = help_overview();
        for g in [
            HelpGroup::Search,
            HelpGroup::Crawl,
            HelpGroup::Impact,
            HelpGroup::Vcs,
            HelpGroup::Gix,
            HelpGroup::Sync,
            HelpGroup::Set,
            HelpGroup::Notes,
            HelpGroup::Sources,
            HelpGroup::Meta,
        ] {
            assert!(s.contains(g.as_str()), "overview must contain group {:?}", g);
        }
    }

    #[test]
    fn topic_search_has_examples() {
        let s = help_topic("search");
        assert!(s.contains("ПРИКЛАДИ"));
        assert!(s.contains("POLER cycle"));
        assert!(s.contains("Ctrl+Y"));
    }

    #[test]
    fn topic_sources_add_has_detect_rules() {
        let s = help_topic("sources add");
        assert!(s.contains("АВТО-ДЕТЕКТ"));
        assert!(s.contains("rust-lang/rust"));
    }

    #[test]
    fn topic_notes_add_mentions_editor() {
        let s = help_topic("notes add");
        assert!(s.contains("TUI редактор"));
        assert!(s.contains("Ctrl+S"));
    }

    #[test]
    fn palette_has_10_scenarios() {
        let v = palette_scenarios();
        assert_eq!(v.len(), 10);
        for sc in &v {
            assert!(!sc.title.is_empty());
            assert!(!sc.cmd.is_empty());
            assert!(!sc.cmd.starts_with("nlm"), "v2.0: nlm удалён");
        }
    }

    #[test]
    fn palette_topic_lists_all() {
        let s = help_topic("?");
        for sc in palette_scenarios() {
            assert!(s.contains(sc.title), "missing {}", sc.title);
        }
    }

    #[test]
    fn topic_unknown_returns_help_message() {
        let s = help_topic("totally-unknown-xyz");
        assert!(s.contains("не знайдена"));
    }

    #[test]
    fn topic_nlm_is_gone_in_v2() {
        let s = help_topic("nlm");
        assert!(s.contains("не знайдена"), "v2.0: темы nlm больше нет: {s}");
    }
}

/// v0.54.0 (цикл S): полная справка Ядра Игры.
fn game_help_topic() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "─── Ядро Игры: POLER как игровой движок (v0.61.0) ───");
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Фундамент игрового движка, построенный на разборе недостатков\nUE/Unity/Godot (docs/GAME_ENGINE_ROADMAP_UE_ANALYSIS.md): сущности\nс поколениями вместо GC/UObject, фиксированный тик вместо плавающего\nвремени, кеплеровская физика вместо подобранных скоростей, рендер\nчерез P³-мост с честной глубиной d_FS, звук из физики мира (T1),\nтекстуры-функции со спектральным сжатием (T2), события/ввод/окно (U)."
    );
    let _ = writeln!(s);
    let _ = writeln!(s, "Команды:");
    let _ = writeln!(s, "  game info                  — статус ядра: демо-сцена, физика, state-hash");
    let _ = writeln!(s, "  game demo [opts]           — прогнать «Этерию» и отрендерить кадр:");
    let _ = writeln!(s, "    opts: --ticks N(1..100000) --size WxH --out DIR --no-orbits");
    let _ = writeln!(s, "    --no-box --json");
    let _ = writeln!(s, "  game scene <file.json>     — своя сцена (JSON; формат — write-demo):");
    let _ = writeln!(s, "    тела (id/class/mass/radius), иерархия parent, орбиты");
    let _ = writeln!(s, "    (orbit_radius/inclination → ω=√(GM)/r^1.5), камера, цвета");
    let _ = writeln!(s, "  game write-demo <file>     — выгрузить демо-сцену как редактируемый JSON");
    let _ = writeln!(s, "  game sound [opts]          — озвучить мир (T1): ω→высота, X→панорама → WAV");
    let _ = writeln!(s, "  game texture [opts]        — процедурная текстура (T2): тайл-функция → PNG");
    let _ = writeln!(s, "    + SVD rank-k кодек (--svd-rank K --rank-curve)");
    let _ = writeln!(s, "  game normalmap [opts]      — normal map из той же функции шума (U0):");
    let _ = writeln!(s, "    --amplitude A(0..1.5) — глубина рельефа в долях тайла");
    let _ = writeln!(s, "  game input-demo [opts]     — ввод→камера→кадры без окна (U1–U4):");
    let _ = writeln!(s, "    скрипт JSON (--script) или встроенный демо-сценарий;");
    let _ = writeln!(s, "    каждый кадр: события → Input → орбит-камера → P³-кадр;");
    let _ = writeln!(s, "    frames_hash — детерминизм всей цепочки бит-в-бит");
    let _ = writeln!(s, "  game window [opts]         — НАСТОЯЩЕЕ X11-окно (dlopen, zero-dep):");
    let _ = writeln!(s, "    ЛКМ+движение — орбита · колесо — зум · WASD/QE · нужен DISPLAY");
    let _ = writeln!(s, "  game asset absorb|emit   — Y «Эхо»: готовое → нейроны → PQW → с нуля:");
    let _ = writeln!(s, "    absorb --in F.(wav|png|pgm|ppm) --out F.pqw");
    let _ = writeln!(s, "    emit --in F.pqw --out F.(wav|png) [--seconds|--width|--height|");
    let _ = writeln!(s, "         --seed|--burst|--compare] — SSN-вихрь даёт тайминг,");
    let _ = writeln!(s, "    синапты — связность; PSD/PSNR/гистограммы — честно");
    let _ = writeln!(s, "  game vortex [opts]        — вихревой кодек «Шеннон-байпас» (V0):");
    let _ = writeln!(s, "    шум = когерентные фазовые вихри (Навье–Стокс, K41): 2D-FFT →");
    let _ = writeln!(s, "    топ-моды → GF(3)-триты (5 трит/байт, 3^5=243≤256) → VRTX;");
    let _ = writeln!(s, "    зачёт против zstd-19 и предела Шеннона, PSNR, хеши");
    let _ = writeln!(s, "  game water [opts]         — нелинейная гидродинамика (X):");
    let _ = writeln!(s, "    море = спектр волн (K41 + дисперсия √(gk+γk³)); эволюция —");
    let _ = writeln!(s, "    целочисленные триты (фикс-точка, без f32-дрейфа); цикл X:");
    let _ = writeln!(s, "    Стокс h₂=(kA²/2)cos2θ + сдвиг частоты, снос гребней (Мичелл),");
    let _ = writeln!(s, "    белые барашки (Бофорт), вихри Ламб–Озеена (ротационное поле);");
    let _ = writeln!(s, "    флаги: --linear (выключить нелинейность), --steepness S;");
    let _ = writeln!(s, "    PSNR против f64-эталона, кадры PNG + шейдинг + VRTX");
    let _ = writeln!(s, "  game panda — мост к Panda3D (W): вода POLER в чужом рендере;");
    let _ = writeln!(s, "    panda-bridge/ (Python): demo_ocean.py — океан с оптикой GLSL");
    let _ = writeln!(s, "    (Френель/пена/блик/Беер–Ламберт); libpoler_ffi.so — C-ABI:");
    let _ = writeln!(s, "    polerf_water_* (тик+FFT+нормали одним вызовом); selftest.py");
    let _ = writeln!(s);
    let _ = writeln!(s, "Честность ядра:");
    let _ = writeln!(s, "  детерминизм: state/audio/crystal/texture/frames/vortex/water-hash бит-в-бит");
    let _ = writeln!(s, "  (одинаковая история → одинаковый мир: replay и lockstep бесплатны);");
    let _ = writeln!(s, "  физика: угловые скорости выводятся из масс (третий закон Кеплера);");
    let _ = writeln!(s, "  рендер: тройной буфер RGB + depth (d_FS) + seg (ID объектов);");
    let _ = writeln!(s, "  ввод: события коалесцируются (MouseMove — суммированием),");
    let _ = writeln!(s, "  рёбра just_pressed живут ровно один кадр, replay = хеш ввода.");
    let _ = writeln!(s);
    let _ = writeln!(s, "Примеры:");
    let _ = writeln!(s, "  poler> game demo --ticks 900 --size 960x540 --out ./demo");
    let _ = writeln!(s, "  poler> game sound --ticks 900 --out eteryya.wav");
    let _ = writeln!(s, "  poler> game normalmap --style marble --amplitude 0.1");
    let _ = writeln!(s, "  poler> game input-demo --frames 300 --every 30 --json");
    let _ = writeln!(s, "  poler> game vortex --style all --size 256 --out-dir ./vortex");
    let _ = writeln!(s, "  poler> game water --wind 20 --steps 900 --out-dir ./storm");
    let _ = writeln!(s, "  полигон Panda3D: pip install panda3d numpy &&");
    let _ = writeln!(s, "    python3 panda-bridge/demo_ocean.py 10 128");
    let _ = writeln!(s, "  poler-engine --exec \"game demo --json\" --json");
    s
}
