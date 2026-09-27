//! # poler-shell TUI — 4-pane Dashboard (v2.0 sovereign stack)
//!
//! Layout с поддержкой мыши, drag-select, встроенным редактором заметок
//! (tui-textarea) и палитрой `?` с готовыми сценариями.
//!
//! ```text
//! ┌──────────────────────────────┬──────────────┐
//! │ CHAT & RESPONSES  (50% h)    │ NOTES (CRUD) │
//! │ • Чистый ответ без мусора    │ • Ctrl+N     │
//! │ • Drag-select мышью → Ctrl+Y │ • Ctrl+E     │
//! ├──────────────────────────────┼──────────────┤
//! │ INPUT BOX (min 3)            │ SOURCES CRUD │
//! │ • ↑/↓ history • Enter — run  │ • list/add/rm│
//! ├──────────────────────────────┴──────────────┤
//! │ poler-shell <ver>  db:web-index.db  F3:лента│
//! └─────────────────────────────────────────────┘
//! ```
//!
//! v2.0: панель NotebookLM (REPO/NB) удалена вместе с Google/NLM;
//! layout — 2 колонки (chat+input | notes+sources).
//!
//! Управление:
//! - **Tab/BackTab** — смена фокуса между панелями
//! - **↑/↓** — навигация в списках / история ввода
//! - **PgUp/PgDn** — прокрутка Chat panel
//! - **Enter** — выполнить команду (Input) / открыть источник (Sources)
//! - **Ctrl+N** — новая заметка (встроенный tui-textarea редактор)
//! - **Ctrl+Y** — копировать текущее выделение в буфер
//! - **?** — палитра сценариев
//! - **Ctrl+E** — редактировать выделенную заметку
//! - **Ctrl+D** — удалить выделенную заметку/источник (с подтверждением)
//! - **Ctrl+T** — тестировать выбранный источник (Sources panel)
//! - **Esc / Ctrl+C** — выход
//!
//! ## Doc Browser: источник → документы → просмотр (клик/Enter на источнике)
//!
//! Клик или Enter на источнике в Sources panel открывает **список его
//! документов** (popup Doc Browser), клик на документе — **окно просмотра
//! в том же терминале** (popup Doc Viewer: ↑↓/PgUp/PgDn/колесо — скролл,
//! `o` — открыть внешне, Ctrl+Y — копировать, Esc — назад).
//!
//! | Источник | Документы внутри | Откуда контент |
//! |---|---|---|
//! | локальный `file`-каталог | файлы и подкаталоги («..» наверх) | `fs::read` |
//! | локальный `file`-файл | сам файл | `fs::read` (лимит 2 МБ, не бинарный) |
//! | локальный `url` | страница | `ureq` GET + html→text |
//! | локальный `repo` | инфо + ссылка | `o` — браузер, `gh repos` — REST |
//!
//! Внешний канал на клавише **`o`** в Sources panel (`$EDITOR` / `xdg-open`)
//! — логика `execute_enter_action` ниже. v2.0: локальная версия без
//! companion-моста (Google удалён).
//!
//! ## Внешний канал: клавиша `o`
//!
//! Источник из `poler_sources` (file/url/repo) превращается в
//! локальный `EnterAction`:
//!
//! | Источник | EnterAction |
//! |---|---|
//! | `file` (`/path/to/x.md`) | `EditLocal(path)` → `$EDITOR` |
//! | `url`  (`https://...`) | `OpenUrl(url)` → `xdg-open` |
//! | `repo` (`owner/name`) | `OpenUrl("https://github.com/{owner/name}")` → `xdg-open` |
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use tui_textarea::TextArea;

use super::commands::{dispatch, CmdResult};
use super::doc_browser::{self, DocEntry, DocKind, SourceRef, MAX_DIR_ENTRIES, MAX_DOC_BYTES};
use super::help;
use super::mouse::{self, MouseAction, SelectionRect};
use super::state::ShellState;
use super::transcript::{self, ChatEntry};

/// Запустить TUI-режим (`poler-engine --tui`).
pub fn run_tui(db_path: PathBuf) -> std::process::ExitCode {
    let mut state = ShellState::new(db_path.clone());

    // Подготовка терминала
    if let Err(e) = enable_raw_mode() {
        eprintln!("poler-shell --tui: raw mode: {e}");
        return std::process::ExitCode::from(2);
    }
    let mut stdout = io::stdout();
    let _ = execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    );
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            let _ = disable_raw_mode();
            eprintln!("poler-shell --tui: terminal: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    // Состояние TUI
    let mut input_buf = String::new();
    let mut input_history: Vec<String> = Vec::new();
    let mut input_history_idx: Option<usize> = None;
    let mut output_lines: Vec<String> = vec![
        "poler-shell TUI Dashboard — v2.0 sovereign stack (без Google/NotebookLM)".into(),
        "  ↑↓ — история ввода; Enter — выполнить; Tab — сменить фокус; Esc — выход".into(),
        "  Ctrl+N — новая заметка; ? — палитра; F3 — лента чата".into(),
        "  Drag мышью по Chat panel → Ctrl+Y → буфер (OSC 52 + системный)".into(),
        "  Вставка из буфера — Ctrl+Shift+V / Ctrl+V (bracketed paste)".into(),
        String::new(),
    ];
    let mut output_scroll: usize = usize::MAX; // row-offset для Paragraph::scroll; usize::MAX = прилипить к низу
    // Список заметок (правая верхняя)
    let mut notes_items: Vec<String> = vec!["(нет заметок — Ctrl+N)".into()];
    let mut notes_state = ListState::default();
    notes_state.select(Some(0));

    // Список источников (правая нижняя)
    let mut sources_items: Vec<String> = vec!["(нет источников — sources add)".into()];
    // Параллельный массив ссылок на локальные источники — по нему
    // клик/Enter открывает Doc Browser. Длина == sources_items только для
    // реальных строк; плейсхолдеры не имеют ссылок.
    let mut sources_refs: Vec<SourceRef> = Vec::new();
    let mut sources_state = ListState::default();
    sources_state.select(Some(0));

    let mut focus = Focus::Input;
    let mut should_quit = false;

    // Старт мгновенный: сеть не трогаем — только локальные заметки/источники.
    refresh_notes_list(&mut state, &mut notes_items);
    refresh_sources_list(&mut state, &mut sources_items, &mut sources_refs);

    // Drag-select
    let mut selection = SelectionRect::new();
    let mut last_click_time: Option<Instant> = None;
    let mut last_click_pos: Option<(u16, u16)> = None;

    // Режим: Normal / Palette / NoteEditor
    let mut mode: Mode = Mode::Normal;
    let mut palette_state = ListState::default();
    palette_state.select(Some(0));

    // Стартовый приветственный вывод
    state.set_output(help::help_overview());
    // Поместить help в output для немедленного отображения
    for l in help::help_overview().lines() {
        output_lines.push(l.to_string());
    }
    output_lines.push(String::new());
    // output_scroll уже usize::MAX (прилипить к низу) — нормализация в цикле

    // Главная петля событий
    while !should_quit {
        // Снапшот layout — нужен для hit-testing мыши
        let term_size = terminal.size().unwrap_or_default();
        let term_rect = Rect::new(0, 0, term_size.width, term_size.height);
        let layout_snapshot = compute_layout(term_rect);
        // Нормализация скролла: сентинел usize::MAX / перелимит → точный bottom-offset.
        // Wrap-оценка: строки длиннее ширины панели занимают >1 рендер-строки.
        {
            let inner_w = layout_snapshot.chat_area.width.saturating_sub(2).max(1) as usize;
            let inner_h = layout_snapshot.chat_area.height.saturating_sub(2).max(1) as usize;
            let bottom = chat_bottom_offset(&output_lines, inner_w, inner_h);
            if output_scroll == usize::MAX || output_scroll > bottom {
                output_scroll = bottom;
            }
        }
        let _ = terminal.draw(|f| {
            render_ui(
                f,
                &layout_snapshot,
                &input_buf,
                &output_lines,
                output_scroll,
                &notes_items,
                &notes_state,
                &sources_items,
                &sources_state,
                focus,
                &selection,
                &state,
                &mode,
                &palette_state,
            );
        });

        // События
        let ev = match event::read() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("poler-shell --tui: event: {e}");
                break;
            }
        };

        // Сначала режимные обработчики
        let new_mode = match &mut mode {
            Mode::NoteEditor(editor_state) => {
                match handle_note_editor_event(ev.clone(), editor_state) {
                    NoteEditorResult::Continue => continue,
                    NoteEditorResult::Save(title, body) => {
                        // Сохранить как новую локальную заметку
                        match state.ensure_notes_conn() {
                            Ok(conn) => {
                                match crate::notes::add_note(
                                    conn,
                                    &title,
                                    &body,
                                    &[],
                                    crate::notes::NoteSource::Manual,
                                    None,
                                ) {
                                    Ok(id) => {
                                        output_lines
                                            .push(format!("✓ Сохранена заметка #{id} «{title}»"));
                                        refresh_notes_list(&mut state, &mut notes_items);
                                    }
                                    Err(e) => output_lines.push(format!("❌ {e}")),
                                }
                            }
                            Err(e) => output_lines.push(format!("❌ {e}")),
                        }
                        output_scroll = usize::MAX; // прилипить к низу
                        Mode::Normal
                    }
                    NoteEditorResult::Cancel => Mode::Normal,
                }
            }
            Mode::Palette => {
                let mut keep_palette = true;
                if let Event::Key(k) = ev {
                    match (k.code, k.modifiers) {
                        (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            keep_palette = false;
                        }
                        (KeyCode::Up, _) => {
                            let i = palette_state.selected().unwrap_or(0);
                            palette_state.select(Some(i.saturating_sub(1)));
                        }
                        (KeyCode::Down, _) => {
                            let i = palette_state.selected().unwrap_or(0);
                            let max = help::palette_scenarios().len().saturating_sub(1);
                            palette_state.select(Some((i + 1).min(max)));
                        }
                        (KeyCode::Enter, _) => {
                            let sc =
                                &help::palette_scenarios()[palette_state.selected().unwrap_or(0)];
                            input_buf.clear();
                            input_buf.push_str(sc.cmd);
                            focus = Focus::Input;
                            keep_palette = false;
                        }
                        _ => {}
                    }
                }
                if let Event::Mouse(me) = ev {
                    if let MouseAction::DragEnd { col, row } = mouse::parse_event(me) {
                        if let Some(area) = layout_snapshot.palette_area() {
                            if mouse::hit(&area, col, row) {
                                let local_row = row.saturating_sub(area.y) as usize;
                                let scenarios = help::palette_scenarios();
                                if local_row < scenarios.len() {
                                    palette_state.select(Some(local_row));
                                }
                            }
                        }
                    }
                }
                if keep_palette {
                    continue;
                } else {
                    Mode::Normal
                }
            }
            Mode::DocBrowser(bs) => {
                // Doc Browser: список документов источника. None — режим остаётся.
                match handle_doc_browser_event(ev.clone(), bs, &mut output_lines, term_rect) {
                    Some(new_mode) => new_mode,
                    None => continue,
                }
            }
            Mode::DocViewer(vs) => {
                // Doc Viewer: окно с документом (scroll/copy/open).
                match handle_doc_viewer_event(ev.clone(), vs, &mut output_lines, term_rect) {
                    Some(new_mode) => new_mode,
                    None => continue,
                }
            }
            Mode::Transcript(ts) => {
                // v0.17.4: Transcript / Response View.
                let mut next: Option<Mode> = None;
                if let Event::Key(k) = ev {
                    match (k.code, k.modifiers) {
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            next = Some(Mode::Normal);
                        }
                        (KeyCode::Esc, _) => {
                            if ts.viewing.is_some() {
                                // Response View → назад к ленте
                                ts.viewing = None;
                                ts.view_scroll = 0;
                                ts.status.clear();
                            } else {
                                next = Some(Mode::Normal);
                            }
                        }
                        (KeyCode::Up, _) => {
                            if ts.viewing.is_some() {
                                ts.view_scroll_up();
                            } else {
                                ts.move_up();
                            }
                        }
                        (KeyCode::Down, _) => {
                            if ts.viewing.is_some() {
                                ts.view_scroll_down();
                            } else {
                                ts.move_down();
                            }
                        }
                        (KeyCode::PageUp, _) => {
                            if ts.viewing.is_some() {
                                ts.view_page_up();
                            } else {
                                for _ in 0..5 {
                                    ts.move_up();
                                }
                            }
                        }
                        (KeyCode::PageDown, _) => {
                            if ts.viewing.is_some() {
                                ts.view_page_down();
                            } else {
                                for _ in 0..5 {
                                    ts.move_down();
                                }
                            }
                        }
                        (KeyCode::Home, _) => {
                            if ts.viewing.is_none() && !ts.entries.is_empty() {
                                ts.list.select(Some(0));
                            }
                        }
                        (KeyCode::End, _) => {
                            if ts.viewing.is_none() && !ts.entries.is_empty() {
                                ts.list.select(Some(ts.entries.len() - 1));
                            }
                        }
                        (KeyCode::Enter, _) => {
                            if ts.viewing.is_none() {
                                ts.open_selected();
                            }
                        }
                        (KeyCode::Char('y'), _) => {
                            // Копировать ответ (текущий в Response View или
                            // выбранный в ленте) в буфер обмена.
                            let src = if ts.viewing.is_some() {
                                ts.viewing_entry()
                            } else {
                                ts.selected()
                            };
                            if let Some(e) = src {
                                match mouse::copy_to_clipboard(&e.answer) {
                                    Ok(via) => ts.status = format!(
                                        "✓ Скопировано {} символов ответа #{} ({via})",
                                        e.answer.chars().count(),
                                        e.id
                                    ),
                                    Err(err) => ts.status = format!("❌ clipboard: {err}"),
                                }
                            }
                        }
                        (KeyCode::Char('r'), _) => {
                            ts.reload(&mut state);
                        }
                        (KeyCode::Char('d'), _) => {
                            // Удалить выбранную пару из ленты.
                            if ts.viewing.is_none() {
                                if let Some(e) = ts.selected() {
                                    let id = e.id;
                                    match state.ensure_notes_conn() {
                                        Ok(conn) => match transcript::delete_entry(conn, id) {
                                            Ok(()) => {
                                                ts.reload(&mut state);
                                                ts.status = format!("✓ Пара #{id} удалена");
                                            }
                                            Err(err) => ts.status = format!("❌ {err}"),
                                        },
                                        Err(err) => ts.status = format!("❌ {err}"),
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Event::Mouse(me) = ev {
                    if let MouseAction::DragEnd { col, row } = mouse::parse_event(me) {
                        if let Some(area) = layout_snapshot.transcript_area() {
                            if mouse::hit(&area, col, row) {
                                // Клик по строке ленты → выбор + открыть ответ.
                                let local = row.saturating_sub(area.y + 1) as usize;
                                if local < ts.entries.len() {
                                    ts.list.select(Some(local));
                                    ts.open_selected();
                                }
                            }
                        }
                    }
                }
                match next {
                    Some(m) => m,
                    None => continue,
                }
            }
            Mode::Calc(cs) => {
                // v0.48.0: Калькулятор Всего — ввод выражения с живым preview.
                let mut next: Option<Mode> = None;
                if let Event::Key(k) = ev {
                    match (k.code, k.modifiers) {
                        (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            next = Some(Mode::Normal);
                        }
                        (KeyCode::Enter, _) => {
                            let input = cs.buf.trim().to_string();
                            if input.is_empty() {
                                next = Some(Mode::Normal);
                            } else {
                                // вычисляем в контексте ShellState (ans, vars)
                                let res = state.calc.eval_line(&input).unwrap_or_else(|e| format!("❌ {e}"));
                                cs.push_result(&input, &res);
                                cs.buf.clear();
                                state.set_output(res.clone());
                            }
                        }
                        (KeyCode::Backspace, _) => {
                            cs.buf.pop();
                        }
                        (KeyCode::Up, _) => cs.recall_prev(),
                        (KeyCode::Down, _) => cs.recall_next(),
                        (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                            cs.buf.push(ch);
                        }
                        _ => {}
                    }
                }
                next.unwrap_or(Mode::Calc(std::mem::replace(cs, CalcUiState::new())))
            }
            Mode::Normal => {
                // Не меняем режим, переходим к обычной обработке событий
                Mode::Normal
            }
        };
        if std::mem::discriminant(&new_mode) != std::mem::discriminant(&mode) {
            mode = new_mode;
            continue;
        }

        // Mode::Normal — обычная обработка событий
        match ev {
            Event::Key(k) => {
                handle_key_event(
                    k,
                    &mut state,
                    &mut input_buf,
                    &mut input_history,
                    &mut input_history_idx,
                    &mut output_lines,
                    &mut output_scroll,
                    &mut notes_items,
                    &mut notes_state,
                    &mut sources_items,
                    &mut sources_state,
                    &mut sources_refs,
                    &mut focus,
                    &mut should_quit,
                    &mut mode,
                    &mut selection,
                );
            }
            Event::Paste(text) => {
                // bracketed paste: терминал прислал содержимое буфера обмена.
                // В строку ввода — в одну строку (переводы строк → пробелы,
                // иначе вставка выполнилась бы как команда).
                let flat = text.replace(['\r', '\n'], " ");
                input_buf.push_str(&flat);
            }
            Event::Mouse(me) => {
                handle_mouse_event(
                    me,
                    &layout_snapshot,
                    &mut state,
                    &mut input_buf,
                    &mut input_history,
                    &mut input_history_idx,
                    &mut output_lines,
                    &mut output_scroll,
                    &mut notes_items,
                    &mut notes_state,
                    &mut sources_items,
                    &mut sources_state,
                    &mut sources_refs,
                    &mut focus,
                    &mut selection,
                    &mut last_click_time,
                    &mut last_click_pos,
                    &mut mode,
                );
            }
            Event::Resize(_, _) => {
                // ratatui автоматически перерисует на следующей итерации
            }
            _ => {}
        }
    }

    // Восстановление терминала
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(
        stdout,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = stdout.flush();

    std::process::ExitCode::SUCCESS
}

/// v2.0: вариант `Notebooks` удалён вместе с NLM-панелью.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Input,
    Output,
    Notes,
    Sources,
}

impl Focus {
    fn next(self) -> Self {
        match self {
            Focus::Input => Focus::Output,
            Focus::Output => Focus::Notes,
            Focus::Notes => Focus::Sources,
            Focus::Sources => Focus::Input,
        }
    }
    fn prev(self) -> Self {
        match self {
            Focus::Input => Focus::Sources,
            Focus::Output => Focus::Input,
            Focus::Notes => Focus::Output,
            Focus::Sources => Focus::Notes,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Focus::Input => "input",
            Focus::Output => "chat",
            Focus::Notes => "notes",
            Focus::Sources => "sources",
        }
    }
}

#[derive(Debug)]
enum Mode {
    Normal,
    Palette,
    NoteEditor(NoteEditorState),
    /// Список документов выбранного источника (popup).
    DocBrowser(DocBrowserState),
    /// Окно просмотра одного документа (popup, read-only).
    DocViewer(DocViewerState),
    /// Transcript / Response View — лента локальной истории вопросов
    /// (F3; таблица poler_chat). `viewing == None` — лента пар;
    /// `Some(i)` — полный ответ записи `entries[i]` (Response View).
    Transcript(TranscriptState),
    /// v0.48.0: Калькулятор Всего — оверлей с живым preview и историей
    /// (открывается клавишей `=` в Normal-режиме).
    Calc(CalcUiState),
}

/// Состояние виджета калькулятора (v0.48.0).
#[derive(Debug)]
struct CalcUiState {
    /// Текущий ввод выражения.
    buf: String,
    /// История результатов (новые снизу), «❯ expr» / «= result».
    lines: Vec<String>,
    /// История ввода для Up/Down.
    inputs: Vec<String>,
    input_idx: Option<usize>,
}

impl CalcUiState {
    fn new() -> Self {
        CalcUiState { buf: String::new(), lines: Vec::new(), inputs: Vec::new(), input_idx: None }
    }

    fn push_result(&mut self, input: &str, result: &str) {
        self.lines.push(format!("❯ {input}"));
        self.lines.push(format!("= {result}"));
        if self.lines.len() > 400 {
            let drop = self.lines.len() - 400;
            self.lines.drain(0..drop);
        }
        self.inputs.push(input.to_string());
        self.input_idx = None;
    }

    fn recall_prev(&mut self) {
        if self.inputs.is_empty() {
            return;
        }
        let idx = match self.input_idx {
            None => self.inputs.len() - 1,
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.input_idx = Some(idx);
        self.buf = self.inputs[idx].clone();
    }

    fn recall_next(&mut self) {
        let idx = match self.input_idx {
            None => return,
            Some(i) if i + 1 >= self.inputs.len() => {
                self.input_idx = None;
                self.buf.clear();
                return;
            }
            Some(i) => i + 1,
        };
        self.input_idx = Some(idx);
        self.buf = self.inputs[idx].clone();
    }
}

/// Состояние окна ленты чата: пары вопрос→ответ + просмотровый режим.
#[derive(Debug)]
struct TranscriptState {
    /// Пары ленты (старые сверху, новые снизу — feed-порядок).
    entries: Vec<ChatEntry>,
    /// Выбранная строка ленты.
    list: ListState,
    /// Индекс записи в Response View (None — показываем ленту).
    viewing: Option<usize>,
    /// Вертикальная прокрутка ответа.
    view_scroll: u16,
    /// Всего записей в БД (лента показывает последние TRANSCRIPT_LIMIT).
    total: i64,
    /// Строка статуса последней операции (копирование и т.п.).
    status: String,
}

/// Сколько последних пар грузим в окно.
const TRANSCRIPT_LIMIT: usize = 200;
/// Шаг прокрутки PgUp/PgDn в Response View.
const VIEW_PAGE: u16 = 12;

impl TranscriptState {
    fn new(state: &mut ShellState) -> Self {
        let mut ts = TranscriptState {
            entries: Vec::new(),
            list: ListState::default(),
            viewing: None,
            view_scroll: 0,
            total: 0,
            status: String::new(),
        };
        ts.reload(state);
        ts
    }

    /// Перечитать ленту из БД (r). Выбор — на самой свежей паре.
    fn reload(&mut self, state: &mut ShellState) {
        self.status.clear();
        match state.ensure_notes_conn() {
            Ok(conn) => match transcript::list_entries(conn, TRANSCRIPT_LIMIT) {
                Ok(feed) => {
                    self.total = transcript::count(conn).unwrap_or(feed.len() as i64);
                    let n = feed.len();
                    self.entries = feed;
                    self.list = ListState::default();
                    if n > 0 {
                        self.list.select(Some(n - 1));
                    }
                    if self.total as usize > n {
                        self.status = format!(
                            "показаны последние {n} из {} пар",
                            self.total
                        );
                    }
                }
                Err(e) => self.status = format!("❌ {e}"),
            },
            Err(e) => self.status = format!("❌ {e}"),
        }
        self.viewing = None;
        self.view_scroll = 0;
    }

    fn move_up(&mut self) {
        let i = self.list.selected().unwrap_or(0);
        self.list.select(Some(i.saturating_sub(1)));
    }

    fn move_down(&mut self) {
        let i = self.list.selected().unwrap_or(0);
        let max = self.entries.len().saturating_sub(1);
        self.list.select(Some((i + 1).min(max)));
    }

    /// Ответ выбранной записи (лента).
    fn selected(&self) -> Option<&ChatEntry> {
        self.list.selected().and_then(|i| self.entries.get(i))
    }

    /// Открыть Response View выбранной пары.
    fn open_selected(&mut self) {
        if self.list.selected().is_some() && !self.entries.is_empty() {
            self.viewing = self.list.selected();
            self.view_scroll = 0;
            self.status.clear();
        }
    }

    /// Ответ в просмотровом режиме.
    fn viewing_entry(&self) -> Option<&ChatEntry> {
        self.viewing.and_then(|i| self.entries.get(i))
    }

    fn view_scroll_up(&mut self) {
        self.view_scroll = self.view_scroll.saturating_sub(1);
    }

    fn view_scroll_down(&mut self) {
        self.view_scroll = self.view_scroll.saturating_add(1).min(65_535);
    }

    fn view_page_up(&mut self) {
        self.view_scroll = self.view_scroll.saturating_sub(VIEW_PAGE);
    }

    fn view_page_down(&mut self) {
        self.view_scroll = self.view_scroll.saturating_add(VIEW_PAGE).min(65_535);
    }
}

#[derive(Debug)]
struct NoteEditorState {
    title_input: String,
    title_active: bool, // true = редактируем title, false = редактируем body
    body: TextArea<'static>,
}

#[derive(Debug)]
enum NoteEditorResult {
    Continue,
    Save(String, String),
    Cancel,
}

/// Состояние Doc Browser: список документов внутри одного источника.
/// Для файловых источников поддерживает drill-down по каталогам
/// (title обновляется, `..` ведёт наверх).
#[derive(Debug, Default)]
struct DocBrowserState {
    /// Заголовок окна: имя источника или текущий каталог при drill-down.
    title: String,
    docs: Vec<DocEntry>,
    state: ListState,
}

/// Состояние Doc Viewer: read-only окно с текстом документа.
/// `parent` — список, из которого открыли (Esc возвращает в него).
#[derive(Debug)]
struct DocViewerState {
    title: String,
    /// Мета-строка: тип/путь/URL — рендерится в заголовке окна.
    meta: String,
    text: String,
    scroll: usize,
    /// URL для клавиши `o` (открыть в браузере), если применимо.
    open_url: Option<String>,
    /// Список документов, из которого открыт просмотр (Esc — назад).
    parent: Option<Box<DocBrowserState>>,
}

/// Снапшот вычисленных прямоугольников layout для hit-testing мыши.
/// v2.0: `nb_area` (панель NotebookLM) удалён.
#[derive(Debug, Clone, Default)]
struct LayoutSnapshot {
    /// v0.17.4: прямоугольник окна Transcript (оверлей F3) для кликов.
    transcript: Option<Rect>,
    chat_area: Rect,
    input_area: Rect,
    notes_area: Rect,
    sources_area: Rect,
    status_area: Rect,
    palette_area: Option<Rect>,
}

impl LayoutSnapshot {
    /// Прямоугольник окна Transcript (совпадает с рендером centered_rect).
    fn transcript_area(&self) -> Option<Rect> {
        self.transcript
    }
    fn palette_area(&self) -> Option<Rect> {
        self.palette_area
    }
}

fn compute_layout(area: Rect) -> LayoutSnapshot {
    // Layout (v2.0: без NLM-панели):
    // ┌──────────────────┬──────────────┐
    // │ Chat (50% h)     │ Notes        │
    // ├──────────────────┼──────────────┤
    // │ Input (min 3)    │ Sources      │
    // ├──────────────────┴──────────────┤
    // │ status bar                      │
    // └─────────────────────────────────┘
    // Ширина: 62% / 38%
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);
    let main = outer[0];
    let status = outer[1];

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(main);
    let center = cols[0];
    let right = cols[1];

    let center_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Min(3)])
        .split(center);
    let chat_area = center_rows[0];
    let input_area = center_rows[1];

    let right_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(right);
    let notes_area = right_rows[0];
    let sources_area = right_rows[1];

    LayoutSnapshot {
        chat_area,
        input_area,
        notes_area,
        sources_area,
        status_area: status,
        palette_area: None,
        transcript: Some(centered_rect(88, 84, area)),
    }
}

#[allow(clippy::too_many_arguments)]
// ---------------------------------------------------------------------------
// v0.17.3-fix: Wrap-оценка высоты чата для скролла
// ---------------------------------------------------------------------------

/// Сколько рендер-строк займёт логическая строка при Wrap по ширине `width`.
/// Оценка по chars().count() — точна для кириллицы/латиницы (глиф ≈ 1 колонка).
fn wrapped_rows(line: &str, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    let len = line.chars().count();
    if len == 0 {
        return 1;
    }
    (len + width - 1) / width
}

/// Row-offset, при котором виден самый низ лога (с учётом Wrap и высоты панели).
fn chat_bottom_offset(lines: &[String], width: usize, height: usize) -> usize {
    let total_rows: usize = lines.iter().map(|l| wrapped_rows(l, width)).sum();
    total_rows.saturating_sub(height)
}

fn render_ui(
    f: &mut ratatui::Frame,
    layout: &LayoutSnapshot,
    input_buf: &str,
    output_lines: &[String],
    output_scroll: usize,
    notes_items: &[String],
    notes_state: &ListState,
    sources_items: &[String],
    sources_state: &ListState,
    focus: Focus,
    selection: &SelectionRect,
    state: &ShellState,
    mode: &Mode,
    palette_state: &ListState,
) {
    // Центр верх — Chat / Output (с drag-select overlay)
    let chat_block = Block::default()
        .borders(Borders::ALL)
        .title("Chat & Responses (drag-select → Ctrl+Y)")
        .border_style(if matches!(focus, Focus::Output) {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        });
    let chat_inner = chat_block.inner(layout.chat_area);
    // Рендерим текст как один Paragraph (с Wrap)
    let chat_text = output_lines.join("\n");
    // v0.17.3-fix: скролл чата теперь применяется к Paragraph (раньше значение
    // писалось, но не читалось — чат не прокручивался). Смещение в рендер-строках.
    let scroll_rows = (output_scroll.min(u16::MAX as usize)) as u16;
    let chat_para = Paragraph::new(chat_text)
        .wrap(Wrap { trim: false })
        .scroll((scroll_rows, 0));
    f.render_widget(chat_para, chat_inner);

    // Drag-select overlay — рамка выделения
    if let Some((min_col, min_row, max_col, max_row)) = selection.bbox() {
        let sel_area = Rect::new(
            min_col,
            min_row,
            max_col - min_col + 1,
            max_row - min_row + 1,
        );
        let sel_block = Block::default().borders(Borders::ALL).border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        f.render_widget(sel_block, sel_area);
    }

    // Border Chat panel — рисуем ПОВЕРХ overlay
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .title("Chat & Responses (drag-select → Ctrl+Y)")
            .border_style(if matches!(focus, Focus::Output) {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            }),
        layout.chat_area,
    );

    // Центр низ — Input
    let input_block = Block::default()
        .borders(Borders::ALL)
        .title("Input (Enter=run, ↑↓=history, ?=palette)")
        .border_style(if matches!(focus, Focus::Input) {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        });
    let input_para = Paragraph::new(format!("poler> {}", input_buf))
        .block(input_block)
        .style(Style::default().fg(Color::White));
    f.render_widget(input_para, layout.input_area);

    // Правая верх — Notes
    let notes_block = Block::default()
        .borders(Borders::ALL)
        .title("Notes (Ctrl+N=new, Ctrl+E=edit, Ctrl+D=del)")
        .border_style(if matches!(focus, Focus::Notes) {
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        });
    let notes_list_items: Vec<ListItem> = notes_items
        .iter()
        .map(|s| ListItem::new(Line::from(s.clone())))
        .collect();
    let notes_widget = List::new(notes_list_items)
        .block(notes_block)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Magenta));
    f.render_stateful_widget(notes_widget, layout.notes_area, &mut notes_state.clone());

    // Правая низ — Sources
    let sources_block = Block::default()
        .borders(Borders::ALL)
        .title("Sources (click/Enter=документы, o=внешне, Ctrl+T=test)")
        .border_style(if matches!(focus, Focus::Sources) {
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        });
    let sources_list_items: Vec<ListItem> = sources_items
        .iter()
        .map(|s| ListItem::new(Line::from(s.clone())))
        .collect();
    let sources_widget = List::new(sources_list_items)
        .block(sources_block)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Blue));
    f.render_stateful_widget(
        sources_widget,
        layout.sources_area,
        &mut sources_state.clone(),
    );

    // Status bar
    let status_text = format!(
        " poler-shell {}  │  db: {:?}  │  fmt: {:?}  │  top: {}  │  focus: {}  │  ==calc  F3=лента  ?=palette  Ctrl+N=note",
        env!("CARGO_PKG_VERSION"),
        state.db_path(),
        state.format,
        state.top,
        focus.as_str(),
    );
    let status_line = Line::from(Span::styled(
        status_text,
        Style::default().fg(Color::Black).bg(Color::DarkGray),
    ));
    let status_para = Paragraph::new(status_line).wrap(Wrap { trim: false });
    f.render_widget(status_para, layout.status_area);

    // Mode overlays
    match mode {
        Mode::Palette => {
            render_palette_overlay(f, palette_state);
        }
        Mode::NoteEditor(editor_state) => {
            render_note_editor_overlay(f, editor_state);
        }
        Mode::DocBrowser(bs) => {
            render_doc_browser_overlay(f, bs);
        }
        Mode::DocViewer(vs) => {
            render_doc_viewer_overlay(f, vs);
        }
        Mode::Transcript(ts) => {
            render_transcript_overlay(f, ts);
        }
        Mode::Calc(cs) => {
            render_calc_overlay(f, cs, state);
        }
        Mode::Normal => {}
    }
}

/// v0.48.0: оверлей «Калькулятора Всего» — ввод + живой preview + история.
fn render_calc_overlay(f: &mut ratatui::Frame, cs: &CalcUiState, state: &ShellState) {
    let area = centered_rect(80, 80, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" 🧮 Калькулятор Всего (v0.48.0) — Esc=закрыть, Enter=считать, ↑↓=история ")
        .border_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD));
    let inner = {
        let b = block.inner(area);
        f.render_widget(&block, area);
        b
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // ввод
            Constraint::Length(2), // preview
            Constraint::Min(3),    // история
            Constraint::Length(2), // подсказки
        ])
        .split(inner);

    // ввод
    let input_line = Line::from(vec![
        Span::styled("❯ ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(cs.buf.clone()),
        Span::styled("▏", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(input_line), chunks[0]);

    // живой preview (безопасный: не мутирует состояние)
    let preview = if cs.buf.trim().is_empty() {
        String::new()
    } else {
        state.calc.preview(cs.buf.trim())
    };
    let (p_style, p_text) = if preview.starts_with('⚠') {
        (Style::default().fg(Color::Yellow), preview)
    } else if preview.is_empty() {
        (Style::default().fg(Color::DarkGray), String::new())
    } else {
        (Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD), preview)
    };
    let preview_line = Paragraph::new(Line::from(Span::styled(p_text, p_style)));
    f.render_widget(preview_line, chunks[1]);

    // история (новые снизу)
    let hist: Vec<Line> = cs
        .lines
        .iter()
        .map(|l| {
            if l.starts_with("❯") {
                Line::from(Span::styled(l.clone(), Style::default().fg(Color::White)))
            } else {
                Line::from(Span::styled(l.clone(), Style::default().fg(Color::Green)))
            }
        })
        .collect();
    let hist_para = Paragraph::new(hist)
        .wrap(Wrap { trim: false })
        .scroll(if cs.lines.len() > chunks[2].height as usize {
            ((cs.lines.len() - chunks[2].height as usize) as u16, 0)
        } else {
            (0, 0)
        });
    f.render_widget(hist_para, chunks[2]);

    // подсказки
    let hints = " примеры: 2^10 · 5 km to mi · solve x^2=4 · expm([0,-1;1,0]*psi) · moon_illum(2024,4,8,18.35) ";
    let hint_line = Line::from(Span::styled(
        hints,
        Style::default().fg(Color::Black).bg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(hint_line).wrap(Wrap { trim: false }), chunks[3]);
}
/// v0.17.4: окно Transcript / Response View.
///
/// Лента (viewing == None): список пар `#id [время] NB вопрос → N симв.`
/// в feed-порядке (новые снизу). Response View (Some): вопрос в шапке,
/// полный ответ с прокруткой — восстановление «Історія чату | Відповідь»
/// Ask-вкладки Web GUI (удалён в v0.17.0).
fn render_transcript_overlay(f: &mut ratatui::Frame, ts: &TranscriptState) {
    let area = centered_rect(88, 84, f.area());
    f.render_widget(Clear, area);

    if let Some(idx) = ts.viewing {
        if let Some(e) = ts.entries.get(idx) {
            // ----- Response View -----
            let block = Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    " Відповідь #{} · {} · {} симв. ",
                    e.id,
                    transcript::format_ts(e.created_at),
                    e.answer.chars().count()
                ))
                .border_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD));
            let inner = {
                let b = block.inner(area);
                f.render_widget(&block, area);
                b
            };
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // вопрос
                    Constraint::Min(3),    // ответ
                    Constraint::Length(2), // статус/подсказки
                ])
                .split(inner);
            // Вопрос (шапка).
            let nb = e.notebook_id.as_deref().unwrap_or("—").to_string();
            let q_text = format!("❯ {}  [{}]", e.question, nb);
            let q_block = Block::default()
                .borders(Borders::ALL)
                .title(" Питання ")
                .border_style(Style::default().fg(Color::Yellow));
            let q_para = Paragraph::new(q_text)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(Color::Yellow));
            f.render_widget(q_para, q_block.inner(chunks[0]));
            f.render_widget(q_block, chunks[0]);
            // Ответ (прокручиваемый).
            let a_block = Block::default()
                .borders(Borders::ALL)
                .title(" Відповідь (↑↓/PgUp/PgDn — прокрутка) ")
                .border_style(Style::default().fg(Color::Green));
            let a_para = Paragraph::new(e.answer.as_str())
                .wrap(Wrap { trim: false })
                .scroll((ts.view_scroll, 0));
            f.render_widget(a_para, a_block.inner(chunks[1]));
            f.render_widget(a_block, chunks[1]);
            // Статус/подсказки.
            let hint = if ts.status.is_empty() {
                " y — копировать ответ · r — обновить · Esc — к ленте ".to_string()
            } else {
                format!(" {} · Esc — к ленте ", ts.status)
            };
            let hint_para = Paragraph::new(Line::from(Span::styled(
                hint,
                Style::default().fg(Color::DarkGray),
            )));
            f.render_widget(hint_para, chunks[2]);
            return;
        }
    }

    // ----- Лента пар -----
    let title = if ts.entries.is_empty() {
        " Transcript — лента чата (локальная история вопросов) ".to_string()
    } else {
        format!(
            " Transcript — лента чата: {} пар ({} всего) · F3 ",
            ts.entries.len(),
            ts.total
        )
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    let inner = {
        let b = block.inner(area);
        f.render_widget(&block, area);
        b
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(inner);
    if ts.entries.is_empty() {
        let empty = Paragraph::new(
            "Лента пуста. Каждая пара вопрос→ответ попадает сюда
             автоматически и переживает перезапуски.",
        )
        .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty, chunks[0]);
    } else {
        let items: Vec<ListItem> = ts
            .entries
            .iter()
            .map(|e| ListItem::new(transcript::feed_line(e)))
            .collect();
        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list, chunks[0], &mut ts.list.clone());
    }
    let hint = if ts.status.is_empty() {
        " ↑↓ — навигация · Enter — ответ · y — копировать · d — удалить · r — обновить · Esc — закрыть ".to_string()
    } else {
        format!(" {} ", ts.status)
    };
    let hint_para = Paragraph::new(Line::from(Span::styled(
        hint,
        Style::default().fg(Color::DarkGray),
    )));
    f.render_widget(hint_para, chunks[1]);
}


fn render_palette_overlay(f: &mut ratatui::Frame, palette_state: &ListState) {
    let area = centered_rect(80, 70, f.area());
    let scenarios = help::palette_scenarios();
    let items: Vec<ListItem> = scenarios
        .iter()
        .map(|sc| ListItem::new(Line::from(format!("{}. {}", sc.title, sc.cmd))))
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("? palette — 10 сценариев (↑↓=select, Enter=use, Esc=cancel)")
        .border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    let widget = List::new(items)
        .block(block)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Yellow));
    f.render_widget(Clear, area);
    f.render_stateful_widget(widget, area, &mut palette_state.clone());
}

fn render_note_editor_overlay(f: &mut ratatui::Frame, editor: &NoteEditorState) {
    let area = centered_rect(80, 70, f.area());
    f.render_widget(Clear, area);

    // Title input
    let title_area = Rect::new(area.x, area.y, area.width, 3);
    let title_block = Block::default()
        .borders(Borders::ALL)
        .title(if editor.title_active {
            "Title (TAB → body)"
        } else {
            "Title (TAB → body)"
        })
        .border_style(if editor.title_active {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        });
    let title_para = Paragraph::new(editor.title_input.as_str())
        .block(title_block)
        .style(Style::default().fg(Color::White));
    f.render_widget(title_para, title_area);

    // Body textarea
    let body_area = Rect::new(
        area.x,
        area.y + 3,
        area.width,
        area.height.saturating_sub(3),
    );
    let body_block = Block::default()
        .borders(Borders::ALL)
        .title("Body (Ctrl+S=save, Esc=cancel)")
        .border_style(if !editor.title_active {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        });
    f.render_widget(&editor.body, body_area);
    f.render_widget(body_block, body_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let popup = popup_layout[1];
    let popup_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup);
    popup_layout[1]
}

/// Прямоугольник popup Doc Browser (совпадает с hit-testing в обработчике).
fn doc_browser_area(term: Rect) -> Rect {
    centered_rect(70, 70, term)
}

/// Прямоугольник popup Doc Viewer.
fn doc_viewer_area(term: Rect) -> Rect {
    centered_rect(92, 88, term)
}

/// Popup со списком документов источника.
fn render_doc_browser_overlay(f: &mut ratatui::Frame, bs: &DocBrowserState) {
    let area = doc_browser_area(f.area());
    f.render_widget(Clear, area);
    let title = truncate_chars(&bs.title, 48);
    let items: Vec<ListItem> = bs
        .docs
        .iter()
        .map(|d| {
            let icon = doc_browser::doc_icon(&d.kind);
            if d.hint.is_empty() {
                ListItem::new(Line::from(format!("{} {}", icon, d.title)))
            } else {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{} {} ", icon, d.title)),
                    Span::styled(
                        format!("({})", d.hint),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            }
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            "📄 {} — {} докум. (Enter/клик=открыть, o=внешне, Esc=назад)",
            title,
            bs.docs.len()
        ))
        .border_style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    let widget = List::new(items)
        .block(block)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Blue));
    f.render_stateful_widget(widget, area, &mut bs.state.clone());
}

/// Popup с текстом документа (read-only, скролл).
fn render_doc_viewer_overlay(f: &mut ratatui::Frame, vs: &DocViewerState) {
    let area = doc_viewer_area(f.area());
    f.render_widget(Clear, area);
    let title = truncate_chars(&vs.title, 40);
    let meta = truncate_chars(&vs.meta, 48);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            format!("📜 {title} • {meta}"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " ↑↓/PgUp/PgDn/колесо=скролл │ o=браузер │ Ctrl+Y=копия │ Esc=назад ",
            Style::default().fg(Color::DarkGray),
        ))
        .border_style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        );
    let scroll = vs.scroll.min(u16::MAX as usize) as u16;
    let para = Paragraph::new(vs.text.as_str())
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(para, area);
}

/// Обрезать строку по границе символов (UTF-8 безопасно).
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn handle_key_event(
    k: KeyEvent,
    state: &mut ShellState,
    input_buf: &mut String,
    input_history: &mut Vec<String>,
    input_history_idx: &mut Option<usize>,
    output_lines: &mut Vec<String>,
    output_scroll: &mut usize,
    notes_items: &mut Vec<String>,
    notes_state: &mut ListState,
    sources_items: &mut Vec<String>,
    sources_state: &mut ListState,
    sources_refs: &mut Vec<SourceRef>,
    focus: &mut Focus,
    should_quit: &mut bool,
    mode: &mut Mode,
    selection: &mut SelectionRect,
) {
    match (k.code, k.modifiers) {
        (KeyCode::Char('='), _) if input_buf.is_empty() => {
            // v0.48.0: `=` открывает Калькулятор Всего (как префикс в REPL)
            *mode = Mode::Calc(CalcUiState::new());
        }
        (KeyCode::F(3), _) => {
            // Transcript — лента локальной истории вопросов (окно-оверлей).
            *mode = Mode::Transcript(TranscriptState::new(state));
        }
        (KeyCode::Esc, _) => {
            if selection.active {
                selection.clear();
            } else {
                *should_quit = true;
            }
        }
        (KeyCode::Tab, _) => {
            *focus = focus.next();
        }
        (KeyCode::BackTab, _) => {
            *focus = focus.prev();
        }
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            *should_quit = true;
        }
        (KeyCode::Char('y'), KeyModifiers::CONTROL) => {
            // Ctrl+Y: скопировать выделение (если активно) или весь последний вывод
            if selection.active {
                if let Some((min_col, min_row, max_col, max_row)) = selection.bbox() {
                    let text = mouse::extract_text(
                        output_lines,
                        &Rect::new(0, 0, 200, 1000),
                        min_col,
                        min_row,
                        max_col,
                        max_row,
                    );
                    match mouse::copy_to_clipboard(&text) {
                        Ok(via) => output_lines.push(format!(
                            "✓ Скопировано {} символов в буфер ({via})",
                            text.chars().count()
                        )),
                        Err(e) => output_lines.push(format!("❌ clipboard: {e}")),
                    }
                    selection.clear();
                }
            } else if !state.last_output.is_empty() {
                match mouse::copy_to_clipboard(&state.last_output) {
                    Ok(via) => output_lines.push(format!(
                        "✓ Скопирован весь вывод ({} символов, {via})",
                        state.last_output.chars().count()
                    )),
                    Err(e) => output_lines.push(format!("❌ clipboard: {e}")),
                }
            } else {
                output_lines.push("ℹ Нет выделения и нет последнего вывода".into());
            }
            *output_scroll = usize::MAX; // прилипить к низу
        }
        (KeyCode::Char('n'), KeyModifiers::CONTROL) => {
            // Ctrl+N: новая заметка (встроенный редактор)
            let mut body = TextArea::default();
            body.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Note body (Ctrl+S=save, Esc=cancel)")
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            *mode = Mode::NoteEditor(NoteEditorState {
                title_input: String::new(),
                title_active: true,
                body,
            });
        }
        (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
            // Ctrl+E: редактировать выбранную заметку → открыть редактор
            if let Some(idx) = notes_state.selected() {
                if let Ok(conn) = state.ensure_notes_conn() {
                    let all = crate::notes::list_notes(conn, 500).unwrap_or_default();
                    if idx < all.len() {
                        let n = &all[idx];
                        let mut body = TextArea::default();
                        body.set_block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(format!("Edit #{} (Ctrl+S=save, Esc=cancel)", n.id))
                                .border_style(Style::default().fg(Color::Yellow)),
                        );
                        // Вставить существующий текст
                        for line in n.body.lines() {
                            body.insert_str(line);
                            body.insert_newline();
                        }
                        *mode = Mode::NoteEditor(NoteEditorState {
                            title_input: n.title.clone(),
                            title_active: true,
                            body,
                        });
                    }
                }
            }
        }
        (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
            // Ctrl+D: удалить выбранную заметку
            if matches!(focus, Focus::Notes) {
                if let Some(idx) = notes_state.selected() {
                    if let Ok(conn) = state.ensure_notes_conn() {
                        let all = crate::notes::list_notes(conn, 500).unwrap_or_default();
                        if idx < all.len() {
                            let id = all[idx].id;
                            match crate::notes::delete_note(conn, id) {
                                Ok(()) => {
                                    output_lines.push(format!("✓ Заметка #{id} удалена"));
                                    refresh_notes_list(state, notes_items);
                                }
                                Err(e) => output_lines.push(format!("❌ {e}")),
                            }
                            *output_scroll = usize::MAX; // прилипить к низу
                        }
                    }
                }
            } else if matches!(focus, Focus::Sources) {
                if let Some(idx) = sources_state.selected() {
                    if let Ok(conn) = state.ensure_sources_conn() {
                        let all = crate::sources::list_sources(conn, 500).unwrap_or_default();
                        if idx < all.len() {
                            let id = all[idx].id;
                            match crate::sources::delete_source(conn, id) {
                                Ok(()) => {
                                    output_lines.push(format!("✓ Источник #{id} удалён"));
                                    refresh_sources_list(state, sources_items, sources_refs);
                                }
                                Err(e) => output_lines.push(format!("❌ {e}")),
                            }
                            *output_scroll = usize::MAX; // прилипить к низу
                        }
                    }
                }
            }
        }
        (KeyCode::Char('t'), KeyModifiers::CONTROL) => {
            // Ctrl+T: тестировать источник
            if matches!(focus, Focus::Sources) {
                if let Some(idx) = sources_state.selected() {
                    if let Ok(conn) = state.ensure_sources_conn() {
                        let all = crate::sources::list_sources(conn, 500).unwrap_or_default();
                        if idx < all.len() {
                            let id = all[idx].id;
                            match crate::sources::test_source(conn, id) {
                                Ok(crate::sources::TestStatus::Ok) => {
                                    output_lines.push(format!("✓ #{id}: доступен"));
                                }
                                Ok(crate::sources::TestStatus::Fail) => {
                                    output_lines.push(format!("✗ #{id}: недоступен"));
                                }
                                Err(e) => output_lines.push(format!("❌ {e}")),
                            }
                            refresh_sources_list(state, sources_items, sources_refs);
                            *output_scroll = usize::MAX; // прилипить к низу
                        }
                    }
                }
            }
        }
        (KeyCode::Enter, _) if matches!(focus, Focus::Sources) => {
            // Doc Browser: Enter на локальном источнике → список его документов.
            if let Some(idx) = sources_state.selected() {
                if idx < sources_refs.len() {
                    let bs = open_doc_browser(&sources_refs[idx], output_lines);
                    *mode = Mode::DocBrowser(bs);
                }
            }
            *output_scroll = usize::MAX; // прилипить к низу
        }
        (KeyCode::Char('o'), _) if matches!(focus, Focus::Sources) => {
            // 'o': внешний канал (M4) — $EDITOR / xdg-open / браузер.
            if let Some(idx) = sources_state.selected() {
                if idx < sources_refs.len() {
                    open_source_external(&sources_refs[idx], output_lines);
                }
            }
            *output_scroll = usize::MAX; // прилипить к низу
        }
        (KeyCode::Char('?'), _) => {
            // ? palette
            *mode = Mode::Palette;
        }
        (KeyCode::PageUp, _) if matches!(focus, Focus::Output) || matches!(focus, Focus::Input) => {
            *output_scroll = output_scroll.saturating_sub(5);
        }
        (KeyCode::PageDown, _)
            if matches!(focus, Focus::Output) || matches!(focus, Focus::Input) =>
        {
            // клампит нормализация в главном цикле (bottom-offset с учётом Wrap)
            *output_scroll = (*output_scroll).saturating_add(5);
        }
        (KeyCode::Up, _) if matches!(focus, Focus::Input) => {
            if !input_history.is_empty() {
                *input_history_idx = Some(match *input_history_idx {
                    None => input_history.len() - 1,
                    Some(i) if i > 0 => i - 1,
                    Some(i) => i,
                });
                if let Some(i) = *input_history_idx {
                    *input_buf = input_history[i].clone();
                }
            }
        }
        (KeyCode::Down, _) if matches!(focus, Focus::Input) => {
            if !input_history.is_empty() {
                *input_history_idx = match *input_history_idx {
                    None => None,
                    Some(i) if i + 1 < input_history.len() => Some(i + 1),
                    _ => None,
                };
                *input_buf = match *input_history_idx {
                    Some(i) => input_history[i].clone(),
                    None => String::new(),
                };
            }
        }
        (KeyCode::Up, _) if matches!(focus, Focus::Notes) => {
            let idx = notes_state.selected().unwrap_or(0);
            notes_state.select(Some(idx.saturating_sub(1)));
        }
        (KeyCode::Down, _) if matches!(focus, Focus::Notes) => {
            let idx = notes_state.selected().unwrap_or(0);
            let max = notes_items.len().saturating_sub(1);
            notes_state.select(Some((idx + 1).min(max)));
        }
        (KeyCode::Up, _) if matches!(focus, Focus::Sources) => {
            let idx = sources_state.selected().unwrap_or(0);
            sources_state.select(Some(idx.saturating_sub(1)));
        }
        (KeyCode::Down, _) if matches!(focus, Focus::Sources) => {
            let idx = sources_state.selected().unwrap_or(0);
            let max = sources_items.len().saturating_sub(1);
            sources_state.select(Some((idx + 1).min(max)));
        }
        (KeyCode::Char(c), _) if matches!(focus, Focus::Input) => {
            input_buf.push(c);
        }
        (KeyCode::Backspace, _) if matches!(focus, Focus::Input) => {
            input_buf.pop();
        }
        (KeyCode::Enter, _) if matches!(focus, Focus::Input) => {
            let line = input_buf.clone();
            output_lines.push(format!("poler> {}", line));
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return;
            }
            input_history.push(trimmed.to_string());
            *input_history_idx = None;
            input_buf.clear();

            // Спец-выход TUI
            if matches!(trimmed, "quit" | "exit" | "q") {
                *should_quit = true;
                return;
            }
            let r = dispatch(state, trimmed);
            match r {
                CmdResult::Quit => {
                    *should_quit = true;
                }
                CmdResult::Empty => {}
                CmdResult::Done(out) => {
                    // После выполнения команды обновим notes/sources если это была CRUD
                    if trimmed.starts_with("notes") {
                        refresh_notes_list(state, notes_items);
                    }
                    if trimmed.starts_with("sources") {
                        refresh_sources_list(state, sources_items, sources_refs);
                    }
                    for l in out.lines() {
                        output_lines.push(l.to_string());
                    }
                    output_lines.push(String::new());
                    *output_scroll = usize::MAX; // прилипить к низу
                }
            }
        }
        _ => {}
    }
}

/// Действие по Enter для источника из poler_sources.
/// v2.0: локальная версия бывшего `companion::EnterAction` — NLM-варианты
/// удалены вместе с Google/NotebookLM.
enum EnterAction {
    /// Открыть URL в системном браузере (xdg-open).
    OpenUrl(String),
    /// Открыть локальный файл в $EDITOR.
    EditLocal(String),
}

/// TUI raw-mode остаётся активным — spawned editor открывается в отдельном
/// процессе; для интерактивного редактирования пользователь переключается
/// на него (Ctrl+Z в большинстве терминалов), либо завершает TUI и
/// повторно открывает.
fn execute_enter_action(action: &EnterAction, output_lines: &mut Vec<String>) {
    match action {
        EnterAction::OpenUrl(url) => {
            super::open_in_user_browser(url);
            output_lines.push(format!("→ открыть в браузере: {}", url));
        }
        EnterAction::EditLocal(path) => {
            if !std::path::Path::new(path).exists() {
                output_lines.push(format!("❌ файл не найден: {}", path));
                return;
            }
            spawn_editor(path);
            output_lines.push(format!(
                "→ открыть в $EDITOR ({}): {}",
                std::env::var("EDITOR").unwrap_or_else(|_| "(nano)".into()),
                path
            ));
        }
    }
}

/// Spawn `$EDITOR` (fallback `nano`) с путём. Fire-and-forget: не блокирует
/// TUI, но оставляет child-процесс запущенным. Пользователь переключается
/// вручную (терминальный Ctrl+Z или открытие нового окна терминала).
fn spawn_editor(path: &str) {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    let _ = std::process::Command::new(&editor)
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

// ---------------------------------------------------------------------------
// Doc Browser: источник → документы → просмотр (v0.17.3+)
// ---------------------------------------------------------------------------

/// Открыть Doc Browser для локального источника: собрать список его
/// документов. Каталог листуется, файл/URL/repo — одна запись. Функция
/// всегда возвращает пригодный к показу список (ошибки — Info-документы).
/// v2.0: NLM-ветка удалена вместе с Google/NotebookLM.
fn open_doc_browser(src_ref: &SourceRef, _output_lines: &mut Vec<String>) -> DocBrowserState {
    let mut bs = DocBrowserState::default();
    bs.state.select(Some(0));
    match src_ref {
        SourceRef::Local { src } => {
            bs.title = format!("[{}] {}", src.kind.as_str(), src.value);
            bs.docs = doc_browser::local_source_documents(src);
        }
    }
    bs
}

/// Сформировать состояние Doc Viewer для выбранного документа.
/// Загрузка контента (файл/веб) происходит здесь, один раз при открытии.
/// v2.0: NLM-варианты удалены вместе с Google/NotebookLM.
fn open_doc_viewer(entry: &DocEntry, parent: DocBrowserState) -> DocViewerState {
    let (meta, text, open_url) = match &entry.kind {
        DocKind::LocalFile { path } => {
            let meta = path.display().to_string();
            match doc_browser::read_local_document(path, MAX_DOC_BYTES) {
                Ok(text) => (meta, text, None),
                Err(e) => (meta, format!("⚠ {e}"), None),
            }
        }
        DocKind::LocalDir { path } => {
            // В viewer директория попадает только теоретически (клик всегда
            // уходит в drill-down) — на всякий случай покажем листинг текстом.
            let meta = path.display().to_string();
            match doc_browser::dir_documents(path, MAX_DIR_ENTRIES) {
                Ok(docs) => {
                    let text = docs
                        .iter()
                        .map(|d| {
                            if d.hint.is_empty() {
                                d.title.clone()
                            } else {
                                format!("{} ({})", d.title, d.hint)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    (meta, text, None)
                }
                Err(e) => (meta, format!("⚠ {e}"), None),
            }
        }
        DocKind::WebPage { url } => {
            let meta = url.clone();
            match doc_browser::fetch_web_document(url, MAX_DOC_BYTES) {
                Ok(text) => (meta, text, Some(url.clone())),
                Err(e) => (meta, format!("⚠ {e}"), Some(url.clone())),
            }
        }
        DocKind::Info { text, open_url } => ("инфо".into(), text.clone(), open_url.clone()),
    };
    DocViewerState {
        title: entry.title.clone(),
        meta,
        text,
        scroll: 0,
        open_url,
        parent: Some(Box::new(parent)),
    }
}

/// Открыть выбранный в Doc Browser документ: LocalDir — drill-down в новый
/// листинг, остальное — Doc Viewer. `None` = остались в списке.
fn open_selected_doc(bs: &mut DocBrowserState) -> Option<Mode> {
    let idx = bs.state.selected()?;
    let entry = bs.docs.get(idx)?.clone();
    if let DocKind::LocalDir { path } = &entry.kind {
        // Drill-down: заменяем содержимое списка («..» добавит родителя),
        // заголовок — путь текущего каталога.
        bs.docs = doc_browser::local_source_documents(&crate::sources::Source {
            id: 0,
            kind: crate::sources::SourceKind::File,
            value: path.display().to_string(),
            label: None,
            added_at: 0,
            last_tested_at: None,
            last_status: String::new(),
        });
        bs.title = format!("📁 {}", path.display());
        bs.state.select(Some(0));
        return None;
    }
    let parent = DocBrowserState {
        title: bs.title.clone(),
        docs: bs.docs.clone(),
        state: bs.state.clone(),
    };
    Some(Mode::DocViewer(open_doc_viewer(&entry, parent)))
}

/// Внешний канал для локального источника (клавиша `o` / правый клик):
/// file — `$EDITOR`, url/repo — системный браузер.
/// v2.0: NLM-ветка удалена вместе с Google/NotebookLM.
fn open_source_external(src_ref: &SourceRef, output_lines: &mut Vec<String>) {
    match src_ref {
        SourceRef::Local { src } => {
            let action = match src.kind {
                crate::sources::SourceKind::File => {
                    EnterAction::EditLocal(src.value.clone())
                }
                crate::sources::SourceKind::Url => {
                    EnterAction::OpenUrl(src.value.clone())
                }
                crate::sources::SourceKind::Repo => EnterAction::OpenUrl(format!(
                    "https://github.com/{}",
                    src.value
                )),
            };
            execute_enter_action(&action, output_lines);
        }
    }
}

/// Обработчик событий Doc Browser (список документов).
/// `Some(new_mode)` — сменить режим, `None` — остались в списке.
fn handle_doc_browser_event(
    ev: Event,
    bs: &mut DocBrowserState,
    output_lines: &mut Vec<String>,
    term: Rect,
) -> Option<Mode> {
    let area = doc_browser_area(term);
    match ev {
        Event::Key(k) => match (k.code, k.modifiers) {
            (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => Some(Mode::Normal),
            (KeyCode::Up, _) => {
                let i = bs.state.selected().unwrap_or(0);
                bs.state.select(Some(i.saturating_sub(1)));
                None
            }
            (KeyCode::Down, _) => {
                let i = bs.state.selected().unwrap_or(0);
                let max = bs.docs.len().saturating_sub(1);
                bs.state.select(Some((i + 1).min(max)));
                None
            }
            (KeyCode::PageUp, _) => {
                let i = bs.state.selected().unwrap_or(0);
                bs.state.select(Some(i.saturating_sub(10)));
                None
            }
            (KeyCode::PageDown, _) => {
                let i = bs.state.selected().unwrap_or(0);
                let max = bs.docs.len().saturating_sub(1);
                bs.state.select(Some((i + 10).min(max)));
                None
            }
            (KeyCode::Home, _) => {
                bs.state.select(Some(0));
                None
            }
            (KeyCode::End, _) => {
                let max = bs.docs.len().saturating_sub(1);
                bs.state.select(Some(max));
                None
            }
            (KeyCode::Enter, _) => open_selected_doc(bs),
            (KeyCode::Char('o'), _) => {
                // внешний канал для выбранного документа
                if let Some(idx) = bs.state.selected() {
                    if let Some(entry) = bs.docs.get(idx) {
                        match &entry.kind {
                            DocKind::WebPage { url } => {
                                super::open_in_user_browser(url);
                                output_lines.push(format!("→ открыть в браузере: {url}"));
                            }
                            DocKind::LocalFile { path } => {
                                let p = path.display().to_string();
                                spawn_editor(&p);
                                output_lines.push(format!("→ открыть в $EDITOR: {p}"));
                            }
                            DocKind::Info { open_url, .. } => {
                                if let Some(u) = open_url {
                                    super::open_in_user_browser(u);
                                    output_lines.push(format!("→ открыть в браузере: {u}"));
                                }
                            }
                            DocKind::LocalDir { .. } => {
                                output_lines
                                    .push("ℹ каталог открывается Enter'ом (drill-down)".into());
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        },
        Event::Mouse(me) => match mouse::parse_event(me) {
            MouseAction::ScrollUp => {
                let i = bs.state.selected().unwrap_or(0);
                bs.state.select(Some(i.saturating_sub(1)));
                None
            }
            MouseAction::ScrollDown => {
                let i = bs.state.selected().unwrap_or(0);
                let max = bs.docs.len().saturating_sub(1);
                bs.state.select(Some((i + 1).min(max)));
                None
            }
            // Клик по строке = выбор + открытие (как просил пользователь:
            // «тыкаешь на документ — открывается окно»)
            MouseAction::DragEnd { col, row } if mouse::hit(&area, col, row) => {
                let local_row = row.saturating_sub(area.y).saturating_sub(1) as usize;
                if local_row < bs.docs.len() {
                    bs.state.select(Some(local_row));
                    open_selected_doc(bs)
                } else {
                    None
                }
            }
            MouseAction::RightClick { col, row } if mouse::hit(&area, col, row) => {
                let local_row = row.saturating_sub(area.y).saturating_sub(1) as usize;
                if local_row < bs.docs.len() {
                    bs.state.select(Some(local_row));
                    // правый клик = внешний канал выбранного документа
                    if let Some(entry) = bs.docs.get(local_row) {
                        match &entry.kind {
                            DocKind::WebPage { url } => {
                                super::open_in_user_browser(url);
                                output_lines.push(format!("→ открыть в браузере: {url}"));
                            }
                            DocKind::LocalFile { path } => {
                                let p = path.display().to_string();
                                spawn_editor(&p);
                                output_lines.push(format!("→ открыть в $EDITOR: {p}"));
                            }
                            _ => {}
                        }
                    }
                }
                None
            }
            _ => None,
        },
        _ => None,
    }
}

/// Сколько рендер-строк занимает текст при Wrap по ширине `width`
/// (оценка — тот же принцип, что у Chat panel).
fn viewer_bottom_scroll(text: &str, width: usize, height: usize) -> usize {
    let total: usize = text.lines().map(|l| wrapped_rows(l, width)).sum();
    total.saturating_sub(height)
}

/// Обработчик событий Doc Viewer (окно с документом).
/// `Some(new_mode)` — сменить режим (Esc → назад в список), `None` — остались.
fn handle_doc_viewer_event(
    ev: Event,
    vs: &mut DocViewerState,
    output_lines: &mut Vec<String>,
    term: Rect,
) -> Option<Mode> {
    let area = doc_viewer_area(term);
    let inner_w = area.width.saturating_sub(2).max(1) as usize;
    let inner_h = area.height.saturating_sub(2).max(1) as usize;
    let bottom = viewer_bottom_scroll(&vs.text, inner_w, inner_h);
    match ev {
        Event::Key(k) => match (k.code, k.modifiers) {
            (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                // Esc — назад к списку документов (не в Normal!)
                vs.parent
                    .take()
                    .map(|b| Mode::DocBrowser(*b))
                    .or(Some(Mode::Normal))
            }
            (KeyCode::Up, _) => {
                vs.scroll = vs.scroll.saturating_sub(1);
                None
            }
            (KeyCode::Down, _) => {
                vs.scroll = (vs.scroll + 1).min(bottom);
                None
            }
            (KeyCode::PageUp, _) => {
                vs.scroll = vs.scroll.saturating_sub(10);
                None
            }
            (KeyCode::PageDown, _) => {
                vs.scroll = (vs.scroll + 10).min(bottom);
                None
            }
            (KeyCode::Home, _) => {
                vs.scroll = 0;
                None
            }
            (KeyCode::End, _) => {
                vs.scroll = bottom;
                None
            }
            (KeyCode::Char('y'), KeyModifiers::CONTROL) => {
                match mouse::copy_to_clipboard(&vs.text) {
                    Ok(via) => output_lines.push(format!(
                        "✓ Документ скопирован ({} символов, {via})",
                        vs.text.chars().count()
                    )),
                    Err(e) => output_lines.push(format!("❌ clipboard: {e}")),
                }
                None
            }
            (KeyCode::Char('o'), _) => {
                if let Some(u) = &vs.open_url {
                    super::open_in_user_browser(u);
                    output_lines.push(format!("→ открыть в браузере: {u}"));
                } else {
                    output_lines.push("ℹ у документа нет внешнего URL".into());
                }
                None
            }
            _ => None,
        },
        Event::Mouse(me) => match mouse::parse_event(me) {
            MouseAction::ScrollUp => {
                vs.scroll = vs.scroll.saturating_sub(3);
                None
            }
            MouseAction::ScrollDown => {
                vs.scroll = (vs.scroll + 3).min(bottom);
                None
            }
            _ => None,
        },
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_mouse_event(
    me: MouseEvent,
    layout: &LayoutSnapshot,
    state: &mut ShellState,
    input_buf: &mut String,
    input_history: &mut Vec<String>,
    input_history_idx: &mut Option<usize>,
    output_lines: &mut Vec<String>,
    output_scroll: &mut usize,
    notes_items: &mut Vec<String>,
    notes_state: &mut ListState,
    sources_items: &mut Vec<String>,
    sources_state: &mut ListState,
    sources_refs: &mut Vec<SourceRef>,
    focus: &mut Focus,
    selection: &mut SelectionRect,
    last_click_time: &mut Option<Instant>,
    last_click_pos: &mut Option<(u16, u16)>,
    mode: &mut Mode,
) {
    let action = mouse::parse_event(me);
    match action {
        MouseAction::Ignore => {}
        MouseAction::DragStart { col, row } => {
            // Drag начинается только если клик в Chat panel
            if mouse::hit(&layout.chat_area, col, row) {
                selection.start(col, row);
                *focus = Focus::Output;
            }
        }
        MouseAction::DragMove { col, row } => {
            selection.extend(col, row);
        }
        MouseAction::DragEnd { col, row } => {
            // Если это был drag с активным выделением — финализируем и копируем
            if selection.active {
                if let Some((min_col, min_row, max_col, max_row)) = selection.finish() {
                    // Проверим что был реальный drag (не клик)
                    let was_drag = (min_col != max_col) || (min_row != max_row);
                    if was_drag {
                        // Копируем выделение в буфер автоматически
                        let text = mouse::extract_text(
                            output_lines,
                            &Rect::new(0, 0, 200, 1000),
                            min_col,
                            min_row,
                            max_col,
                            max_row,
                        );
                        match mouse::copy_to_clipboard(&text) {
                            Ok(via) => output_lines.push(format!(
                                "✓ Скопировано {} символов (drag-select, {via})",
                                text.chars().count()
                            )),
                            Err(e) => output_lines.push(format!("❌ clipboard: {e}")),
                        }
                        *output_scroll = usize::MAX; // прилипить к низу
                    } else {
                        // Это был одиночный клик — обрабатываем как клик
                        handle_single_click(
                            col,
                            row,
                            layout,
                            state,
                            input_buf,
                            input_history,
                            input_history_idx,
                            output_lines,
                            output_scroll,
                            notes_items,
                            notes_state,
                            sources_items,
                            sources_state,
                            sources_refs,
                            focus,
                            last_click_time,
                            last_click_pos,
                            mode,
                        );
                    }
                }
            } else {
                // Событие Up без активного drag — обрабатываем как одиночный клик
                handle_single_click(
                    col,
                    row,
                    layout,
                    state,
                    input_buf,
                    input_history,
                    input_history_idx,
                    output_lines,
                    output_scroll,
                    notes_items,
                    notes_state,
                    sources_items,
                    sources_state,
                    sources_refs,
                    focus,
                    last_click_time,
                    last_click_pos,
                    mode,
                );
            }
        }
        MouseAction::Click { .. } | MouseAction::DoubleClick { .. } => {
            // Используется только в handle_single_click через timing
        }
        MouseAction::ScrollUp => {
            if mouse::hit(&layout.chat_area, me.column, me.row) {
                *output_scroll = output_scroll.saturating_sub(3);
            } else if mouse::hit(&layout.notes_area, me.column, me.row) {
                let idx = notes_state.selected().unwrap_or(0);
                notes_state.select(Some(idx.saturating_sub(1)));
            } else if mouse::hit(&layout.sources_area, me.column, me.row) {
                let idx = sources_state.selected().unwrap_or(0);
                sources_state.select(Some(idx.saturating_sub(1)));
            }
        }
        MouseAction::ScrollDown => {
            if mouse::hit(&layout.chat_area, me.column, me.row) {
                let max = output_lines.len().saturating_sub(1);
                *output_scroll = (*output_scroll + 3).min(max);
            } else if mouse::hit(&layout.notes_area, me.column, me.row) {
                let idx = notes_state.selected().unwrap_or(0);
                let max = notes_items.len().saturating_sub(1);
                notes_state.select(Some((idx + 1).min(max)));
            } else if mouse::hit(&layout.sources_area, me.column, me.row) {
                let idx = sources_state.selected().unwrap_or(0);
                let max = sources_items.len().saturating_sub(1);
                sources_state.select(Some((idx + 1).min(max)));
            }
        }
        MouseAction::RightClick { col, row } => {
            // Правый клик по источнику → внешний канал: xdg-open/$EDITOR.
            if mouse::hit(&layout.sources_area, col, row) {
                if let Some(idx) = sources_state.selected() {
                    if idx < sources_refs.len() {
                        open_source_external(&sources_refs[idx], output_lines);
                        *output_scroll = usize::MAX; // прилипить к низу
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_single_click(
    col: u16,
    row: u16,
    layout: &LayoutSnapshot,
    _state: &mut ShellState,
    _input_buf: &mut String,
    _input_history: &mut Vec<String>,
    _input_history_idx: &mut Option<usize>,
    output_lines: &mut Vec<String>,
    output_scroll: &mut usize,
    _notes_items: &mut Vec<String>,
    notes_state: &mut ListState,
    _sources_items: &mut Vec<String>,
    sources_state: &mut ListState,
    sources_refs: &mut Vec<SourceRef>,
    focus: &mut Focus,
    _last_click_time: &mut Option<Instant>,
    _last_click_pos: &mut Option<(u16, u16)>,
    mode: &mut Mode,
) {
    // Клик по Notes → выбор + переход фокуса
    if mouse::hit(&layout.notes_area, col, row) {
        *focus = Focus::Notes;
        let local_row = row.saturating_sub(layout.notes_area.y).saturating_sub(1) as usize;
        notes_state.select(Some(local_row));
        return;
    }

    // Клик по Sources → выбор + Doc Browser (список документов источника)
    if mouse::hit(&layout.sources_area, col, row) {
        *focus = Focus::Sources;
        let local_row = row.saturating_sub(layout.sources_area.y).saturating_sub(1) as usize;
        sources_state.select(Some(local_row));
        // Плейсхолдеры («нет источников», «⚠ …») не имеют ссылок.
        if local_row < sources_refs.len() {
            let bs = open_doc_browser(&sources_refs[local_row], output_lines);
            *mode = Mode::DocBrowser(bs);
            *output_scroll = usize::MAX; // прилипить к низу
        }
        return;
    }

    // Клик по Chat panel → фокус + клир выделения
    if mouse::hit(&layout.chat_area, col, row) {
        *focus = Focus::Output;
        return;
    }

    // Клик по Input panel → фокус
    if mouse::hit(&layout.input_area, col, row) {
        *focus = Focus::Input;
        return;
    }
}

fn handle_note_editor_event(ev: Event, state: &mut NoteEditorState) -> NoteEditorResult {
    if let Event::Key(k) = ev {
        match (k.code, k.modifiers) {
            (KeyCode::Esc, _) => return NoteEditorResult::Cancel,
            (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
                let body = state.body.lines().join("\n");
                return NoteEditorResult::Save(state.title_input.clone(), body);
            }
            (KeyCode::Tab, _) => {
                state.title_active = !state.title_active;
                return NoteEditorResult::Continue;
            }
            (KeyCode::BackTab, _) => {
                state.title_active = !state.title_active;
                return NoteEditorResult::Continue;
            }
            (KeyCode::Char(c), _) if state.title_active => {
                state.title_input.push(c);
                return NoteEditorResult::Continue;
            }
            (KeyCode::Backspace, _) if state.title_active => {
                state.title_input.pop();
                return NoteEditorResult::Continue;
            }
            // Все остальные клавиши идут в body (если title не активен)
            _ if !state.title_active => {
                state.body.input(tui_textarea::Input::from(k));
                return NoteEditorResult::Continue;
            }
            _ => {}
        }
    }
    // bracketed paste: в заголовок — в одну строку, в тело — как есть
    // (TextArea сам раскладывает переводы строк)
    if let Event::Paste(text) = ev {
        if state.title_active {
            state.title_input.push_str(&text.replace(['\r', '\n'], " "));
        } else {
            state.body.insert_str(&text);
        }
    }
    NoteEditorResult::Continue
}

/// Кэш ноутбука: метаданные из списка + (после полной загрузки) источники.
///
/// Notes panel: все локальные заметки (v2.0: NLM-фильтр ноутбука удалён;
/// метка [nlm] у старых записей сохраняется для обратной совместимости БД).
fn refresh_notes_list(state: &mut ShellState, notes_items: &mut Vec<String>) {
    let Some(conn) = state.ensure_notes_conn().ok() else {
        return;
    };
    let all = crate::notes::list_notes(conn, 500).unwrap_or_default();
    if all.is_empty() {
        *notes_items = vec!["(нет заметок — Ctrl+N)".into()];
        return;
    }
    *notes_items = all
        .iter()
        .map(|n| {
            let origin = if n.source == "nlm" {
                "[nlm]"
            } else {
                "[лок]"
            };
            let preview = n
                .body
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(36)
                .collect::<String>();
            format!(
                "#{} {} {}{}",
                n.id,
                origin,
                n.title,
                if preview.is_empty() {
                    String::new()
                } else {
                    format!(" — {preview}")
                }
            )
        })
        .collect();
}

/// Обновить Sources panel из poler_sources (локальные источники) и
/// синхронно заполнить `sources_refs` — по нему клик/Enter открывает
/// Doc Browser с правильным типом источника. v2.0: только локальные.
fn refresh_sources_list(
    state: &mut ShellState,
    sources_items: &mut Vec<String>,
    sources_refs: &mut Vec<SourceRef>,
) {
    sources_refs.clear();
    if let Ok(conn) = state.ensure_sources_conn() {
        let all = crate::sources::list_sources(conn, 500).unwrap_or_default();
        if all.is_empty() {
            *sources_items = vec!["(нет источников — sources add)".into()];
        } else {
            *sources_items = all
                .iter()
                .map(|s| {
                    let lbl = s
                        .label
                        .as_ref()
                        .map(|l| format!(" ({})", l))
                        .unwrap_or_default();
                    let st = match s.last_status.as_str() {
                        "ok" => "✓",
                        "fail" => "✗",
                        _ => "?",
                    };
                    format!("#{} [{}] {} {}{}", s.id, st, s.kind.as_str(), s.value, lbl)
                })
                .collect();
            for s in all {
                sources_refs.push(SourceRef::Local { src: s });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_cycle_next() {
        assert_eq!(Focus::Input.next(), Focus::Output);
        assert_eq!(Focus::Output.next(), Focus::Notes);
        assert_eq!(Focus::Notes.next(), Focus::Sources);
        assert_eq!(Focus::Sources.next(), Focus::Input);
    }

    #[test]
    fn focus_cycle_prev() {
        assert_eq!(Focus::Input.prev(), Focus::Sources);
        assert_eq!(Focus::Sources.prev(), Focus::Notes);
        assert_eq!(Focus::Notes.prev(), Focus::Output);
        assert_eq!(Focus::Output.prev(), Focus::Input);
    }

    #[test]
    fn focus_as_str_correct() {
        assert_eq!(Focus::Input.as_str(), "input");
        assert_eq!(Focus::Output.as_str(), "chat");
        assert_eq!(Focus::Notes.as_str(), "notes");
        assert_eq!(Focus::Sources.as_str(), "sources");
    }

    #[test]
    fn layout_snapshot_default_is_empty() {
        let ls = LayoutSnapshot::default();
        assert_eq!(ls.chat_area, Rect::default());
        assert_eq!(ls.palette_area, None);
    }

    #[test]
    fn v2_no_notebooks_focus_left() {
        // регрессия v2.0: вариант Notebooks удалён вместе с NLM-панелью
        assert!(!format!("{:?}", Focus::Input).contains("Notebooks"));
    }

    // ---- Doc Browser / Doc Viewer ----

    #[test]
    fn truncate_chars_utf8_safe() {
        assert_eq!(truncate_chars("short", 10), "short");
        assert_eq!(truncate_chars("12345", 3), "12…");
        // кириллица — режем по границе символов, не байтов
        let s = "привіт".repeat(20);
        let t = truncate_chars(&s, 10);
        assert_eq!(t.chars().count(), 10);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn viewer_bottom_scroll_counts_wrapped_rows() {
        // 10 строк по ≤10 символов при ширине 10 → 10 рендер-строк,
        // высота 3 → bottom = 7
        let text = "aaaa\nbbbb\ncccc\ndddd\neeee\nffff\ngggg\nhhhh\niiii\njjjj";
        assert_eq!(viewer_bottom_scroll(text, 10, 3), 7);
        // текст меньше окна → скролл 0
        assert_eq!(viewer_bottom_scroll("одна строка", 40, 10), 0);
        // длинная строка занимает несколько рендер-строк (Wrap)
        let long = "x".repeat(25);
        assert_eq!(viewer_bottom_scroll(&long, 10, 5), 0); // 3 строки < 5
        assert_eq!(viewer_bottom_scroll(&long, 10, 2), 1); // 3 строки - 2
    }

    #[test]
    fn doc_browser_state_default_selects_nothing() {
        let bs = DocBrowserState::default();
        assert!(bs.docs.is_empty());
        assert!(bs.title.is_empty());
        assert!(bs.state.selected().is_none());
    }

    #[test]
    fn open_doc_viewer_local_file_reads_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("doc.md");
        std::fs::write(&p, "# Заголовок\nтекст документа").unwrap();

        let entry = DocEntry {
            title: "doc.md".into(),
            hint: "24 B".into(),
            kind: DocKind::LocalFile { path: p.clone() },
        };
        let parent = DocBrowserState {
            title: "src".into(),
            ..Default::default()
        };
        let vs = open_doc_viewer(&entry, parent);
        assert_eq!(vs.title, "doc.md");
        assert!(vs.text.contains("Заголовок"));
        assert_eq!(vs.meta, p.display().to_string());
        assert!(vs.parent.is_some());
        assert_eq!(vs.scroll, 0);
    }

    #[test]
    fn open_doc_viewer_info_entry_is_verbatim() {
        let entry = DocEntry {
            title: "Инфо".into(),
            hint: String::new(),
            kind: DocKind::Info {
                text: "просто текст".into(),
                open_url: Some("https://example.com".into()),
            },
        };
        let vs = open_doc_viewer(&entry, DocBrowserState::default());
        assert_eq!(vs.text, "просто текст");
        assert_eq!(vs.open_url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn open_selected_doc_dir_drills_down() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("inner.txt"), "x").unwrap();

        let mut bs = DocBrowserState {
            title: "источник".into(),
            docs: vec![DocEntry {
                title: "sub".into(),
                hint: "каталог".into(),
                kind: DocKind::LocalDir { path: sub.clone() },
            }],
            state: ListState::default(),
        };
        bs.state.select(Some(0));
        // drill-down: остаёмся в списке (None), docs заменились
        assert!(open_selected_doc(&mut bs).is_none());
        assert!(bs.title.contains("sub"));
        let titles: Vec<&str> = bs.docs.iter().map(|d| d.title.as_str()).collect();
        assert!(titles.contains(&".."));
        assert!(titles.contains(&"inner.txt"));
    }

    #[test]
    fn open_selected_doc_file_opens_viewer() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, "контент").unwrap();
        let mut bs = DocBrowserState {
            title: "src".into(),
            docs: vec![DocEntry {
                title: "a.txt".into(),
                hint: "14 B".into(),
                kind: DocKind::LocalFile { path: f },
            }],
            state: ListState::default(),
        };
        bs.state.select(Some(0));
        match open_selected_doc(&mut bs) {
            Some(Mode::DocViewer(vs)) => {
                assert!(vs.text.contains("контент"));
                assert!(vs.parent.is_some());
            }
            other => panic!("ожидали DocViewer, получили {other:?}"),
        }
    }

    #[test]
    fn transcript_state_navigation() {
        let mut ts = TranscriptState {
            entries: vec![
                ChatEntry { id: 1, notebook_id: None, question: "q1".into(), answer: "a1".into(), created_at: 100 },
                ChatEntry { id: 2, notebook_id: Some("nb".into()), question: "q2".into(), answer: "ответ 2".into(), created_at: 200 },
            ],
            list: ListState::default(),
            viewing: None,
            view_scroll: 0,
            total: 2,
            status: String::new(),
        };
        ts.list.select(Some(1)); // самая свежая
        assert_eq!(ts.selected().unwrap().id, 2);
        ts.move_up();
        assert_eq!(ts.selected().unwrap().id, 1);
        ts.move_up();
        assert_eq!(ts.selected().unwrap().id, 1, "не выше первой");
        ts.move_down();
        ts.move_down();
        assert_eq!(ts.selected().unwrap().id, 2, "не ниже последней");
        // Response View
        ts.open_selected();
        assert_eq!(ts.viewing, Some(1));
        assert_eq!(ts.viewing_entry().unwrap().question, "q2");
        ts.view_scroll_down();
        assert_eq!(ts.view_scroll, 1);
        ts.view_page_up();
        assert_eq!(ts.view_scroll, 0, "скролл не уходит в минус");
    }

    #[test]
    fn transcript_overlay_renders_feed_and_response() {
        use ratatui::backend::TestBackend;
        let entries = vec![
            ChatEntry {
                id: 7,
                notebook_id: Some("nb-12345678".into()),
                question: "Как добавить квитки?".into(),
                answer: "Короткий ответ на вопрос.".into(),
                created_at: 1_787_920_496,
            },
        ];
        // Лента
        let mut ts = TranscriptState {
            entries: entries.clone(),
            list: ListState::default(),
            viewing: None,
            view_scroll: 0,
            total: 1,
            status: String::new(),
        };
        ts.list.select(Some(0));
        let backend = TestBackend::new(100, 30);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_transcript_overlay(f, &ts);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = (0..buf.area.area() as usize)
            .map(|i| buf.content()[i].symbol().to_string())
            .collect();
        assert!(text.contains("Transcript"), "заголовок ленты: {text}");
        assert!(text.contains("Как добавить"), "строка пары: {text}");
        // Response View
        ts.viewing = Some(0);
        term.draw(|f| {
            render_transcript_overlay(f, &ts);
        })
        .unwrap();
        let buf2 = term.backend().buffer().clone();
        let text2: String = (0..buf2.area.area() as usize)
            .map(|i| buf2.content()[i].symbol().to_string())
            .collect();
        assert!(text2.contains("Відповідь #7"), "шапка ответа: {text2}");
        assert!(text2.contains("Питання"), "шапка вопроса: {text2}");
        assert!(text2.contains("Короткий ответ"), "тело ответа: {text2}");
    }

    #[test]
    fn transcript_overlay_empty_feed() {
        use ratatui::backend::TestBackend;
        let ts = TranscriptState {
            entries: Vec::new(),
            list: ListState::default(),
            viewing: None,
            view_scroll: 0,
            total: 0,
            status: String::new(),
        };
        let backend = TestBackend::new(80, 24);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        term.draw(|f| {
            render_transcript_overlay(f, &ts);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = (0..buf.area.area() as usize)
            .map(|i| buf.content()[i].symbol().to_string())
            .collect();
        assert!(text.contains("Лента пуста"), "пустая лента: {text}");
    }
}
