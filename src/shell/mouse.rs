//! # Mouse capture + drag-select (v0.17.0)
//!
//! Полная поддержка мыши в терминале (как в mimocode от Xiaomi):
//!
//! - **Клик** на ноутбуке/источнике слева/справа → активирует его в центре
//! - **Двойной клик** на ноутбуке → мгновенный `nlm sync <NB_ID>`
//! - **Drag-select** на Chat panel → выделяет текст → Ctrl+Y копирует в буфер
//! - **Shift+Drag** → нативное выделение Linux (mouse capture отключается)
//!
//! ## Реализация drag-select
//!
//! Crossterm в raw-mode перехватывает все мышиные события. Когда пользователь
//! зажал ЛКМ на Chat panel, мы запоминаем стартовую (col,row). Каждый
//! `MouseEvent(MouseEventKind::Drag(MouseButton::Left, ...))` обновляет
//! прямоугольник выделения. `MouseEvent(MouseEventKind::Up(MouseButton::Left, ...))`
//! финализирует выделение и кладёт текст в буфер через `arboard`.
//!
//! Для Shift+Drag терминал сам передаёт нативное выделение (мышь в raw-mode
//! ловит только события БЕЗ модификаторов), поэтому гики получают привычное
//! поведение.

use std::sync::{Mutex, OnceLock};

use crossterm::event::{MouseEvent, MouseEventKind, MouseButton, KeyModifiers};
use ratatui::layout::Rect;

/// Прямоугольник выделения мыши (в абсолютных координатах терминала).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SelectionRect {
    pub start_col: u16,
    pub start_row: u16,
    pub end_col: u16,
    pub end_row: u16,
    pub active: bool,
}

impl SelectionRect {
    pub fn new() -> Self {
        Self::default()
    }

    /// Начать drag в точке (col, row).
    pub fn start(&mut self, col: u16, row: u16) {
        self.start_col = col;
        self.start_row = row;
        self.end_col = col;
        self.end_row = row;
        self.active = true;
    }

    /// Обновить текущее положение drag.
    pub fn extend(&mut self, col: u16, row: u16) {
        if self.active {
            self.end_col = col;
            self.end_row = row;
        }
    }

    /// Завершить drag. Возвращает `Some(rect)`, если выделение было
    /// непустым (хотя бы 1 ячейка).
    pub fn finish(&mut self) -> Option<(u16, u16, u16, u16)> {
        if !self.active {
            return None;
        }
        self.active = false;
        let (min_col, max_col) = if self.start_col <= self.end_col {
            (self.start_col, self.end_col)
        } else {
            (self.end_col, self.start_col)
        };
        let (min_row, max_row) = if self.start_row <= self.end_row {
            (self.start_row, self.end_row)
        } else {
            (self.end_row, self.start_row)
        };
        if min_col == max_col && min_row == max_row {
            None
        } else {
            Some((min_col, min_row, max_col, max_row))
        }
    }

    /// Отменить выделение (Esc, клик в другом месте).
    pub fn clear(&mut self) {
        self.active = false;
    }

    /// Нормализованный прямоугольник для рендеринга.
    pub fn bbox(&self) -> Option<(u16, u16, u16, u16)> {
        if !self.active {
            return None;
        }
        let (min_col, max_col) = if self.start_col <= self.end_col {
            (self.start_col, self.end_col)
        } else {
            (self.end_col, self.start_col)
        };
        let (min_row, max_row) = if self.start_row <= self.end_row {
            (self.start_row, self.end_row)
        } else {
            (self.end_row, self.start_row)
        };
        Some((min_col, min_row, max_col, max_row))
    }
}

/// Точка попадания клика (col, row) в прямоугольник панели.
pub fn hit(area: &Rect, col: u16, row: u16) -> bool {
    col >= area.x && col < area.x + area.width && row >= area.y && row < area.y + area.height
}

/// Перевести абсолютные (col,row) в координаты внутри прямоугольника.
pub fn to_local(area: &Rect, col: u16, row: u16) -> (u16, u16) {
    (col.saturating_sub(area.x), row.saturating_sub(area.y))
}

/// Извлечь текст из вектора строк по прямоугольнику выделения (абсолютные
/// координаты, чтобы работало между строками). `lines` — строки текста
/// (по одной ячейке на символ).
///
/// Координаты автоматически нормализуются (start<=end не обязателен).
pub fn extract_text(
    lines: &[String],
    area: &Rect,
    a_col: u16,
    a_row: u16,
    b_col: u16,
    b_row: u16,
) -> String {
    // Нормализуем (start может быть больше end если пользователь тянул вверх/влево)
    let (min_col, max_col) = if a_col <= b_col {
        (a_col, b_col)
    } else {
        (b_col, a_col)
    };
    let (min_row, max_row) = if a_row <= b_row {
        (a_row, b_row)
    } else {
        (b_row, a_row)
    };
    // Конвертируем абсолютные в локальные
    let (lcol0, lrow0) = to_local(area, min_col, min_row);
    let (lcol1, lrow1) = to_local(area, max_col, max_row);
    let mut out = String::new();
    for r in lrow0..=lrow1 {
        if (r as usize) >= lines.len() {
            break;
        }
        let line = &lines[r as usize];
        let row_chars: Vec<char> = line.chars().collect();
        let start = lcol0 as usize;
        // Последняя колонка — это позиция курсора, обычно на один символ меньше
        let end = (lcol1 as usize).min(row_chars.len());
        if start < end {
            let chunk: String = row_chars[start..end].iter().collect();
            out.push_str(&chunk);
        }
        // Перенос строки между строками (не после последней)
        if r < lrow1 {
            out.push('\n');
        }
    }
    out
}

/// Классифицировать мышиное событие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseAction {
    /// Клик ЛКМ (Up(MouseButton::Left) без перемещения).
    Click { col: u16, row: u16 },
    /// Двойной клик (детектируется вызовом по времени, здесь только сигнал).
    DoubleClick { col: u16, row: u16 },
    /// Начало drag ЛКМ.
    DragStart { col: u16, row: u16 },
    /// Продолжение drag ЛКМ.
    DragMove { col: u16, row: u16 },
    /// Конец drag ЛКМ — возвращает прямоугольник.
    DragEnd { col: u16, row: u16 },
    /// Скролл вверх.
    ScrollUp,
    /// Скролл вниз.
    ScrollDown,
    /// Правый клик (контекстное меню).
    RightClick { col: u16, row: u16 },
    /// Игнорировать (не наша мышь).
    Ignore,
}

/// Распарсить MouseEvent в MouseAction.
pub fn parse_event(ev: MouseEvent) -> MouseAction {
    match ev.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if ev.modifiers.contains(KeyModifiers::SHIFT) {
                // Shift+Click в raw-mode — игнорируем, чтобы терминал сделал нативное выделение
                MouseAction::Ignore
            } else {
                MouseAction::DragStart { col: ev.column, row: ev.row }
            }
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            if ev.modifiers.contains(KeyModifiers::SHIFT) {
                MouseAction::Ignore
            } else {
                MouseAction::DragMove { col: ev.column, row: ev.row }
            }
        }
        MouseEventKind::Up(MouseButton::Left) => {
            MouseAction::DragEnd { col: ev.column, row: ev.row }
        }
        MouseEventKind::Down(MouseButton::Right) => MouseAction::RightClick {
            col: ev.column,
            row: ev.row,
        },
        MouseEventKind::ScrollUp => MouseAction::ScrollUp,
        MouseEventKind::ScrollDown => MouseAction::ScrollDown,
        MouseEventKind::Down(MouseButton::Middle) => MouseAction::Ignore,
        _ => MouseAction::Ignore,
    }
}

/// Скопировать текст в системный буфер обмена.
///
/// # Почему не только arboard
///
/// `arboard::Clipboard` во временной переменной — ловушка на X11: содержимое
/// буфера живёт, пока жив владелец-процесс соединения. Старая реализация
/// (`Clipboard::new().set_text(..)` в одну строку) роняла владение сразу
/// после вызова — терминал отдавал пустой/протухший буфер, хотя статус
/// был «✓ Скопировано».
///
/// # Стратегия (два независимых канала, пробуем оба)
///
/// 1. **OSC 52** — escape-последовательность `\x1b]52;c;<base64>\x07`:
///    терминал САМ кладёт текст в системный буфер. Работает в SSH-сессиях,
///    tmux (через DCS-passthrough), Wayland- и X11-терминалах — там, где
///    arboard бессилен. Тихо игнорируется терминалами без поддержки.
/// 2. **arboard** — прямой доступ к буферу (X11/Wayland/macOS/Windows),
///    экземпляр держим на всё время процесса (см. [`ARBOARD`]).
///
/// Возвращает описание сработавших каналов, например `"OSC 52 + arboard"`.
pub fn copy_to_clipboard(text: &str) -> Result<String, String> {
    let mut via: Vec<&'static str> = Vec::new();
    let mut errs: Vec<String> = Vec::new();
    match osc52_copy(text) {
        Ok(()) => via.push("OSC 52"),
        Err(e) => errs.push(e),
    }
    match arboard_copy(text) {
        Ok(()) => via.push("arboard"),
        Err(e) => errs.push(e),
    }
    if via.is_empty() {
        Err(errs.join("; "))
    } else {
        Ok(via.join(" + "))
    }
}

/// arboard-Clipboard со временем жизни процесса.
///
/// На X11 буфер живёт, пока жив владелец: держим один экземпляр в static,
/// при ошибке `set_text` пересоздаём (соединение могло протухнуть).
static ARBOARD: OnceLock<Mutex<Option<arboard::Clipboard>>> = OnceLock::new();

fn arboard_copy(text: &str) -> Result<(), String> {
    let cell = ARBOARD.get_or_init(|| Mutex::new(None));
    let mut guard = cell
        .lock()
        .map_err(|e| format!("arboard: lock отравлен ({e})"))?;
    if guard.is_none() {
        *guard = Some(arboard::Clipboard::new().map_err(|e| format!("arboard: {e}"))?);
    }
    let cb = guard.as_mut().expect("инициализирован выше");
    if let Err(e) = cb.set_text(text.to_string()) {
        *guard = None; // сломанное соединение — пересоздадим при следующем копировании
        return Err(format!("arboard: {e}"));
    }
    Ok(())
}

/// Отправить OSC 52 в терминал (текст → base64 → escape-последовательность).
fn osc52_copy(text: &str) -> Result<(), String> {
    use std::io::Write;
    let payload = osc52_payload(
        &base64_encode(text.as_bytes()),
        std::env::var_os("TMUX").is_some(),
    );
    // /dev/tty — прямой канал к терминалу даже если stdout перенаправлен;
    // в TUI-режиме stdout тоже терминал — годится как fallback.
    let via_tty = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .and_then(|mut f| f.write_all(payload.as_bytes()).and_then(|_| f.flush()));
    if via_tty.is_ok() {
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(payload.as_bytes())
        .and_then(|_| out.flush())
        .map_err(|e| format!("osc52: {e}"))
}

/// OSC 52 payload: `\x1b]52;c;<base64>\x07`; в tmux — DCS-passthrough
/// с удвоением ESC внутри (как в helix/neovim).
fn osc52_payload(b64: &str, in_tmux: bool) -> String {
    let seq = format!("\x1b]52;c;{b64}\x07");
    if !in_tmux {
        return seq;
    }
    let mut wrapped = String::from("\x1bPtmux;");
    for c in seq.chars() {
        if c == '\x1b' {
            wrapped.push(c);
        }
        wrapped.push(c);
    }
    wrapped.push_str("\x1b\\");
    wrapped
}

/// Алфавит base64 (RFC 4648, стандартный, с padding).
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64-кодирование без внешних зависимостей (для OSC 52).
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_lifecycle_start_extend_finish() {
        let mut s = SelectionRect::new();
        assert!(!s.active);
        s.start(10, 5);
        assert!(s.active);
        assert_eq!(s.bbox(), Some((10, 5, 10, 5)));
        s.extend(20, 15);
        // drag идёт от (10,5) до (20,15) — bbox нормализован
        assert_eq!(s.bbox(), Some((10, 5, 20, 15)));
        s.extend(5, 1);
        // drag продолжается — теперь end=5,1; bbox = (5,1,10,5)
        // (между (10,5) и (5,1) нормализованный bbox)
        assert_eq!(s.bbox(), Some((5, 1, 10, 5)));
        let r = s.finish().unwrap();
        assert_eq!(r, (5, 1, 10, 5));
        assert!(!s.active);
    }

    #[test]
    fn finish_no_active_returns_none() {
        let mut s = SelectionRect::new();
        assert_eq!(s.finish(), None);
    }

    #[test]
    fn finish_single_cell_returns_none() {
        let mut s = SelectionRect::new();
        s.start(5, 5);
        assert_eq!(s.finish(), None, "single cell is not a selection");
    }

    #[test]
    fn hit_inside_rect() {
        let r = Rect::new(10, 5, 30, 20);
        assert!(hit(&r, 10, 5));
        assert!(hit(&r, 39, 24));
        assert!(!hit(&r, 9, 5));
        assert!(!hit(&r, 40, 5));
        assert!(!hit(&r, 10, 25));
    }

    #[test]
    fn extract_single_line() {
        let lines = vec!["Hello, world!".to_string()];
        let area = Rect::new(0, 0, 80, 24);
        // Выделить "world"
        let text = extract_text(&lines, &area, 7, 0, 12, 0);
        assert_eq!(text, "world");
    }

    #[test]
    fn extract_multi_line() {
        let lines = vec![
            "Line one".to_string(),
            "Line two".to_string(),
            "Line three".to_string(),
        ];
        let area = Rect::new(0, 0, 80, 24);
        // с позиции (5,0) до (10,2) — нормализованный прямоугольник
        let text = extract_text(&lines, &area, 5, 0, 10, 2);
        // row0: "Line one"  cols[5..8] → "one"
        // row1: "Line two"  cols[5..8] → "two"
        // row2: "Line three" cols[5..10] → "three" (но в строке 10 символов, end=min(10,10)=10)
        assert_eq!(text, "one\ntwo\nthree");
    }

    #[test]
    fn extract_multi_line_reversed_drag() {
        // drag снизу-вверх: end выше start — extract_text должен нормализовать
        let lines = vec![
            "Line one".to_string(),
            "Line two".to_string(),
        ];
        let area = Rect::new(0, 0, 80, 24);
        // с позиции (5,1) до (8,0) — drag вверх
        let text = extract_text(&lines, &area, 5, 1, 8, 0);
        // должно дать то же что и с (5,0) до (8,1): row0[5..8]="one", row1[5..8]="two"
        assert_eq!(text, "one\ntwo");
    }

    #[test]
    fn extract_clipped_to_area() {
        let lines = vec!["abc".to_string()];
        // area начинается в (10,5), но выделение в (5,5) — за пределами
        let area = Rect::new(10, 5, 80, 24);
        let text = extract_text(&lines, &area, 5, 5, 9, 5);
        // После to_local получатся отрицательные (saturating_sub) → 0,0..0,0 → пусто
        assert_eq!(text, "");
    }

    #[test]
    fn extract_when_line_shorter_than_end() {
        let lines = vec!["hi".to_string()];
        let area = Rect::new(0, 0, 80, 24);
        // Выделить с col 0 до col 10 — но в строке только 2 символа
        let text = extract_text(&lines, &area, 0, 0, 10, 0);
        assert_eq!(text, "hi");
    }

    #[test]
    fn parse_left_click() {
        let ev = crossterm::event::MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 5,
            row: 10,
            modifiers: KeyModifiers::empty(),
        };
        match parse_event(ev) {
            MouseAction::DragEnd { col, row } => {
                assert_eq!(col, 5);
                assert_eq!(row, 10);
            }
            _ => panic!("expected DragEnd"),
        }
    }

    #[test]
    fn parse_shift_click_ignored() {
        let ev = crossterm::event::MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 10,
            modifiers: KeyModifiers::SHIFT,
        };
        assert_eq!(parse_event(ev), MouseAction::Ignore);
    }

    #[test]
    fn parse_scroll() {
        let up = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        };
        assert_eq!(parse_event(up), MouseAction::ScrollUp);
        let dn = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        };
        assert_eq!(parse_event(dn), MouseAction::ScrollDown);
    }

    #[test]
    fn selection_clear_resets() {
        let mut s = SelectionRect::new();
        s.start(1, 1);
        s.extend(5, 5);
        s.clear();
        assert!(!s.active);
        assert_eq!(s.bbox(), None);
    }

    #[test]
    fn base64_rfc4648_vectors() {
        // классические тест-векторы RFC 4648
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // кириллица (UTF-8 → 2× байтов)
        assert_eq!(base64_encode("привет".as_bytes()), "0L/RgNC40LLQtdGC");
    }

    #[test]
    fn osc52_payload_plain() {
        let p = osc52_payload("Zm9v", false);
        assert_eq!(p, "\x1b]52;c;Zm9v\x07");
    }

    #[test]
    fn osc52_payload_tmux_passthrough() {
        // в tmux: DCS-обёртка Ptmux; + ESC удвоен внутри + ST
        let p = osc52_payload("Zm9v", true);
        assert_eq!(p, "\x1bPtmux;\x1b\x1b]52;c;Zm9v\x07\x1b\\");
    }

    #[test]
    fn copy_to_clipboard_reports_channel_or_error() {
        // В headless-окружении (CI) оба канала могут упасть — тогда Err;
        // на десктопе хотя бы один сработает — тогда Ok с именем канала.
        // Проверяем только контракт: Ok — непустая строка, Err — непустая.
        match copy_to_clipboard("poler-engine clipboard test") {
            Ok(via) => assert!(!via.is_empty()),
            Err(e) => assert!(!e.is_empty()),
        }
    }
}
