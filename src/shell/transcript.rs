//! # Transcript — лента чата `nlm ask` (v0.17.4)
//!
//! Персистентный журнал вопросов/ответов NotebookLM в той же SQLite-БД
//! (`web-index.db`), таблица `poler_chat`. Это восстановление ключевой
//! функции Ask-вкладки Web GUI (удалён в v0.17.0): «Історія чату» —
//! лента пар вопрос→ответ — и «Відповідь» — просмотр полного ответа.
//!
//! ## Схема
//! ```sql
//! CREATE TABLE IF NOT EXISTS poler_chat (
//!   id          INTEGER PRIMARY KEY AUTOINCREMENT,
//!   notebook_id TEXT,            -- NLM notebook UUID (nullable)
//!   question    TEXT NOT NULL,
//!   answer      TEXT NOT NULL,
//!   created_at  INTEGER NOT NULL  -- unix epoch
//! );
//! ```
//!
//! В TUI открывается окном-оверлеем **F3**: лента пар (↑↓, Enter —
//! полный ответ, y — копировать, Esc — закрыть). Записи создаются
//! автоматически при каждом успешном `nlm ask`.

use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

/// Одна пара «вопрос → ответ» из ленты чата.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatEntry {
    pub id: i64,
    pub notebook_id: Option<String>,
    pub question: String,
    pub answer: String,
    pub created_at: i64,
}

/// Создать таблицу `poler_chat`, если её ещё нет (идемпотентно).
pub fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS poler_chat (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            notebook_id TEXT,
            question    TEXT NOT NULL,
            answer      TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_polychat_nb ON poler_chat(notebook_id);
        CREATE INDEX IF NOT EXISTS idx_polychat_ts ON poler_chat(created_at);",
    )
    .map_err(|e| format!("transcript::ensure_schema: {e}"))?;
    Ok(())
}

/// Добавить пару в ленту. Возвращает id записи.
pub fn add_entry(
    conn: &Connection,
    notebook_id: Option<&str>,
    question: &str,
    answer: &str,
) -> Result<i64, String> {
    ensure_schema(conn)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO poler_chat (notebook_id, question, answer, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![notebook_id, question, answer, ts],
    )
    .map_err(|e| format!("transcript::add_entry: {e}"))?;
    Ok(conn.last_insert_rowid())
}

/// Лента: последние `limit` пар, **от старых к новым** (feed-порядок —
/// новые снизу, как в чате). Пустой результат — пустая лента.
pub fn list_entries(conn: &Connection, limit: usize) -> Result<Vec<ChatEntry>, String> {
    ensure_schema(conn)?;
    let recent: Vec<ChatEntry> = {
        let mut stmt = conn
            .prepare(
                "SELECT id, notebook_id, question, answer, created_at
                 FROM poler_chat
                 ORDER BY id DESC
                 LIMIT ?1",
            )
            .map_err(|e| format!("transcript::list_entries: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                Ok(ChatEntry {
                    id: row.get(0)?,
                    notebook_id: row.get(1)?,
                    question: row.get(2)?,
                    answer: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| format!("transcript::list_entries: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("transcript::list_entries: {e}"))?
    };
    let mut feed = recent;
    feed.reverse(); // старые сверху, новые снизу
    Ok(feed)
}

/// Общее число пар в ленте (для заголовка окна).
pub fn count(conn: &Connection) -> Result<i64, String> {
    ensure_schema(conn)?;
    conn.query_row("SELECT COUNT(*) FROM poler_chat", [], |row| row.get(0))
        .map_err(|e| format!("transcript::count: {e}"))
}

/// Удалить запись из ленты.
pub fn delete_entry(conn: &Connection, id: i64) -> Result<(), String> {
    conn.execute("DELETE FROM poler_chat WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| format!("transcript::delete_entry: {e}"))?;
    Ok(())
}

/// Unix epoch → «DD.MM HH:MM» (локальное время не отслеживаем — UTC;
/// алгоритм Г. Хиннанта days_from_civil, без внешних зависимостей).
pub fn format_ts(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    // civil_from_days: дней с 1970-01-01 → (год, месяц, день)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    format!("{d:02}.{month:02}.{year:04} {h:02}:{m:02}")
}

/// Строка ленты: `#id [время] NB — вопрос… (N символов ответа)`.
pub fn feed_line(e: &ChatEntry) -> String {
    let nb = e
        .notebook_id
        .as_deref()
        .unwrap_or("—")
        .chars()
        .take(8)
        .collect::<String>();
    let q: String = e
        .question
        .replace(['\n', '\r', '\t'], " ")
        .chars()
        .take(48)
        .collect();
    format!(
        "#{:<4} [{}] {:<8} {:<48} → {:>6} симв.",
        e.id,
        format_ts(e.created_at),
        nb,
        q,
        e.answer.chars().count()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn add_list_feed_order() {
        let conn = mem();
        add_entry(&conn, Some("nb-uuid-1234"), "вопрос 1", "ответ 1").unwrap();
        add_entry(&conn, None, "вопрос 2", "ответ 2 подлиннее").unwrap();
        assert_eq!(count(&conn).unwrap(), 2);
        let feed = list_entries(&conn, 10).unwrap();
        assert_eq!(feed.len(), 2);
        // Feed-порядок: старые сверху, новые снизу.
        assert_eq!(feed[0].question, "вопрос 1");
        assert_eq!(feed[1].question, "вопрос 2");
        assert_eq!(feed[1].id, 2);
        assert!(feed[1].created_at >= feed[0].created_at);
    }

    #[test]
    fn limit_takes_recent() {
        let conn = mem();
        for i in 0..10 {
            add_entry(&conn, None, &format!("q{i}"), "a").unwrap();
        }
        let feed = list_entries(&conn, 3).unwrap();
        assert_eq!(feed.len(), 3);
        // Последние 3: id 8, 9, 10 в порядке возрастания.
        assert_eq!(feed[0].id, 8);
        assert_eq!(feed[2].id, 10);
    }

    #[test]
    fn delete_entry_works() {
        let conn = mem();
        let id = add_entry(&conn, None, "q", "a").unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
        delete_entry(&conn, id).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
        assert!(list_entries(&conn, 10).unwrap().is_empty());
    }

    #[test]
    fn schema_idempotent() {
        let conn = mem();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        add_entry(&conn, None, "q", "a").unwrap();
    }

    #[test]
    fn ts_format_civil() {
        // 2026-08-28 12:34:56 UTC → 28.08.2026 12:34
        let ts = 1_787_920_496_i64; // известная точка: 2026-08-28T12:34:56Z
        let s = format_ts(ts);
        assert!(s.starts_with("28.08.2026 12:34"), "got {s}");
        // Эпоха.
        assert_eq!(format_ts(0), "01.01.1970 00:00");
        // Високосный 2024-02-29.
        let leap = 1_709_164_800_i64; // 2024-02-29T00:00:00Z
        assert!(format_ts(leap).starts_with("29.02.2024"), "got {}", format_ts(leap));
    }

    #[test]
    fn feed_line_layout() {
        let e = ChatEntry {
            id: 7,
            notebook_id: Some("abcdefgh-1234".into()),
            question: "Как добавить квитки?".into(),
            answer: "очень длинный ответ".repeat(50),
            created_at: 1_787_920_496,
        };
        let line = feed_line(&e);
        assert!(line.contains("#7"));
        assert!(line.contains("abcdefgh"));
        assert!(line.contains("Как добавить"));
        assert!(line.contains("симв."));
    }
}
