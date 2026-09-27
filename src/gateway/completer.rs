//! # Terminal Gateway: Tab-completion (v0.22.0)
//!
//! Первый токен: команды движка + бинарники из PATH (кэш на первый вызов).
//! Подкоманды: `service`/`attach`/`weblens`. Остальные позиции — имена
//! файлов текущего каталога (rustyline FilenameCompleter).

use rustyline::completion::{Completer, FilenameCompleter, Pair};
use std::sync::OnceLock;

use super::dispatch::is_engine_command;

/// Кэш исполняемых файлов PATH (один readdir на сессию).
static PATH_BINS: OnceLock<Vec<String>> = OnceLock::new();

fn path_binaries() -> &'static Vec<String> {
    PATH_BINS.get_or_init(|| {
        let mut names: Vec<String> = Vec::new();
        if let Ok(paths) = std::env::var("PATH") {
            for dir in paths.split(':') {
                if dir.is_empty() {
                    continue;
                }
                if let Ok(rd) = std::fs::read_dir(dir) {
                    for e in rd.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if !name.is_empty()
                            && !name.contains('/')
                            && e.path().is_file()
                            && is_executable(&e.path())
                        {
                            names.push(name);
                        }
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        names
    })
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_p: &std::path::Path) -> bool {
    true
}

/// Подкоманды сервисного блока.
const SERVICE_SUBS: &[&str] = &["start", "stop", "restart", "status", "attach"];
const SERVICE_NAMES: &[&str] = &["mcp", "weblens", "companion"];
const WEBLENS_SUBS: &[&str] = &["start", "stop", "status"];
/// v0.25.0: подкоманды Container Jail.
const BOX_SUBS: &[&str] = &["on", "off", "status", "shell", "runner", "sudo", "root", "hunt", "allow"];

/// Комплетер Terminal Gateway.
pub struct GatewayCompleter {
    files: FilenameCompleter,
}

impl Default for GatewayCompleter {
    fn default() -> Self {
        Self {
            files: FilenameCompleter::new(),
        }
    }
}

impl Completer for GatewayCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let head = &line[..pos];
        let tokens: Vec<&str> = head.split_whitespace().collect();
        let in_first_token = !head.ends_with(' ') && !head.is_empty();

        // --- первое слово: команды движка + PATH ---
        if tokens.is_empty() || (tokens.len() == 1 && in_first_token) {
            let prefix = tokens.first().copied().unwrap_or("");
            let mut cands: Vec<String> = Vec::new();
            for c in engine_command_list() {
                if c.starts_with(prefix) {
                    cands.push(c.to_string());
                }
            }
            for b in path_binaries() {
                if b.starts_with(prefix) && !is_engine_command(b) {
                    cands.push(b.clone());
                }
            }
            let start = pos - prefix.len();
            return Ok((
                start,
                cands
                    .into_iter()
                    .map(|c| Pair { display: c.clone(), replacement: c })
                    .collect(),
            ));
        }

        // --- подкоманды сервисного блока ---
        let cmd = tokens[0];
        let cur = if in_first_token { "" } else { tokens.last().copied().unwrap_or("") };
        let word_start = pos - cur.len();
        let last_is_current = !in_first_token || tokens.len() == 1;
        let _ = last_is_current;

        if tokens.len() >= 2 || !in_first_token {
            let subs: Vec<String> = match cmd {
                "service" => {
                    // service <sub> [name]
                    if tokens.len() == 2 && in_first_token {
                        SERVICE_NAMES
                            .iter()
                            .filter(|n| n.starts_with(cur))
                            .map(|s| s.to_string())
                            .collect()
                    } else if !in_first_token && tokens.len() == 2 {
                        SERVICE_NAMES.iter().map(|s| s.to_string()).collect()
                    } else {
                        SERVICE_SUBS
                            .iter()
                            .filter(|s| s.starts_with(cur))
                            .map(|s| s.to_string())
                            .collect()
                    }
                }
                "attach" => SERVICE_NAMES
                    .iter()
                    .filter(|n| n.starts_with(cur))
                    .map(|s| s.to_string())
                    .collect(),
                "weblens" => WEBLENS_SUBS
                    .iter()
                    .filter(|s| s.starts_with(cur))
                    .map(|s| s.to_string())
                    .collect(),
                "box" => BOX_SUBS
                    .iter()
                    .filter(|s| s.starts_with(cur))
                    .map(|s| s.to_string())
                    .collect(),
                _ => Vec::new(),
            };
            if !subs.is_empty() {
                return Ok((
                    word_start,
                    subs.into_iter()
                        .map(|c| Pair { display: c.clone(), replacement: c })
                        .collect(),
                ));
            }
        }

        // --- остальное: имена файлов (как в обычном шелле) ---
        self.files.complete(line, pos, ctx)
    }
}

/// Полный список команд движка первого уровня (gateway-словарь).
fn engine_command_list() -> &'static Vec<String> {
    static LIST: OnceLock<Vec<String>> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut v: Vec<String> = [
            "search", "web", "stats", "sync", "set", "crawl", "impact", "gh", "gl", "gt",
            "gix", "notes", "sources", "grep", "chunk", "benchmark", "service", "attach",
            "weblens", "license", "cd", "pwd", "clear", "host", "help", "version", "quit",
            // v0.23.0
            "workspace", "grant", "pty",
            // v0.24.0
            "allow",
            // v0.25.0
            "box",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.sort();
        v
    })
}

impl rustyline::highlight::Highlighter for GatewayCompleter {}

impl rustyline::hint::Hinter for GatewayCompleter {
    type Hint = String;
}

impl rustyline::validate::Validator for GatewayCompleter {}

// Helper требует всех четырёх трейтов (Completer + Hinter + Highlighter +
// Validator) — blanket impl в rustyline не предусмотрен (канон из
// shell/completer.rs)
impl rustyline::Helper for GatewayCompleter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_list_contains_core() {
        let l = engine_command_list();
        for c in ["grep", "chunk", "search", "service", "license"] {
            assert!(l.contains(&c.to_string()), "нет {c}");
        }
    }

    #[test]
    fn path_binaries_cache_populated() {
        let bins = path_binaries();
        // в тестовом окружении PATH непуст: ls/cat обязаны найтись
        assert!(bins.iter().any(|b| b == "ls"), "ls не найден в PATH-кэше");
    }
}
