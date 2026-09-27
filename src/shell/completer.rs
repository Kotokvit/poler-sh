//! Tab-completion для REPL poler-shell. Реализует `rustyline::Completer`
//! поверх списка команд `ShellState::commands()` + `set_keys()`.
//! Завершает первое слово команды и подкоманды `set`/`notes`/`sources`/vcs.
//!
//! v2.0: NLM-подкоманды удалены вместе с Google/NotebookLM.

use rustyline::completion::Completer;

use super::state::ShellState;

/// Комплетер poler-shell: завершает команды и подкоманды.
pub struct PolerCompleter;

impl Default for PolerCompleter {
    fn default() -> Self {
        Self
    }
}

static CMD_HINTS: &[(&str, &str)] = &[
    ("search", "search \"<query>\" [--top N]"),
    ("web", "web \"<query>\" [--top N]"),
    ("stats", "stats"),
    ("sync", "sync vcs [gh|gl|gt|gix|all] [OWNER]"),
    ("crawl", "crawl <URL> [--depth N] [--max M] [--cross] [--delay-ms N]"),
    ("impact", "impact <PATH> <SYMBOL> [--depth N] [--cache <DB>]"),
    ("gh", "gh search|repos|commits|issues ... (GitHub REST)"),
    ("gl", "gl search|repos|commits|issues ... (GitLab REST v4)"),
    ("gt", "gt search|repos|commits|issues ... (Gitea REST)"),
    ("gix", "gix log <PATH> [--top N] | gix clone <URL> <PATH> [--depth N] [--branch B] | gix lfs <list|fetch> <PATH>"),
    ("set", "set format|top <value>"),
    ("help", "help"),
    ("quit", "quit"),
    ("exit", "exit"),
    ("version", "version"),
];

/// Чистая функция: вернуть список кандидатов для замены `prefix`.
/// Тестируется без rustyline Context (через `complete_prefix`).
pub fn complete_prefix(prefix: &str) -> (usize, Vec<String>) {
    let tokens = prefix.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return (
            0,
            ShellState::commands().iter().map(|s| s.to_string()).collect(),
        );
    }
    let first = tokens[0];
    let in_first_token = !prefix.ends_with(' ');

    // Печатаем первое слово, курсор в нём
    if tokens.len() == 1 && in_first_token {
        let cands: Vec<String> = ShellState::commands()
            .iter()
            .filter(|c| c.starts_with(first))
            .map(|c| (*c).to_string())
            .collect();
        return (prefix.len() - first.len(), cands);
    }

    // Команда `set` — завершаем ключ
    if first == "set" {
        let sub_prefix = if tokens.len() >= 2 && in_first_token {
            tokens[1]
        } else {
            ""
        };
        let cands: Vec<String> = ShellState::set_keys()
            .iter()
            .filter(|s| s.starts_with(sub_prefix))
            .map(|s| (*s).to_string())
            .collect();
        let replace_from = prefix.find("set ").map(|i| i + 4).unwrap_or(prefix.len());
        return (replace_from, cands);
    }

    // v0.16.0: gh/gl/gt — завершаем подкоманду (search/repos/commits/issues)
    if matches!(first, "gh" | "gl" | "gt") {
        let sub_prefix = if tokens.len() >= 2 && in_first_token {
            tokens[1]
        } else {
            ""
        };
        let cands: Vec<String> = ShellState::vcs_subcommands()
            .iter()
            .filter(|s| s.starts_with(sub_prefix))
            .map(|s| (*s).to_string())
            .collect();
        let replace_from = prefix
            .find(&format!("{first} "))
            .map(|i| i + first.len() + 1)
            .unwrap_or(prefix.len());
        return (replace_from, cands);
    }

    // v0.16.0: gix — завершаем подкоманду (log/clone)
    if first == "gix" {
        let sub_prefix = if tokens.len() >= 2 && in_first_token {
            tokens[1]
        } else {
            ""
        };
        let cands: Vec<String> = ShellState::gix_subcommands()
            .iter()
            .filter(|s| s.starts_with(sub_prefix))
            .map(|s| (*s).to_string())
            .collect();
        let replace_from = prefix.find("gix ").map(|i| i + 4).unwrap_or(prefix.len());
        return (replace_from, cands);
    }

    // notes — завершаем подкоманду (list/add/show/edit/rm)
    if first == "notes" {
        let sub_prefix = if tokens.len() >= 2 && in_first_token {
            tokens[1]
        } else {
            ""
        };
        let cands: Vec<String> = ShellState::notes_subcommands()
            .iter()
            .filter(|s| s.starts_with(sub_prefix))
            .map(|s| (*s).to_string())
            .collect();
        let replace_from = prefix.find("notes ").map(|i| i + 6).unwrap_or(prefix.len());
        return (replace_from, cands);
    }

    // v0.17.0: sources — завершаем подкоманду (list/add/rm/test/open)
    if first == "sources" {
        let sub_prefix = if tokens.len() >= 2 && in_first_token {
            tokens[1]
        } else {
            ""
        };
        let cands: Vec<String> = ShellState::sources_subcommands()
            .iter()
            .filter(|s| s.starts_with(sub_prefix))
            .map(|s| (*s).to_string())
            .collect();
        let replace_from = prefix.find("sources ").map(|i| i + 8).unwrap_or(prefix.len());
        return (replace_from, cands);
    }

    // v0.17.0: `sources add <value> --kind <TAB>` — завершаем kind
    if first == "sources" && tokens.len() >= 3 && tokens[1] == "add" {
        // ищем --kind в args
        if tokens.iter().any(|t| *t == "--kind") && in_first_token {
            let last = tokens[tokens.len() - 1];
            let cands: Vec<String> = ShellState::source_kinds()
                .iter()
                .filter(|s| s.starts_with(last))
                .map(|s| (*s).to_string())
                .collect();
            let replace_from = prefix.rfind(last).unwrap_or(prefix.len());
            return (replace_from, cands);
        }
    }

    // v0.16.0: `sync vcs <scheme>` — завершаем scheme после "sync vcs "
    if first == "sync" {
        if tokens.len() >= 2 && tokens[1] == "vcs" {
            // ожидаем scheme как 3-й токен
            let sub_prefix = if tokens.len() >= 3 && in_first_token {
                tokens[2]
            } else {
                ""
            };
            let cands: Vec<String> = ShellState::vcs_schemes()
                .iter()
                .filter(|s| s.starts_with(sub_prefix))
                .map(|s| (*s).to_string())
                .collect();
            let replace_from = prefix
                .find("sync vcs ")
                .map(|i| i + "sync vcs ".len())
                .unwrap_or(prefix.len());
            return (replace_from, cands);
        }
        // `sync ` без vcs — подсказываем vcs как первую подкоманду
        let sub_prefix = if tokens.len() >= 2 && in_first_token {
            tokens[1]
        } else {
            ""
        };
        let cands: Vec<String> = ["vcs", "all"]
            .iter()
            .filter(|s| s.starts_with(sub_prefix))
            .map(|s| (*s).to_string())
            .collect();
        let replace_from = prefix.find("sync ").map(|i| i + 5).unwrap_or(prefix.len());
        return (replace_from, cands);
    }

    // v0.15.1: crawl/impact — завершаем флаги (--depth/--max/...)
    // после первого слова. После флага со значением можно продолжать.
    if first == "crawl" {
        return complete_crawl_flags(prefix, &tokens, in_first_token);
    }
    if first == "impact" {
        return complete_impact_flags(prefix, &tokens, in_first_token);
    }

    (prefix.len(), Vec::new())
}

/// v0.15.1: Завершение флагов `crawl`. Если курсор в начале нового токена
/// (префикс заканчивается пробелом) и предыдущий токен — value-флаг
/// (требует значение, например --depth), то не предлагаем флаги (ждём число).
/// Иначе предлагаем флаги, начинающиеся с введённого префикса.
fn complete_crawl_flags(prefix: &str, tokens: &[&str], in_first_token: bool) -> (usize, Vec<String>) {
    const FLAGS: &[&str] = &[
        "--depth", "--max", "--cross", "--delay-ms", "--wait-ms", "--cdp-port", "--help",
    ];
    // value-флаги: после них ждётся число, а не другой флаг
    const VALUE_FLAGS: &[&str] = &["--depth", "--max", "--delay-ms", "--wait-ms", "--cdp-port"];

    // Текущий токен (если курсор в нём) или пустой (если курсор после пробела)
    let cur = if in_first_token { tokens.last().copied().unwrap_or("") } else { "" };

    // Если курсор сразу после пробела и предыдущий токен — value-флаг, не дополняем.
    if !in_first_token {
        if let Some(prev) = tokens.last() {
            if VALUE_FLAGS.contains(prev) {
                return (prefix.len(), Vec::new());
            }
        }
        // после пробела — предлагать все флаги
        let cands: Vec<String> = FLAGS.iter().map(|s| (*s).to_string()).collect();
        let replace_from = prefix.len();
        return (replace_from, cands);
    }

    // Курсор в токене — фильтруем по префиксу (только если начинается с --)
    if !cur.starts_with('-') {
        return (prefix.len(), Vec::new());
    }
    let cands: Vec<String> = FLAGS
        .iter()
        .filter(|f| f.starts_with(cur))
        .map(|s| (*s).to_string())
        .collect();
    let replace_from = prefix.len() - cur.len();
    (replace_from, cands)
}

/// v0.15.1: Завершение флагов `impact`. Аналогично crawl, но свой набор.
fn complete_impact_flags(prefix: &str, tokens: &[&str], in_first_token: bool) -> (usize, Vec<String>) {
    const FLAGS: &[&str] = &["--depth", "--cache", "--max-file-bytes", "--help"];
    const VALUE_FLAGS: &[&str] = &["--depth", "--cache", "--max-file-bytes"];

    let cur = if in_first_token { tokens.last().copied().unwrap_or("") } else { "" };

    if !in_first_token {
        if let Some(prev) = tokens.last() {
            if VALUE_FLAGS.contains(prev) {
                return (prefix.len(), Vec::new());
            }
        }
        let cands: Vec<String> = FLAGS.iter().map(|s| (*s).to_string()).collect();
        let replace_from = prefix.len();
        return (replace_from, cands);
    }

    if !cur.starts_with('-') {
        return (prefix.len(), Vec::new());
    }
    let cands: Vec<String> = FLAGS
        .iter()
        .filter(|f| f.starts_with(cur))
        .map(|s| (*s).to_string())
        .collect();
    let replace_from = prefix.len() - cur.len();
    (replace_from, cands)
}

impl Completer for PolerCompleter {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let prefix = &line[..pos.min(line.len())];
        Ok(complete_prefix(prefix))
    }
}

impl rustyline::hint::Hinter for PolerCompleter {
    type Hint = String;

    fn hint(&self, line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<Self::Hint> {
        hint_for_line(line)
    }
}

/// Чистая функция: вернуть подсказку для строки ввода (используется и Hinter'ом).
pub fn hint_for_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.split_whitespace().next()?;
    CMD_HINTS.iter().find_map(|(k, v)| {
        if first == *k {
            Some(format!("  # {}", v))
        } else {
            None
        }
    })
}



impl rustyline::highlight::Highlighter for PolerCompleter {}

impl rustyline::validate::Validator for PolerCompleter {}

/// v0.15.1: PolerCompleter реализует все 4 трейта (Completer + Hinter +
/// Highlighter + Validator). Helper — это supertrait, который требует всех
/// четырёх, но blanket impl в rustyline НЕ предусмотрен — нужно явное объявление
/// `impl Helper for PolerCompleter {}`. Это и позволяет подключить его в
/// `Editor::<PolerCompleter, _>::new()` в `commands::run_shell` —
/// Tab-completion, hints, validation включены.
impl rustyline::Helper for PolerCompleter {}

#[cfg(test)]
fn _poler_completer_implements_helper() {
    fn assert_helper<H: rustyline::Helper>(_h: H) {}
    assert_helper(PolerCompleter::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_first_token_search() {
        let (start, cands) = complete_prefix("sear");
        assert!(cands.iter().any(|c| c == "search"), "search should complete from 'sear'");
        assert_eq!(start, 0);
    }

    #[test]
    fn complete_nlm_is_gone_in_v2() {
        // v2.0: NLM-команда удалена — подсказок нет
        let (_, cands) = complete_prefix("nlm l");
        assert!(cands.is_empty(), "v2.0: nlm-подкоманд больше нет: {cands:?}");
    }

    #[test]
    fn complete_set_keys() {
        let (start, cands) = complete_prefix("set fo");
        assert!(cands.iter().any(|c| c == "format"));
        assert!(start >= 4);
    }

    #[test]
    fn complete_set_after_space() {
        let (_, cands) = complete_prefix("set ");
        assert!(cands.iter().any(|c| c == "format"));
        assert!(cands.iter().any(|c| c == "top"));
    }

    #[test]
    fn complete_empty_line_returns_all_commands() {
        let (_, cands) = complete_prefix("");
        assert!(cands.len() >= 8);
        assert!(cands.iter().any(|c| c == "search"));
        // v0.17.0: notes/sources должны быть в списке команд
        assert!(cands.iter().any(|c| c == "notes"));
        assert!(cands.iter().any(|c| c == "sources"));
    }

    #[test]
    fn complete_notes_subcommands_v017() {
        let (start, cands) = complete_prefix("notes l");
        assert!(cands.iter().any(|c| c == "list"));
        assert!(cands.iter().any(|c| c == "add") == false, "add doesn't start with 'l'");
        assert!(start >= 6);
    }

    #[test]
    fn complete_notes_after_space() {
        let (_, cands) = complete_prefix("notes ");
        assert!(cands.iter().any(|c| c == "list"));
        assert!(cands.iter().any(|c| c == "add"));
        assert!(cands.iter().any(|c| c == "show"));
        assert!(cands.iter().any(|c| c == "edit"));
        assert!(cands.iter().any(|c| c == "rm"));
    }

    #[test]
    fn complete_sources_subcommands_v017() {
        let (start, cands) = complete_prefix("sources ad");
        assert!(cands.iter().any(|c| c == "add"));
        assert!(cands.iter().any(|c| c == "rm") == false, "rm doesn't start with 'ad'");
        assert!(start >= 8);
    }

    #[test]
    fn complete_sources_after_space() {
        let (_, cands) = complete_prefix("sources ");
        assert!(cands.iter().any(|c| c == "list"));
        assert!(cands.iter().any(|c| c == "add"));
        assert!(cands.iter().any(|c| c == "rm"));
        assert!(cands.iter().any(|c| c == "test"));
        assert!(cands.iter().any(|c| c == "open"));
    }

    #[test]
    fn complete_empty_line_returns_all_commands_full() {
        let (_, cands) = complete_prefix("");
        assert!(!cands.iter().any(|c| c == "nlm"), "v2.0: nlm удалён");
        assert!(cands.iter().any(|c| c == "quit"));
        assert!(cands.iter().any(|c| c == "notes"));
    }

    #[test]
    fn complete_unknown_prefix_returns_empty() {
        let (_, cands) = complete_prefix("zzz");
        assert!(cands.is_empty(), "unknown prefix should yield no completions");
    }

    #[test]
    fn hint_for_search_command() {
        let h = hint_for_line("search ");
        assert!(h.is_some());
        assert!(h.unwrap().contains("search"));
    }

    #[test]
    fn hint_empty_line_is_none() {
        assert!(hint_for_line("").is_none());
    }

    #[test]
    fn hint_for_nlm_is_none_in_v2() {
        assert!(hint_for_line("nlm ").is_none(), "v2.0: nlm-подсказок больше нет");
    }

    // v0.15.1: crawl/impact completion tests

    #[test]
    fn complete_crawl_first_token() {
        let (start, cands) = complete_prefix("cra");
        assert!(cands.iter().any(|c| c == "crawl"));
        assert_eq!(start, 0);
    }

    #[test]
    fn complete_crawl_flags_after_space() {
        let (_, cands) = complete_prefix("crawl https://example.com ");
        assert!(cands.iter().any(|c| c == "--depth"));
        assert!(cands.iter().any(|c| c == "--max"));
        assert!(cands.iter().any(|c| c == "--cross"));
        assert!(cands.iter().any(|c| c == "--help"));
    }

    #[test]
    fn complete_crawl_flag_prefix() {
        let (start, cands) = complete_prefix("crawl https://example.com --de");
        assert!(cands.iter().any(|c| c == "--depth"));
        assert!(!cands.iter().any(|c| c == "--max"));
        assert!(start > 0, "replace_from must point to '--' position");
    }

    #[test]
    fn complete_crawl_after_value_flag_returns_empty() {
        // После --depth (value-флаг) ждём число, не флаги
        let (_, cands) = complete_prefix("crawl https://example.com --depth ");
        assert!(cands.is_empty(), "after --depth (value flag) we expect no flag completions");
    }

    #[test]
    fn complete_crawl_no_flag_completion_for_url() {
        // Курсор в URL (не --) — не предлагаем флаги
        let (_, cands) = complete_prefix("crawl https://example.com");
        assert!(cands.is_empty(), "no flag completions when typing URL");
    }

    #[test]
    fn complete_crawl_max_flag() {
        let (start, cands) = complete_prefix("crawl https://example.com --m");
        assert!(cands.iter().any(|c| c == "--max"));
        assert!(!cands.iter().any(|c| c == "--depth"));
        assert!(start > 0);
    }

    #[test]
    fn complete_impact_first_token() {
        let (start, cands) = complete_prefix("imp");
        assert!(cands.iter().any(|c| c == "impact"));
        assert_eq!(start, 0);
    }

    #[test]
    fn complete_impact_flags_after_space() {
        let (_, cands) = complete_prefix("impact ./src main ");
        assert!(cands.iter().any(|c| c == "--depth"));
        assert!(cands.iter().any(|c| c == "--cache"));
        assert!(cands.iter().any(|c| c == "--help"));
    }

    #[test]
    fn complete_impact_flag_prefix() {
        let (start, cands) = complete_prefix("impact ./src main --c");
        assert!(cands.iter().any(|c| c == "--cache"));
        assert!(!cands.iter().any(|c| c == "--depth"));
        assert!(start > 0);
    }

    #[test]
    fn complete_impact_after_value_flag_returns_empty() {
        let (_, cands) = complete_prefix("impact ./src main --depth ");
        assert!(cands.is_empty(), "after --depth we expect no flag completions");
    }

    #[test]
    fn complete_impact_no_flag_completion_for_symbol() {
        // Курсор в symbol (не --) — не предлагаем флаги
        let (_, cands) = complete_prefix("impact ./src mai");
        assert!(cands.is_empty());
    }

    #[test]
    fn hint_for_crawl_command() {
        let h = hint_for_line("crawl ");
        assert!(h.is_some());
        assert!(h.unwrap().contains("URL"));
    }

    #[test]
    fn hint_for_impact_command() {
        let h = hint_for_line("impact ");
        assert!(h.is_some());
        assert!(h.unwrap().contains("PATH"));
    }

    // ---- v0.16.0: VCS-команды (gh/gl/gt/gix/sync vcs) ----

    #[test]
    fn complete_gh_first_token() {
        let (_, cands) = complete_prefix("g");
        assert!(cands.iter().any(|c| c == "gh"));
        assert!(cands.iter().any(|c| c == "gix"));
    }

    #[test]
    fn complete_gh_subcommands() {
        let (_, cands) = complete_prefix("gh ");
        assert!(cands.iter().any(|c| c == "search"));
        assert!(cands.iter().any(|c| c == "repos"));
        assert!(cands.iter().any(|c| c == "commits"));
        assert!(cands.iter().any(|c| c == "issues"));
    }

    #[test]
    fn complete_gh_prefix_filters() {
        let (_, cands) = complete_prefix("gh sea");
        assert!(cands.iter().any(|c| c == "search"));
        assert!(!cands.iter().any(|c| c == "repos"));
    }

    #[test]
    fn complete_gl_subcommands() {
        let (_, cands) = complete_prefix("gl ");
        assert!(cands.iter().any(|c| c == "search"));
        assert!(cands.iter().any(|c| c == "commits"));
    }

    #[test]
    fn complete_gt_subcommands() {
        let (_, cands) = complete_prefix("gt ");
        assert!(cands.iter().any(|c| c == "issues"));
    }

    #[test]
    fn complete_gix_subcommands() {
        let (_, cands) = complete_prefix("gix ");
        assert!(cands.iter().any(|c| c == "log"));
        assert!(cands.iter().any(|c| c == "clone"));
    }

    #[test]
    fn complete_gix_prefix_filters() {
        let (_, cands) = complete_prefix("gix lo");
        assert!(cands.iter().any(|c| c == "log"));
        assert!(!cands.iter().any(|c| c == "clone"));
    }

    #[test]
    fn complete_sync_suggests_vcs() {
        let (_, cands) = complete_prefix("sync ");
        assert!(cands.iter().any(|c| c == "vcs"));
    }

    #[test]
    fn complete_sync_vcs_suggests_schemes() {
        let (_, cands) = complete_prefix("sync vcs ");
        assert!(cands.iter().any(|c| c == "gh"));
        assert!(cands.iter().any(|c| c == "gl"));
        assert!(cands.iter().any(|c| c == "gt"));
        assert!(cands.iter().any(|c| c == "gix"));
        assert!(cands.iter().any(|c| c == "all"));
    }

    #[test]
    fn complete_sync_vcs_prefix_filters() {
        // "sync vcs g" должно дать gh, gl, gt, gix (все начинаются на 'g')
        // — это валидная фильтрация по префиксу.
        let (_, cands) = complete_prefix("sync vcs g");
        assert!(cands.iter().any(|c| c == "gh"));
        assert!(cands.iter().any(|c| c == "gl"));
        assert!(cands.iter().any(|c| c == "gt"));
        assert!(cands.iter().any(|c| c == "gix"));
        assert!(!cands.iter().any(|c| c == "all"));
    }

    #[test]
    fn complete_sync_vcs_gi_filters_only_gix() {
        // "sync vcs gi" — только gix
        let (_, cands) = complete_prefix("sync vcs gi");
        assert_eq!(cands, vec!["gix"]);
    }

    #[test]
    fn hint_for_gh_command() {
        let h = hint_for_line("gh");
        assert!(h.is_some());
        let h = h.unwrap();
        assert!(h.contains("search"));
        assert!(h.contains("GitHub"));
    }

    #[test]
    fn hint_for_gl_command() {
        let h = hint_for_line("gl");
        assert!(h.is_some());
        assert!(h.unwrap().contains("GitLab"));
    }

    #[test]
    fn hint_for_gt_command() {
        let h = hint_for_line("gt");
        assert!(h.is_some());
        assert!(h.unwrap().contains("Gitea"));
    }

    #[test]
    fn hint_for_gix_command() {
        let h = hint_for_line("gix");
        assert!(h.is_some());
        let h = h.unwrap();
        assert!(h.contains("log"));
        assert!(h.contains("clone"));
    }

    #[test]
    fn hint_for_sync_command_has_vcs_hint() {
        let h = hint_for_line("sync");
        assert!(h.is_some());
        assert!(h.unwrap().contains("vcs"));
    }

    #[test]
    fn hint_for_unknown_vcs_command_is_none() {
        // если ввести что-то непонятное — hint должен вернуть None
        let h = hint_for_line("bogus_vcs_cmd");
        assert!(h.is_none());
    }
}
