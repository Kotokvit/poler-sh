//! # Terminal Gateway: парсер конвейеров (v0.22.0)
//!
//! Строка ввода → `Pipeline`: сегменты через `|`, редирект `>` / `>>` / `2>`
//! в конце, кавычки `'…'` / `"…"`. Подстановки (`$(…)`), `&&`, `;` и
//! подобная шелл-магия **не поддерживаются сознательно**: gateway сам
//! токенизирует строку и запускает бинарники напрямую, без `/bin/sh`
//! (см. docs/terminal-gateway-architecture.md §2 — модель исполнения).

// ---------------------------------------------------------------------------
// Лексер
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// Слово (кавычки сняты, содержимое сохранено дословно).
    Word(String),
    /// `|`
    Pipe,
    /// `>` (перезапись)
    Out,
    /// `>>` (дозапись)
    Append,
    /// `2>` (перенаправление stderr)
    Err,
}

/// Ошибка парсинга — человекочитаемая, без паник.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Лексер: кавычки, пайпы, редиректы. Пайп/редирект внутри кавычек —
/// обычный символ (как в POSIX shell).
fn lex(line: &str) -> Result<Vec<Tok>, ParseError> {
    let mut toks = Vec::new();
    let mut buf = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if in_dq {
            if c == '"' {
                in_dq = false;
            } else {
                buf.push(c);
            }
        } else if in_sq {
            if c == '\'' {
                in_sq = false;
            } else {
                buf.push(c);
            }
        } else {
            match c {
                '"' => in_dq = true,
                '\'' => in_sq = true,
                '|' => {
                    // `||` не поддерживаем (это shell-OR, не пайп)
                    if i + 1 < chars.len() && chars[i + 1] == '|' {
                        return Err(ParseError(
                            "оператор `||` не поддерживается (gateway исполняет команды напрямую, без shell)"
                                .into(),
                        ));
                    }
                    flush_word(&mut toks, &mut buf);
                    toks.push(Tok::Pipe);
                }
                '>' => {
                    // «слово2>» → stderr-редирект: буфер == "2" без пробела перед >
                    let glued_err = buf == "2";
                    if glued_err {
                        buf.clear();
                    } else {
                        flush_word(&mut toks, &mut buf);
                    }
                    if i + 1 < chars.len() && chars[i + 1] == '>' {
                        toks.push(if glued_err { Tok::Err } else { Tok::Append });
                        i += 1;
                    } else {
                        toks.push(if glued_err { Tok::Err } else { Tok::Out });
                    }
                }
                c if c.is_whitespace() => flush_word(&mut toks, &mut buf),
                c => buf.push(c),
            }
        }
        i += 1;
    }
    if in_dq || in_sq {
        return Err(ParseError("незакрытая кавычка в строке".into()));
    }
    flush_word(&mut toks, &mut buf);
    Ok(toks)
}

fn flush_word(toks: &mut Vec<Tok>, buf: &mut String) {
    if !buf.is_empty() {
        toks.push(Tok::Word(std::mem::take(buf)));
    }
}

// ---------------------------------------------------------------------------
// Модель конвейера
// ---------------------------------------------------------------------------

/// Один сегмент конвейера: либо команда движка, либо хостовая команда
/// (классификация — в dispatch.rs, здесь только структура).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Токены (первый — имя команды; кавычки раскрыты).
    pub tokens: Vec<String>,
    /// Сырой текст сегмента (для сообщений об ошибках).
    pub raw: String,
}

impl Segment {
    /// Первое слово — имя команды (или пустая строка).
    pub fn cmd(&self) -> &str {
        self.tokens.first().map(|s| s.as_str()).unwrap_or("")
    }
}

/// Редирект финального вывода конвейера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub path: String,
    pub append: bool,
    pub stderr: bool,
}

/// Разобранный конвейер: `cat x | grep TODO > out.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub segments: Vec<Segment>,
    pub redirect: Option<Redirect>,
}

impl Pipeline {
    /// Есть ли хоть один сегмент.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// Разбор строки в конвейер. Ошибки — для REPL (печать и продолжение).
pub fn parse_line(line: &str) -> Result<Pipeline, ParseError> {
    let toks = lex(line)?;
    let mut segments: Vec<Segment> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut cur_raw = String::new();
    let mut redirect: Option<Redirect> = None;
    let mut i = 0usize;

    while i < toks.len() {
        match &toks[i] {
            Tok::Word(w) => {
                cur.push(w.clone());
                if !cur_raw.is_empty() {
                    cur_raw.push(' ');
                }
                cur_raw.push_str(w);
            }
            Tok::Pipe => {
                if cur.is_empty() {
                    return Err(ParseError(
                        "пустой сегмент конвейера (пайп без команды)".into(),
                    ));
                }
                if redirect.is_some() {
                    return Err(ParseError(
                        "редирект допустим только в конце конвейера".into(),
                    ));
                }
                segments.push(Segment {
                    tokens: std::mem::take(&mut cur),
                    raw: std::mem::take(&mut cur_raw),
                });
            }
            Tok::Out | Tok::Append | Tok::Err => {
                let stderr = matches!(toks[i], Tok::Err);
                let append = matches!(toks[i], Tok::Append);
                // путь — следующий токен, обязательно Word
                let path = match toks.get(i + 1) {
                    Some(Tok::Word(p)) => p.clone(),
                    _ => {
                        return Err(ParseError(
                            "после `>` / `>>` / `2>` ожидается имя файла".into(),
                        ))
                    }
                };
                // после пути — только конец строки
                if i + 2 < toks.len() {
                    return Err(ParseError(
                        "редирект допустим только в конце конвейера (после пути)".into(),
                    ));
                }
                redirect = Some(Redirect { path, append, stderr });
                i += 1;
            }
        }
        i += 1;
    }
    if !cur.is_empty() {
        segments.push(Segment {
            tokens: cur,
            raw: cur_raw,
        });
    }
    if segments.is_empty() {
        return Err(ParseError("пустая команда".into()));
    }
    Ok(Pipeline { segments, redirect })
}

// ---------------------------------------------------------------------------
// Префикс poler / poler-engine
// ---------------------------------------------------------------------------

/// Срезать ведущий `poler` / `poler-engine` с сегмента, если за ним идёт
/// известная команда движка: `ls | poler chunk` ≡ `ls | chunk`.
/// Полный CLI-синтаксис (`poler --grep x`) НЕ поддерживается — gateway
/// использует REPL-словарь движка (см. help).
pub fn strip_poler_prefix(tokens: &[String], engine_cmds: &dyn Fn(&str) -> bool) -> Vec<String> {
    if tokens.len() >= 2 {
        let first = tokens[0].as_str();
        let is_poler = first == "poler" || first == "poler-engine" || first == "./poler-engine";
        if is_poler {
            let second = tokens[1].as_str();
            if engine_cmds(second) {
                return tokens[1..].to_vec();
            }
        }
    }
    tokens.to_vec()
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_basic_pipe_and_redirect() {
        let p = parse_line("ls -la | grep foo > out.txt").unwrap();
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0].tokens, vec!["ls", "-la"]);
        assert_eq!(p.segments[1].tokens, vec!["grep", "foo"]);
        let r = p.redirect.unwrap();
        assert_eq!(r.path, "out.txt");
        assert!(!r.append);
        assert!(!r.stderr);
    }

    #[test]
    fn lex_append_and_stderr_redirect() {
        let p = parse_line("echo hi >> log.txt").unwrap();
        assert_eq!(p.redirect.unwrap().append, true);
        let p = parse_line("cmd 2> err.txt").unwrap();
        assert!(p.redirect.unwrap().stderr);
        // glued `2>`: слово «2» приклеено к `>`
        let p = parse_line("cmd 2>x");
        assert!(p.unwrap().redirect.unwrap().stderr);
    }

    #[test]
    fn lex_quotes_preserve_spaces() {
        let p = parse_line("grep \"два слова\" file").unwrap();
        assert_eq!(p.segments[0].tokens, vec!["grep", "два слова", "file"]);
    }

    #[test]
    fn lex_pipe_inside_quotes_is_literal() {
        let p = parse_line("echo \"a|b\"").unwrap();
        assert_eq!(p.segments.len(), 1);
        assert_eq!(p.segments[0].tokens, vec!["echo", "a|b"]);
    }

    #[test]
    fn lex_unterminated_quote_is_error() {
        assert!(parse_line("echo \"oops").is_err());
    }

    #[test]
    fn lex_double_pipe_rejected() {
        // `||` — shell-OR, gateway не исполняет shell-операторы
        assert!(parse_line("a || b").is_err());
    }

    #[test]
    fn lex_empty_segment_rejected() {
        assert!(parse_line("a | | b").is_err());
        assert!(parse_line("| ls").is_err());
    }

    #[test]
    fn lex_redirect_must_be_last() {
        assert!(parse_line("a > f | b").is_err());
        assert!(parse_line("a > f b").is_err());
        assert!(parse_line("a > ").is_err());
    }

    #[test]
    fn lex_empty_line_rejected() {
        assert!(parse_line("").is_err());
        assert!(parse_line("   ").is_err());
    }

    #[test]
    fn lex_unicode_ok() {
        let p = parse_line("grep «кот» src").unwrap();
        assert_eq!(p.segments[0].tokens, vec!["grep", "«кот»", "src"]);
    }

    #[test]
    fn strip_poler_prefix_known_and_unknown() {
        let is_engine = |s: &str| s == "chunk" || s == "grep";
        let t = strip_poler_prefix(
            &["poler".to_string(), "chunk".into(), "--x".into()],
            &is_engine,
        );
        assert_eq!(t, vec!["chunk", "--x"]);
        // poler --grep: второй токен не движковая команда → не срезаем
        let t = strip_poler_prefix(&["poler".into(), "--grep".into()], &is_engine);
        assert_eq!(t.len(), 2);
        // без префикса — нетронуто
        let t = strip_poler_prefix(&["ls".into(), "-la".into()], &is_engine);
        assert_eq!(t.len(), 2);
        // poler-engine variant
        let t = strip_poler_prefix(
            &["poler-engine".into(), "grep".into(), "x".into()],
            &is_engine,
        );
        assert_eq!(t, vec!["grep", "x"]);
    }
}
