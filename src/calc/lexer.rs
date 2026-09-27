//! Лексер калькулятора POLER (цикл M, v0.48.0).
//!
//! Превращает строку выражения в поток токенов. Требования, выведенные
//! инцидентом прошлой сессии (бесконечный цикл → 2.5 ГБ аллокаций):
//!   ИНВАРИАНТ: каждая ветка `advance`-цикла ОБЯЗАНА двигать `i` вперёд.
//!   Регрессионный тест `lexer_terminates_on_hostile_input` держит это.
//!
//! Поддержка:
//! - десятичные числа: `1`, `1.5`, `.5`, `5.`, `1e3`, `1.5e-3`, `2E+8`
//! - системы счисления: `0xFF`, `0b1010`, `0o17`
//! - идентификаторы: `pi`, `x`, `km`, `moon_illum` (a-z, A-Z, `_`, 0-9 после первой)
//! - строки: `"mars"` (без экранирования — до закрывающей кавычки)
//! - операторы: `+ - * / % ^ ! = ( ) [ ] , ;`
//! - `to` для конверсии единиц — обычный идентификатор, семантика в парсере.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Num(f64),
    Str(String),
    Ident(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Bang,
    Assign,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semicolon,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Num(n) => write!(f, "{n}"),
            Tok::Str(s) => write!(f, "\"{s}\""),
            Tok::Ident(s) => write!(f, "{s}"),
            Tok::Plus => write!(f, "+"),
            Tok::Minus => write!(f, "-"),
            Tok::Star => write!(f, "*"),
            Tok::Slash => write!(f, "/"),
            Tok::Percent => write!(f, "%"),
            Tok::Caret => write!(f, "^"),
            Tok::Bang => write!(f, "!"),
            Tok::Assign => write!(f, "="),
            Tok::LParen => write!(f, "("),
            Tok::RParen => write!(f, ")"),
            Tok::LBracket => write!(f, "["),
            Tok::RBracket => write!(f, "]"),
            Tok::Comma => write!(f, ","),
            Tok::Semicolon => write!(f, ";"),
        }
    }
}

/// Разбить строку на токены. Ошибка — с позицией (1-based колонкой).
pub fn tokenize(src: &str) -> Result<Vec<(Tok, usize)>, String> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < n {
        let c = b[i];
        let col = i + 1;

        // --- пропуск пробелов (двигаем i) ---
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // --- числа (десятичные / hex / bin / oct) ---
        if c.is_ascii_digit() || (c == b'.' && i + 1 < n && b[i + 1].is_ascii_digit()) {
            let (tok, next) = lex_number(b, i)?;
            if next <= i {
                return Err(format!("колонка {col}: внутренняя ошибка лексера числа"));
            }
            out.push((tok, col));
            i = next;
            continue;
        }

        // --- идентификаторы ---
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push((Tok::Ident(src[start..i].to_string()), col));
            continue;
        }

        // --- строки "…" (до закрывающей кавычки) ---
        if c == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < n && b[j] != b'"' {
                j += 1;
            }
            if j >= n {
                return Err(format!("колонка {col}: незакрытая строка"));
            }
            let s = src[start..j].to_string();
            out.push((Tok::Str(s), col));
            i = j + 1;
            continue;
        }

        // --- одиночные греческие литеры: φ (phi), π (pi), ψ (psi) ---
        // UTF-8: φ = 0xCF 0x86, π = 0xCF 0x80, ψ = 0xCF 0x88
        if c == 0xCF && i + 1 < n {
            let g = b[i + 1];
            let name = match g {
                0x86 => Some("phi"),
                0x80 => Some("pi"),
                0x88 => Some("psi"),
                _ => None,
            };
            if let Some(nm) = name {
                out.push((Tok::Ident(nm.into()), col));
                i += 2;
                continue;
            }
        }

        // --- операторы и скобки: каждая ветка делает i += 1 ---
        let tok = match c {
            b'+' => Tok::Plus,
            b'-' => Tok::Minus,
            b'*' => Tok::Star,
            b'/' => Tok::Slash,
            b'%' => Tok::Percent,
            b'^' => Tok::Caret,
            b'!' => Tok::Bang,
            b'=' => Tok::Assign,
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'[' => Tok::LBracket,
            b']' => Tok::RBracket,
            b',' => Tok::Comma,
            b';' => Tok::Semicolon,
            _ => {
                let ch = src[i..].chars().next().unwrap_or('?');
                return Err(format!("колонка {col}: неожиданный символ {ch:?}"));
            }
        };
        out.push((tok, col));
        i += 1;
    }
    Ok(out)
}

/// Лекс числа. Возвращает (токен, новая позиция). Гарантирует next > start.
fn lex_number(b: &[u8], start: usize) -> Result<(Tok, usize), String> {
    let n = b.len();
    let col = start + 1;

    // 0x / 0b / 0o
    if b[start] == b'0' && start + 1 < n {
        let radix = match b[start + 1] {
            b'x' | b'X' => Some(16u32),
            b'b' | b'B' => Some(2u32),
            b'o' | b'O' => Some(8u32),
            _ => None,
        };
        if let Some(radix) = radix {
            let mut i = start + 2;
            let mut digits = String::new();
            while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                if b[i] != b'_' {
                    digits.push(b[i] as char);
                }
                i += 1;
            }
            if digits.is_empty() {
                return Err(format!("колонка {col}: пустая запись числа по основанию {radix}"));
            }
            let v = u64::from_str_radix(&digits, radix)
                .map_err(|_| format!("колонка {col}: неверная запись числа «{digits}» по основанию {radix}"))?;
            return Ok((Tok::Num(v as f64), i));
        }
    }

    // десятичное: [цифры][.цифры][(e|E)[+|-]цифры]
    let mut i = start;
    let mut seen_dot = false;
    while i < n {
        let c = b[i];
        if c.is_ascii_digit() {
            i += 1;
        } else if c == b'.' && !seen_dot {
            seen_dot = true;
            i += 1;
        } else {
            break;
        }
    }
    // экспонента — только если после мантиссы стоит e/E и ДАЛЬШЕ есть цифры/знак+цифры
    if i < n && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < n && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        if j < n && b[j].is_ascii_digit() {
            while j < n && b[j].is_ascii_digit() {
                j += 1;
            }
            i = j;
        }
        // иначе: e — начало следующего идентификатора (напр. `2e` без цифр —
        // не экспонента; сам по себе такой идентификатор позже не разрешится)
    }
    let text = std::str::from_utf8(&b[start..i]).unwrap_or("");
    let v: f64 = text
        .parse()
        .map_err(|_| format!("колонка {col}: неверное число «{text}»"))?;
    let next = if i > start { i } else { start + 1 };
    Ok((Tok::Num(v), next))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ================================================================
    // РЕГРЕССИЯ инцидента прошлой сессии: операторные ветки без i += 1
    // набивали Vec до 2.5 ГБ. Любой «враждебный» ввод обязан завершаться.
    // ================================================================
    #[test]
    fn lexer_terminates_on_hostile_input() {
        let hostile = [
            "++**//", "^^^", "!!!", "===", "(((((", ")))))", "]]][[[", ";;,,",
            "+-*/%^!=", "1++++2", "0x", "0b2", "1e", "1e+", "..", ".e3",
            "\u{CF}\u{86}", "π+φ", "5 π", "@#$", "🙂+1", "", " ", "   ",
        ];
        for s in hostile {
            // зависание здесь убьёт тест по тайм-ауту — это и есть защита
            let _ = tokenize(s);
        }
    }

    #[test]
    fn numbers_decimal() {
        let ts = tokenize("1 1.5 .5 5. 1e3 1.5e-3 2E+8").unwrap();
        let vals: Vec<f64> = ts.iter().map(|(t, _)| match t {
            Tok::Num(v) => *v,
            _ => panic!("не число"),
        }).collect();
        assert_eq!(vals, vec![1.0, 1.5, 0.5, 5.0, 1000.0, 0.0015, 2e8]);
    }

    #[test]
    fn numbers_radix() {
        let ts = tokenize("0xFF 0b1010 0o17 0X10 0B11").unwrap();
        let vals: Vec<f64> = ts.iter().map(|(t, _)| match t {
            Tok::Num(v) => *v,
            _ => panic!(),
        }).collect();
        assert_eq!(vals, vec![255.0, 10.0, 15.0, 16.0, 3.0]);
    }

    #[test]
    fn identifiers_and_greek() {
        let ts = tokenize("pi x_1 km φ π psi").unwrap();
        let ids: Vec<&str> = ts.iter().map(|(t, _)| match t {
            Tok::Ident(s) => s.as_str(),
            _ => panic!(),
        }).collect();
        assert_eq!(ids, vec!["pi", "x_1", "km", "phi", "pi", "psi"]);
    }

    #[test]
    fn operators_roundtrip() {
        let ts = tokenize("+-*/%^!=()[],;").unwrap();
        let expect = [
            Tok::Plus, Tok::Minus, Tok::Star, Tok::Slash, Tok::Percent,
            Tok::Caret, Tok::Bang, Tok::Assign, Tok::LParen, Tok::RParen,
            Tok::LBracket, Tok::RBracket, Tok::Comma, Tok::Semicolon,
        ];
        let got: Vec<&Tok> = ts.iter().map(|(t, _)| t).collect();
        assert_eq!(got, expect.iter().collect::<Vec<_>>());
    }

    #[test]
    fn exp_without_digits_is_separate_token() {
        // `2e` → число 2, затем идентификатор `e` (константа Эйлера)
        let ts = tokenize("2e").unwrap();
        assert_eq!(ts[0].0, Tok::Num(2.0));
        assert_eq!(ts[1].0, Tok::Ident("e".into()));
    }

    #[test]
    fn strings_lex() {
        let ts = tokenize("\"mars\" \"1TT\" x").unwrap();
        assert_eq!(ts[0].0, Tok::Str("mars".into()));
        assert_eq!(ts[1].0, Tok::Str("1TT".into()));
        assert_eq!(ts[2].0, Tok::Ident("x".into()));
        assert!(tokenize("\"unterminated").is_err());
        assert!(tokenize("\"a\" \"b").is_err());
    }

    #[test]
    fn error_positions() {
        assert!(tokenize("@").is_err());
        assert!(tokenize("0x").is_err());
        assert!(tokenize("1 @ 2").is_err());
    }
}
