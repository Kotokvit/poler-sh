//! # Калькулятор Всего (цикл M, v0.48.0)
//!
//! Универсальный вычислительный полигон poler-engine: от бытовой
//! арифметики (`calc (1538*485)/1024`) до планковских единиц, матричных
//! экспонент Ли, тритной логики POLER, астрономии Шлhyter/NOAA,
//! геодезии, зондирования железа и генерации скриптов по законам
//! физики.
//!
//! ## Слои
//! ```text
//! commands.rs: `calc …`, `hw`, префикс `=`  ──►  REPL / --exec --json
//! TUI: Mode::Calc (клавиша `=`)             ──►  живой preview + история
//! MCP: poler_calc                            ──►  Antigravity
//!                     │
//!                     ▼
//! calc::CalcState ── parser ──► Expr ──► Value
//!                     │                       ├─ Scalar / Quantity(единицы)
//!                     │                       ├─ Matrix (expm, Фаддеев, Ли)
//!                     │                       ├─ Complex (корни, спектры)
//!                     │                       └─ List / Str
//!                     ├─ solve: Дюран–Кернер + Ньютон/бисекция
//!                     ├─ numbers: Миллер–Рабин, ρ-Поллард
//!                     ├─ astro: Шлhyter + NOAA (якоря — затмения)
//!                     ├─ geodesy: WGS84, большие круги
//!                     ├─ hardware: /proc, /sys, nvidia-smi
//!                     └─ scriptgen: законы → скрипты/.poler-правила
//! ```
//!
//! Все баги прошлой (погибшей) сессии закрыты регрессионными тестами:
//! вечный цикл лексера, «to» в неявном умножении, `x = x` в solve,
//! заём тритов при остатке 2, Паде b4 = 1/792, Фаддеев только-диагональ,
//! перигей Луны 0.1643573223 °/день, радианы в освещённости, внешний
//! множитель t в erf, дзета Эйлера–Маклорена.

use std::collections::HashMap;
use std::fmt;

use crate::calc::matrix::Matrix;
use crate::calc::solve::Complex;
use crate::calc::units::Unit;

pub mod astro;
pub mod constants;
pub mod functions;
pub mod geodesy;
pub mod hardware;
pub mod lexer;
pub mod matrix;
pub mod numbers;
pub mod parser;
pub mod scriptgen;
pub mod solve;
pub mod trits;
pub mod units;

/// Значение калькулятора.
#[derive(Clone, PartialEq)]
pub enum Value {
    /// Число (безразмерное или радианы по конвенции).
    Scalar(f64),
    /// Число с единицей измерения.
    Quantity(f64, Unit),
    /// Матрица (безразмерная).
    Matrix(Matrix),
    /// Комплексное число (корни уравнений, собственные значения,
    /// авточисленные sqrt/ln отрицательных).
    Complex(Complex),
    /// Точное большое целое (fib(1000), 1000!, 2^10000) — десятичная
    /// запись, возможен ведущий '-'. Цикл N: «невозможное → возможное».
    BigInt(String),
    /// Список значений (корни, делители, midpoint…).
    List(Vec<Value>),
    /// Строка (имена планет, тритные записи).
    Str(String),
}

impl Value {
    /// Числовой доступ: Scalar — значение; Quantity — значение,
    /// пересчитанное в БАЗОВЫЕ единицы СИ (5 km → 5000.0; au³/(m³/s²) →
    /// секунды²). Это единственная самосогласованная интерпретация для
    /// составных единиц с неединичным фактором.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Scalar(v) => Some(*v),
            Value::Quantity(v, u) => Some(v * u.factor),
            // приближение (для физики/solve достаточно; точность — в Display)
            Value::BigInt(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Scalar(_) => "число",
            Value::Quantity(..) => "величина",
            Value::Matrix(_) => "матрица",
            Value::Complex(_) => "комплексное",
            Value::BigInt(_) => "точное целое",
            Value::List(_) => "список",
            Value::Str(_) => "строка",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Scalar(v) => write!(f, "{}", py_float(*v)),
            Value::Quantity(v, u) => {
                if u.is_dimensionless() {
                    write!(f, "{}", py_float(v * u.factor))
                } else if u.name.is_empty() && (u.factor - 1.0).abs() > 1e-12 {
                    // составная единица с неединичным множителем (напр.
                    // au³/(m³/s²) после законов Кеплера) — канонический
                    // СИ-вид: значение×фактор + базовые размерности.
                    // Прошлая версия теряла фактор: 6e-15 вместо 3.16e7 с.
                    write!(f, "{} {}", py_float(v * u.factor), u.display())
                } else {
                    write!(f, "{} {}", py_float(*v), u.display())
                }
            }
            Value::Matrix(m) => {
                // вещественная матрица — канонический вид [a, b; c, d]
                // (нулевая регрессия); комплексная — поэлементный ℂ-вид
                // (цикл O: [0, -i; i, 0])
                let all_real = m.data.iter().all(|c| c.im == 0.0);
                write!(f, "[")?;
                for i in 0..m.rows {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    for j in 0..m.cols {
                        if j > 0 {
                            write!(f, ", ")?;
                        }
                        if all_real {
                            write!(f, "{}", py_float(m.get(i, j).re))?;
                        } else {
                            write!(f, "{}", m.get(i, j))?;
                        }
                    }
                }
                write!(f, "]")
            }
            Value::Complex(c) => write!(f, "{c}"),
            Value::BigInt(s) => {
                // длинные точные целые: значение целиком + подсказка порядка
                if s.len() > 40 {
                    let approx: f64 = s.parse::<f64>().unwrap_or(f64::NAN);
                    let digits = s.trim_start_matches('-').len();
                    write!(f, "{s}  (≈ {approx:.3e}, {digits} цифр)")
                } else {
                    write!(f, "{s}")
                }
            }
            Value::List(items) => {
                write!(f, "[")?;
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{it}")?;
                }
                write!(f, "]")
            }
            Value::Str(s) => write!(f, "\"{s}\""),
        }
    }
}

/// Debug = Display: ошибки читаемы ({:?} в сообщениях).
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Число в стиле Python repr: shortest roundtrip, целые с «.0»,
/// экспонента для крайних порядков.
pub fn py_float(v: f64) -> String {
    if v.is_nan() {
        // расширенная прямая: NaN = неопределённость (0/0, ∞−∞ и т.п.)
        return "неопределённость".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "∞".into() } else { "-∞".into() };
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    format!("{v:?}")
}

// ---------------------------------------------------------------------
// Состояние сессии калькулятора
// ---------------------------------------------------------------------

/// Запись истории.
#[derive(Clone)]
pub struct HistoryEntry {
    pub input: String,
    pub output: String,
}

/// Состояние калькулятора REPL/TUI: переменные + история.
pub struct CalcState {
    pub vars: HashMap<String, Value>,
    pub history: Vec<HistoryEntry>,
}

const HISTORY_CAP: usize = 200;

impl Default for CalcState {
    fn default() -> Self {
        Self::new()
    }
}

impl CalcState {
    pub fn new() -> Self {
        CalcState { vars: HashMap::new(), history: Vec::new() }
    }

    fn push_history(&mut self, input: &str, output: &str) {
        self.history.push(HistoryEntry {
            input: input.to_string(),
            output: output.to_string(),
        });
        if self.history.len() > HISTORY_CAP {
            self.history.remove(0);
        }
    }

    /// Главная точка входа: вычислить строку (calc <expr> / =<expr>).
    pub fn eval_line(&mut self, line: &str) -> Result<String, String> {
        let src = line.trim();
        if src.is_empty() {
            return Err("пустое выражение".into());
        }
        // solve-режим?
        if let Some(rest) = src.strip_prefix("solve ").or_else(|| {
            if src == "solve" { Some("") } else { None }
        }) {
            let out = self.solve(rest)?;
            self.push_history(src, &out);
            return Ok(out);
        }
        let expr = parser::parse(src, false)?;
        let val = parser::eval(&expr, &mut self.vars)?;
        self.vars.insert("ans".into(), val.clone());
        let out = format!("{val}");
        self.push_history(src, &out);
        Ok(out)
    }

    /// Решить уравнение (`solve f(x) = 0` или `solve lhs = rhs`).
    pub fn solve(&mut self, src: &str) -> Result<String, String> {
        let (out, roots) = self.solve_readonly(src)?;
        if let Some(roots) = roots {
            self.vars.insert(
                "ans".into(),
                Value::List(roots.into_iter().map(Value::Complex).collect()),
            );
        }
        Ok(out)
    }

    /// Чистое решение без мутаций (для preview). Возвращает текст и
    /// найденные корни для сохранения в ans.
    fn solve_readonly(&self, src: &str) -> Result<(String, Option<Vec<Complex>>), String> {
        let src = src.trim();
        if src.is_empty() {
            return Err("solve <уравнение>: например, solve x^2 - 4 = 0".into());
        }
        let expr = parser::parse(src, true).map_err(|e| format!("solve: {e}"))?;

        // без '=': трактуем всё как f(x) = 0
        let (lhs, rhs) = match expr {
            parser::Expr::Equation { lhs, rhs } => (lhs, rhs),
            other => (Box::new(other), Box::new(parser::Expr::Num(0.0))),
        };

        let mut vars = BTreeSet::new();
        parser::free_vars(&lhs, &mut vars);
        parser::free_vars(&rhs, &mut vars);

        // частные случаи без переменных
        if vars.is_empty() {
            let l = parser::eval(&lhs, &mut self.vars.clone())?;
            let r = parser::eval(&rhs, &mut self.vars.clone())?;
            let (ln, rn) = (l.as_f64().unwrap_or(f64::NAN), r.as_f64().unwrap_or(f64::NAN));
            if (ln - rn).abs() < 1e-9 {
                return Ok(("тождество: обе части равны при всех значениях".into(), None));
            }
            return Ok((format!("нет решений: {ln} ≠ {rn}"), None));
        }
        if vars.len() > 1 {
            let list: Vec<String> = vars.iter().cloned().collect();
            return Err(format!(
                "уравнение с несколькими переменными ({}) — задайте значения: {}",
                list.join(", "),
                list.iter().map(|v| format!("calc {v} = …")).collect::<Vec<_>>().join("; ")
            ));
        }
        let var = vars.iter().next().unwrap().clone();

        // f(x) = lhs(x) − rhs(x)
        let base_vars = self.vars.clone();
        let f = |x: f64| -> f64 {
            let mut env = base_vars.clone();
            env.insert(var.clone(), Value::Scalar(x));
            let l = parser::eval(&lhs, &mut env).unwrap_or(Value::Scalar(f64::NAN));
            let r = parser::eval(&rhs, &mut env).unwrap_or(Value::Scalar(f64::NAN));
            l.as_f64().unwrap_or(f64::NAN) - r.as_f64().unwrap_or(f64::NAN)
        };

        match solve::solve_real(&f) {
            solve::SolveOutcome::Identity => {
                Ok(("тождество: любое значение является решением".into(), None))
            }
            solve::SolveOutcome::Contradiction(c) => {
                Ok((format!("нет решений (f ≡ {c} ≠ 0)"), None))
            }
            solve::SolveOutcome::AsymptoticZero => Ok((
                "вещественных корней нет: f(x) → 0 лишь асимптотически — нуль не достигается \
                 никогда (классика: e^x → 0 при x → −∞); в зоне x ≲ −708 экспонента уходит в \
                 машинный underflow f64 и округляется в 0.0, но это предел, не решение"
                    .into(),
                None,
            )),
            solve::SolveOutcome::Roots(roots, how) => {
                if roots.is_empty() {
                    return Ok((format!("вещественных корней не найдено ({how})"), None));
                }
                let n = roots.len();
                let shown: Vec<String> =
                    roots.iter().take(12).map(|r| r.to_string()).collect();
                let more = if n > 12 {
                    format!("\n  … и ещё {} корней (всего {}; полный список — в ans)", n - 12, n)
                } else {
                    String::new()
                };
                let text = format!(
                    "{} {} {}{}\n  [{}]",
                    var,
                    if n == 1 { "=" } else { "∈" },
                    shown.join(", "),
                    more,
                    how
                );
                Ok((text, Some(roots)))
            }
        }
    }

    /// Вычислить выражение и вернуть комплексное число (re, im).
    ///
    /// Цикл P: парсинг амплитуд для сферы Блоха (`quantum bloch 1/sqrt(2) …`)
    /// — скаляр трактуется как вещественное, комплексное проходит как есть.
    pub fn eval_complex(&mut self, src: &str) -> Result<(f64, f64), String> {
        let expr = parser::parse(src.trim(), false)?;
        let val = parser::eval(&expr, &mut self.vars)?;
        match val {
            Value::Scalar(x) => Ok((x, 0.0)),
            Value::Complex(c) => Ok((c.re, c.im)),
            Value::Quantity(v, u) => {
                if u.is_dimensionless() {
                    Ok((v * u.factor, 0.0))
                } else {
                    Err(format!(
                        "амплитуда не может иметь единицу: {} {}",
                        v,
                        u.display()
                    ))
                }
            }
            other => Err(format!(
                "ожидалось число или комплексное, получено: {}",
                other.type_name()
            )),
        }
    }

    /// Безопасный предпросмотр для TUI (не мутирует состояние, не паникует).
    pub fn preview(&self, src: &str) -> String {
        let src = src.trim();
        if src.is_empty() {
            return String::new();
        }
        let mut env = self.vars.clone();
        let res = if let Some(rest) = src.strip_prefix("solve ") {
            self.solve_readonly(rest).map(|(t, _)| t)
        } else {
            match parser::parse(src, false).and_then(|e| parser::eval(&e, &mut env)) {
                Ok(v) => Ok(format!("{v}")),
                Err(e) => Err(e),
            }
        };
        match res {
            Ok(v) => format!("= {v}"),
            Err(e) => format!("⚠ {e}"),
        }
    }

    /// Структурированный результат для MCP/JSON.
    pub fn eval_structured(&mut self, line: &str) -> serde_json::Value {
        match self.eval_line(line) {
            Ok(text) => {
                let ans = self.vars.get("ans");
                serde_json::json!({
                    "ok": true,
                    "input": line.trim(),
                    "result": text,
                    "ans": ans.map(|v| v.to_string()),
                    "type": ans.map(|v| v.type_name()),
                })
            }
            Err(e) => serde_json::json!({
                "ok": false,
                "input": line.trim(),
                "error": e,
            }),
        }
    }

    /// История для TUI/`calc hist`.
    pub fn history_text(&self, last: usize) -> String {
        let start = self.history.len().saturating_sub(last);
        let mut out = String::new();
        for e in &self.history[start..] {
            out.push_str(&format!("❯ {}\n  = {}\n", e.input, e.output));
        }
        if out.is_empty() {
            out.push_str("(история пуста)");
        }
        out
    }

    /// Список переменных.
    pub fn vars_text(&self) -> String {
        if self.vars.is_empty() {
            return "(нет переменных — calc x = 5)".into();
        }
        let mut names: Vec<&String> = self.vars.keys().collect();
        names.sort();
        let mut out = String::new();
        for n in names {
            out.push_str(&format!("{n} = {}\n", self.vars[n]));
        }
        out
    }
}

use std::collections::BTreeSet;

#[cfg(test)]
mod tests {
    use super::*;

    fn calc(line: &str) -> String {
        let mut st = CalcState::new();
        st.eval_line(line).unwrap()
    }

    #[test]
    fn value_display() {
        assert_eq!(Value::Scalar(1024.0).to_string(), "1024.0");
        assert_eq!(Value::Scalar(0.5).to_string(), "0.5");
        assert_eq!(Value::Scalar(-0.0).to_string(), "-0.0");
        assert_eq!(Value::Scalar(f64::NAN).to_string(), "неопределённость");
        assert_eq!(Value::Scalar(f64::INFINITY).to_string(), "∞");
        assert_eq!(Value::Scalar(f64::NEG_INFINITY).to_string(), "-∞");
        assert_eq!(Value::Str("mars".into()).to_string(), "\"mars\"");
        assert_eq!(
            Value::List(vec![Value::Scalar(1.0), Value::Scalar(2.0)]).to_string(),
            "[1.0, 2.0]"
        );
        let m = Matrix::from_rows(&[vec![1.0, 2.0], vec![3.0, 4.0]]).unwrap();
        assert_eq!(Value::Matrix(m).to_string(), "[1.0, 2.0; 3.0, 4.0]");
        assert_eq!(Value::Complex(Complex::new(0.0, 1.0)).to_string(), "i");
    }

    #[test]
    fn py_float_python_style() {
        // регрессия прошлой сессии: формат «как в Python»
        assert_eq!(py_float(1.0), "1.0");
        assert_eq!(py_float(-2.0), "-2.0");
        assert_eq!(py_float(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(py_float(1e21), "1e21");
        assert_eq!(py_float(1.5e-7), "1.5e-7");
        assert_eq!(py_float(1024.0), "1024.0");
    }

    #[test]
    fn eval_line_spots() {
        assert_eq!(calc("(1538 * 485) / 1024"), "728.447265625");
        assert_eq!(calc("2^10"), "1024.0");
        assert_eq!(calc("5!"), "120.0");
        // единицы
        assert_eq!(calc("5 km to mi"), "3.1068559611866697");
        // ans
        let mut st = CalcState::new();
        st.eval_line("42 * 10").unwrap();
        assert_eq!(st.eval_line("ans / 6").unwrap(), "70.0");
        // история пишется
        assert_eq!(st.history.len(), 2);
        assert!(st.history_text(10).contains("42 * 10"));
        assert!(st.vars_text().contains("ans"));
    }

    #[test]
    fn assignment_and_vars() {
        let mut st = CalcState::new();
        st.eval_line("a = 5 km").unwrap();
        assert_eq!(st.eval_line("a to m").unwrap(), "5000.0");
        assert_eq!(st.eval_line("a + 500 m").unwrap(), "5.5 km");
        st.eval_line("b = a * 2").unwrap();
        assert_eq!(st.eval_line("b to km").unwrap(), "10.0");
    }

    #[test]
    fn solve_paths() {
        assert!(calc("solve x^2 - 4 = 0").contains("2.0"));
        assert!(calc("solve x^2 - 4 = 0").contains("-2.0"));
        assert!(calc("solve x^2 = 2").contains("1.4142135623730951"));
        // линейное
        let r = calc("solve 2*x + 1 = 5");
        assert!(r.contains("2.0"), "{r}");
        // комплексные корни
        let r = calc("solve x^2 + 1 = 0");
        assert!(r.contains("i"), "{r}");
        // тождество
        assert!(calc("solve x = x").contains("тождество"));
        // противоречие
        assert!(calc("solve x + 1 = x + 2").contains("нет решений"));
        // трансцендентное: много корней — показываются первые 12 + нота
        let r = calc("solve sin(x) = 0.5");
        assert!(r.contains("Ньютон"), "{r}");
        assert!(r.contains("и ещё"), "{r}");
        assert!(r.contains("полный список — в ans"), "{r}");
        // несколько переменных — ошибка
        assert!(CalcState::new().eval_line("solve x + y = 3").is_err());
        // без '=': f(x) = 0
        let r = calc("solve x^2 - 9");
        assert!(r.contains("3.0"), "{r}");
    }

    #[test]
    fn preview_is_safe() {
        let st = CalcState::new();
        assert_eq!(st.preview(""), "");
        assert_eq!(st.preview("2 + 2"), "= 4.0");
        assert!(st.preview("2 +").starts_with("⚠"));
        assert!(st.preview("unknown_x").starts_with("⚠"));
        // solve в preview
        assert!(st.preview("solve x^2 = 4").contains("2.0"));
    }

    // =================================================================
    // ЦИКЛ N: «НЕВОЗМОЖНОЕ → ВОЗМОЖНОЕ» — интеграционные якоря
    // =================================================================

    #[test]
    fn extended_reals_infinity() {
        // расширенная прямая: деление на ноль вместо ошибки
        assert!(calc("1 / 0").contains("∞"), "{}", calc("1 / 0"));
        assert!(calc("-1 / 0").contains("-∞"));
        assert!(calc("1 / 0 + 5").contains("∞"));
        // ln(0) = −∞ (предел, не ошибка)
        assert!(calc("ln(0)").contains("-∞"));
        // 0/0 — честная неопределённость с пояснением
        let r = CalcState::new().eval_line("0 / 0");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("0/0"));
        // gamma-полюса → расходимость
        assert!(calc("gamma(-1)").contains("∞"));
        assert!(calc("gamma(0)").contains("∞"));
    }

    #[test]
    fn auto_complex_arithmetic() {
        // sqrt отрицательного — мнимая ось без обхода через solve
        assert!(calc("sqrt(-4)").contains("2.0i"), "{}", calc("sqrt(-4)"));
        // тахионный Лоренц: γ(1.5) = −i/√(1.25) ≈ −0.894i
        let r = calc("lorentz(1.5)");
        assert!(r.contains("i"), "{r}");
        // прямая формула через sqrt отрицательного дискриминанта
        let r = calc("1 / sqrt(1 - 1.5^2)");
        assert!(r.contains("i"), "{r}");
        // рациональная нечётная степень: (-8)^(1/3) = -2
        let r = calc("(-8)^(1/3)");
        assert!(r.contains("-2"), "{r}");
        // чётный знаменатель — комплексная ветвь: (-2)^0.5 = i·√2
        let r = calc("(-2)^0.5");
        assert!(r.contains("i"), "{r}");
        // ln(-1) = iπ
        let r = calc("ln(-1)");
        assert!(r.contains("i"), "{r}");
        // комплексная арифметика продолжается: (0+2i)·(0+2i) = -4
        let r = calc("sqrt(-4) * sqrt(-4)");
        assert!(r.contains("-4"), "{r}");
    }

    #[test]
    fn exact_big_integers() {
        // fib за f64-пределом — ТОЧНО (стресс-тест прошлой сессии: fib(100))
        assert!(calc("fib(100)").contains("354224848179261915075"), "{}", calc("fib(100)"));
        // совместимость: малые остались Scalar
        assert!(calc("fib(10)").contains("55.0"));
        // факториал точен за 18!
        let r = calc("factorial(25)");
        assert!(r.contains("15511210043330985984000000"), "{r}");
        // 2^100 — точное целое (f64 давал 1.2676506002282294e30)
        let r = calc("2^100");
        assert!(r.contains("1267650600228229401496703205376"), "{r}");
        // совместимость степени: 2^10 остаётся Scalar 1024.0
        assert!(calc("2^10").contains("1024.0"));
        // знак нечётной степени: (-3)^41 — точное отрицательное целое
        let r = calc("(-3)^41");
        assert!(r.starts_with("-"), "{r}");
        assert!(r.contains("36472996377170786403"), "{r}");
        // binomial точен: C(100,50)
        let r = calc("binomial(100, 50)");
        assert!(r.contains("100891344545564193334812497256"), "{r}");
        // малые binomial остаются Scalar
        assert!(calc("binomial(5, 2)").contains("10.0"));
        // catalan за f64: C_31 = 14544636039226909
        let r = calc("catalan(31)");
        assert!(r.contains("14544636039226909"), "{r}");
        // big-арифметика: fib(100) + 1 — точный путь
        let r = calc("fib(100) + 1");
        assert!(r.contains("354224848179261915076"), "{r}");
        // fib(100) * fib(100) — точное умножение (F(100)² ≈ 1.2547e41)
        let r = calc("fib(100) * fib(100)");
        assert!(r.contains("125475243067621153271396401396356512255625"), "{}", r);
        // деление нацело большого: fib(100) / 5
        let r = calc("fib(100) / 5");
        assert!(r.contains("70844969635852383015"), "{r}");
        // fib(1000) — 209 цифр, точность сохранена (канонический якорь)
        let r = calc("fib(1000)");
        assert!(r.contains("43466557686937456435688527675040625802564660517371780402481729089536555417949051890403879840079255169295922593080322634775209689623239873322471161642996440906533187938298969649928516003704476137795166849228875"), "{r}");
    }

    #[test]
    fn solve_underflow_asymptotic() {
        // ГЛАВНАЯ регрессия цикла N: exp(x) = 0 не имеет корней,
        // а старый решатель возвращал ложные [-200, -90] из-за underflow
        let r = calc("solve exp(x) = 0");
        assert!(r.contains("асимптотически"), "{r}");
        assert!(!r.contains("x ∈"), "ложные корни: {r}");
        // настоящий трансцендентный корень работает как раньше
        let r = calc("solve exp(x) = 2");
        assert!(r.contains("0.693"), "{r}");
        // касание нуля (чётная кратность) — численный путь: sin²(x) = 0
        // имеет корни ровно в кратных π — все настоящие (47 найдено)
        let r = calc("solve sin(x)^2 = 0");
        assert!(r.contains("корней"), "{r}");
        // полный список — в ans: π и 0 присутствуют точно
        let mut st = CalcState::new();
        st.eval_line("solve sin(x)^2 = 0").unwrap();
        let s = format!("{}", st.vars.get("ans").unwrap());
        assert!(s.contains("3.1415"), "{s}");
        assert!(s.contains("0.0"), "{s}");
    }

    #[test]
    fn lorentz_tachyon() {
        // досветовая γ
        let r = calc("lorentz(0.5)");
        assert!(r.contains("1.154"), "{r}");
        // v = c → расходимость
        let r = calc("lorentz(1)");
        assert!(r.contains("∞"), "{r}");
        // тахионная ветвь: γ(1.5) = −i/√1.25 ≈ −0.894i
        let r = calc("lorentz(1.5)");
        assert!(r.contains("-0.894"), "{r}");
    }

    #[test]
    fn pinv_singular_and_rect() {
        // ГЛАВНАЯ регрессия цикла N: inv([1,2;2,4]) был «невозможен»
        // (det = 0) — псевдообратная Мура–Пенроуза считает любую матрицу
        let r = calc("pinv([1, 2; 2, 4])");
        assert!(r.contains("0.04"), "{r}");
        assert!(r.contains("0.16"), "{r}");
        // inv вырожденной — ошибка с подсказкой на pinv
        let r = CalcState::new().eval_line("inv([1, 2; 2, 4])");
        assert!(r.unwrap_err().contains("pinv"));
        // прямоугольная строка: [1,2,3]⁺ = [1,2,3]ᵀ/14
        let r = calc("pinv([1, 2, 3])");
        assert!(r.contains("0.071"), "{r}"); // 1/14 ≈ 0.0714
        assert!(r.contains("0.214"), "{r}"); // 3/14 ≈ 0.2143
        // ζ(1) — полюс на расширенной прямой, как у Γ в целых точках
        let r = calc("zeta(1)");
        assert!(r.contains("∞"), "{r}");
    }

    // ================================================================
    // Цикл O «Шрёдингер»: невозможное → возможное
    // ================================================================
    #[test]
    fn cycle_o_complex_literals_and_matrices() {
        // мнимая единица — встроенный идентификатор (2i = 2·i)
        assert_eq!(calc("i * i"), "-1.0");
        assert_eq!(calc("1 + 2i"), "1.0 + 2.0i");
        // ТОЖДЕСТВО ЭЙЛЕРА: exp(iπ) = −1 (мнимый шум 1e-16 — как в Python cmath)
        let r = calc("exp(i * pi)");
        assert!(r.starts_with("-1.0"), "{r}");
        // модуль: |3+4i| = 5 — квантовые вероятности
        assert_eq!(calc("abs(3 + 4i)"), "5.0");
        // sin(i) = i·sinh(1) ≈ 1.1752i (комплексная тригонометрия)
        let r = calc("sin(i)");
        assert!(r.contains("1.175"), "{r}");
        // σ_y литералом: эрмитова, det = −1, спектр ±1
        assert_eq!(calc("dagger([0, -i; i, 0])"), "[0.0, -i; i, 0.0]");
        let r = calc("det([0, -i; i, 0])");
        assert!((r.parse::<f64>().unwrap() + 1.0).abs() < 1e-12, "{r}");
        let r = calc("eigen([0, -i; i, 0])");
        assert!(r.contains("-1.0") && r.contains("1.0"), "{r}");
        // комплексное скалярное умножение: i·I
        let r = calc("i * [1, 0; 0, 1]");
        assert!(r.contains("i"), "{r}");
        // expm комплексной матрицы: expm(σ_y) = cosh(1)·I + sinh(1)·σ_y
        let r = calc("expm([0, -i; i, 0])");
        assert!(r.contains("1.54"), "{r}"); // cosh(1) ≈ 1.5431
        // переменная пользователя перекрывает i (приоритет vars)
        let mut st = CalcState::new();
        st.eval_line("i = 5").unwrap();
        assert_eq!(st.eval_line("i * 2").unwrap(), "10.0");
    }

    #[test]
    fn cycle_o_schrodinger_solver() {
        // СПИН-ФЛИП: σ_y за время π/2 переводит |↑⟩ точно в |↓⟩
        let r = calc("schrodinger(pauli_y(), [1; 0], pi/2)");
        assert!(r.contains("1.0000000"), "{r}");
        assert!(!r.contains('i'), "{r}");
        // π-импульс σ_x: амплитуда на |↓⟩ = −i (фазовая структура Раби)
        let r = calc("schrodinger(pauli_x(), [1; 0], pi/2)");
        assert!(r.contains("-i"), "{r}");
        // ħ-параметр: t/ħ сокращаются — эволюция совпадает
        let r1 = calc("schrodinger(pauli_y(), [1; 0], pi/2, 1)");
        let r2 = calc("schrodinger(pauli_y(), [1; 0], pi, 2)");
        assert_eq!(r1, r2);
        // СОХРАНЕНИЕ НОРМЫ (фундаментальный закон): ψ†ψ = 1 в любой момент
        let mut st = CalcState::new();
        st.eval_line("g1 = schrodinger([0, 1; 1, 0], [1; 0], 1.234)").unwrap();
        let r = st.eval_line("dagger(g1) * g1").unwrap();
        assert!(r.contains("1.0"), "{r}");
        // Раби: ⟨1|ψ(π/4)⟩ = −0.707i → вероятность перехода 0.5
        st.eval_line("g2 = schrodinger(pauli_x(), [1; 0], pi/4)").unwrap();
        let r = st.eval_line("[0, 1] * g2").unwrap();
        assert!(r.contains("-0.707"), "{r}");
        // диагностика: psi0 обязан быть столбцом
        let err = CalcState::new().eval_line("schrodinger(pauli_x(), [1, 0], 1)").unwrap_err();
        assert!(err.contains("столбец"), "{err}");
    }

    #[test]
    fn cycle_o_bell_and_grover() {
        // ЗАПУТАННОСТЬ: CNOT·(H⊗I)|00⟩ = (|00⟩+|11⟩)/√2
        let r = calc(
            "[1, 0, 0, 0; 0, 1, 0, 0; 0, 0, 0, 1; 0, 0, 1, 0] * kron(hadamard(), eye(2)) * [1; 0; 0; 0]",
        );
        assert!(r.contains("0.707"), "{r}");
        // амплитуды ровно две ненулевые: 0.707 и 0.707
        assert_eq!(r.matches("0.707").count(), 2, "{r}");
        // норма белла = 1
        let mut st = CalcState::new();
        st.eval_line("bell = [1, 0, 0, 0; 0, 1, 0, 0; 0, 0, 0, 1; 0, 0, 1, 0] * kron(hadamard(), eye(2)) * [1; 0; 0; 0]").unwrap();
        let r = st.eval_line("dagger(bell) * bell").unwrap();
        assert!(r.contains("1.0"), "{r}");

        // ГРОУЕР 2 КУБИТА: ОДНА итерация находит |11⟩ с вероятностью 1
        st.eval_line("gs = kron(hadamard(), hadamard()) * [1; 0; 0; 0]").unwrap();
        st.eval_line("go = [1, 0, 0, 0; 0, 1, 0, 0; 0, 0, 1, 0; 0, 0, 0, -1]").unwrap();
        st.eval_line("gd = 2 * gs * dagger(gs) - eye(4)").unwrap();
        let r = st.eval_line("gd * go * gs").unwrap();
        // [~0; ~0; ~0; 1]: три нуля машинного порядка и единица
        assert!(r.contains("1.0000000"), "{r}");
        assert!(r.matches("e-").count() >= 3, "{r}");
    }

    #[test]
    fn cycle_o_infinite_well_tridiag() {
        // УРАВНЕНИЕ ШРЁДИНГЕРА НА СЕТКЕ: H = −½·d²/dx² в яме [0,1],
        // n = 16 узлов (h = 1/17): уровни λ_k = 289·(1−cos(πk/17))
        let r = calc("eigen(tridiag(289, -144.5, 16))");
        // λ₁ = 289·(1−cos(π/17)) ≈ 4.9215 (непрерывный предел π²/2 ≈ 4.9348)
        assert!(r.starts_with("[4.92"), "{r}");
        // λ₂ = 289·(1−cos(2π/17)) ≈ 19.5156
        assert!(r.contains("19.5"), "{r}");
        // тритовая диагностика лимита
        let err = CalcState::new().eval_line("tridiag(1, 1, 100)").unwrap_err();
        assert!(err.contains("2..=64"), "{err}");
    }

    #[test]
    fn structured_json() {
        let mut st = CalcState::new();
        let j = st.eval_structured("2^10");
        assert_eq!(j["ok"], serde_json::json!(true));
        assert_eq!(j["result"], serde_json::json!("1024.0"));
        assert_eq!(j["ans"], serde_json::json!("1024.0"));
        let j = st.eval_structured("boom boom");
        assert_eq!(j["ok"], serde_json::json!(false));
        assert!(j["error"].is_string());
    }

    #[test]
    fn history_cap() {
        let mut st = CalcState::new();
        for i in 0..(HISTORY_CAP + 50) {
            st.eval_line(&format!("{i} + 1")).unwrap();
        }
        assert_eq!(st.history.len(), HISTORY_CAP);
    }

    #[test]
    fn compound_units_canonical_display() {
        // РЕГРЕССИЯ: составные единицы с неединичным фактором обязаны
        // показывать каноническое СИ-значение (фактор не теряется!):
        // год по Кеплеру из (1 au)³/(G·M) — раньше выводило 6e-15 s
        let r = calc("2*pi*sqrt((1 au)^3 / (G*(M_sun+M_earth)))");
        assert!(r.contains('s'), "{r}");
        let secs: f64 = r.trim_end_matches(" s").parse().unwrap();
        let days = secs / 86400.0;
        assert!((days - 365.25).abs() < 1.0, "год = {days} дней ({r})");
        // в днях через конверсию
        let r = calc("2*pi*sqrt((1 au)^3 / (G*(M_sun+M_earth))) to day");
        let d2: f64 = r.parse().unwrap();
        assert!((d2 - 365.25).abs() < 1.0, "{r}");
        // безразмерное сокращение: 1 m / 1 km = 0.001
        assert_eq!(calc("1 m / 1 km"), "0.001");
        assert_eq!(calc("500000 kg / 50000 kg"), "10.0");
        // именованные единицы не канонизируются
        assert_eq!(calc("5 km + 300 m"), "5.3 km");
    }

    #[test]
    fn full_stack_examples() {
        // «тяжёлая» физика: планковская длина как выражение
        let r = calc("sqrt(hbar * G / c^3) to m");
        assert!(r.starts_with("1.6162"), "{r}");
        // квант: ротор Ли с фазой Ψ
        let r = calc("det(expm([0, -1; 1, 0] * psi))");
        assert!((r.parse::<f64>().unwrap() - 1.0).abs() < 1e-12, "{r}");
        // астро: освещённость в новолуние-затмение
        let r = calc("moon_illum(2024, 4, 8, 18.35)");
        assert!(r.parse::<f64>().unwrap() < 0.01, "{r}");
        // гео: Київ—Львів
        let r = calc("dist(50.45, 30.52, 49.84, 24.03)");
        let d: f64 = r.parse().unwrap();
        assert!(d > 450.0 && d < 475.0, "{d}");
        // триты
        assert_eq!(calc("trits(5)"), "\"1TT\"");
        // теория чисел
        assert_eq!(calc("next_prime(1e6)"), "1000003.0");
    }
}
