//! Парсер и вычислитель выражений калькулятора (цикл M, v0.48.0).
//!
//! Грамматика (приоритет сверху вниз — от слабейшего):
//! ```text
//! statement := ['let'] (ident '=' convert | convert ['=' convert])
//! convert   := add ['to' unit-spec]
//! add       := term (('+'|'-') term)*
//! term      := unary (('*'|'/'|'%') unary | implicit-unary)*
//! unary     := ('-'|'+') unary | power
//! power     := postfix ('^' unary)?            // правоассоц., 2^3^2 = 512
//! postfix   := primary ('!')*
//! primary   := num | str | ident | funcall | '(' convert ')' | '[' matrix ']'
//! ```
//!
//! РЕГРЕССИИ прошлой сессии, закрытые здесь:
//! - «to» захватывался неявным умножением → теперь `to` — зарезервированное
//!   слово, исключённое из implicit-mult;
//! - неявное умножение «съедало» стартовый токен → здесь только peek;
//! - `x = x` внутри solve парсился как присваивание → в eq_mode `=`
//!   трактуется как уравнение, присваивание отключено;
//! - free_vars не заходил в аргументы Call → заходит.

use std::collections::BTreeSet;
use std::collections::HashMap;

use super::constants;
use super::functions;
use super::lexer::{tokenize, Tok};
use super::matrix::Matrix;
use super::numbers;
use super::solve::Complex;
use super::units;
use super::units::Unit;
use super::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Num(f64),
    /// Числовой литерал с единицей: `5 km`, `30 deg`, `100 km/h`.
    UnitLit(f64, String),
    Str(String),
    Ident(String),
    Call { name: String, args: Vec<Expr> },
    Neg(Box<Expr>),
    Bin { op: BinOp, lhs: Box<Expr>, rhs: Box<Expr> },
    Fact(Box<Expr>),
    MatrixLit(Vec<Vec<Expr>>),
    Assign { name: String, expr: Box<Expr> },
    Convert { expr: Box<Expr>, spec: String },
    Equation { lhs: Box<Expr>, rhs: Box<Expr> },
}

// ---------------------------------------------------------------------
// Парсер
// ---------------------------------------------------------------------

pub struct Parser {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    eq_mode: bool,
}

/// Разобрать полное выражение-выражение (statement). `eq_mode = true`
/// включает трактовку `=` как уравнения (для `calc solve …`).
pub fn parse(src: &str, eq_mode: bool) -> Result<Expr, String> {
    let toks = tokenize(src)?;
    if toks.is_empty() {
        return Err("пустое выражение".into());
    }
    let mut p = Parser { toks, pos: 0, eq_mode };
    let e = p.parse_statement()?;
    if p.pos < p.toks.len() {
        let (t, col) = &p.toks[p.pos];
        return Err(format!("колонка {col}: неожидаемый токен «{t}»"));
    }
    Ok(e)
}

/// Утилита для scriptgen и тестов: разобрать и вычислить без переменных.
pub fn parse_and_eval(src: &str, vars: &HashMap<String, Value>) -> Result<Value, String> {
    let e = parse(src, false)?;
    let mut vars = vars.clone();
    eval(&e, &mut vars)
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(t, _)| t)
    }
    fn peek2(&self) -> Option<&Tok> {
        self.toks.get(self.pos + 1).map(|(t, _)| t)
    }
    fn at_col(&self) -> usize {
        self.toks.get(self.pos).map(|(_, c)| *c).unwrap_or(0)
    }
    fn bump(&mut self) -> Tok {
        let (t, _) = self.toks[self.pos].clone();
        self.pos += 1;
        t
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, t: &Tok) -> Result<(), String> {
        if self.eat(t) {
            Ok(())
        } else {
            Err(format!(
                "колонка {}: ожидалось «{t}», найдено «{}»",
                self.at_col(),
                self.peek().map(|t| t.to_string()).unwrap_or_else(|| "конец".into())
            ))
        }
    }

    fn parse_statement(&mut self) -> Result<Expr, String> {
        // `let x = …` (сахар)
        if matches!(self.peek(), Some(Tok::Ident(w)) if w == "let") {
            if matches!(self.peek2(), Some(Tok::Ident(_)))
                && matches!(self.toks.get(self.pos + 2), Some((Tok::Assign, _)))
            {
                self.bump(); // let
            }
        }
        // присваивание — ТОЛЬКО вне eq_mode (регрессия: `x = x` в solve)
        if !self.eq_mode {
            if let (Some(Tok::Ident(name)), Some(Tok::Assign)) =
                (self.peek().cloned(), self.peek2().cloned())
            {
                let name = name;
                self.bump();
                self.bump();
                let expr = self.parse_convert()?;
                return Ok(Expr::Assign { name, expr: Box::new(expr) });
            }
        }
        let lhs = self.parse_convert()?;
        if self.eq_mode && self.eat(&Tok::Assign) {
            let rhs = self.parse_convert()?;
            return Ok(Expr::Equation { lhs: Box::new(lhs), rhs: Box::new(rhs) });
        }
        Ok(lhs)
    }

    /// add ['to' unit] — конверсия единиц.
    fn parse_convert(&mut self) -> Result<Expr, String> {
        let e = self.parse_add()?;
        // `to` — только если дальше идёт идентификатор единицы
        if let (Some(Tok::Ident(w)), Some(Tok::Ident(_))) = (self.peek(), self.peek2()) {
            if w == "to" {
                self.bump(); // to
                let spec = self.collect_unit_spec()?;
                return Ok(Expr::Convert { expr: Box::new(e), spec });
            }
        }
        Ok(e)
    }

    /// Сбор спецификации единицы: km, km/h, N*m, m^2, s^-1 …
    fn collect_unit_spec(&mut self) -> Result<String, String> {
        let mut spec = String::new();
        match self.bump() {
            Tok::Ident(u) => spec.push_str(&u),
            t => return Err(format!("после «to» ожидалась единица, найдено «{t}»")),
        }
        loop {
            match self.peek() {
                // `*`/`/` продолжают спецификацию ТОЛЬКО перед именем единицы:
                // в `3 N * 4 m` звёздочка — умножение величин, а не часть «N*m».
                // Конфликт имён единиц и констант (h = часы/Планка, c = свет/
                // санти-) решается В ПОЛЬЗУ единицы: km/h — каноничнее.
                // Размерные константы после юнита пишите в скобках: (5 kg)*c^2.
                Some(Tok::Star) if matches!(self.peek2(), Some(Tok::Ident(_))) => {
                    self.bump();
                    spec.push('*');
                    match self.bump() {
                        Tok::Ident(u) => spec.push_str(&u),
                        t => return Err(format!("после «*» ожидалась единица, найдено «{t}»")),
                    }
                }
                Some(Tok::Slash) if matches!(self.peek2(), Some(Tok::Ident(_))) => {
                    self.bump();
                    spec.push('/');
                    match self.bump() {
                        Tok::Ident(u) => spec.push_str(&u),
                        t => return Err(format!("после «/» ожидалась единица, найдено «{t}»")),
                    }
                }
                Some(Tok::Caret) => {
                    self.bump();
                    spec.push('^');
                    let neg = self.eat(&Tok::Minus);
                    if neg {
                        spec.push('-');
                    }
                    match self.bump() {
                        Tok::Num(v) => {
                            if v.fract() == 0.0 {
                                spec.push_str(&format!("{}", v as i64));
                            } else {
                                spec.push_str(&format!("{v}"));
                            }
                        }
                        t => return Err(format!("после «^» ожидалась степень, найдено «{t}»")),
                    }
                }
                _ => break,
            }
        }
        Ok(spec)
    }

    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_term()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => BinOp::Add,
                Some(Tok::Minus) => BinOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_term()?;
            lhs = Expr::Bin { op, lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }

    /// Может ли токен начинать операнд (для неявного умножения)?
    /// `to` — зарезервированное слово, НЕ операнд (регрессия прошлой сессии).
    fn starts_operand(&self) -> bool {
        match self.peek() {
            Some(Tok::Num(_)) => true,
            Some(Tok::LParen) => true,
            Some(Tok::Ident(w)) => w != "to" && w != "let",
            _ => false,
        }
    }

    fn parse_term(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => BinOp::Mul,
                Some(Tok::Slash) => BinOp::Div,
                Some(Tok::Percent) => BinOp::Mod,
                _ => {
                    // неявное умножение: 2pi, 3(4+1), x y — только peek!
                    if self.starts_operand() {
                        BinOp::Mul
                    } else {
                        break;
                    }
                }
            };
            if matches!(self.peek(), Some(Tok::Star) | Some(Tok::Slash) | Some(Tok::Percent)) {
                self.bump();
            }
            let rhs = self.parse_unary()?;
            lhs = Expr::Bin { op, lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::Minus) => {
                self.bump();
                let e = self.parse_unary()?;
                Ok(Expr::Neg(Box::new(e)))
            }
            Some(Tok::Plus) => {
                self.bump();
                self.parse_unary()
            }
            _ => self.parse_power(),
        }
    }

    fn parse_power(&mut self) -> Result<Expr, String> {
        let base = self.parse_postfix()?;
        if self.eat(&Tok::Caret) {
            let exp = self.parse_unary()?; // правоассоциативность + унарный минус
            Ok(Expr::Bin { op: BinOp::Pow, lhs: Box::new(base), rhs: Box::new(exp) })
        } else {
            Ok(base)
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_primary()?;
        while self.eat(&Tok::Bang) {
            e = Expr::Fact(Box::new(e));
        }
        Ok(e)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        let col = self.at_col();
        match self.peek().cloned() {
            Some(Tok::Num(v)) => {
                self.bump();
                // литерал с единицей? `5 km`, `100 km/h`, `30 deg`
                if let Some(Tok::Ident(u)) = self.peek().cloned() {
                    if u != "to" && units::by_name(&u).is_some() {
                        let spec = self.collect_unit_spec()?;
                        return Ok(Expr::UnitLit(v, spec));
                    }
                }
                Ok(Expr::Num(v))
            }
            Some(Tok::Str(s)) => {
                self.bump();
                Ok(Expr::Str(s))
            }
            Some(Tok::LParen) => {
                self.bump();
                let e = self.parse_convert()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::LBracket) => {
                self.bump();
                let m = self.parse_matrix()?;
                self.expect(&Tok::RBracket)?;
                Ok(Expr::MatrixLit(m))
            }
            Some(Tok::Ident(name)) => {
                // вызов функции — только если имя известно реестру;
                // иначе x(y+1) — неявное умножение переменной на скобку
                let is_call = matches!(self.toks.get(self.pos + 1), Some((Tok::LParen, _)))
                    && functions::is_function(&name);
                if is_call {
                    self.bump(); // имя
                    self.bump(); // (
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(Tok::RParen)) {
                        loop {
                            args.push(self.parse_convert()?);
                            if !self.eat(&Tok::Comma) {
                                break;
                            }
                        }
                    }
                    self.expect(&Tok::RParen)?;
                    Ok(Expr::Call { name, args })
                } else {
                    self.bump();
                    Ok(Expr::Ident(name))
                }
            }
            other => Err(format!(
                "колонка {col}: ожидалось выражение, найдено «{}»",
                other.map(|t| t.to_string()).unwrap_or_else(|| "конец".into())
            )),
        }
    }

    fn parse_matrix(&mut self) -> Result<Vec<Vec<Expr>>, String> {
        let mut rows: Vec<Vec<Expr>> = Vec::new();
        let mut row: Vec<Expr> = Vec::new();
        loop {
            row.push(self.parse_convert()?);
            if self.eat(&Tok::Comma) {
                continue;
            }
            if self.eat(&Tok::Semicolon) {
                rows.push(std::mem::take(&mut row));
                if matches!(self.peek(), Some(Tok::RBracket)) {
                    break;
                }
                continue;
            }
            break;
        }
        rows.push(row);
        // проверка прямоугольности по количеству выражений
        let n = rows[0].len();
        if rows.iter().any(|r| r.len() != n) {
            return Err("строки матрицы разной длины".into());
        }
        if n == 0 || rows.is_empty() {
            return Err("пустая матрица".into());
        }
        Ok(rows)
    }
}

// ---------------------------------------------------------------------
// Свободные переменные
// ---------------------------------------------------------------------

/// Собрать имена свободных переменных (не функции, не константы).
/// РЕГРЕССИЯ: обязана заходить в аргументы вызовов функций.
pub fn free_vars(e: &Expr, out: &mut BTreeSet<String>) {
    match e {
        Expr::Num(_) | Expr::UnitLit(..) | Expr::Str(_) => {}
        Expr::Ident(name) => {
            if name != "let"
                && name != "to"
                && !functions::is_function(name)
                && constants::lookup(name).is_none()
            {
                out.insert(name.clone());
            }
        }
        Expr::Call { args, .. } => {
            for a in args {
                free_vars(a, out);
            }
        }
        Expr::Neg(x) | Expr::Fact(x) | Expr::Convert { expr: x, .. } => free_vars(x, out),
        Expr::Bin { lhs, rhs, .. } => {
            free_vars(lhs, out);
            free_vars(rhs, out);
        }
        Expr::MatrixLit(rows) => {
            for r in rows {
                for c in r {
                    free_vars(c, out);
                }
            }
        }
        Expr::Assign { expr, .. } => free_vars(expr, out),
        Expr::Equation { lhs, rhs } => {
            free_vars(lhs, out);
            free_vars(rhs, out);
        }
    }
}

// ---------------------------------------------------------------------
// Вычислитель
// ---------------------------------------------------------------------

/// Вычислить AST. `vars` может пополняться присваиваниями.
pub fn eval(e: &Expr, vars: &mut HashMap<String, Value>) -> Result<Value, String> {
    match e {
        Expr::Num(v) => Ok(Value::Scalar(*v)),
        Expr::UnitLit(v, spec) => {
            let unit = units::parse_spec(spec)?;
            Ok(Value::Quantity(*v, unit))
        }
        Expr::Str(s) => Ok(Value::Str(s.clone())),
        Expr::Ident(name) => {
            if let Some(v) = vars.get(name) {
                return Ok(v.clone());
            }
            // цикл O: мнимая единица — встроенный идентификатор (2i, [0, −i; i, 0]);
            // переменная пользователя имеет приоритет (calc i = 5 работает)
            if name == "i" {
                return Ok(Value::Complex(Complex::I));
            }
            if let Some((v, unit)) = constants::lookup(name) {
                return Ok(if unit.is_dimensionless() && unit.factor == 1.0 {
                    Value::Scalar(v)
                } else {
                    Value::Quantity(v, unit)
                });
            }
            Err(format!(
                "неизвестный идентификатор «{name}» — переменная (calc {name} = …), константа (calc constants) или функция (calc funcs)?"
            ))
        }
        Expr::Call { name, args } => {
            let mut vals = Vec::with_capacity(args.len());
            for a in args {
                vals.push(eval(a, vars)?);
            }
            functions::call_function(name, &vals)
        }
        Expr::Neg(x) => {
            let v = eval(x, vars)?;
            negate(&v)
        }
        Expr::Bin { op, lhs, rhs } => {
            let a = eval(lhs, vars)?;
            let b = eval(rhs, vars)?;
            binary_op(*op, &a, &b)
        }
        Expr::Fact(x) => {
            let v = eval(x, vars)?;
            factorial(&v)
        }
        Expr::MatrixLit(rows) => {
            // цикл O: элементы — числа ИЛИ комплексные (σ_y = [0, −i; i, 0])
            let mut data: Vec<Vec<Complex>> = Vec::with_capacity(rows.len());
            for r in rows {
                let mut row = Vec::with_capacity(r.len());
                for c in r {
                    let v = eval(c, vars)?;
                    match v {
                        Value::Scalar(x) => row.push(Complex::new(x, 0.0)),
                        Value::Complex(z) => row.push(z),
                        Value::BigInt(s) => {
                            // точное целое → f64 (с потерей точности за пределами 2⁵³)
                            let x = s
                                .parse::<f64>()
                                .map_err(|_| format!("элемент матрицы не число: {s}"))?;
                            if !x.is_finite() {
                                return Err(format!("элемент матрицы слишком велик: {s}"));
                            }
                            row.push(Complex::new(x, 0.0));
                        }
                        other => {
                            return Err(format!(
                                "элементы матрицы должны быть числами или комплексными, получено {other:?}"
                            ))
                        }
                    }
                }
                data.push(row);
            }
            Ok(Value::Matrix(Matrix::from_complex_rows(&data)?))
        }
        Expr::Assign { name, expr } => {
            let v = eval(expr, vars)?;
            vars.insert(name.clone(), v.clone());
            Ok(v)
        }
        Expr::Convert { expr, spec } => {
            let v = eval(expr, vars)?;
            convert_value(v, spec)
        }
        Expr::Equation { .. } => {
            Err("уравнение решается через `calc solve …`".into())
        }
    }
}

fn negate(v: &Value) -> Result<Value, String> {
    match v {
        Value::Scalar(x) => Ok(Value::Scalar(-x)),
        Value::Quantity(x, u) => Ok(Value::Quantity(-x, *u)),
        Value::Matrix(m) => Ok(Value::Matrix(m.scale(-1.0))),
        Value::Complex(c) => Ok(Value::Complex(Complex::new(-c.re, -c.im))),
        Value::BigInt(s) => Ok(Value::BigInt(
            if s.starts_with('-') {
                s[1..].to_string()
            } else if s != "0" {
                format!("-{s}")
            } else {
                s.clone()
            },
        )),
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(negate(it)?);
            }
            Ok(Value::List(out))
        }
        Value::Str(_) => Err("нельзя negate строку".into()),
    }
}

pub fn binary_op(op: BinOp, a: &Value, b: &Value) -> Result<Value, String> {
    use BinOp::*;
    // --- списки: поэлементно / broadcast ---
    if let Value::List(items) = a {
        return broadcast_lhs(op, items, b);
    }
    if let Value::List(items) = b {
        return broadcast_rhs(op, a, items);
    }

    match (a, b) {
        // --- скаляры ---
        (Value::Scalar(x), Value::Scalar(y)) => {
            if op == Pow {
                // цикл N: точный большой целый путь (2^100 → 21 цифра, без потерь)
                if let Some(v) = try_big_pow(*x, *y)? {
                    return Ok(v);
                }
                // цикл N: отрицательное основание с дробной степенью —
                // (-8)^(1/3) = -2 (нечётный знаменатель), иначе комплексная ветвь
                if *x < 0.0 && y.fract() != 0.0 {
                    return Ok(neg_frac_pow(*x, *y));
                }
            }
            Ok(Value::Scalar(scalar_op(op, *x, *y)?))
        }

        // --- точные большие целые (цикл N) ---
        (Value::BigInt(a), Value::BigInt(b)) => big_int_op(op, a, b),
        (Value::BigInt(a), Value::Scalar(y)) => {
            // целый малый скаляр — точный big-путь (fib(100) + 1)
            if y.fract() == 0.0 && y.abs() <= 9.0e15 {
                let ys = small_int_str(*y);
                return big_int_op(op, a, &ys);
            }
            // дробное — осознанный f64-мир (fib(100)/2.5)
            let xa = a.parse::<f64>().unwrap_or(f64::NAN);
            Ok(Value::Scalar(scalar_op(op, xa, *y)?))
        }
        (Value::Scalar(x), Value::BigInt(b)) => {
            if x.fract() == 0.0 && x.abs() <= 9.0e15 {
                let xs = small_int_str(*x);
                return big_int_op(op, &xs, b);
            }
            let yb = b.parse::<f64>().unwrap_or(f64::NAN);
            Ok(Value::Scalar(scalar_op(op, *x, yb)?))
        }

        // --- величины с единицами ---
        (Value::Quantity(x, u), Value::Scalar(y)) => match op {
            Mul => Ok(Value::Quantity(x * y, *u)),
            Div => Ok(Value::Quantity(x / y, *u)),
            // безразмерная величина ведёт себя как число (sqrt(2·r2/(r1+r2)) − 1)
            Add | Sub if u.is_dimensionless() => Ok(Value::Scalar(if op == Add {
                x * u.factor + y
            } else {
                x * u.factor - y
            })),
            Add | Sub => Err(dimension_mismatch_hint(op, a, b)),
            Pow => {
                if y.fract() == 0.0 && y.abs() <= 8.0 {
                    let k = *y as i8;
                    if k == 0 {
                        return Ok(Value::Scalar(1.0));
                    }
                    Ok(Value::Quantity(x.powf(*y), u.pow(k)))
                } else if u.is_dimensionless() {
                    // безразмерная величина в любой степени (roche: (ρ1/ρ2)^(1/3))
                    Ok(Value::Quantity(x.powf(*y), Unit::dimensionless()))
                } else {
                    Err("степень размерной величины должна быть целой |k| ≤ 8".into())
                }
            }
            Mod => Err("остаток не определён для размерных величин".into()),
        },
        (Value::Scalar(x), Value::Quantity(y, u)) => match op {
            Mul => Ok(Value::Quantity(x * y, *u)),
            Div => {
                // 1 / (5 s) → 0.2 s^-1; 1 m / (1 km) → 0.001 (безразмерная)
                let inv = u.pow(-1);
                Ok(collapse_dimensionless(x / y, inv))
            }
            Add | Sub if u.is_dimensionless() => Ok(Value::Scalar(if op == Add {
                x + y * u.factor
            } else {
                x - y * u.factor
            })),
            Add | Sub => Err(dimension_mismatch_hint(op, a, b)),
            Pow | Mod => Err("число^величина не поддерживается (степень должна быть числом)".into()),
        },
        (Value::Quantity(x, u1), Value::Quantity(y, u2)) => match op {
            Add | Sub => {
                if !u1.same_dim(u2) {
                    return Err(format!(
                        "несовместимые единицы: {} {} {}",
                        u1.display(),
                        if op == Add { "+" } else { "−" },
                        u2.display()
                    ));
                }
                let y2 = units::convert(*y, u2, u1)?;
                Ok(Value::Quantity(if op == Add { x + y2 } else { x - y2 }, *u1))
            }
            Mul => Ok(collapse_dimensionless(x * y, u1.mul(u2))),
            Div => Ok(collapse_dimensionless(x / y, u1.div(u2))),
            Pow => {
                let k = int_power(*y)?;
                if k == 0 {
                    return Ok(Value::Scalar(1.0));
                }
                Ok(collapse_dimensionless(x.powf(*y), u1.pow(k)))
            }
            Mod => Err("остаток не определён для размерных величин".into()),
        },

        // --- матрицы ---
        (Value::Matrix(m), Value::Scalar(s)) => match op {
            Mul => Ok(Value::Matrix(m.scale(*s))),
            Div => Ok(Value::Matrix(m.scale(1.0 / *s))),
            Add | Sub => Err("матрица ± число: не определено".into()),
            Pow => {
                let k = int_power(*s)?;
                matrix_pow(m, k)
            }
            Mod => Err("остаток для матриц не определён".into()),
        },
        (Value::Scalar(s), Value::Matrix(m)) => match op {
            Mul => Ok(Value::Matrix(m.scale(*s))),
            _ => Err("операция числа с матрицей не определена (кроме умножения)".into()),
        },
        (Value::Matrix(m), Value::Matrix(m2)) => match op {
            Add => Ok(Value::Matrix(m.add(m2)?)),
            Sub => Ok(Value::Matrix(m.sub(m2)?)),
            Mul => Ok(Value::Matrix(m.mul(m2)?)),
            Div | Pow => Err(
                "матрица/матрица и матрица^матрица не поддерживаются (степень — число; A^(-1) — обратная)"
                    .into(),
            ),
            Mod => Err("остаток для матриц не определён".into()),
        },
        (Value::Matrix(_), Value::Quantity(_, _)) | (Value::Quantity(_, _), Value::Matrix(_)) => {
            Err("матрицы в калькуляторе безразмерны (единицы — со скалярами)".into())
        }

        // --- комплексные (корни/собственные значения) ---
        (Value::Complex(c), Value::Scalar(s)) => Ok(Value::Complex(cplx_op_scalar(op, *c, *s)?)),
        (Value::Scalar(s), Value::Complex(c)) => Ok(Value::Complex(scalar_op_cplx(op, *s, *c)?)),
        (Value::Complex(c1), Value::Complex(c2)) => Ok(Value::Complex(cplx_op(op, *c1, *c2)?)),
        (Value::Complex(_), Value::Quantity(_, _)) | (Value::Quantity(_, _), Value::Complex(_)) => {
            Err("комплексные величины с единицами не поддерживаются".into())
        }
        // цикл O: комплексный скаляр × матрица — унитарные генераторы i·A,
        // гамильтонианы с фазами
        (Value::Complex(c), Value::Matrix(m)) => match op {
            Mul => Ok(Value::Matrix(m.scale_c(*c))),
            _ => Err("комплексное с матрицей: определено только умножение (c·A)".into()),
        },
        (Value::Matrix(m), Value::Complex(c)) => match op {
            Mul => Ok(Value::Matrix(m.scale_c(*c))),
            Div => Ok(Value::Matrix(m.scale_c(Complex::ONE.div(*c)))),
            _ => Err("матрица с комплексным: определены · и / (A·c, A/c)".into()),
        },

        (Value::Str(_), _) | (_, Value::Str(_)) => {
            Err("арифметика со строками не определена".into())
        }
        // --- BigInt с остальными типами: f64-приближение (физика/матрицы ---
        // живут в f64-мире; точность больших целых — в big-операциях выше)
        (Value::BigInt(a), _) => {
            let xa = a.parse::<f64>().unwrap_or(f64::NAN);
            binary_op(op, &Value::Scalar(xa), b)
        }
        (_, Value::BigInt(b)) => {
            let yb = b.parse::<f64>().unwrap_or(f64::NAN);
            binary_op(op, a, &Value::Scalar(yb))
        }
        // списки пойманы выше broadcast-ами — сюда попадаем только с
        // нестандартными комбинациями (List с матрицей и т.п.)
        _ => Err("операция не определена для этих типов".into()),
    }
}

fn broadcast_lhs(op: BinOp, items: &[Value], b: &Value) -> Result<Value, String> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        out.push(binary_op(op, it, b)?);
    }
    Ok(Value::List(out))
}
fn broadcast_rhs(op: BinOp, a: &Value, items: &[Value]) -> Result<Value, String> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        out.push(binary_op(op, a, it)?);
    }
    Ok(Value::List(out))
}

/// Малое целое → каноническая строка (для моста BigInt↔Scalar).
fn small_int_str(v: f64) -> String {
    if v < 0.0 {
        format!("-{}", (-v) as u64)
    } else {
        format!("{}", v as u64)
    }
}

/// Знаковые операции над точными большими целыми.
fn big_int_op(op: BinOp, a: &str, b: &str) -> Result<Value, String> {
    use BinOp::*;
    let approx = |s: &str| s.parse::<f64>().unwrap_or(f64::NAN);
    Ok(match op {
        Add => Value::BigInt(numbers::big_add(a, b)),
        Sub => Value::BigInt(numbers::big_sub(a, b)),
        Mul => Value::BigInt(numbers::big_mul(a, b)),
        Div => {
            if let Ok(d) = b.parse::<i64>() {
                if d == 0 {
                    if a == "0" {
                        return Err(
                            "0/0 — неопределённость: предел зависит от пути (x/x → 1, 0/x → 0)"
                                .into(),
                        );
                    }
                    // расширенная прямая: ±∞ по знаку числителя
                    return Ok(Value::Scalar(if a.starts_with('-') {
                        f64::NEG_INFINITY
                    } else {
                        f64::INFINITY
                    }));
                }
                // деление нацело? q·d == a — тогда точный путь
                let q = numbers::big_div_small(a, d.unsigned_abs());
                let mut qs = q.clone();
                if (d < 0) != a.starts_with('-') && q != "0" {
                    qs = format!("-{q}");
                }
                if numbers::big_mul(&qs, b) == a {
                    return Ok(Value::BigInt(qs));
                }
            }
            // неточное деление — f64-приближение
            Value::Scalar(scalar_op(op, approx(a), approx(b))?)
        }
        Pow => {
            let e: i64 = b
                .parse()
                .map_err(|_| "степень точного целого должна быть малым целым".to_string())?;
            if e < 0 {
                return Ok(Value::Scalar(scalar_op(op, approx(a), e as f64)?));
            }
            if let Ok(base) = a.parse::<i64>() {
                return Ok(Value::BigInt(numbers::big_pow(base, e as u64)?));
            }
            // большое основание, малый целый показатель
            Value::BigInt(numbers::big_pow_big(a, e as u64)?)
        }
        Mod => {
            return Err(
                "остаток для точных больших целых не поддерживается (mod — целочисленный f64-путь)"
                    .into(),
            )
        }
    })
}

/// Точный большой целый путь для Scalar^Scalar: 2^100, (-3)^71…
/// Возвращает None, если результат точно представим в f64 (совместимость).
fn try_big_pow(x: f64, y: f64) -> Result<Option<Value>, String> {
    if x.fract() != 0.0 || y.fract() != 0.0 || y <= 0.0 {
        return Ok(None);
    }
    let ax = x.abs();
    if !(2.0..=9.0e18).contains(&ax) {
        return Ok(None);
    }
    // оценка числа цифр результата
    let digits = ax.log10() * y;
    if digits <= 15.95 {
        return Ok(None); // точно в f64 — остаёмся в Scalar (2^10 → 1024.0)
    }
    let base = x as i64;
    let exp = y as u64;
    Ok(Some(Value::BigInt(numbers::big_pow(base, exp)?)))
}

/// Поиск рационального p/q (q ≤ max_q), ближайшего к y с точностью f64.
fn rat_denominator(y: f64, max_q: u64) -> Option<(i64, u64)> {
    fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = a % b;
            a = b;
            b = t;
        }
        if a == 0 { 1 } else { a }
    }
    if y.abs() > 1e6 {
        return None; // гигантские дробные степени — сразу комплексная ветвь
    }
    for q in 2..=max_q {
        let p = (y * q as f64).round();
        if (y - p / q as f64).abs() < 1e-12 * (1.0 + y.abs()) {
            let g = gcd_u64(p.abs() as u64, q);
            return Some(((p as i64) / g as i64, q / g));
        }
    }
    None
}

/// Отрицательное основание с дробной степенью (цикл N):
/// нечётный знаменатель рациональной степени → вещественный корень
/// ((-8)^(1/3) = -2); иначе главная комплексная ветвь
/// x^y = |x|^y·(cos πy + i·sin πy) ((-2)^0.5 = i·√2).
fn neg_frac_pow(x: f64, y: f64) -> Value {
    if let Some((p, q)) = rat_denominator(y, 64) {
        if q % 2 == 1 {
            let mag = x.abs().powf(y);
            return Value::Scalar(if p % 2 != 0 { -mag } else { mag });
        }
    }
    let mag = x.abs().powf(y);
    let (s, c) = (std::f64::consts::PI * y).sin_cos();
    Value::Complex(Complex::new(mag * c, mag * s))
}

fn scalar_op(op: BinOp, x: f64, y: f64) -> Result<f64, String> {
    use BinOp::*;
    Ok(match op {
        Add => x + y,
        Sub => x - y,
        Mul => x * y,
        Div => {
            if y == 0.0 {
                if x == 0.0 {
                    return Err(
                        "0/0 — неопределённость: предел зависит от пути (x/x → 1, 0/x → 0); используйте solve для предельного анализа"
                            .into(),
                    );
                }
                // расширенная прямая: ±∞ (1/0 → ∞, -1/0 → -∞)
                x / y
            } else {
                x / y
            }
        }
        Mod => {
            if y == 0.0 {
                return Err("x mod 0 не определён".into());
            }
            x.rem_euclid(y)
        }
        Pow => x.powf(y),
    })
}

fn cplx_op(op: BinOp, a: Complex, b: Complex) -> Result<Complex, String> {
    use BinOp::*;
    Ok(match op {
        Add => a.add(b),
        Sub => a.sub(b),
        Mul => a.mul(b),
        Div => a.div(b),
        Pow => {
            // z^w = exp(w·Ln z) — главная ветвь
            let r = a.abs();
            if r == 0.0 {
                return Err("0^комплексное не определено".into());
            }
            let theta = a.im.atan2(a.re);
            let mag = r.powf(b.re) * (-b.im * theta).exp();
            let ang = b.re * theta + b.im * r.ln();
            Complex::new(mag * ang.cos(), mag * ang.sin())
        }
        Mod => return Err("остаток для комплексных не определён".into()),
    })
}

fn cplx_op_scalar(op: BinOp, c: Complex, s: f64) -> Result<Complex, String> {
    use BinOp::*;
    match op {
        Add => Ok(c.add(Complex::new(s, 0.0))),
        Sub => Ok(c.sub(Complex::new(s, 0.0))),
        Mul => Ok(c.scale(s)),
        Div => Ok(c.div(Complex::new(s, 0.0))),
        Pow => cplx_op(op, c, Complex::new(s, 0.0)),
        Mod => Err("остаток для комплексных не определён".into()),
    }
}

fn scalar_op_cplx(op: BinOp, s: f64, c: Complex) -> Result<Complex, String> {
    use BinOp::*;
    match op {
        Add => Ok(Complex::new(s, 0.0).add(c)),
        Sub => Ok(Complex::new(s, 0.0).sub(c)),
        Mul => Ok(c.scale(s)),
        Div => Ok(Complex::new(s, 0.0).div(c)),
        Pow => cplx_op(op, Complex::new(s, 0.0), c),
        Mod => Err("остаток для комплексных не определён".into()),
    }
}

fn int_power(y: f64) -> Result<i8, String> {
    if y.fract() == 0.0 && y.abs() <= 8.0 {
        Ok(y as i8)
    } else {
        Err("степень с единицами должна быть целой |k| ≤ 8".into())
    }
}

fn matrix_pow(m: &Matrix, k: i8) -> Result<Value, String> {
    if !m.is_square() {
        return Err("степень матрицы — только для квадратных".into());
    }
    match k.cmp(&0) {
        std::cmp::Ordering::Equal => Ok(Value::Matrix(Matrix::identity(m.rows))),
        std::cmp::Ordering::Less => {
            if k == -1 {
                Ok(Value::Matrix(m.inv()?))
            } else {
                // A^(-k) = (A^-1)^k
                let inv = m.inv()?;
                let mut acc = Matrix::identity(m.rows);
                for _ in 0..(-k) {
                    acc = acc.mul(&inv)?;
                }
                Ok(Value::Matrix(acc))
            }
        }
        std::cmp::Ordering::Greater => {
            let mut acc = Matrix::identity(m.rows);
            for _ in 0..k {
                acc = acc.mul(m)?;
            }
            Ok(Value::Matrix(acc))
        }
    }
}

/// Безразмерный результат операции сворачивается в скаляр (фактор
/// входит в значение): `1 m / 1 km` → 0.001, `500000 kg / 50000 kg` → 10.
fn collapse_dimensionless(v: f64, u: Unit) -> Value {
    if u.is_dimensionless() {
        Value::Scalar(v * u.factor)
    } else {
        Value::Quantity(v, u)
    }
}

fn dimension_mismatch_hint(op: BinOp, a: &Value, b: &Value) -> String {
    let sym = if op == BinOp::Add { "+" } else { "−" };
    format!(
        "нельзя складывать число с размерной величиной: {a:?} {sym} {b:?} — \
         приведите единицы (например, `5 km + 300 m`)"
    )
}

/// Факториал: целые 0..=170 — произведение; иначе Γ(x+1).
pub fn factorial(v: &Value) -> Result<Value, String> {
    let x = match v {
        Value::Scalar(s) => *s,
        Value::Quantity(q, u) if u.is_dimensionless() => *q,
        _ => return Err("факториал определён для чисел".into()),
    };
    if x < 0.0 && x.fract() == 0.0 {
        return Err("факториал отрицательного целого не определён (полюса Γ)".into());
    }
    if x.fract() == 0.0 && x <= 170.0 {
        let mut acc = 1.0f64;
        let n = x as u64;
        for i in 1..=n {
            acc *= i as f64;
        }
        return Ok(Value::Scalar(acc));
    }
    if x > 171.0 {
        return Err("факториал > 170! переполняет f64".into());
    }
    // Γ(x+1) через Ланцоса (functions::gamma)
    Ok(Value::Scalar(super::functions::gamma_impl(x + 1.0)?))
}

/// Конверсия значения по спецификации единицы.
fn convert_value(v: Value, spec: &str) -> Result<Value, String> {
    let target = units::parse_spec(spec)?;
    match v {
        Value::Scalar(x) => {
            // число трактуем как РАДИАНЫ при конверсии в углы (asin(0.5) to deg)
            if target.dim[units::DIM_ANGLE] == 1
                && target.dim.iter().enumerate().all(|(i, &d)| i == units::DIM_ANGLE || d == 0)
            {
                let rad = units::by_name("rad").unwrap();
                return Ok(Value::Scalar(units::convert(x, &rad, &target)?));
            }
            if target.is_dimensionless() {
                return Ok(Value::Scalar(x)); // `to 1`? — без изменений
            }
            Err(format!(
                "число без единиц нельзя перевести в «{spec}» — укажите единицу у значения: `5 {spec}`"
            ))
        }
        Value::Quantity(x, u) => Ok(Value::Scalar(units::convert(x, &u, &target)?)),
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(convert_value(it, spec)?);
            }
            Ok(Value::List(out))
        }
        other => Err(format!("конверсия единиц неприменима к {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval_str(src: &str) -> Result<Value, String> {
        parse_and_eval(src, &HashMap::new())
    }
    fn num(src: &str) -> f64 {
        match eval_str(src).unwrap() {
            Value::Scalar(v) => v,
            other => panic!("ожидалось число, получено {other:?}"),
        }
    }

    // ================================================================
    // Арифметика и приоритеты
    // ================================================================
    #[test]
    fn basic_arithmetic() {
        assert_eq!(num("1 + 2 * 3"), 7.0);
        assert_eq!(num("(1 + 2) * 3"), 9.0);
        assert_eq!(num("2^10"), 1024.0);
        assert_eq!(num("2^3^2"), 512.0); // правоассоциативность
        assert_eq!(num("-2^2"), -4.0); // унарный минус слабее ^
        assert_eq!(num("2^-1"), 0.5);
        assert_eq!(num("10 % 3"), 1.0);
        assert_eq!(num("-7 % 3"), 2.0); // семантика rem_euclid (как в Python)
        assert_eq!(num("5!"), 120.0);
        assert_eq!(num("3! + 1"), 7.0);
        assert_eq!(num("2 * 3!"), 12.0);
        assert!((num("0.5!") - std::f64::consts::PI.sqrt() / 2.0).abs() < 1e-12); // Γ(1.5) = √π/2
    }

    #[test]
    fn implicit_multiplication() {
        // 2pi, 2(3+4), (1+2)(3+4)
        assert!((num("2 pi") - 6.283185307179586).abs() < 1e-15);
        assert_eq!(num("2(3 + 4)"), 14.0);
        assert_eq!(num("(1 + 2)(3 + 4)"), 21.0);
        // РЕГРЕССИЯ: x(y+1) с переменной x — умножение, а не вызов
        let mut vars = HashMap::new();
        vars.insert("x".into(), Value::Scalar(3.0));
        let v = parse_and_eval("x (y + 1)", &{
            let mut v2 = vars.clone();
            v2.insert("y".into(), Value::Scalar(5.0));
            v2
        })
        .unwrap();
        assert_eq!(v, Value::Scalar(18.0));
        // и напрямую:
        let mut env = HashMap::new();
        env.insert("x".to_string(), Value::Scalar(3.0));
        env.insert("y".to_string(), Value::Scalar(5.0));
        assert_eq!(eval(&parse("x(y+1)", false).unwrap(), &mut env).unwrap(), Value::Scalar(18.0));
    }

    #[test]
    fn functions_and_constants() {
        assert!((num("sin(pi/2)") - 1.0).abs() < 1e-15);
        assert!((num("cos(0)") - 1.0).abs() < 1e-15);
        assert!((num("sqrt(16)") - 4.0).abs() < 1e-15);
        assert!((num("exp(1)") - std::f64::consts::E).abs() < 1e-15);
        assert!((num("ln(e)") - 1.0).abs() < 1e-15);
        assert!((num("log2(1024)") - 10.0).abs() < 1e-12);
        assert!(num("phi^2 - phi - 1").abs() < 1e-12); // золотое сечение
        assert!((num("sind(30)") - 0.5).abs() < 1e-14); // градусные версии
        assert!((num("sin(30 deg)") - 0.5).abs() < 1e-14); // через единицы
    }

    // ================================================================
    // РЕГРЕССИЯ: «to» не должен захватываться неявным умножением
    // ================================================================
    #[test]
    fn to_conversion_not_eaten() {
        let v = eval_str("5 km to mi").unwrap();
        match v {
            Value::Scalar(x) => assert!((x - 3.1068559611866697).abs() < 1e-9),
            other => panic!("{other:?}"),
        }
        assert!((num("180 deg to rad") - std::f64::consts::PI).abs() < 1e-12);
        // скаляр asin → to deg трактуется как радианы
        assert!((num("asin(0.5) to deg") - 30.0).abs() < 1e-9);
        // составные единицы
        assert!((num("100 km/h to m/s") - 27.777777777777779).abs() < 1e-12);
        // константа-единица (c) после юнита: в скобках — корректно
        match eval_str("(1e-3 kg) * c^2 to J").unwrap() {
            Value::Scalar(v) => assert!((v - 8.9875517873681764e13).abs() < 1e3, "{v:e}"),
            other => panic!("{other:?}"),
        }
        // ошибка размерностей — с сообщением
        assert!(eval_str("5 km to kg").is_err());
        // число без единиц в размерную единицу — ошибка с подсказкой
        assert!(eval_str("5 to km").is_err());
        // в скобках тоже работает
        assert!((num("(5 km to mi) * 2") - 6.213711922373339).abs() < 1e-9);
    }

    // ================================================================
    // Присваивание и уравнения
    // ================================================================
    #[test]
    fn assignment_works() {
        let mut vars = HashMap::new();
        let e = parse("x = 5", false).unwrap();
        let v = eval(&e, &mut vars).unwrap();
        assert_eq!(v, Value::Scalar(5.0));
        assert_eq!(vars.get("x"), Some(&Value::Scalar(5.0)));
        // использование
        let e2 = parse("x * 2 + 1", false).unwrap();
        assert_eq!(eval(&e2, &mut vars).unwrap(), Value::Scalar(11.0));
        // let-сахар
        let e3 = parse("let y = x + 1", false).unwrap();
        eval(&e3, &mut vars).unwrap();
        assert_eq!(vars.get("y"), Some(&Value::Scalar(6.0)));
    }

    // РЕГРЕССИЯ: `x = x` внутри solve — уравнение, а не присваивание
    #[test]
    fn equation_mode_x_eq_x() {
        let e = parse("x = x", true).unwrap();
        assert!(matches!(e, Expr::Equation { .. }), "{e:?}");
        // и не паникует на free_vars
        let mut fv = BTreeSet::new();
        free_vars(&e, &mut fv);
        assert!(fv.contains("x"));
        // в обычном режиме — присваивание
        let e = parse("x = x", false).unwrap();
        assert!(matches!(e, Expr::Assign { .. }));
    }

    // РЕГРЕССИЯ: free_vars заходит в аргументы Call
    #[test]
    fn free_vars_enters_call_args() {
        let e = parse("sin(x) + cos(2*y) + z", false).unwrap();
        let mut fv = BTreeSet::new();
        free_vars(&e, &mut fv);
        assert_eq!(fv.iter().cloned().collect::<Vec<_>>(), vec!["x", "y", "z"]);
        // константы и функции не считаются переменными
        let e = parse("sin(pi) + sqrt(2)", false).unwrap();
        let mut fv = BTreeSet::new();
        free_vars(&e, &mut fv);
        assert!(fv.is_empty(), "{fv:?}");
    }

    // ================================================================
    // Величины с единицами
    // ================================================================
    #[test]
    fn quantity_arithmetic() {
        // 5 km + 300 m = 5.3 km
        match eval_str("5 km + 300 m").unwrap() {
            Value::Quantity(v, u) => {
                assert!((v - 5.3).abs() < 1e-12);
                assert_eq!(u.display(), "km");
            }
            other => panic!("{other:?}"),
        }
        // м² → красивое имя через обратный поиск не находится — каноника
        match eval_str("2 m * 3 m").unwrap() {
            Value::Quantity(v, u) => {
                assert!((v - 6.0).abs() < 1e-12);
                assert_eq!(u.display(), "m^2");
            }
            other => panic!("{other:?}"),
        }
        // Н·м = Дж
        match eval_str("3 N * 4 m").unwrap() {
            Value::Quantity(v, u) => {
                assert!((v - 12.0).abs() < 1e-12);
                assert_eq!(u.display(), "J");
            }
            other => panic!("{other:?}"),
        }
        // c как константа + m/s → сокращение в безразмерную скорость
        match eval_str("299792458 m/s to c").unwrap() {
            Value::Scalar(v) => assert!((v - 1.0).abs() < 1e-15),
            other => panic!("{other:?}"),
        }
        // число + величина → ошибка с подсказкой
        assert!(eval_str("5 + 3 km").is_err());
        assert!(eval_str("5 km + 3 kg").is_err());
        // деление величин
        match eval_str("100 km / 2 h").unwrap() {
            Value::Quantity(v, _) => assert!((v - 50.0).abs() < 1e-12),
            other => panic!("{other:?}"),
        }
    }

    // ================================================================
    // Матрицы
    // ================================================================
    #[test]
    fn matrix_literals_and_ops() {
        match eval_str("[1, 2; 3, 4] * [5; 6]").unwrap() {
            Value::Matrix(m) => {
                assert_eq!(m.rows, 2);
                assert_eq!(m.cols, 1);
                assert_eq!(m.get(0, 0), 17.0);
                assert_eq!(m.get(1, 0), 39.0);
            }
            other => panic!("{other:?}"),
        }
        // транспонирование, det, inv, след
        match eval_str("det([1, 2; 3, 4])").unwrap() {
            Value::Scalar(v) => assert!((v + 2.0).abs() < 1e-12),
            other => panic!("{other:?}"),
        }
        match eval_str("trace([1, 2; 3, 4])").unwrap() {
            Value::Scalar(v) => assert!((v - 5.0).abs() < 1e-12),
            other => panic!("{other:?}"),
        }
        // A^(-1) — обратная через степень
        match eval_str("[1, 2; 3, 4]^(-1)").unwrap() {
            Value::Matrix(m) => {
                assert!((m.get(0, 0) + 2.0).abs() < 1e-12);
                assert!((m.get(0, 1) - 1.0).abs() < 1e-12);
                assert!((m.get(1, 0) - 1.5).abs() < 1e-12);
                assert!((m.get(1, 1) + 0.5).abs() < 1e-12);
            }
            other => panic!("{other:?}"),
        }
        // неровные строки — ошибка
        assert!(parse("[1, 2; 3]", false).is_err());
        assert!(parse("[1, 2, 3]", false).is_ok()); // 1×3 — валидно
    }

    // ================================================================
    // Квантовая часть: expm(J·θ) — вращение Ли
    // ================================================================
    #[test]
    fn lie_rotation_via_expm() {
        // J = A − Aᵀ ротор: expm(J * pi/2) поворачивает x→y
        let expr = "expm([0, -1; 1, 0] * (pi/2))";
        match eval_str(expr).unwrap() {
            Value::Matrix(m) => {
                assert!((m.get(0, 0) - 0.0).abs() < 1e-12);
                assert!((m.get(1, 0) - 1.0).abs() < 1e-12);
                assert!((m.get(0, 1) + 1.0).abs() < 1e-12);
            }
            other => panic!("{other:?}"),
        }
        // rot2 + собственные значения ±i (на π/6 это e^{±iπ/6} — не ±i!)
        match eval_str("eigen(rot2(pi/2))").unwrap() {
            Value::List(items) => {
                assert_eq!(items.len(), 2);
                for it in &items {
                    if let Value::Complex(c) = it {
                        assert!((c.re.abs()) < 1e-9, "{c:?}");
                        assert!(c.im.abs() > 0.99, "{c:?}");
                    } else {
                        panic!("ожидались комплексные: {it:?}");
                    }
                }
            }
            other => panic!("{other:?}"),
        }
        // so_gen + expm = rotation
        match eval_str("expm(so_gen(3, 0, 2) * 1.0)").unwrap() {
            Value::Matrix(m) => {
                // вращение в плоскости (x,z) на 1 рад
                assert!((m.get(0, 0) - 1.0_f64.cos()).abs() < 1e-12);
            }
            other => panic!("{other:?}"),
        }
    }

    // ================================================================
    // Триты в выражениях
    // ================================================================
    #[test]
    fn trits_in_expressions() {
        match eval_str("trits(5)").unwrap() {
            Value::Str(s) => assert_eq!(s, "1TT"),
            other => panic!("{other:?}"),
        }
        match eval_str("trit_val(\"1TT\")").unwrap() {
            Value::Scalar(v) => assert!((v - 5.0).abs() < 1e-12),
            other => panic!("{other:?}"),
        }
    }

    // ================================================================
    // Ошибки — сообщения вместо паник
    // ================================================================
    #[test]
    fn errors_are_messages() {
        assert!(eval_str("unknown_var + 1").is_err());
        assert!(eval_str("sin()").is_err());
        assert!(eval_str("2 +").is_err());
        assert!(eval_str("(2 + 3").is_err());
        assert!(eval_str("[1, 2; 3]").is_err());
        assert!(eval_str("5 !").is_ok()); // пробел перед ! — ок
        assert!(eval_str("factorial(-1)").is_err());
        assert!(eval_str("1/0").is_ok()); // inf — не ошибка парсинга
        assert!(parse("", false).is_err());
        assert!(parse("= 5", false).is_err());
    }

    #[test]
    fn hostile_inputs_terminate() {
        // регрессия: парсер не должен зацикливаться ни на каком вводе
        for src in [
            "", "+", "*", "^", "!", "(", ")", "[", "]", ",", ";", "=", "to", "let",
            "to km", "5 to", "5 to 5", "x =", "= x", "(((", "]]]", "sin(", "sin(,",
            "[;]", "[1;]", "1 e", "a a a a a", "--", "++", "**", "//",
        ] {
            let _ = parse(src, false);
            let _ = parse(src, true);
        }
    }
}
