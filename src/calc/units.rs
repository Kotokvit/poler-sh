//! Единицы измерения (цикл M, v0.48.0).
//!
//! Модель: `Unit = { dim: [i8; 9], factor: f64, name }` — линейный множитель
//! к базовой единице СИ своей размерности. Температура — аффинная
//! (degC/degF несут смещение только при конверсии «в/из»).
//!
//! Размерности: [длина, масса, время, ток, температура, количество,
//! сила света, угол, информация].
//!
//! Источники множителей: BIPM SI Brochure 9th ed., NIST SP 811,
//! IAU 2012 Res. B2 (au), WGS84 (морская миля = 1852 м — точно).

pub const DIM_LEN: usize = 0;
pub const DIM_MASS: usize = 1;
pub const DIM_TIME: usize = 2;
pub const DIM_CURRENT: usize = 3;
pub const DIM_TEMP: usize = 4;
pub const DIM_AMOUNT: usize = 5;
pub const DIM_LUMIN: usize = 6;
pub const DIM_ANGLE: usize = 7;
pub const DIM_INFO: usize = 8;
pub const NDIM: usize = 9;

/// Базовые имена размерностей для канонического вывода (порядок СИ + наши).
const BASE_NAMES: [&str; NDIM] = [
    "m", "kg", "s", "A", "K", "mol", "cd", "rad", "bit",
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Unit {
    /// Показатели базовых размерностей.
    pub dim: [i8; NDIM],
    /// Линейный множитель к базовой единице размерности.
    pub factor: f64,
    /// Человекочитаемое имя (для табличных единиц).
    pub name: &'static str,
    /// Аффинное смещение (только температура: значение_базовое = factor·v + offset).
    pub offset: f64,
}

impl Unit {
    /// Безразмерная единица.
    pub const fn dimensionless() -> Self {
        Unit { dim: [0; NDIM], factor: 1.0, name: "", offset: 0.0 }
    }

    pub fn is_dimensionless(&self) -> bool {
        self.dim.iter().all(|&d| d == 0)
    }

    /// Одинаковая ли размерность (для +, -, to).
    pub fn same_dim(&self, other: &Unit) -> bool {
        self.dim == other.dim
    }

    /// Единица·единица (умножение).
    pub fn mul(&self, other: &Unit) -> Unit {
        let mut dim = [0i8; NDIM];
        for i in 0..NDIM {
            dim[i] = self.dim[i] + other.dim[i];
        }
        Unit { dim, factor: self.factor * other.factor, name: "", offset: 0.0 }
    }

    /// Единица/единица (деление).
    pub fn div(&self, other: &Unit) -> Unit {
        let mut dim = [0i8; NDIM];
        for i in 0..NDIM {
            dim[i] = self.dim[i] - other.dim[i];
        }
        Unit { dim, factor: self.factor / other.factor, name: "", offset: 0.0 }
    }

    /// Единица в степени k.
    pub fn pow(&self, k: i8) -> Unit {
        let mut dim = [0i8; NDIM];
        for i in 0..NDIM {
            dim[i] = self.dim[i].saturating_mul(k);
        }
        Unit { dim, factor: self.factor.powi(k as i32), name: "", offset: 0.0 }
    }

    /// Каноническое текстовое представление (m·kg/s^2 …).
    pub fn display(&self) -> String {
        if self.is_dimensionless() {
            return String::new();
        }
        // Красивое имя, если есть точное совпадение с табличной единицей.
        if let Some((nm, _u)) = lookup(self) {
            return nm.to_string();
        }
        let mut num = Vec::new();
        let mut den = Vec::new();
        for (i, &d) in self.dim.iter().enumerate() {
            if d > 0 {
                num.push(if d == 1 {
                    BASE_NAMES[i].to_string()
                } else {
                    format!("{}^{}", BASE_NAMES[i], d)
                });
            } else if d < 0 {
                den.push(if d == -1 {
                    BASE_NAMES[i].to_string()
                } else {
                    format!("{}^{}", BASE_NAMES[i], -d)
                });
            }
        }
        match (num.len(), den.len()) {
            (0, _) => format!("1/{}", den.join("·")),
            (_, 0) => num.join("·"),
            _ => format!("{}/{}", num.join("·"), den.join("·")),
        }
    }
}

/// Табличная единица (имя, множитель, показатели размерностей, аффинное смещение).
struct UnitDef {
    name: &'static str,
    factor: f64,
    dim: [i8; NDIM],
    offset: f64,
}

const fn d(len: i8, mass: i8, time: i8, cur: i8, temp: i8, amt: i8, lum: i8, ang: i8, info: i8) -> [i8; NDIM] {
    [len, mass, time, cur, temp, amt, lum, ang, info]
}

macro_rules! unit {
    ($name:literal, $factor:expr, $dim:expr) => {
        UnitDef { name: $name, factor: $factor, dim: $dim, offset: 0.0 }
    };
}

/// Полный реестр единиц. Порядок важен только для вывода списков.
static UNITS: &[UnitDef] = &[
    // ---- длина (базовая m) ----
    unit!("m", 1.0, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("km", 1e3, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("cm", 1e-2, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("mm", 1e-3, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("um", 1e-6, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("nm", 1e-9, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("ang", 1e-10, d(1, 0, 0, 0, 0, 0, 0, 0, 0)), // ангстрём
    unit!("au", 1.495978707e11, d(1, 0, 0, 0, 0, 0, 0, 0, 0)), // IAU 2012 B2, точно
    unit!("pc", 3.0856775814913673e16, d(1, 0, 0, 0, 0, 0, 0, 0, 0)), // 648000/pi·au
    unit!("ly", 9.4607304725808e15, d(1, 0, 0, 0, 0, 0, 0, 0, 0)), // юлианский год·c (IAU)
    unit!("mi", 1609.344, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("ft", 0.3048, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("in", 0.0254, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("nmi", 1852.0, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),
    unit!("R_earth", 6378137.0, d(1, 0, 0, 0, 0, 0, 0, 0, 0)), // WGS84 экватор.
    unit!("R_sun", 6.957e8, d(1, 0, 0, 0, 0, 0, 0, 0, 0)),      // IAU 2015 номинал.
    // ---- масса (базовая kg) ----
    unit!("kg", 1.0, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    unit!("g", 1e-3, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    unit!("t", 1e3, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    unit!("mg", 1e-6, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    unit!("lb", 0.45359237, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    unit!("oz", 0.028349523125, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    unit!("u", 1.66053906892e-27, d(0, 1, 0, 0, 0, 0, 0, 0, 0)), // CODATA 2022
    unit!("M_sun", 1.9885e30, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),     // IAU 2015 номинал.
    unit!("M_earth", 5.9722e24, d(0, 1, 0, 0, 0, 0, 0, 0, 0)),
    // ---- время (базовая s) ----
    unit!("s", 1.0, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("ms", 1e-3, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("us", 1e-6, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("ns", 1e-9, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("min", 60.0, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("h", 3600.0, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("day", 86400.0, d(0, 0, 1, 0, 0, 0, 0, 0, 0)),
    unit!("yr", 31557600.0, d(0, 0, 1, 0, 0, 0, 0, 0, 0)), // юлианский год (IAU)
    // ---- ток (базовая A) ----
    unit!("A", 1.0, d(0, 0, 0, 1, 0, 0, 0, 0, 0)),
    unit!("mA", 1e-3, d(0, 0, 0, 1, 0, 0, 0, 0, 0)),
    // ---- температура (базовая K, аффинные) ----
    UnitDef { name: "K", factor: 1.0, dim: d(0, 0, 0, 0, 1, 0, 0, 0, 0), offset: 0.0 },
    UnitDef { name: "degC", factor: 1.0, dim: d(0, 0, 0, 0, 1, 0, 0, 0, 0), offset: 273.15 },
    UnitDef { name: "degF", factor: 5.0 / 9.0, dim: d(0, 0, 0, 0, 1, 0, 0, 0, 0), offset: 255.372222222222222 },
    // degF: base_K = 5/9·(v − 32) + 273.15 = 5/9·v + 255.3722…
    // ---- количество вещества ----
    unit!("mol", 1.0, d(0, 0, 0, 0, 0, 1, 0, 0, 0)),
    // ---- сила света ----
    unit!("cd", 1.0, d(0, 0, 0, 0, 0, 0, 1, 0, 0)),
    unit!("lm", 1.0, d(0, 0, 0, 0, 0, 0, 1, 0, 0)), // кандела·стерадиан (sr безразм.)
    unit!("lux", 1.0, d(0, 1, 0, 0, 0, 0, 1, 0, -2)), // lm/m^2 → cd·m^-2 (угол безразмерен)
    // ---- угол (базовая rad) ----
    unit!("rad", 1.0, d(0, 0, 0, 0, 0, 0, 0, 1, 0)),
    unit!("deg", std::f64::consts::PI / 180.0, d(0, 0, 0, 0, 0, 0, 0, 1, 0)),
    unit!("arcmin", std::f64::consts::PI / 10800.0, d(0, 0, 0, 0, 0, 0, 0, 1, 0)),
    unit!("arcsec", std::f64::consts::PI / 648000.0, d(0, 0, 0, 0, 0, 0, 0, 1, 0)),
    unit!("turn", 2.0 * std::f64::consts::PI, d(0, 0, 0, 0, 0, 0, 0, 1, 0)),
    // ---- информация (базовая bit) ----
    unit!("bit", 1.0, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("byte", 8.0, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("KB", 8e3, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),   // десятичная (SI)
    unit!("MB", 8e6, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("GB", 8e9, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("TB", 8e12, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("KiB", (1u64 << 10) as f64, d(0, 0, 0, 0, 0, 0, 0, 0, 1)), // двоичная (IEC 80000-13)
    unit!("MiB", (1u64 << 20) as f64, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("GiB", (1u64 << 30) as f64, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("TiB", (1u64 << 40) as f64, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("PiB", (1u64 << 50) as f64, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),
    unit!("nat", 1.0 / std::f64::consts::LN_2, d(0, 0, 0, 0, 0, 0, 0, 0, 1)), // nat = 1/ln2 bit
    unit!("ban", 1.0 / 3.321928094887362, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),       // = 1/log2(10)
    unit!("trit", 1.584962500721156, d(0, 0, 0, 0, 0, 0, 0, 0, 1)),            // log2(3)
    // ---- производные СИ (factor 1 в своей размерности) ----
    unit!("N", 1.0, d(1, 1, -2, 0, 0, 0, 0, 0, 0)),      // кг·м/с^2
    unit!("J", 1.0, d(2, 1, -2, 0, 0, 0, 0, 0, 0)),      // Н·м
    unit!("kJ", 1e3, d(2, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("eV", 1.602176634e-19, d(2, 1, -2, 0, 0, 0, 0, 0, 0)), // точно (СИ 2019)
    unit!("keV", 1.602176634e-16, d(2, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("MeV", 1.602176634e-13, d(2, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("W", 1.0, d(2, 1, -3, 0, 0, 0, 0, 0, 0)),      // Дж/с
    unit!("kW", 1e3, d(2, 1, -3, 0, 0, 0, 0, 0, 0)),
    unit!("MW", 1e6, d(2, 1, -3, 0, 0, 0, 0, 0, 0)),
    unit!("Pa", 1.0, d(-1, 1, -2, 0, 0, 0, 0, 0, 0)),    // Н/м^2
    unit!("kPa", 1e3, d(-1, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("MPa", 1e6, d(-1, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("atm", 101325.0, d(-1, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("bar", 1e5, d(-1, 1, -2, 0, 0, 0, 0, 0, 0)),
    unit!("Hz", 1.0, d(0, 0, -1, 0, 0, 0, 0, 0, 0)),
    unit!("kHz", 1e3, d(0, 0, -1, 0, 0, 0, 0, 0, 0)),
    unit!("MHz", 1e6, d(0, 0, -1, 0, 0, 0, 0, 0, 0)),
    unit!("GHz", 1e9, d(0, 0, -1, 0, 0, 0, 0, 0, 0)),
    unit!("C", 1.0, d(0, 0, 1, 1, 0, 0, 0, 0, 0)),       // А·с (кулон)
    unit!("V", 1.0, d(2, 1, -3, -1, 0, 0, 0, 0, 0)),     // Вт/А
    unit!("mV", 1e-3, d(2, 1, -3, -1, 0, 0, 0, 0, 0)),
    unit!("kV", 1e3, d(2, 1, -3, -1, 0, 0, 0, 0, 0)),
    unit!("ohm", 1.0, d(2, 1, -3, -2, 0, 0, 0, 0, 0)),   // В/А
    unit!("kohm", 1e3, d(2, 1, -3, -2, 0, 0, 0, 0, 0)),
    unit!("Mohm", 1e6, d(2, 1, -3, -2, 0, 0, 0, 0, 0)),
    unit!("F", 1.0, d(-2, -1, 4, 2, 0, 0, 0, 0, 0)),     // Кл/В
    unit!("uF", 1e-6, d(-2, -1, 4, 2, 0, 0, 0, 0, 0)),
    unit!("nF", 1e-9, d(-2, -1, 4, 2, 0, 0, 0, 0, 0)),
    unit!("pF", 1e-12, d(-2, -1, 4, 2, 0, 0, 0, 0, 0)),
    unit!("H", 1.0, d(2, 1, -2, -2, 0, 0, 0, 0, 0)),     // Вб/А (генри)
    unit!("T", 1.0, d(0, 1, -2, -1, 0, 0, 0, 0, 0)),     // Вб/м^2 (тесла)
    unit!("Wb", 1.0, d(2, 1, -2, -1, 0, 0, 0, 0, 0)),
    // ---- скорость света как единица (для `to c`) ----
    unit!("c", 299792458.0, d(1, 0, -1, 0, 0, 0, 0, 0, 0)),
];

/// Найти табличную единицу по имени. РЕГИСТРОЗАВИСИМО (стандарт СИ):
/// `c` — скорость света, но `C` — кулон; `t` — тонна, но `T` — тесла
/// (коллизия прошлой сессии: `to c` находил кулон).
pub fn by_name(name: &str) -> Option<Unit> {
    UNITS
        .iter()
        .find(|u| u.name == name)
        .map(|u| Unit { dim: u.dim, factor: u.factor, name: u.name, offset: u.offset })
}

/// Точное совпадение (dim, factor) с табличной — для красивого вывода.
fn lookup(u: &Unit) -> Option<(&'static str, &'static UnitDef)> {
    UNITS
        .iter()
        .find(|t| t.dim == u.dim && t.factor == u.factor)
        .map(|t| (t.name, t))
}

/// Линейный множитель именованной единицы относительно базовой СИ своей
/// размерности (v0.48.0: `factor_of` для scriptgen и диагностики).
pub fn factor_of(name: &str) -> Option<f64> {
    by_name(name).map(|u| u.factor)
}

/// Разобрать составную спецификацию единицы: `km`, `km/h`, `m*s`, `N*m`,
/// `m^2`, `J/(mol*K)`, `W/(m^2*K^4)`, `1/mol`.
/// Скобки учитываются (регрессия прошлой сессии: `J/(mol*K)` падал).
pub fn parse_spec(spec: &str) -> Result<Unit, String> {
    let s: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() {
        return Err("пустая спецификация единицы".into());
    }
    parse_unit_expr(&s)
}

/// Рекурсивный разбор: деление (право-охватывающее: a/b/c = a/(b·c)),
/// затем умножение, затем атом (имя / имя^k / «1» / «(expr)»).
fn parse_unit_expr(s: &str) -> Result<Unit, String> {
    let s = strip_parens(s);
    if let Some(parts) = split_top_level(s, '/') {
        let mut u = parse_unit_expr(&parts[0])?;
        for p in &parts[1..] {
            u = u.div(&parse_unit_expr(p)?);
        }
        return Ok(u);
    }
    if let Some(parts) = split_top_level(s, '*') {
        let mut u = parse_unit_expr(&parts[0])?;
        for p in &parts[1..] {
            u = u.mul(&parse_unit_expr(p)?);
        }
        return Ok(u);
    }
    parse_atom(s)
}

/// `m^2` / `s^-1` / `km` / `1` → Unit.
fn parse_atom(atom: &str) -> Result<Unit, String> {
    let (base, exp) = match atom.split_once('^') {
        Some((b, e)) => {
            let k: i8 = e
                .trim()
                .parse()
                .map_err(|_| format!("степень единицы должна быть целой: «{atom}»"))?;
            (b.trim(), k)
        }
        None => (atom, 1),
    };
    if base == "1" {
        return Ok(Unit::dimensionless());
    }
    let u = by_name(base).ok_or_else(|| format!("неизвестная единица «{base}»"))?;
    // ВАЖНО: pow() обнуляет offset — аффинные единицы (degC/degF) обязаны
    // проходить без искажения при exp == 1 (баг: 100 °C → 671.67 °F)
    if exp == 1 {
        Ok(u)
    } else {
        Ok(u.pow(exp))
    }
}

/// Снять ОДИН слой обёртывающих скобок: "(mol*K)" → "mol*K".
fn strip_parens(s: &str) -> &str {
    if !(s.starts_with('(') && s.ends_with(')')) {
        return s;
    }
    // закрывающая скобка обязана совпадать с открывающей (глубина 0 только в конце)
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i + 1 < s.len() {
                    return s; // внутри есть самостоятельная группа — не обёртка
                }
            }
            _ => {}
        }
    }
    &s[1..s.len() - 1]
}

/// Разбивка по разделителю ВНЕ скобок. None — если разделителя на верхнем
/// уровне нет (для отличия «нет» от «одна часть»).
fn split_top_level(s: &str, sep: char) -> Option<Vec<String>> {
    let mut depth = 0i32;
    let mut found = false;
    let mut parts = vec![String::new()];
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                parts.last_mut().unwrap().push(ch);
            }
            ')' => {
                depth -= 1;
                parts.last_mut().unwrap().push(ch);
            }
            c if c == sep && depth == 0 => {
                found = true;
                parts.push(String::new());
            }
            c => parts.last_mut().unwrap().push(c),
        }
    }
    if found {
        Some(parts)
    } else {
        None
    }
}

/// Конверсия значения из одной единицы в другую. Требует совпадения
/// размерностей; аффинность (температура) учитывается.
pub fn convert(value: f64, from: &Unit, to: &Unit) -> Result<f64, String> {
    if !from.same_dim(to) {
        return Err(format!(
            "несовместимые размерности: {} → {}",
            if from.display().is_empty() { "(безразмерная)".into() } else { from.display() },
            if to.display().is_empty() { "(безразмерная)".into() } else { to.display() }
        ));
    }
    // базовое значение (например, кельвины): v_base = from.factor·v + from.offset
    let base = from.factor * value + from.offset;
    // целевое: v = (v_base − to.offset) / to.factor
    Ok((base - to.offset) / to.factor)
}

/// Список всех имён единиц (для `calc units`).
pub fn all_names() -> Vec<&'static str> {
    UNITS.iter().map(|u| u.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_factors() {
        assert_eq!(factor_of("km"), Some(1e3));
        assert_eq!(factor_of("lb"), Some(0.45359237));
        assert_eq!(factor_of("nmi"), Some(1852.0));
        assert_eq!(factor_of("eV"), Some(1.602176634e-19));
        assert_eq!(factor_of("missing"), None);
    }

    #[test]
    fn binary_prefixes() {
        // регрессия прошлой сессии: 1u64<<40 — точный TiB, не 1.1e12
        assert_eq!(factor_of("KiB"), Some(1024.0));
        assert_eq!(factor_of("MiB"), Some((1u64 << 20) as f64));
        assert_eq!(factor_of("TiB"), Some((1u64 << 40) as f64));
        assert!((factor_of("GB").unwrap() - 8e9).abs() < 1e-3);
    }

    #[test]
    fn parenthesized_specs() {
        // регрессия прошлой сессии: скобки ломали спецификации констант
        let r = parse_spec("J/(mol*K)").unwrap(); // газовая постоянная
        assert_eq!(r.dim, d(2, 1, -2, 0, -1, -1, 0, 0, 0)); // J − mol − K
        let sb = parse_spec("W/(m^2*K^4)").unwrap(); // σ
        assert_eq!(sb.dim, d(0, 1, -3, 0, -4, 0, 0, 0, 0));
        let gm = parse_spec("m^3/(kg*s^2)").unwrap(); // G
        assert_eq!(gm.dim, d(3, -1, -2, 0, 0, 0, 0, 0, 0));
        let na = parse_spec("1/mol").unwrap(); // N_A
        assert_eq!(na.dim, d(0, 0, 0, 0, 0, -1, 0, 0, 0));
        // вложенные скобки
        let nested = parse_spec("(N*m)/s").unwrap(); // Вт
        assert_eq!(nested.dim, d(2, 1, -3, 0, 0, 0, 0, 0, 0));
        assert!((nested.factor - 1.0).abs() < 1e-12);
        // не-обёртка: "(a*b)*c" — первая скобка закрывается до конца
        let not_wrap = parse_spec("N*(m*s)").unwrap();
        assert_eq!(not_wrap.dim, d(2, 1, -1, 0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn compound_parsing() {
        let kmh = parse_spec("km/h").unwrap();
        assert_eq!(kmh.dim, d(1, 0, -1, 0, 0, 0, 0, 0, 0));
        assert!((kmh.factor - 1000.0 / 3600.0).abs() < 1e-15);

        let ms2 = parse_spec("m/s^2").unwrap();
        assert_eq!(ms2.dim, d(1, 0, -2, 0, 0, 0, 0, 0, 0));

        let nm = parse_spec("N*m").unwrap();
        assert_eq!(nm.dim, d(2, 1, -2, 0, 0, 0, 0, 0, 0)); // Дж
        assert!((nm.factor - 1.0).abs() < 1e-12);

        assert!(parse_spec("km/").is_err());
        assert!(parse_spec("wat").is_err());
        assert!(parse_spec("m^x").is_err());
    }

    #[test]
    fn conversions() {
        let km = by_name("km").unwrap();
        let mi = by_name("mi").unwrap();
        let v = convert(42.0, &km, &mi).unwrap();
        assert!((v - 42.0 * 1000.0 / 1609.344).abs() < 1e-12);

        let m = by_name("m").unwrap();
        let ft = by_name("ft").unwrap();
        assert!((convert(1.0, &ft, &m).unwrap() - 0.3048).abs() < 1e-15);

        // размерностная ошибка
        assert!(convert(1.0, &km, &by_name("kg").unwrap()).is_err());
    }

    #[test]
    fn temperature_affine() {
        let c = by_name("degC").unwrap();
        let f = by_name("degF").unwrap();
        let k = by_name("K").unwrap();
        assert!((convert(25.0, &c, &f).unwrap() - 77.0).abs() < 1e-9);
        assert!((convert(0.0, &c, &k).unwrap() - 273.15).abs() < 1e-9);
        assert!((convert(100.0, &c, &f).unwrap() - 212.0).abs() < 1e-9);
        assert!((convert(-40.0, &f, &c).unwrap() - (-40.0)).abs() < 1e-9);
    }

    #[test]
    fn speed_of_light_unit() {
        let c = by_name("c").unwrap();
        let ms = parse_spec("m/s").unwrap();
        assert!((convert(1.0, &c, &ms).unwrap() - 299792458.0).abs() < 1e-6);
        let kmh = parse_spec("km/h").unwrap();
        assert!((convert(1.0, &c, &kmh).unwrap() - 1.0792528488e9).abs() < 1e0);
    }

    #[test]
    fn display_names() {
        let j = parse_spec("N*m").unwrap();
        assert_eq!(j.display(), "J");
        let weird = parse_spec("m*s").unwrap();
        assert_eq!(weird.display(), "m·s");
        let compound = parse_spec("kg*m/s^2").unwrap();
        assert_eq!(compound.display(), "N");
        assert_eq!(Unit::dimensionless().display(), "");
    }

    #[test]
    fn angle_and_info_units() {
        let deg = by_name("deg").unwrap();
        let rad = by_name("rad").unwrap();
        assert!((convert(180.0, &deg, &rad).unwrap() - std::f64::consts::PI).abs() < 1e-12);
        assert!((convert(1.0, &by_name("trit").unwrap(), &by_name("bit").unwrap()).unwrap() - 1.5849625007211562).abs() < 1e-12);
        assert!((convert(1.0, &by_name("byte").unwrap(), &by_name("bit").unwrap()).unwrap() - 8.0).abs() < 1e-12);
    }

    #[test]
    fn astronomy_units() {
        let au = by_name("au").unwrap();
        let pc = by_name("pc").unwrap();
        // парсек = 648000/pi а.е. — определение МАС
        let ratio = convert(1.0, &pc, &au).unwrap();
        assert!((ratio - 648000.0 / std::f64::consts::PI).abs() < 1e-6);
        let ly = by_name("ly").unwrap();
        // световой год ≈ 63241 а.е.
        assert!((convert(1.0, &ly, &au).unwrap() - 63241.077).abs() < 0.1);
    }
}
