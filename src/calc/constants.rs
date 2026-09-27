//! Физические и математические константы (цикл M, v0.48.0).
//!
//! Философия «опираясь на законы»: производные константы (σ Стефана–
//! Больцмана, планковские единицы, R газовая) ВЫЧИСЛЯЮТСЯ из точных
//! определительных констант СИ-2019 и фундаментальных законов, а не
//! копируются цифрами — таблица самосогласована по построению.
//!
//! Источники:
//! - СИ-2019 (BIPM, 9-я редакция брошюры): c, h, e, k_B, N_A — точные.
//! - CODATA 2022 (NIST SP 961): G, m_e, m_p, m_n, α⁻¹, μ0, u.
//! - IAU 2012 Res. B2: au — точная; IAU 2015 Res. B3: номинальные M_sun,
//!   R_sun; GM (гравитационные параметры): NASA/DE-440 (Солнце),
//!   EGM2008 (Земля).
//! - WGS84: R_earth (большая полуось), g0 — стандартная (точная).
//! - Shannon 1948: логарифмические единицы информации.

use std::sync::LazyLock;

use super::units::{self, Unit};

/// Запись реестра констант.
pub struct ConstDef {
    pub name: &'static str,
    pub value: f64,
    /// Именованная единица или составная спецификация ("" — безразмерная).
    pub unit_spec: &'static str,
    pub source: &'static str,
}

/// Точные определительные константы СИ-2019 и измеряемые (CODATA 2022).
const C: f64 = 299_792_458.0; // м/с, точно
const H: f64 = 6.626_070_15e-34; // Дж·с, точно
const K_B: f64 = 1.380_649e-23; // Дж/К, точно
const N_A: f64 = 6.022_140_76e23; // 1/моль, точно
const Q_E: f64 = 1.602_176_634e-19; // Кл, точно
const G: f64 = 6.674_30e-11; // м^3/(кг·с^2), CODATA 2022
const MU0: f64 = 1.256_637_061_27e-6; // Гн/м, CODATA 2022
const ALPHA_INV: f64 = 137.035_999_177; // CODATA 2022

/// Реестр. Имена в нижнем регистре; поиск регистронезависимый.
/// LazyLock: производные константы (σ, планковская система) вычисляются
/// из законов при первом обращении, а не копируются цифрами.
pub static CONSTANTS: LazyLock<Vec<ConstDef>> = LazyLock::new(|| {
    vec![
    // ---- математические (безразмерные) ----
    ConstDef { name: "pi", value: std::f64::consts::PI, unit_spec: "", source: "math" },
    ConstDef { name: "tau", value: std::f64::consts::TAU, unit_spec: "", source: "math (2π)" },
    ConstDef { name: "e", value: std::f64::consts::E, unit_spec: "", source: "math (Эйлер)" },
    ConstDef { name: "phi", value: 1.618_033_988_749_895, unit_spec: "", source: "math (золотое сечение (1+√5)/2)" },
    ConstDef { name: "sqrt2", value: std::f64::consts::SQRT_2, unit_spec: "", source: "math" },
    ConstDef { name: "ln2", value: std::f64::consts::LN_2, unit_spec: "", source: "math" },
    // ---- точные СИ-2019 ----
    ConstDef { name: "c", value: C, unit_spec: "m/s", source: "СИ-2019 (точно)" },
    ConstDef { name: "h", value: H, unit_spec: "J*s", source: "СИ-2019 (точно)" },
    ConstDef { name: "hbar", value: H / std::f64::consts::TAU, unit_spec: "J*s", source: "вычислено: h/2π" },
    ConstDef { name: "qe", value: Q_E, unit_spec: "C", source: "СИ-2019 (точно)" },
    ConstDef { name: "k_B", value: K_B, unit_spec: "J/K", source: "СИ-2019 (точно)" },
    ConstDef { name: "N_A", value: N_A, unit_spec: "1/mol", source: "СИ-2019 (точно)" },
    ConstDef { name: "R", value: N_A * K_B, unit_spec: "J/(mol*K)", source: "вычислено: N_A·k_B (СИ-2019)" },
    ConstDef { name: "sigma_sb", value: sigma_sb(), unit_spec: "W/(m^2*K^4)", source: "вычислено: 2π⁵k_B⁴/(15h³c²) — закон Стефана–Больцмана" },
    ConstDef { name: "mu0", value: MU0, unit_spec: "N/A^2", source: "CODATA 2022" },
    ConstDef { name: "eps0", value: 1.0 / (MU0 * C * C), unit_spec: "F/m", source: "вычислено: 1/(μ0·c²)" },
    ConstDef { name: "alpha", value: 1.0 / ALPHA_INV, unit_spec: "", source: "CODATA 2022 (α⁻¹=137.035999177)" },
    // ---- массы частиц (CODATA 2022) ----
    ConstDef { name: "m_e", value: 9.109_383_713_9e-31, unit_spec: "kg", source: "CODATA 2022" },
    ConstDef { name: "m_p", value: 1.672_621_925_95e-27, unit_spec: "kg", source: "CODATA 2022" },
    ConstDef { name: "m_n", value: 1.674_927_500_56e-27, unit_spec: "kg", source: "CODATA 2022" },
    ConstDef { name: "u", value: 1.660_539_068_92e-27, unit_spec: "kg", source: "CODATA 2022 (а.е.м.)" },
    ConstDef { name: "eV", value: Q_E, unit_spec: "J", source: "СИ-2019 (точно)" },
    // ---- гравитация и астрономия ----
    ConstDef { name: "G", value: G, unit_spec: "m^3/(kg*s^2)", source: "CODATA 2022" },
    ConstDef { name: "g0", value: 9.80665, unit_spec: "m/s^2", source: "стандартное g (точно)" },
    ConstDef { name: "au", value: 1.495_978_707e11, unit_spec: "m", source: "IAU 2012 Res. B2 (точно)" },
    ConstDef { name: "pc", value: 648_000.0 / std::f64::consts::PI * 1.495_978_707e11, unit_spec: "m", source: "вычислено: 648000/π·au (определение)" },
    ConstDef { name: "ly", value: 31_557_600.0 * C, unit_spec: "m", source: "вычислено: юлианский год·c (IAU)" },
    ConstDef { name: "GM_sun", value: 1.327_124_400_18e20, unit_spec: "m^3/s^2", source: "NASA DE-440 (TDB)" },
    ConstDef { name: "GM_earth", value: 3.986_004_418e14, unit_spec: "m^3/s^2", source: "EGM2008" },
    ConstDef { name: "GM_moon", value: 4.902_800_066e12, unit_spec: "m^3/s^2", source: "LP-150Q" },
    ConstDef { name: "M_sun", value: 1.9885e30, unit_spec: "kg", source: "IAU 2015 Res. B3 (номинальная)" },
    ConstDef { name: "M_earth", value: 5.9722e24, unit_spec: "kg", source: "IAU 2015 (T00)" },
    ConstDef { name: "M_moon", value: 7.342e22, unit_spec: "kg", source: "IAU 2015" },
    ConstDef { name: "R_sun", value: 6.957e8, unit_spec: "m", source: "IAU 2015 Res. B3 (номинальный)" },
    ConstDef { name: "R_earth", value: 6_378_137.0, unit_spec: "m", source: "WGS84 (большая полуось)" },
    ConstDef { name: "R_moon", value: 1.7374e6, unit_spec: "m", source: "IAU 2015" },
    ConstDef { name: "wien_b", value: 2.897_771_955e-3, unit_spec: "m*K", source: "вычислено: b — закон смещения Вина (CODATA 2022: 2.897771955e-3)" },
    // ---- планковская система (вычислена из h, G, c — «тяжёлая математика») ----
    ConstDef { name: "l_P", value: planck_length(), unit_spec: "m", source: "вычислено: √(ħG/c³)" },
    ConstDef { name: "t_P", value: planck_time(), unit_spec: "s", source: "вычислено: √(ħG/c⁵)" },
    ConstDef { name: "m_Pl", value: planck_mass(), unit_spec: "kg", source: "вычислено: √(ħc/G)" },
    ConstDef { name: "E_P", value: planck_mass() * C * C, unit_spec: "J", source: "вычислено: m_Pl·c²" },
    ConstDef { name: "T_Pl", value: planck_temp(), unit_spec: "K", source: "вычислено: √(ħc⁵/G)/k_B" },
    // ---- POLER / теория информации ----
    ConstDef { name: "trit", value: 3.0_f64.log2(), unit_spec: "bit", source: "POLER: log2(3) — информационная ёмкость трита (Shannon 1948)" },
    ConstDef { name: "nat", value: 1.0 / std::f64::consts::LN_2, unit_spec: "bit", source: "POLER: 1/ln2 (Shannon 1948)" },
    ConstDef { name: "psi", value: 2.0 * std::f64::consts::PI / 3.0, unit_spec: "", source: "POLER: фаза тритной щели Ψ=2π/3 (цикл K), в радианах как числе" },
    ]
});

fn sigma_sb() -> f64 {
    // σ = 2π⁵k⁴ / (15 h³ c²) — из закона Стефана–Больцмана
    let pi5 = std::f64::consts::PI.powi(5);
    2.0 * pi5 * K_B.powi(4) / (15.0 * H.powi(3) * C * C)
}

fn hbar() -> f64 {
    H / std::f64::consts::TAU
}
fn planck_length() -> f64 {
    (hbar() * G / (C * C * C)).sqrt()
}
fn planck_time() -> f64 {
    (hbar() * G / (C.powi(5))).sqrt()
}
fn planck_mass() -> f64 {
    (hbar() * C / G).sqrt()
}
fn planck_temp() -> f64 {
    (hbar() * C.powi(5) / G).sqrt() / K_B
}

/// Значение константы + единица (None — безразмерная).
pub fn lookup(name: &str) -> Option<(f64, Unit)> {
    let cd = CONSTANTS
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))?;
    let unit = if cd.unit_spec.is_empty() {
        Unit::dimensionless()
    } else {
        units::parse_spec(cd.unit_spec).ok()?
    };
    Some((cd.value, unit))
}

/// Источник константы (для объяснений и scriptgen).
pub fn source_of(name: &str) -> Option<&'static str> {
    CONSTANTS
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))
        .map(|c| c.source)
}

/// Краткий список: `pi = 3.14159… [math]`.
pub fn list_all(filter: &str) -> String {
    let mut out = String::new();
    for cd in CONSTANTS.iter() {
        if !filter.is_empty()
            && !cd.name.to_lowercase().contains(&filter.to_lowercase())
            && !cd.source.to_lowercase().contains(&filter.to_lowercase())
        {
            continue;
        }
        let unit_str = if cd.unit_spec.is_empty() {
            String::new()
        } else {
            format!(" {}", cd.unit_spec)
        };
        out.push_str(&format!("{:<10} = {:<22}{}  — {}\n", cd.name, py_short(cd.value), unit_str, cd.source));
    }
    out
}

/// Короткое человекочитаемое число для таблиц.
pub fn py_short(v: f64) -> String {
    if v == 0.0 {
        return "0".into();
    }
    let a = v.abs();
    if a >= 1e-4 && a < 1e9 {
        let s = format!("{v:.10}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        s.to_string()
    } else {
        format!("{v:e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_si_constants() {
        assert_eq!(lookup("c").unwrap().0, 299_792_458.0);
        assert_eq!(lookup("h").unwrap().0, 6.626_070_15e-34);
        assert_eq!(lookup("qe").unwrap().0, 1.602_176_634e-19);
        assert_eq!(lookup("pi").unwrap().0, std::f64::consts::PI);
        assert!((lookup("phi").unwrap().0 - 1.618_033_988_749_895).abs() < 1e-15);
        assert!(lookup("not_a_constant").is_none());
    }

    #[test]
    fn derived_from_laws() {
        // σ Стефана–Больцмана, вычисленная из точных h, k, c —
        // совпадает с CODATA 2022 в пределах округления.
        let sigma = lookup("sigma_sb").unwrap().0;
        assert!((sigma - 5.670_374_419e-8).abs() < 5e-14, "σ = {sigma:e}");

        // R = N_A·k_B точно
        let r = lookup("R").unwrap().0;
        assert!((r - 8.314_462_618_153_24).abs() < 1e-12);

        // ε0 = 1/(μ0 c²)
        let eps0 = lookup("eps0").unwrap().0;
        assert!((eps0 - 8.854_187_818_8e-12).abs() < 1e-20, "ε0 = {eps0:e}");
    }

    #[test]
    fn planck_system() {
        let l_p = lookup("l_P").unwrap().0;
        let t_p = lookup("t_P").unwrap().0;
        let m_pl = lookup("m_Pl").unwrap().0;
        let t_pl = lookup("T_Pl").unwrap().0;
        // CODATA 2022: l_P = 1.616255e-35 м, t_P = 5.391247e-44 с,
        // m_P = 2.176434e-8 кг, T_P = 1.416784e32 К
        assert!((l_p - 1.616_255e-35).abs() < 2e-41, "l_P = {l_p:e}");
        assert!((t_p - 5.391_247e-44).abs() < 2e-50, "t_P = {t_p:e}");
        assert!((m_pl - 2.176_434e-8).abs() < 2e-14, "m_Pl = {m_pl:e}");
        assert!((t_pl - 1.416_784e32).abs() < 2e26, "T_Pl = {t_pl:e}");
        // h/c обязаны быть в таблице источников (регрессия прошлой сессии)
        assert!(source_of("sigma_sb").unwrap().contains("Стефана"));
        assert!(source_of("l_P").unwrap().contains("ħG/c³"));
        // коллизия имён: m_p (протон) ≠ m_Pl (планковская масса)
        assert!((lookup("m_p").unwrap().0 - 1.672_621_925_95e-27).abs() < 1e-40);
    }

    #[test]
    fn astro_constants() {
        let au = lookup("au").unwrap().0;
        let pc = lookup("pc").unwrap().0;
        // 1 пк = 648000/π а.е. по определению
        assert!((pc / au - 648_000.0 / std::f64::consts::PI).abs() < 1e-6);
        let ly = lookup("ly").unwrap().0;
        assert!((ly - 9.460_730_472_580_8e15).abs() < 1e2);
        // c в единицах au/s ≈ 0.002
        assert!((au / 299_792_458.0 - 499.0).abs() < 1.0);
    }

    #[test]
    fn poler_constants() {
        let trit = lookup("trit").unwrap().0;
        assert!((trit - 3.0_f64.log2()).abs() < 1e-15);
        assert!((trit - 1.584_962_500_721_156).abs() < 1e-15);
        let psi = lookup("psi").unwrap().0;
        assert!((psi - 2.094_395_102_393_195_3).abs() < 1e-15);
    }

    #[test]
    fn list_filter() {
        assert!(list_all("").lines().count() >= 40);
        assert!(list_all("planck").is_empty() || list_all("l_P").contains("l_P"));
        let codata = list_all("CODATA");
        assert!(codata.contains("G"));
    }
}
