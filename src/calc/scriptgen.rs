//! Генератор скриптов и .poler-правил по законам физики (цикл M, v0.48.0).
//!
//! Отвечает на требование: «чтобы программа сама писала скрипты или
//! правила poler-engine при надобности, опираясь на законы». Реестр
//! законов несёт формулу, набор переменных с_units по умолчанию и
//! ИСТОЧНИК; генератор подставляет значения в выражение калькулятора
//! (константы — по именам из calc::constants, т.е. из CODATA/IAU/СИ-2019)
//! и излучает два артефакта:
//!   1) готовую команду `calc …` для poler-shell;
//!   2) машинное .poler-правило (name/expr/vars) для загрузки движком.

use std::fmt::Write;

pub struct LawVar {
    pub name: &'static str,
    pub default: &'static str,
    pub unit: &'static str,
    pub desc: &'static str,
}

pub struct LawSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub formula: &'static str,
    pub expr: &'static str, // выражение с {var}-подстановками
    pub vars: &'static [LawVar],
    pub source: &'static str,
}

/// Реестр законов (расширяется одной строкой).
pub static LAWS: &[LawSpec] = &[
    LawSpec {
        id: "kepler3",
        title: "Третий закон Кеплера",
        formula: "T = 2π·√(a³ / (G·(M₁+M₂)))",
        expr: "2*pi*sqrt({a}^3 / (G*({M1}+{M2})))",
        vars: &[
            LawVar { name: "a", default: "149.6e9 m", unit: "m", desc: "большая полуось орбиты" },
            LawVar { name: "M1", default: "M_sun", unit: "kg", desc: "масса центрального тела" },
            LawVar { name: "M2", default: "M_earth", unit: "kg", desc: "масса спутника" },
        ],
        source: "Newton/Kepler; G — CODATA 2022, M_sun — IAU 2015",
    },
    LawSpec {
        id: "emc2",
        title: "Эквивалентность массы и энергии",
        formula: "E = m·c²",
        expr: "{m} * c^2",
        vars: &[LawVar { name: "m", default: "1e-3 kg", unit: "kg", desc: "масса" }],
        source: "СИ-2019: c точно 299792458 м/с",
    },
    LawSpec {
        id: "planck_e",
        title: "Энергия фотона",
        formula: "E = h·f",
        expr: "h * {f}",
        vars: &[LawVar { name: "f", default: "5.45e14 Hz", unit: "Hz", desc: "частота (зелёный свет)" }],
        source: "СИ-2019: h точно 6.62607015e-34 Дж·с",
    },
    LawSpec {
        id: "schwarzschild",
        title: "Радиус Шварцшильда",
        formula: "r_s = 2·G·M / c²",
        expr: "2*G*{M} / c^2",
        vars: &[LawVar { name: "M", default: "M_sun", unit: "kg", desc: "масса" }],
        source: "ОТО; G — CODATA 2022, c — СИ-2019",
    },
    LawSpec {
        id: "stefan_boltzmann",
        title: "Закон Стефана–Больцмана",
        formula: "P = σ·A·T⁴",
        expr: "sigma_sb * {A} * {T}^4",
        vars: &[
            LawVar { name: "A", default: "1.0 m^2", unit: "m^2", desc: "площадь излучателя" },
            LawVar { name: "T", default: "5772 K", unit: "K", desc: "температура (Солнце)" },
        ],
        source: "σ вычислена из точных h, k_B, c (СИ-2019)",
    },
    LawSpec {
        id: "wien",
        title: "Закон смещения Вина",
        formula: "λ_max = b / T",
        expr: "wien_b / {T}",
        vars: &[LawVar { name: "T", default: "310 K", unit: "K", desc: "температура (человек)" }],
        source: "b = 2.897771955e-3 м·К (CODATA 2022)",
    },
    LawSpec {
        id: "escape",
        title: "Вторая космическая скорость",
        formula: "v = √(2·G·M / r)",
        expr: "sqrt(2*G*{M} / {r})",
        vars: &[
            LawVar { name: "M", default: "M_earth", unit: "kg", desc: "масса тела" },
            LawVar { name: "r", default: "R_earth", unit: "m", desc: "радиус (можно: R_earth + 400e3 m)" },
        ],
        source: "Newton; M_earth/R_earth — IAU 2015 / WGS84",
    },
    LawSpec {
        id: "newton_gravity",
        title: "Закон всемирного тяготения",
        formula: "F = G·m₁·m₂ / r²",
        expr: "G * {m1} * {m2} / {r}^2",
        vars: &[
            LawVar { name: "m1", default: "70 kg", unit: "kg", desc: "масса 1" },
            LawVar { name: "m2", default: "70 kg", unit: "kg", desc: "масса 2" },
            LawVar { name: "r", default: "1 m", unit: "m", desc: "расстояние" },
        ],
        source: "Newton; G — CODATA 2022",
    },
    LawSpec {
        id: "pendulum",
        title: "Период математического маятника",
        formula: "T = 2π·√(L/g)",
        expr: "2*pi*sqrt({L} / g0)",
        vars: &[LawVar { name: "L", default: "1 m", unit: "m", desc: "длина" }],
        source: "g0 = 9.80665 м/с² (стандартное, точно)",
    },
    LawSpec {
        id: "rc_tau",
        title: "Постоянная времени RC-цепи",
        formula: "τ = R·C",
        expr: "{R} * {C}",
        vars: &[
            LawVar { name: "R", default: "10e3 ohm", unit: "ohm", desc: "сопротивление" },
            LawVar { name: "C", default: "100e-6 F", unit: "F", desc: "ёмкость" },
        ],
        source: "электротехника (СИ)",
    },
    LawSpec {
        id: "ohm",
        title: "Закон Ома",
        formula: "U = I·R",
        expr: "{I} * {R}",
        vars: &[
            LawVar { name: "I", default: "0.5 A", unit: "A", desc: "ток" },
            LawVar { name: "R", default: "220 ohm", unit: "ohm", desc: "сопротивление" },
        ],
        source: "электротехника (СИ)",
    },
    LawSpec {
        id: "lens",
        title: "Формула тонкой линзы",
        formula: "1/F = 1/d + 1/f",
        expr: "1 / (1/{d} + 1/{f})",
        vars: &[
            LawVar { name: "d", default: "0.5 m", unit: "m", desc: "дистанция до предмета" },
            LawVar { name: "f", default: "0.2 m", unit: "m", desc: "дистанция до изображения" },
        ],
        source: "геометрическая оптика",
    },
    LawSpec {
        id: "hohmann",
        title: "Гомановский перелёт: первый импульс",
        formula: "Δv₁ = √(μ/r₁)·(√(2·r₂/(r₁+r₂)) − 1)",
        expr: "sqrt({mu} / {r1}) * (sqrt(2*{r2}/({r1}+{r2})) - 1)",
        vars: &[
            LawVar { name: "mu", default: "GM_earth", unit: "m^3/s^2", desc: "гравитационный параметр" },
            LawVar { name: "r1", default: "R_earth + 400e3 m", unit: "m", desc: "радиус низкой орбиты" },
            LawVar { name: "r2", default: "R_earth + 35786e3 m", unit: "m", desc: "радиус высокой орбиты (ГСО)" },
        ],
        source: "Hohmann 1925; GM_earth — EGM2008",
    },
    LawSpec {
        id: "roche",
        title: "Предел Роша",
        formula: "d = R·(2·ρ_спутника/ρ_первичного)^(1/3)  [жёсткий спутник ×1.26]",
        expr: "{R} * (2*{rho_s} / {rho_p})^(1/3)",
        vars: &[
            LawVar { name: "R", default: "R_earth", unit: "m", desc: "радиус первичного тела" },
            LawVar { name: "rho_s", default: "3300 kg/m^3", unit: "kg/m^3", desc: "плотность спутника" },
            LawVar { name: "rho_p", default: "5513 kg/m^3", unit: "kg/m^3", desc: "плотность первичного" },
        ],
        source: "Roche 1848",
    },
    LawSpec {
        id: "planck_units",
        title: "Планковская система единиц",
        formula: "l_P = √(ħG/c³),  t_P = √(ħG/c⁵),  m_P = √(ħc/G)",
        expr: "sqrt(hbar*G/c^3)",
        vars: &[],
        source: "вычисляется из точных h, c и CODATA G",
    },
    LawSpec {
        id: "signal_wavelength",
        title: "Длина волны сигнала",
        formula: "λ = c / f",
        expr: "c / {f}",
        vars: &[LawVar { name: "f", default: "2.4e9 Hz", unit: "Hz", desc: "частота (Wi-Fi 2.4 ГГц)" }],
        source: "СИ-2019: c точно",
    },
    LawSpec {
        id: "kinetic",
        title: "Кинетическая энергия",
        formula: "E = ½·m·v²",
        expr: "0.5 * {m} * {v}^2",
        vars: &[
            LawVar { name: "m", default: "1500 kg", unit: "kg", desc: "масса (автомобиль)" },
            LawVar { name: "v", default: "30 m/s", unit: "m/s", desc: "скорость" },
        ],
        source: "классическая механика",
    },
    LawSpec {
        id: "ideal_gas",
        title: "Уравнение состояния идеального газа",
        formula: "p·V = n·R·T",
        expr: "{n} * R * {T} / {V}",
        vars: &[
            LawVar { name: "n", default: "1", unit: "mol", desc: "количество вещества" },
            LawVar { name: "T", default: "273.15 K", unit: "K", desc: "температура" },
            LawVar { name: "V", default: "0.022414 m^3", unit: "m^3", desc: "объём" },
        ],
        source: "R = N_A·k_B точно (СИ-2019)",
    },
    LawSpec {
        id: "tsiolkovsky",
        title: "Формула Циолковского",
        formula: "Δv = v_e·ln(m₀/m₁)",
        expr: "{ve} * ln({m0} / {m1})",
        vars: &[
            LawVar { name: "ve", default: "3500 m/s", unit: "m/s", desc: "скорость истечения" },
            LawVar { name: "m0", default: "500000 kg", unit: "kg", desc: "стартовая масса" },
            LawVar { name: "m1", default: "50000 kg", unit: "kg", desc: "конечная масса" },
        ],
        source: "Tsiolkovsky 1903",
    },
    LawSpec {
        id: "doppler",
        title: "Эффект Доплера (источник приближается)",
        formula: "f = f₀·v / (v − v_s)",
        expr: "{f0} * {v} / ({v} - {vs})",
        vars: &[
            LawVar { name: "f0", default: "440 Hz", unit: "Hz", desc: "частота источника" },
            LawVar { name: "v", default: "343 m/s", unit: "m/s", desc: "скорость звука" },
            LawVar { name: "vs", default: "30 m/s", unit: "m/s", desc: "скорость источника" },
        ],
        source: "классический Доплер",
    },
];

/// Найти закон по id (или по части названия).
pub fn find_law(query: &str) -> Option<&'static LawSpec> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return None;
    }
    LAWS
        .iter()
        .find(|l| l.id == q)
        .or_else(|| LAWS.iter().find(|l| l.id.contains(&q) || l.title.to_lowercase().contains(&q)))
}

/// Список законов одной строкой на каждый.
pub fn list_laws() -> String {
    let mut out = String::new();
    for l in LAWS {
        let _ = writeln!(out, "{:<18} {:<42} {}", l.id, l.title, l.formula);
    }
    out
}

/// Подстановка значений переменных в выражение.
/// `overrides` — пары «имя=значение» (без пробелов).
fn substitute(expr: &str, law: &LawSpec, overrides: &[(String, String)]) -> Result<String, String> {
    let mut out = expr.to_string();
    for v in law.vars {
        let raw = overrides
            .iter()
            .find(|(k, _)| k == v.name)
            .map(|(_, val)| val.clone())
            .unwrap_or_else(|| v.default.to_string());
        // составные значения (с операторами/единицами) оборачиваются в
        // скобки: иначе «R_earth + 400e3 m» внутри «({r1}+{r2})» ломает
        // структуру выражения, а «1e-3 kg * c^2» склеивается в «kg*c»
        let val = if raw.chars().any(|c| " +-*/^".contains(c)) {
            format!("({raw})")
        } else {
            raw
        };
        let placeholder = format!("{{{}}}", v.name);
        out = out.replace(&placeholder, &val);
    }
    // незаполненные плейсхолдеры
    if out.contains('{') || out.contains('}') {
        return Err(format!("не удалось подставить все переменные: {out}"));
    }
    Ok(out)
}

/// Сгенерировать полный скрипт: человекочитаемая часть + команда calc +
/// машинное .poler-правило.
pub fn generate(law: &LawSpec, overrides: &[(String, String)]) -> Result<String, String> {
    // валидация имён переменных
    for (k, _) in overrides {
        if !law.vars.iter().any(|v| v.name == k) {
            return Err(format!(
                "закон «{}» не имеет переменной «{k}» (доступны: {})",
                law.id,
                law.vars.iter().map(|v| v.name).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let expr = substitute(law.expr, law, overrides)?;

    let mut out = String::new();
    let _ = writeln!(out, "# ────────────────────────────────────────────────");
    let _ = writeln!(out, "# ЗАКОН: {} ({})", law.title, law.id);
    let _ = writeln!(out, "#   {}", law.formula);
    let _ = writeln!(out, "# Источник: {}", law.source);
    let _ = writeln!(out, "# ────────────────────────────────────────────────");
    if !law.vars.is_empty() {
        let _ = writeln!(out, "#");
        let _ = writeln!(out, "# Переменные:");
        for v in law.vars {
            let used = overrides
                .iter()
                .find(|(k, _)| k == v.name)
                .map(|(_, val)| val.clone())
                .unwrap_or_else(|| v.default.to_string());
            let marker = if used != v.default { " ← ваш ввод" } else { "" };
            let _ = writeln!(out, "#   {:<6} = {:<14} [{:^6}]  {}{}", v.name, used, v.unit, v.desc, marker);
        }
    }
    let _ = writeln!(out, "#");
    let _ = writeln!(out, "# 1) Проверьте прямо сейчас в poler-shell:");
    let _ = writeln!(out, "#");
    let _ = writeln!(out, "poler> calc {}", expr);
    let _ = writeln!(out, "#");
    let _ = writeln!(out, "# 2) Машинное правило .poler (загружается движком):");
    let _ = writeln!(out, "#");
    let _ = writeln!(out, "[[rule]]");
    let _ = writeln!(out, "name = \"{}\"", law.id);
    let _ = writeln!(out, "title = \"{}\"", law.title);
    let _ = writeln!(out, "law = \"{}\"", law.formula);
    let _ = writeln!(out, "source = \"{}\"", law.source);
    let _ = writeln!(out, "expr = \"{}\"", expr);
    for v in law.vars {
        let used = overrides
            .iter()
            .find(|(k, _)| k == v.name)
            .map(|(_, val)| val.clone())
            .unwrap_or_else(|| v.default.to_string());
        let _ = writeln!(out, "var.{} = {}  # {}, {}", v.name, used, v.unit, v.desc);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calc::parser;

    // ================================================================
    // Урок прошлой сессии: scriptgen генерировал фрагменты, которые НЕ
    // собираются. Инвариант теперь: выражение каждого закона обязано
    // парситься и вычисляться движком калькулятора.
    // ================================================================
    #[test]
    fn every_law_expression_parses_and_evals() {
        for law in LAWS {
            let expr = substitute(law.expr, law, &[]).unwrap_or_else(|e| {
                panic!("закон {}: подстановка сломана: {e}", law.id)
            });
            let val = parser::parse_and_eval(&expr, &Default::default()).unwrap_or_else(|e| {
                panic!("закон {}: выражение «{expr}» не вычисляется: {e}", law.id)
            });
            assert!(
                val.as_f64().is_some_and(|v| v.is_finite()),
                "закон {}: невалидный результат {val:?}",
                law.id
            );
        }
    }

    #[test]
    fn law_count_and_ids() {
        assert!(LAWS.len() >= 19, "сейчас {} законов — реестр усох?", LAWS.len());
        let mut ids: Vec<&str> = LAWS.iter().map(|l| l.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), LAWS.len(), "дубликаты id законов");
    }

    #[test]
    fn generate_contains_both_artifacts() {
        let law = find_law("kepler3").unwrap();
        let script = generate(law, &[]).unwrap();
        assert!(script.contains("poler> calc 2*pi*sqrt((149.6e9 m)^3"));
        assert!(script.contains("[[rule]]"));
        assert!(script.contains("name = \"kepler3\""));
        assert!(script.contains("CODATA"));
    }

    #[test]
    fn overrides_flow_into_expression() {
        let law = find_law("emc2").unwrap();
        let script = generate(law, &[("m".into(), "1.0".into())]).unwrap();
        assert!(script.contains("poler> calc 1.0 * c^2"));
        assert!(script.contains("← ваш ввод"));
        // неизвестная переменная — внятная ошибка
        let err = generate(law, &[("zzz".into(), "1".into())]).unwrap_err();
        assert!(err.contains("zzz"));
    }

    #[test]
    fn find_law_by_partial() {
        assert!(find_law("kepler").is_some());
        assert!(find_law("Циолковский").is_none()); // поиск по id/title в нижнем регистре
        assert!(find_law("tsiolkovsky").is_some());
        assert!(find_law("").is_none());
        assert!(find_law("no-such-law").is_none());
    }

    #[test]
    fn numeric_sanity_of_selected_laws() {
        // Земля на орбите: T ≈ 365.26 дней
        let law = find_law("kepler3").unwrap();
        let expr = substitute(law.expr, law, &[]).unwrap();
        let v = parser::parse_and_eval(&expr, &Default::default())
            .unwrap()
            .as_f64()
            .unwrap();
        let days = v / 86400.0;
        assert!((days - 365.25).abs() < 1.0, "T = {days} дней");

        // E = mc² для 1 г: ≈ 9e13 Дж
        let expr = substitute(find_law("emc2").unwrap().expr, find_law("emc2").unwrap(), &[]).unwrap();
        let v = parser::parse_and_eval(&expr, &Default::default())
            .unwrap()
            .as_f64()
            .unwrap();
        assert!((v - 9.0e13).abs() / 9.0e13 < 0.01, "E = {v:e}");

        // вторая космическая Земли ≈ 11.2 км/с
        let law = find_law("escape").unwrap();
        let expr = substitute(law.expr, law, &[]).unwrap();
        let v = parser::parse_and_eval(&expr, &Default::default())
            .unwrap()
            .as_f64()
            .unwrap();
        assert!((v - 11186.0).abs() < 60.0, "v_esc = {v}");

        // Wi-Fi 2.4 ГГц: λ ≈ 12.5 см
        let law = find_law("signal_wavelength").unwrap();
        let expr = substitute(law.expr, law, &[]).unwrap();
        let v = parser::parse_and_eval(&expr, &Default::default())
            .unwrap()
            .as_f64()
            .unwrap();
        assert!((v - 0.1249).abs() < 0.001, "λ = {v}");
    }
}
