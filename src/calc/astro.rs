//! Астрономия: Солнце, Луна, планеты (цикл M, v0.48.0).
//!
//! Модель: Paul Schlyter «How to compute planetary positions» (низкая
//! точность ~1-2 угл. минуты — достаточна для фаз, затмений, навигации)
//! + NOAA Solar Calculator (восход/закат по уравнению времени).
//!
//! ВЕРИФИКАЦИЯ (уроки прошлой сессии, зашиты в тесты):
//! - СКОРОСТЬ ПЕРИГЕЯ ЛУНЫ: 0.1643573223 °/день (опечатка 1.6402e-3
//!   наматывала 4 лишних оборота за 26 лет — сидерический месяц 29.93 д
//!   вместо 29.53 д);
//! - ОСВЕЩЁННОСТЬ: фазовый угол в ГРАДУСАХ перед cos() переводится в
//!   радианы (прямая передача градусов в cos давала мусор);
//! - ЯКОРЯ: солнечные затмения 2024-04-08 и 2025-03-29 (новолуние),
//!   лунные затмения 2025-03-14 и 2022-11-08 (полнолуние) — элонгация
//!   в пределах ±2°; равноденствия/солнцестояния 2024 — долгота 0/90/180/270.
//!
//! Все углы — в градусах, расстояния — в км (если не указано иное).

// ---------------------------------------------------------------------
// Время
// ---------------------------------------------------------------------

/// Юлианская дата из календарной (григорианской) даты + время UTC (часы,
/// дробные). Алгоритм из Meeus (глава 7) — корректен для всех дат ≥ 1583.
pub fn jd(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month as i64 + 12 } else { month as i64 };
    let d = day as f64 + hour_utc / 24.0;
    let a = (y as f64 / 100.0).floor();
    let b = (a / 4.0).floor();
    let c = if (year, month) >= (1582, 10) { 2.0 - a + b } else { 0.0 };
    let (yf, mf) = (y as f64, m as f64);
    (365.25 * (yf + 4716.0)).floor() + (30.6001 * (mf + 1.0)).floor() + d + c - 1524.5
}

/// Дни от эпохи Шлhyтера (2000 Jan 0.0 = JD 2451543.5) из полной даты.
fn d_schlyter(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    jd(year, month, day, hour_utc) - 2451543.5
}

/// Нормализация угла в [0, 360).
fn norm(x: f64) -> f64 {
    x.rem_euclid(360.0)
}

/// sin/cos от угла в градусах.
fn sind(x: f64) -> f64 {
    x.to_radians().sin()
}
fn cosd(x: f64) -> f64 {
    x.to_radians().cos()
}

// ---------------------------------------------------------------------
// Солнце (Шлhyтер)
// ---------------------------------------------------------------------

/// Элементы Солнца на эпоху d (дней от 2000 Jan 0.0).
struct SunElements {
    w: f64, // долгота перигелия
    e: f64, // эксцентриситет
    m: f64, // средняя аномалия
}

fn sun_elements(d: f64) -> SunElements {
    SunElements {
        w: 282.9404 + 4.70935e-5 * d,
        e: 0.016709 - 1.151e-9 * d,
        m: norm(356.0470 + 0.9856002585 * d),
    }
}

/// Наклон эклиптики, град.
fn obliquity(d: f64) -> f64 {
    23.4393 - 3.563e-7 * d
}

/// Эклиптическая долгота Солнца (геометрическая), град.
pub fn sun_ecliptic_lon(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    let d = d_schlyter(year, month, day, hour_utc);
    let s = sun_elements(d);
    // уравнение центра
    let e = s.e;
    let ecc = (360.0 / std::f64::consts::PI) * e
        * sind(s.m)
        * (1.0 + e * cosd(s.m));
    // истинная аномалия и долгота
    let true_lon = norm(s.m + s.w + ecc);
    true_lon
}

/// Экваториальные координаты Солнца (Ra град [0,360), Dec град).
pub fn sun_ra_dec(year: i32, month: u32, day: u32, hour_utc: f64) -> (f64, f64) {
    let d = d_schlyter(year, month, day, hour_utc);
    let lon = sun_ecliptic_lon(year, month, day, hour_utc);
    ecl_to_equ(lon, 0.0, obliquity(d))
}

// ---------------------------------------------------------------------
// Луна (Шлhyter, с 13 возмущениями долготы / 5 широты)
// ---------------------------------------------------------------------

struct MoonElements {
    n: f64, // долгота восходящего узла
    _i: f64, // наклон
    w: f64, // аргумент перигея — скорость 0.1643573223 °/день!
    _a: f64, // большая полуось (радиусы Земли)
    e: f64, // эксцентриситет
    m: f64, // средняя аномалия
}

fn moon_elements(d: f64) -> MoonElements {
    MoonElements {
        n: norm(125.1228 - 0.0529538083 * d),
        _i: 5.1454,
        w: norm(318.0634 + 0.1643573223 * d),
        _a: 60.2666,
        e: 0.054900,
        m: norm(115.3654 + 13.0649929509 * d),
    }
}

/// Геоцентрическая эклиптическая позиция Луны: (долгота°, широта°, расстояние км).
pub fn moon_position(year: i32, month: u32, day: u32, hour_utc: f64) -> (f64, f64, f64) {
    let d = d_schlyter(year, month, day, hour_utc);
    let me = moon_elements(d);
    let se = sun_elements(d);

    // средняя долгота и элонгация
    let ls = norm(se.m + se.w); // средняя долгота Солнца
    let lm = norm(me.m + me.w + me.n); // средняя долгота Луны
    let d_elong = norm(lm - ls); // средняя элонгация
    let f = norm(lm - me.n); // аргумент широты

    // уравнение центра Луны
    let e = me.e;
    let mut lon = norm(
        me.m + me.w + me.n
            + (360.0 / std::f64::consts::PI) * e * sind(me.m) * (1.0 + e * cosd(me.m)),
    );

    // возмущения долготы (13 членов Шлhyтера), град
    lon += -1.274 * sind(me.m - 2.0 * d_elong) // evection (изменение)
        + 0.658 * sind(2.0 * d_elong) // variation
        - 0.186 * sind(se.m) // годовое уравнение
        - 0.059 * sind(2.0 * me.m - 2.0 * d_elong)
        - 0.057 * sind(me.m - 2.0 * d_elong + se.m)
        + 0.053 * sind(me.m + 2.0 * d_elong)
        + 0.046 * sind(2.0 * d_elong - se.m)
        + 0.041 * sind(me.m - se.m)
        - 0.035 * sind(d_elong) // параллактическое
        - 0.031 * sind(me.m + se.m)
        - 0.015 * sind(2.0 * f - 2.0 * d_elong)
        + 0.011 * sind(me.m - 4.0 * d_elong);

    // широта (5 членов)
    let mut lat = 5.128 * sind(f)
        + 0.280 * sind(me.m + f)
        + 0.277 * sind(me.m - f)
        + 0.173 * sind(2.0 * d_elong - f)
        + 0.055 * sind(2.0 * d_elong - me.m + f)
        + 0.046 * sind(2.0 * d_elong - me.m - f);

    // расстояние: Шлhyter — возмущения в ЗЕМНЫХ РАДИУСАХ, НЕ умножаются
    // на 60.2666 (ошибка прошлой сессии: r выходил за 418 тыс. км)
    let r_er = 60.2666 * (1.0 - e * cosd(me.m))
        - 0.58 * cosd(me.m - 2.0 * d_elong)
        - 0.46 * cosd(2.0 * d_elong);

    // финальная нормализация
    lon = norm(lon);
    lat = lat.max(-90.0).min(90.0);
    // радиусы Земли → км (WGS84 большая полуось)
    let r = r_er * 6378.137;
    (lon, lat, r)
}

/// Элонгация Луна—Солнце (разность эклиптических долгот), град [0, 360).
pub fn moon_elongation(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    let (mlon, _, _) = moon_position(year, month, day, hour_utc);
    let slon = sun_ecliptic_lon(year, month, day, hour_utc);
    norm(mlon - slon)
}

/// Фазовый угол Луну (угол Солнце—Луна—Земля), град.
pub fn moon_phase_angle(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    let elong = moon_elongation(year, month, day, hour_utc);
    // фазовый угол ≈ 180° − элонгация (для точности хватает)
    180.0 - elong
}

/// Освещённая доля диска Луны [0, 1].
/// РЕГРЕССИЯ: k = (1 + cos(i))/2, где i — фазовый угол В РАДИАНАХ.
pub fn moon_illumination(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    let i = moon_phase_angle(year, month, day, hour_utc).to_radians();
    let k = (1.0 + i.cos()) / 2.0;
    k.clamp(0.0, 1.0)
}

/// Возраст Луны в днях (0 — новолуние, ~14.77 — полнолуние).
pub fn moon_age_days(year: i32, month: u32, day: u32, hour_utc: f64) -> f64 {
    let elong = moon_elongation(year, month, day, hour_utc);
    // синодический месяц 29.530588853 дней
    elong / 360.0 * 29.530588853
}

/// Экваториальные координаты Луны (Ra град, Dec град).
pub fn moon_ra_dec(year: i32, month: u32, day: u32, hour_utc: f64) -> (f64, f64) {
    let d = d_schlyter(year, month, day, hour_utc);
    let (lon, lat, _) = moon_position(year, month, day, hour_utc);
    ecl_to_equ(lon, lat, obliquity(d))
}

// ---------------------------------------------------------------------
// Планеты (Шлhyter: элементы + гелиоцентрическая позиция + возмущения
// Юпитера/Сатурна)
// ---------------------------------------------------------------------

pub struct PlanetElements {
    pub n: f64, // долгота восходящего узла
    pub i: f64, // наклон
    pub w: f64, // аргумент перигелия
    pub a: f64, // большая полуось (а.е.)
    pub e: f64, // эксцентриситет
    pub m: f64, // средняя аномалия
}

/// Орбитальные элементы планеты (Шлhyter, эпоха 2000 Jan 0.0).
pub fn planet_elements(name: &str, d: f64) -> Result<PlanetElements, String> {
    let (n, ni, w, a, e, m, dm) = match name.to_lowercase().as_str() {
        "mercury" | "merkury" | "меркурий" => (
            48.3313, 7.0047, 29.1241, 0.387098, 0.205635, 168.6562, 4.0923344368,
        ),
        "venus" | "венера" => (
            76.6799, 3.3946, 54.8910, 0.723330, 0.006773, 48.0052, 1.6021302244,
        ),
        "earth" | "земля" | "terra" => (
            0.0, 0.0, 282.9404, 1.0, 0.016709, 356.0470, 0.9856002585,
        ),
        "mars" | "марс" => (
            49.5574, 1.8497, 286.5016, 1.523688, 0.093405, 18.6021, 0.5240207766,
        ),
        "jupiter" | "юпитер" => (
            100.4644, 1.3030, 273.8777, 5.20256, 0.048498, 19.8950, 0.0830853001,
        ),
        "saturn" | "сатурн" => (
            113.6634, 2.4886, 339.3939, 9.55475, 0.055546, 316.9670, 0.0334442282,
        ),
        "uranus" | "уран" => (
            74.0005, 0.7733, 96.6612, 19.18171, 0.047318, 142.5905, 0.011725806,
        ),
        "neptune" | "нептун" => (
            131.7806, 1.7700, 272.8461, 30.05826, 0.008606, 260.2471, 0.005995147,
        ),
        other => return Err(format!("неизвестная планета «{other}» (mercury…neptune)")),
    };
    Ok(PlanetElements {
        n: norm(n),
        i: ni,
        w: norm(w),
        a,
        e,
        m: norm(m + dm * d),
    })
}

/// Заполнить наклон (i) и учесть вековые члены.
fn planet_elements_full(name: &str, d: f64) -> Result<PlanetElements, String> {
    let mut p = planet_elements(name, d)?;
    let i_rates: &[(&str, f64, f64, f64, f64, f64)] = &[
        // (имя, i, di/d, dw/d, de/d, dN/d)
        ("mercury", 7.0047, 5.00e-8, 1.01444e-5, 5.59e-10, 3.24587e-5),
        ("venus", 3.3946, 2.75e-8, 1.38374e-5, -1.302e-9, 2.46590e-5),
        ("earth", 0.0, 0.0, 4.70935e-5, -1.151e-9, 0.0),
        ("mars", 1.8497, -1.78e-8, 2.92961e-5, 2.516e-9, 2.11081e-5),
        ("jupiter", 1.3030, -1.557e-7, 1.64505e-5, 4.469e-9, 2.76854e-5),
        ("saturn", 2.4886, -1.081e-7, 2.97661e-5, -9.499e-9, 2.38980e-5),
        ("uranus", 0.7733, 1.9e-8, 3.0565e-5, 7.45e-9, 1.3978e-5),
        ("neptune", 1.7700, -2.55e-7, -6.027e-6, 2.15e-9, 3.0173e-5),
    ];
    let name_lc = name.to_lowercase();
    let key = match name_lc.as_str() {
        "merkury" | "меркурий" => "mercury",
        "венера" => "venus",
        "земля" | "terra" => "earth",
        "марс" => "mars",
        "юпитер" => "jupiter",
        "сатурн" => "saturn",
        "уран" => "uranus",
        "нептун" => "neptune",
        other => other,
    };
    if let Some(&(_, i0, di, dw, de, dn)) = i_rates.iter().find(|(n, ..)| *n == key) {
        p.i = i0 + di * d;
        p.w = norm(p.w + dw * d);
        p.e += de * d;
        p.n = norm(p.n + dn * d);
    }
    Ok(p)
}

/// Гелиоцентрические эклиптические координаты планеты: (x, y, z) в а.е.
pub fn planet_heliocentric(name: &str, d: f64) -> Result<(f64, f64, f64), String> {
    let p = planet_elements_full(name, d)?;
    // уравнение центра
    let e = p.e;
    let ecc_anom_approx = p.m + (360.0 / std::f64::consts::PI) * e * sind(p.m);
    // одна итерация уточнения эксцентрической аномалии (Кеплер)
    let mut ea = ecc_anom_approx;
    for _ in 0..3 {
        let dm = (p.m - (ea - (360.0 / std::f64::consts::PI) * e * ea.to_radians().sin()))
            .rem_euclid(360.0);
        ea += dm;
    }
    let ea_rad = ea.to_radians();
    let xv = p.a * (ea_rad.cos() - e);
    let yv = p.a * ((1.0 - e * e).sqrt() * ea_rad.sin());
    let v = yv.atan2(xv).to_degrees(); // истинная аномалия
    let r = (xv * xv + yv * yv).sqrt(); // радиус

    // положение в плоскости эклиптики
    let xo = r * (cosd(p.n) * cosd(v + p.w) - sind(p.n) * sind(v + p.w) * cosd(p.i));
    let yo = r * (sind(p.n) * cosd(v + p.w) + cosd(p.n) * sind(v + p.w) * cosd(p.i));
    let zo = r * sind(v + p.w) * sind(p.i);
    Ok((xo, yo, zo))
}

/// Возмущения долготы/широты/радиуса Юпитера и Сатурна (взаимные,
/// «Великое неравенство»).
fn jupiter_saturn_perturbations(
    which: &str,
    mj: f64,
    ms: f64,
) -> (f64, f64, f64) {
    // (Δдолгота°, Δширотa°, Δрадиус а.е.)
    if which == "jupiter" {
        (
            -0.332 * sind(2.0 * mj - 5.0 * ms - 67.6)
                - 0.056 * sind(2.0 * mj - 2.0 * ms + 21.0)
                + 0.042 * sind(3.0 * mj - 5.0 * ms - 71.0)
                - 0.036 * sind(mj - 2.0 * ms)
                + 0.022 * cosd(mj - ms)
                + 0.023 * sind(2.0 * mj - 3.0 * ms + 52.0)
                - 0.016 * sind(mj - 5.0 * ms - 69.0),
            0.0,
            -0.047 * cosd(mj - ms) - 0.010 * cosd(2.0 * mj - 2.0 * ms) + 0.005 * cosd(mj + ms),
        )
    } else {
        (
            0.812 * sind(2.0 * mj - 5.0 * ms - 67.6)
                - 0.229 * cosd(2.0 * mj - 4.0 * ms - 2.0)
                + 0.119 * sind(mj - 2.0 * ms - 3.0)
                + 0.046 * sind(2.0 * mj - 6.0 * ms - 69.0)
                + 0.014 * sind(mj - 3.0 * ms + 32.0),
            -0.020 * cosd(2.0 * mj - 4.0 * ms - 2.0) + 0.018 * sind(2.0 * mj - 6.0 * ms - 49.0),
            0.055 * cosd(mj - ms) - 0.046 * cosd(2.0 * mj - 2.0 * ms) + 0.011 * cosd(2.0 * mj - 4.0 * ms - 2.0),
        )
    }
}

/// Геоцентрическая эклиптическая позиция планеты: (долгота°, широта°, расстояние а.е.).
/// Для Земли возвращает гелиоцентрические координаты Солнца.
pub fn planet_geocentric(
    name: &str,
    year: i32,
    month: u32,
    day: u32,
    hour_utc: f64,
) -> Result<(f64, f64, f64), String> {
    let d = d_schlyter(year, month, day, hour_utc);
    let (mut px, mut py, mut pz) = planet_heliocentric(name, d)?;

    // возмущения Юпитера/Сатурна
    let name_l = name.to_lowercase();
    if name_l == "jupiter" || name_l == "юпитер" || name_l == "saturn" || name_l == "сатурн" {
        let pj = planet_elements_full("jupiter", d)?;
        let ps = planet_elements_full("saturn", d)?;
        let which = if name_l == "jupiter" || name_l == "юпитер" { "jupiter" } else { "saturn" };
        let (dl, _db, dr) = jupiter_saturn_perturbations(which, pj.m, ps.m);
        // применяем к радиус-вектору поворотом: проще растянуть r и повернуть λ
        let r = (px * px + py * py + pz * pz).sqrt();
        let lon = py.atan2(px).to_degrees();
        let lat = pz.atan2((px * px + py * py).sqrt()).to_degrees();
        let r2 = r + dr;
        let lon2 = lon + dl;
        px = r2 * cosd(lon2) * cosd(lat);
        py = r2 * sind(lon2) * cosd(lat);
        pz = r2 * sind(lat);
    }

    // положение Земли (гелиоцентрическое) вычитаем
    let (ex, ey, ez) = planet_heliocentric("earth", d)?;
    let gx = px - ex;
    let gy = py - ey;
    let gz = pz - ez;
    let r = (gx * gx + gy * gy + gz * gz).sqrt();
    let lon = gy.atan2(gx).to_degrees();
    let lat = gz.atan2((gx * gx + gy * gy).sqrt()).to_degrees();
    Ok((norm(lon), lat, r))
}

/// Эклиптика → экватор: (Ra град, Dec град).
fn ecl_to_equ(lon_deg: f64, lat_deg: f64, obl_deg: f64) -> (f64, f64) {
    let (l, b, o) = (lon_deg.to_radians(), lat_deg.to_radians(), obl_deg.to_radians());
    let x = l.cos() * b.cos();
    let y = l.sin() * b.cos() * o.cos() - b.sin() * o.sin();
    let z = l.sin() * b.cos() * o.sin() + b.sin() * o.cos();
    let ra = y.atan2(x).to_degrees().rem_euclid(360.0);
    let dec = z.asin().to_degrees();
    (ra, dec)
}

// ---------------------------------------------------------------------
// NOAA: уравнение времени, склонение, восход/закат
// ---------------------------------------------------------------------

fn day_of_year(year: i32, month: u32, day: u32) -> f64 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let cum = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut doy = cum[(month - 1) as usize] as f64 + day as f64;
    if leap && month > 2 {
        doy += 1.0;
    }
    doy
}

/// (уравнение времени [мин], склонение [рад]) — NOAA Solar Calculator.
fn equation_of_time_and_decl(year: i32, month: u32, day: u32, hour_utc: f64) -> (f64, f64) {
    let doy = day_of_year(year, month, day);
    let g = 2.0 * std::f64::consts::PI / 365.0 * (doy - 1.0 + (hour_utc - 12.0) / 24.0);
    let eq_time = 229.18
        * (0.000075
            + 0.001868 * g.cos()
            - 0.032077 * g.sin()
            - 0.014615 * (2.0 * g).cos()
            - 0.040849 * (2.0 * g).sin());
    let decl = 0.006918
        - 0.399912 * g.cos()
        + 0.070257 * g.sin()
        - 0.006758 * (2.0 * g).cos()
        + 0.000907 * (2.0 * g).sin()
        - 0.002697 * (3.0 * g).cos()
        + 0.00148 * (3.0 * g).sin();
    (eq_time, decl)
}

/// Восход и закат Солнца (UTC, часы) для широты/долготы в градусах.
/// Возвращает None в полярных условиях (полярный день/ночь).
pub fn sunrise_sunset_utc(
    year: i32,
    month: u32,
    day: u32,
    lat_deg: f64,
    lon_deg: f64,
) -> Result<Option<(f64, f64)>, String> {
    if !(-90.0..=90.0).contains(&lat_deg) {
        return Err("широта должна быть в [−90, 90]".into());
    }
    let (eq_time_min, decl) = equation_of_time_and_decl(year, month, day, 12.0);
    let lat = lat_deg.to_radians();
    let zenith = 90.833f64.to_radians(); // с рефракцией и диском
    let cos_ha = zenith.cos() / (lat.cos() * decl.cos()) - lat.tan() * decl.tan();
    if !(-1.0..=1.0).contains(&cos_ha) {
        return Ok(None);
    }
    let ha = cos_ha.acos().to_degrees() / 15.0; // часы
    let noon_utc = 12.0 - lon_deg / 15.0 - eq_time_min / 60.0;
    Ok(Some((noon_utc - ha, noon_utc + ha)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    // ================================================================
    // Время
    // ================================================================
    #[test]
    fn julian_dates() {
        // J2000.0 = JD 2451545.0 (1 янв 2000 12:00 TT)
        assert!(close(jd(2000, 1, 1, 12.0), 2451545.0, 1e-6));
        // 6 янв 2000 18:14 UTC ≈ JD 2451550.26
        let j = jd(2000, 1, 6, 18.23);
        assert!(j > 2451549.5 && j < 2451551.0, "jd = {j}");
        // 1 янв 2024 00:00 = JD 2460310.5
        assert!(close(jd(2024, 1, 1, 0.0), 2460310.5, 1e-6));
    }

    // ================================================================
    // СОЛНЦЕ: равноденствия и солнцестояния 2024 (астрономические факты)
    // ================================================================
    #[test]
    fn sun_equinox_solstice_2024() {
        // весеннее равноденствие 2024-03-20 03:06 UTC → λ = 0°
        let lon = sun_ecliptic_lon(2024, 3, 20, 3.1);
        assert!(close(lon, 0.0, 1.5) || close(lon, 360.0, 1.5), "equinox λ = {lon}");
        // летнее солнцестояние 2024-06-20 20:51 UTC → λ = 90°
        let lon = sun_ecliptic_lon(2024, 6, 20, 20.85);
        assert!(close(lon, 90.0, 1.5), "solstice λ = {lon}");
        // осеннее равноденствие 2024-09-22 12:44 UTC → λ = 180°
        let lon = sun_ecliptic_lon(2024, 9, 22, 12.73);
        assert!(close(lon, 180.0, 1.5), "equinox λ = {lon}");
        // зимнее солнцестояние 2024-12-21 09:20 UTC → λ = 270°
        let lon = sun_ecliptic_lon(2024, 12, 21, 9.33);
        assert!(close(lon, 270.0, 1.5), "solstice λ = {lon}");
    }

    #[test]
    fn sun_dec_seasons() {
        // зимой в Киеве склонение отрицательное, летом положительное
        let (_, dec_summer) = sun_ra_dec(2024, 6, 21, 12.0);
        let (_, dec_winter) = sun_ra_dec(2024, 12, 21, 12.0);
        assert!(dec_summer > 22.0 && dec_summer < 24.0, "dec_summer = {dec_summer}");
        assert!(dec_winter < -22.0 && dec_winter > -24.0, "dec_winter = {dec_winter}");
        // равноденствие: dec ≈ 0
        let (_, dec_eq) = sun_ra_dec(2024, 3, 20, 3.1);
        assert!(dec_eq.abs() < 1.5, "dec_eq = {dec_eq}");
    }

    // ================================================================
    // ЛУНА: якоря затмений (независимые астрономические события!)
    // РЕГРЕССИЯ: скорость перигея 0.1643573223 °/день; освещённость —
    // фазовый угол в радианах.
    // ================================================================
    #[test]
    fn moon_new_moon_eclipse_2024_04_08() {
        // Полное солнечное затмение 8 апреля 2024, 18:21 UTC → новолуние
        let elong = moon_elongation(2024, 4, 8, 18.35);
        let dev = (elong).min(360.0 - elong);
        assert!(dev < 2.0, "элонгация = {elong}° (должна быть ~0)");
        let illum = moon_illumination(2024, 4, 8, 18.35);
        assert!(illum < 0.01, "illum = {illum}");
    }

    #[test]
    fn moon_new_moon_eclipse_2025_03_29() {
        // Частное солнечное затмение 29 марта 2025, 10:47 UTC
        let elong = moon_elongation(2025, 3, 29, 10.8);
        let dev = elong.min(360.0 - elong);
        assert!(dev < 2.0, "элонгация = {elong}°");
        assert!(moon_illumination(2025, 3, 29, 10.8) < 0.01);
    }

    #[test]
    fn moon_full_moon_eclipse_2025_03_14() {
        // Полное лунное затмение 14 марта 2025, 06:55 UTC → полнолуние
        let elong = moon_elongation(2025, 3, 14, 6.9);
        assert!((elong - 180.0).abs() < 2.0, "элонгация = {elong}°");
        let illum = moon_illumination(2025, 3, 14, 6.9);
        assert!(illum > 0.99, "illum = {illum}");
    }

    #[test]
    fn moon_full_moon_eclipse_2022_11_08() {
        // Полное лунное затмение 8 ноября 2022, 11:02 UTC (якорь, который
        // ломала опечатка perigee-скорости — тогда выходило 262°)
        let elong = moon_elongation(2022, 11, 8, 11.03);
        assert!((elong - 180.0).abs() < 2.0, "элонгация = {elong}° (было 262° с багом)");
    }

    #[test]
    fn moon_new_moon_2000_01_06() {
        // Новолуние 6 января 2000, 18:14 UTC — классический якорь Шлhyter
        let elong = moon_elongation(2000, 1, 6, 18.23);
        let dev = elong.min(360.0 - elong);
        assert!(dev < 2.0, "элонгация = {elong}°");
    }

    #[test]
    fn moon_synodic_month() {
        // Сидерический период из элементов: 360/13.0649929509 ≈ 27.5545 д
        // (аномалистический). Синодический: два соседних новолуния.
        let e1 = moon_elongation(2025, 3, 29, 10.8);
        // ищем следующее новолуние: +29.53 дня
        let e2 = moon_elongation(2025, 4, 28, 0.0);
        let dev = (e2).min(360.0 - e2);
        assert!(dev < 5.0, "элонгация через синод. месяц = {e2}°");
        let _ = e1;
    }

    #[test]
    fn moon_distance_range() {
        // физический диапазон 356.5–406.7 тыс. км + допуск модели
        for (y, m, d) in [(2024, 1, 1), (2024, 4, 15), (2025, 6, 10)] {
            let (_, _, r) = moon_position(y, m, d, 12.0);
            assert!(r > 345_000.0 && r < 415_000.0, "r = {r}");
        }
    }

    #[test]
    fn moon_illumination_radians_regression() {
        // Полнолуние: k ≈ 1; кВАРталь: элонгация 90° → k ≈ 0.5
        // (если забыть to_radians, cos(180)≠−1 и k получается ~0.57)
        // берём момент элонгации ~90°: возраст ~7.38 дней от новолуния
        // 2024-04-08 18:21 + 7.38 дн ≈ 2024-04-16 03:00
        let k = moon_illumination(2024, 4, 16, 3.0);
        assert!(k > 0.40 && k < 0.60, "k(quad) = {k}");
        let k_full = moon_illumination(2025, 3, 14, 6.9);
        assert!(k_full > 0.98);
    }

    #[test]
    fn moon_age_ranges() {
        let age = moon_age_days(2024, 4, 8, 18.35);
        assert!(age < 0.5 || age > 29.0, "возраст в новолуние = {age}");
        let age = moon_age_days(2025, 3, 14, 6.9);
        assert!((13.5..15.5).contains(&age), "возраст в полнолуние = {age}");
    }

    // ================================================================
    // ПЛАНЕТЫ: внутренняя согласованность (периоды из средних движений)
    // ================================================================
    #[test]
    fn planet_periods_from_mean_motion() {
        let cases = [
            ("mercury", 87.969),
            ("venus", 224.701),
            ("earth", 365.256),
            ("mars", 686.980),
            ("jupiter", 4332.589),
            ("saturn", 10759.22),
        ];
        for (name, period) in cases {
            let p = planet_elements(name, 0.0).unwrap();
            // вычисляем dm из m(1) − m(0)
            let p1 = planet_elements(name, 1.0).unwrap();
            let dm = (p1.m - p.m).rem_euclid(360.0);
            let t = 360.0 / dm;
            assert!(
                (t - period).abs() / period < 0.001,
                "{name}: период {t} vs {period}"
            );
        }
    }

    #[test]
    fn planet_orbits_sane() {
        let ranges = [
            ("mercury", 0.30, 0.48),
            ("venus", 0.71, 0.73),
            ("earth", 0.98, 1.02),
            ("mars", 1.38, 1.68),
            ("jupiter", 4.9, 5.5),
            ("saturn", 9.0, 10.2),
        ];
        for (name, lo, hi) in ranges {
            // гелиоцентрический радиус — в диапазоне орбиты
            let (hx, hy, hz) = planet_heliocentric(name, 0.0).unwrap();
            let hr = (hx * hx + hy * hy + hz * hz).sqrt();
            assert!(hr > lo && hr < hi, "{name}: r_helio = {hr}");
            // геоцентрическое расстояние положительно (кроме самой Земли)
            if name != "earth" {
                let (_, _, r) = planet_geocentric(name, 2024, 6, 1, 0.0).unwrap();
                assert!(r > 0.1, "{name}: r_geo = {r}");
            }
        }
    }

    #[test]
    fn planet_unknown() {
        assert!(planet_elements("pluto", 0.0).is_err());
        assert!(planet_elements("vulcan", 0.0).is_err());
        assert!(planet_geocentric("pluto", 2024, 1, 1, 0.0).is_err());
        // русские имена работают
        assert!(planet_elements("Марс", 0.0).is_ok());
        assert!(planet_elements("юпитер", 0.0).is_ok());
    }

    // ================================================================
    // NOAA: восход/закат
    // ================================================================
    #[test]
    fn sunrise_equator_equinox() {
        // На экваторе в равноденствие: ~06:00 и ~18:00 UTC (±15 мин)
        let ss = sunrise_sunset_utc(2024, 3, 20, 0.0, 0.0).unwrap().unwrap();
        assert!(close(ss.0, 6.0, 0.25), "восход = {}", ss.0);
        assert!(close(ss.1, 18.0, 0.25), "закат = {}", ss.1);
    }

    #[test]
    fn sunrise_kyiv_summer_winter() {
        // Київ (50.45 N, 30.52 E), 21 июня: восход ~02:00 UTC (05:00 Kyiv+3)
        // закат ~18:15 UTC. День длинный: > 16 часов.
        let (lat, lon) = (50.45, 30.52);
        let summer = sunrise_sunset_utc(2024, 6, 21, lat, lon).unwrap().unwrap();
        let day_len = summer.1 - summer.0;
        assert!(day_len > 16.0 && day_len < 17.0, "летний день = {day_len} ч");
        let winter = sunrise_sunset_utc(2024, 12, 21, lat, lon).unwrap().unwrap();
        let day_len = winter.1 - winter.0;
        assert!(day_len > 7.5 && day_len < 9.0, "зимний день = {day_len} ч");
        // полдень по местному солнечному времени: 12 − 30.52/15 ≈ 9.97 UTC
        let noon = (summer.0 + summer.1) / 2.0;
        assert!(close(noon, 9.97, 0.3), "полдень = {noon}");
    }

    #[test]
    fn polar_day_and_night() {
        // Шпицберген 21 июня — полярный день; 21 декабря — полярная ночь
        assert!(sunrise_sunset_utc(2024, 6, 21, 78.22, 15.65).unwrap().is_none());
        assert!(sunrise_sunset_utc(2024, 12, 21, 78.22, 15.65).unwrap().is_none());
        assert!(sunrise_sunset_utc(2024, 6, 21, 95.0, 0.0).is_err());
    }
}
