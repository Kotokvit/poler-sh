//! Геодезия и навигация (цикл M, v0.48.0).
//!
//! Урок прошлой сессии: midpoint и earth_radius были запутаны — здесь обе
//! функции записаны РОВНО по каноническим формулам (Aviation Formulary /
//! GeographicLib-конвенции для сферы, эллипсоид WGS84 для радиуса).
//!
//! Все широты/долготы — в ГРАДУСАХ (навигационная конвенция).

/// Средний радиус Земли, км (IUGG).
pub const R_MEAN_KM: f64 = 6371.0087714;

/// Большая полуось WGS84, км.
pub const WGS84_A: f64 = 6378.137;
/// Сжатие WGS84.
pub const WGS84_F: f64 = 1.0 / 298.257223563;

/// Радиус кривизны сфероида на широте φ (км) — стандартная формула:
/// R(φ) = √(((a²cosφ)² + (b²sinφ)²) / ((a·cosφ)² + (b·sinφ)²)),
/// где b = a(1−f) — малая полуось.
pub fn earth_radius_km(lat_deg: f64) -> f64 {
    let lat = lat_deg.to_radians();
    let b = WGS84_A * (1.0 - WGS84_F);
    let a2 = WGS84_A * WGS84_A;
    let b2 = b * b;
    let c = lat.cos();
    let s = lat.sin();
    let num = (a2 * c).powi(2) + (b2 * s).powi(2);
    let den = (WGS84_A * c).powi(2) + (b * s).powi(2);
    (num / den).sqrt()
}

/// Центральный угол между двумя точками (рад), гаверсинус.
fn central_angle(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, l1, p2, l2) = (
        lat1.to_radians(),
        lon1.to_radians(),
        lat2.to_radians(),
        lon2.to_radians(),
    );
    let dp = p2 - p1;
    let dl = l2 - l1;
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * h.sqrt().clamp(-1.0, 1.0).asin()
}

/// Длина большого круга между точками (км), средний радиус.
pub fn great_circle_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    R_MEAN_KM * central_angle(lat1, lon1, lat2, lon2)
}

/// Начальный азимут (курс) из точки 1 на точку 2, градусы [0, 360).
pub fn bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, l1, p2, l2) = (
        lat1.to_radians(),
        lon1.to_radians(),
        lat2.to_radians(),
        lon2.to_radians(),
    );
    let dl = l2 - l1;
    let y = dl.sin() * p2.cos();
    let x = p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos();
    let mut brg = y.atan2(x).to_degrees();
    brg = brg.rem_euclid(360.0);
    brg
}

/// Середина большого круга — КАНОНИЧЕСКАЯ формула (Aviation Formulary):
///   Bx = cos φ2 · cos Δλ;  By = cos φ2 · sin Δλ
///   φm = atan2(sin φ1 + sin φ2, √((cos φ1 + Bx)² + By²))
///   λm = λ1 + atan2(By, cos φ1 + Bx)
/// Возвращает (широта, долгота) в градусах.
pub fn midpoint(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> (f64, f64) {
    let (p1, l1, p2, l2) = (
        lat1.to_radians(),
        lon1.to_radians(),
        lat2.to_radians(),
        lon2.to_radians(),
    );
    let dl = l2 - l1;
    let bx = p2.cos() * dl.cos();
    let by = p2.cos() * dl.sin();
    let pm = (p1.sin() + p2.sin()).atan2((p1.cos() + bx).hypot(by));
    let lm = l1 + by.atan2(p1.cos() + bx);
    (pm.to_degrees(), norm_lon(lm.to_degrees()))
}

/// Точка на расстоянии d (км) по азимуту brg (град) от старта —
/// прямая геодезическая задача на сфере.
pub fn destination(lat1: f64, lon1: f64, brg: f64, dist_km: f64) -> (f64, f64) {
    let (p1, l1, b) = (lat1.to_radians(), lon1.to_radians(), brg.to_radians());
    let delta = dist_km / R_MEAN_KM;
    let p2 = (p1.sin() * delta.cos() + p1.cos() * delta.sin() * b.cos()).asin();
    // Aviation Formulary: числитель atan2 — cos ШИРОТЫ СТАРТА (p1),
    // не p2 (баг: обратная дистанция 482 вместо 500 км)
    let l2 = l1
        + (b.sin() * delta.sin() * p1.cos()).atan2(delta.cos() - p1.sin() * p2.sin());
    (p2.to_degrees(), l2.to_degrees().rem_euclid(360.0))
}

/// Нормализация долготы в (−180, 180].
fn norm_lon(lon: f64) -> f64 {
    let mut x = lon.rem_euclid(360.0);
    if x > 180.0 {
        x -= 360.0;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    // К/calendar точек:
    // Київ (50.45, 30.52), Львів (49.84, 24.03), Одеса (46.48, 30.73),
    // Нью-Йорк (40.71, −74.01), Лондон (51.51, −0.13), Токіо (35.68, 139.69)

    #[test]
    fn earth_radius_wgs84() {
        // экватор — большая полуось
        assert!(close(earth_radius_km(0.0), 6378.137, 1e-9));
        // полюс — малая полуось b = a(1−f) = 6356.752
        assert!(close(earth_radius_km(90.0), 6356.752314, 1e-5));
        // монотонность от экватора к полюсу
        assert!(earth_radius_km(0.0) > earth_radius_km(45.0));
        assert!(earth_radius_km(45.0) > earth_radius_km(90.0));
        // симметрия север/юг
        assert!(close(earth_radius_km(45.0), earth_radius_km(-45.0), 1e-12));
        // R(45°) ≈ 6367.49
        assert!(close(earth_radius_km(45.0), 6367.4895, 1e-3));
    }

    #[test]
    fn distances_known_pairs() {
        // Київ — Львів ≈ 462 км (картографический факт)
        let d = great_circle_km(50.45, 30.52, 49.84, 24.03);
        assert!(d > 450.0 && d < 475.0, "Київ—Львів = {d}");
        // Нью-Йорк — Лондон ≈ 5570 км
        let d = great_circle_km(40.71, -74.01, 51.51, -0.13);
        assert!(d > 5480.0 && d < 5660.0, "NY—London = {d}");
        // нулевое расстояние
        assert!(close(great_circle_km(10.0, 20.0, 10.0, 20.0), 0.0, 1e-9));
        // четверть экватора: (0,0) → (0,90) ≈ 6371·π/2 ≈ 10007.5 км
        let d = great_circle_km(0.0, 0.0, 0.0, 90.0);
        assert!(close(d, R_MEAN_KM * std::f64::consts::FRAC_PI_2, 1e-6));
        // симметрия
        let a = great_circle_km(50.45, 30.52, 46.48, 30.73);
        let b = great_circle_km(46.48, 30.73, 50.45, 30.52);
        assert!(close(a, b, 1e-9));
    }

    #[test]
    fn bearings() {
        // строго на восток: (0, 0) → (0, 10) → 90°
        assert!(close(bearing_deg(0.0, 0.0, 0.0, 10.0), 90.0, 1e-6));
        // строго на север: (0, 0) → (10, 0) → 0°
        assert!(close(bearing_deg(0.0, 0.0, 10.0, 0.0), 0.0, 1e-6));
        // на запад → 270°
        assert!(close(bearing_deg(0.0, 0.0, 0.0, -10.0), 270.0, 1e-6));
        // на юг → 180°
        assert!(close(bearing_deg(10.0, 0.0, 0.0, 0.0), 180.0, 1e-6));
        // Київ → Львів ≈ 267° (почти на запад)
        let b = bearing_deg(50.45, 30.52, 49.84, 24.03);
        assert!(b > 255.0 && b < 280.0, "Kоїв→Львів azimuth = {b}");
    }

    // ================================================================
    // РЕГРЕССИЯ прошлой сессии: midpoint переписан по канону.
    // Свойства: коммутативность, середина отрезка экватора,
    // |mid − A| ≈ |mid − B|.
    // ================================================================
    #[test]
    fn midpoint_canonical() {
        // середина экваториального отрезка
        let (m, _) = midpoint(0.0, 10.0, 0.0, 20.0);
        assert!(close(m, 0.0, 1e-12));
        // на экваторе долгота середины = средняя (без перехода 180°)
        let (_, lm) = midpoint(0.0, 10.0, 0.0, 20.0);
        assert!(close(lm, 15.0, 1e-9), "lon_mid = {lm}");
        // меридиональная середина
        let (pm, _) = midpoint(10.0, 5.0, 20.0, 5.0);
        assert!(close(pm, 15.0, 1e-9), "lat_mid = {pm}");
        // коммутативность
        let (a1, b1) = midpoint(50.45, 30.52, 49.84, 24.03);
        let (a2, b2) = midpoint(49.84, 24.03, 50.45, 30.52);
        assert!(close(a1, a2, 1e-9) && close(b1, b2, 1e-9));
        // равноудалённость от концов
        let (mlat, mlon) = midpoint(50.45, 30.52, 40.71, -74.01);
        let d1 = great_circle_km(50.45, 30.52, mlat, mlon);
        let d2 = great_circle_km(mlat, mlon, 40.71, -74.01);
        assert!(
            (d1 - d2).abs() / d1.max(d2) < 1e-6,
            "mid не в середине: {d1} vs {d2}"
        );
        // Київ—Львів midpoint ≈ (50.16, 27.29)
        let (mlat, mlon) = midpoint(50.45, 30.52, 49.84, 24.03);
        assert!(close(mlat, 50.15, 0.1), "mlat = {mlat}");
        assert!(close(norm_lon(mlon), 27.3, 0.15), "mlon = {mlon}");
    }

    #[test]
    fn destination_roundtrip() {
        // прямая + обратная задача: едем 500 км по азимуту 45° и назад
        let (lat2, lon2) = destination(50.45, 30.52, 45.0, 500.0);
        // обратный азимут ≈ 225° + поправка сходимости меридианов
        let back = bearing_deg(lat2, lon2, 50.45, 30.52);
        assert!((back - 225.0).abs() < 6.0, "back = {back}"); // +сходимость меридианов (~4°)
        let d = great_circle_km(lat2, lon2, 50.45, 30.52);
        assert!(close(d, 500.0, 0.5), "distance back = {d}");
        // нулевая дистанция — та же точка
        let (lat2, lon2) = destination(10.0, 20.0, 77.0, 0.0);
        assert!(close(lat2, 10.0, 1e-9) && close(norm_lon(lon2), 20.0, 1e-9));
        // 1/4 экватора на восток → (0, 90)
        let (lat2, lon2) = destination(0.0, 0.0, 90.0, R_MEAN_KM * std::f64::consts::FRAC_PI_2);
        assert!(close(lat2, 0.0, 1e-9));
        assert!(close(norm_lon(lon2), 90.0, 1e-6), "lon = {lon2}");
    }
}
