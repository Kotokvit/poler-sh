//! Решение уравнений и комплексная арифметика (цикл M, v0.48.0).
//!
//! Три этажа:
//! 1. `Complex` — комплексные числа (для корней и собственных значений).
//! 2. `durand_kerner` — одновременное нахождение ВСЕХ корней полинома
//!    (метод Дюрана–Кернера / Вайерштрасса), комплексный.
//! 3. `solve_real` — уравнение f(x) = 0 с произвольной f: попытка
//!    распознать полином по выборкам (Вандермонд + контрольные точки),
//!    затем — мультстарт-Ньютон с численной производной и бисекция.
//!
//! Извлечённые уроки прошлой сессии:
//! - `x = x` внутри solve — это УРАВНЕНИЕ (тождество), а не присваивание;
//! - free_vars обязан заходить в аргументы вызовов функций.

use std::fmt;

/// Комплексное число (двойная точность).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub const fn new(re: f64, im: f64) -> Self {
        Complex { re, im }
    }
    pub const ZERO: Complex = Complex { re: 0.0, im: 0.0 };
    pub const ONE: Complex = Complex { re: 1.0, im: 0.0 };
    pub const I: Complex = Complex { re: 0.0, im: 1.0 };

    pub fn abs(self) -> f64 {
        self.re.hypot(self.im)
    }
    pub fn conj(self) -> Self {
        Complex::new(self.re, -self.im)
    }
    pub fn add(self, o: Complex) -> Self {
        Complex::new(self.re + o.re, self.im + o.im)
    }
    pub fn sub(self, o: Complex) -> Self {
        Complex::new(self.re - o.re, self.im - o.im)
    }
    pub fn mul(self, o: Complex) -> Self {
        Complex::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
    pub fn div(self, o: Complex) -> Self {
        let d = o.re * o.re + o.im * o.im;
        Complex::new(
            (self.re * o.re + self.im * o.im) / d,
            (self.im * o.re - self.re * o.im) / d,
        )
    }
    pub fn scale(self, k: f64) -> Self {
        Complex::new(self.re * k, self.im * k)
    }
    /// Деление на вещественный скаляр без промежуточного обращения —
    /// побитовая преемственность с f64-путём (pinv-регрессия цикла O).
    pub fn div_real(self, d: f64) -> Self {
        Complex::new(self.re / d, self.im / d)
    }
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Complex::new(r * theta.cos(), r * theta.sin())
    }
    /// Целочисленная степень (малые степени — горячего пути нет).
    pub fn powi(self, k: i32) -> Self {
        if k == 0 {
            return Complex::ONE;
        }
        let neg = k < 0;
        let mut acc = Complex::ONE;
        for _ in 0..k.unsigned_abs() {
            acc = acc.mul(self);
        }
        if neg {
            Complex::ONE.div(acc)
        } else {
            acc
        }
    }
    /// Приблизить к вещественной оси (шум мнимой части корней).
    pub fn snap_real(self, tol: f64) -> Self {
        if self.im.abs() < tol {
            Complex::new(self.re, 0.0)
        } else {
            self
        }
    }
}

/// Смешанная арифметика Complex ↔ f64 (цикл O): детерминированная,
/// математически однозначная (f64 ≡ вещественное с im = 0).
/// Нужна матричному слою (Vec<Complex>) и тестам, чтобы старые
/// f64-сравнения продолжали компилироваться без перепахивания.
impl PartialEq<f64> for Complex {
    fn eq(&self, other: &f64) -> bool {
        self.im == 0.0 && self.re == *other
    }
}
impl std::ops::Add for Complex {
    type Output = Complex;
    fn add(self, o: Complex) -> Complex {
        Complex::new(self.re + o.re, self.im + o.im)
    }
}
impl std::ops::Sub for Complex {
    type Output = Complex;
    fn sub(self, o: Complex) -> Complex {
        Complex::new(self.re - o.re, self.im - o.im)
    }
}
impl std::ops::Mul for Complex {
    type Output = Complex;
    fn mul(self, o: Complex) -> Complex {
        Complex::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
}
impl std::ops::Div for Complex {
    type Output = Complex;
    fn div(self, o: Complex) -> Complex {
        let d = o.re * o.re + o.im * o.im;
        Complex::new(
            (self.re * o.re + self.im * o.im) / d,
            (self.im * o.re - self.re * o.im) / d,
        )
    }
}
impl std::ops::Add<f64> for Complex {
    type Output = Complex;
    fn add(self, o: f64) -> Complex {
        Complex::new(self.re + o, self.im)
    }
}
impl std::ops::Sub<f64> for Complex {
    type Output = Complex;
    fn sub(self, o: f64) -> Complex {
        Complex::new(self.re - o, self.im)
    }
}
impl std::ops::Mul<f64> for Complex {
    type Output = Complex;
    fn mul(self, o: f64) -> Complex {
        self.scale(o)
    }
}

impl fmt::Display for Complex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let re = super::py_float(self.re);
        if self.im == 0.0 {
            write!(f, "{re}")
        } else if self.re == 0.0 {
            if (self.im - 1.0).abs() < 1e-15 {
                write!(f, "i")
            } else if (self.im + 1.0).abs() < 1e-15 {
                write!(f, "-i")
            } else {
                write!(f, "{}i", super::py_float(self.im))
            }
        } else {
            let sign = if self.im < 0.0 { "-" } else { "+" };
            let im = super::py_float(self.im.abs());
            if (self.im.abs() - 1.0).abs() < 1e-15 {
                write!(f, "{re} {sign} i")
            } else {
                write!(f, "{re} {sign} {}i", im)
            }
        }
    }
}

/// Значение полинома по коэффициентам (по убыванию степени, c[0] — старший).
pub fn poly_eval(coeffs: &[f64], z: Complex) -> Complex {
    let mut acc = Complex::ZERO;
    for &c in coeffs {
        acc = acc.mul(z).add(Complex::new(c, 0.0));
    }
    acc
}

/// Метод Дюрана–Кернера: все корни полинома сразу.
/// `coeffs` — по убыванию степени, coeffs[0] != 0 (monic после нормировки).
pub fn durand_kerner(coeffs: &[f64], iters: usize) -> Vec<Complex> {
    let n = coeffs.len() - 1;
    if n == 0 {
        return Vec::new();
    }
    // нормируем к monic
    let lead = coeffs[0];
    let c: Vec<f64> = coeffs.iter().map(|v| v / lead).collect();

    // стартовые точки по спирали (классика Дюрана–Кернера)
    let mut roots: Vec<Complex> = (0..n)
        .map(|i| {
            let ang = 0.4 * (i + 1) as f64;
            let r = 0.9_f64.powi(i as i32 + 1);
            Complex::from_polar(r, ang).add(Complex::new(0.4, 0.9))
        })
        .collect();

    let tol = 1e-14;
    for _ in 0..iters {
        let mut max_delta = 0.0f64;
        for i in 0..n {
            let zi = roots[i];
            let num = poly_eval(&c, zi);
            let mut den = Complex::ONE;
            for (j, &rj) in roots.iter().enumerate() {
                if j != i {
                    den = den.mul(zi.sub(rj));
                }
            }
            if den.abs() < 1e-300 {
                continue;
            }
            let step = num.div(den);
            let delta = step.abs();
            if delta.is_finite() {
                roots[i] = zi.sub(step);
                max_delta = max_delta.max(delta);
            }
        }
        if max_delta < tol {
            break;
        }
    }
    // прибиваем мнимый шум к нулю (вещественные коэффициенты)
    let scale = c
        .iter()
        .skip(1)
        .fold(1.0f64, |a, &v| a.max(v.abs()))
        .max(1.0);
    roots
        .iter()
        .map(|&r| r.snap_real(1e-8 * scale))
        .collect()
}

/// Значение полинома с КОМПЛЕКСНЫМИ коэффициентами (по убыванию степени).
/// Цикл O: характеристический полином комплексной матрицы комплексен.
pub fn poly_eval_c(coeffs: &[Complex], z: Complex) -> Complex {
    let mut acc = Complex::ZERO;
    for &c in coeffs {
        acc = acc.mul(z).add(c);
    }
    acc
}

/// Дюран–Кернер для комплексных коэффициентов (зеркало f64-версии).
/// Для вещественных коэффициентов ведёт себя идентично ей (im = 0).
pub fn durand_kerner_c(coeffs: &[Complex], iters: usize) -> Vec<Complex> {
    let n = coeffs.len() - 1;
    if n == 0 {
        return Vec::new();
    }
    // нормируем к monic
    let lead = coeffs[0];
    let c: Vec<Complex> = coeffs.iter().map(|v| v.div(lead)).collect();
    let mut roots: Vec<Complex> = (0..n)
        .map(|i| {
            let ang = 0.4 * (i + 1) as f64;
            let r = 0.9_f64.powi(i as i32 + 1);
            Complex::from_polar(r, ang).add(Complex::new(0.4, 0.9))
        })
        .collect();
    let tol = 1e-14;
    for _ in 0..iters {
        let mut max_delta = 0.0f64;
        for i in 0..n {
            let zi = roots[i];
            let num = poly_eval_c(&c, zi);
            let mut den = Complex::ONE;
            for (j, &rj) in roots.iter().enumerate() {
                if j != i {
                    den = den.mul(zi.sub(rj));
                }
            }
            if den.abs() < 1e-300 {
                continue;
            }
            let step = num.div(den);
            let delta = step.abs();
            if delta.is_finite() {
                roots[i] = zi.sub(step);
                max_delta = max_delta.max(delta);
            }
        }
        if max_delta < tol {
            break;
        }
    }
    roots
}

/// Сортировка корней для стабильного вывода: по Re, затем по Im.
pub fn sort_roots(mut roots: Vec<Complex>) -> Vec<Complex> {
    roots.sort_by(|a, b| {
        a.re.partial_cmp(&b.re)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.im.partial_cmp(&b.im).unwrap_or(std::cmp::Ordering::Equal))
    });
    roots
}

// ---------------------------------------------------------------------
// Решение f(x) = 0 для произвольной вещественной f
// ---------------------------------------------------------------------

/// Результат решения уравнения.
#[derive(Debug)]
pub enum SolveOutcome {
    /// Тождество: 0 = 0 — любое значение.
    Identity,
    /// Противоречие: c = 0 при c ≠ 0 — решений нет.
    Contradiction(f64),
    /// Найденные корни (полином — все; численно — найденные).
    Roots(Vec<Complex>, &'static str),
    /// f(x) → 0 лишь асимптотически (exp(x) = 0): нуль не достигается
    /// никогда. Цикл N: честный вердикт вместо ложных корней в зоне
    /// машинного underflow (e^x округляется в 0.0 при x ≲ −708).
    AsymptoticZero,
}

/// Попытка распознать полином степени ≤ max_deg по значениям f в
/// равноотстоящих точках: решаем Вандермонда и проверяем на контрольных.
fn try_poly_fit(f: &dyn Fn(f64) -> f64, max_deg: usize) -> Option<Vec<f64>> {
    // точки: x_k = k·0.7 − 7 → диапазон [−7, ~7]
    let xs: Vec<f64> = (0..=max_deg).map(|k| k as f64 * 0.7 - 7.0).collect();
    let ys: Vec<f64> = xs.iter().map(|&x| f(x)).collect();
    if ys.iter().any(|y| !y.is_finite()) {
        return None;
    }
    if ys.iter().all(|&y| y == 0.0) {
        return Some(vec![]); // нулевой полином — тождество
    }

    // пробуем степени от 1 до max_deg (низшие — сначала)
    for deg in 1..=max_deg {
        let m = deg + 1;
        // Вандермонд xs[i]^j, j = 0..deg (по возрастанию)
        let mut a = vec![vec![0.0; m]; m];
        for (i, &x) in xs.iter().take(m).enumerate() {
            let mut p = 1.0;
            for j in 0..m {
                a[i][j] = p;
                p *= x;
            }
        }
        let b: Vec<f64> = ys[..m].to_vec();
        let Some(coeffs_asc) = solve_linear(&a, &b) else {
            continue;
        };
        // контрольные точки
        let check = [-13.3, -5.1, 2.9, 9.4, 16.7];
        let ok = check.iter().all(|&x| {
            let mut v = 0.0;
            let mut p = 1.0;
            for &c in &coeffs_asc {
                v += c * p;
                p *= x;
            }
            let fv = f(x);
            fv.is_finite() && (v - fv).abs() <= 1e-6 * (1.0 + v.abs() + fv.abs())
        });
        if ok {
            // по убыванию степени
            let mut coeffs_desc: Vec<f64> = coeffs_asc.iter().rev().cloned().collect();
            // срезаем старшие ~нулевые коэффициенты
            while coeffs_desc.len() > 1 && coeffs_desc[0].abs() < 1e-12 {
                coeffs_desc.remove(0);
            }
            if coeffs_desc.len() == 1 && coeffs_desc[0].abs() < 1e-12 {
                return Some(vec![]); // константа ~0 → почти тождество
            }
            return Some(coeffs_desc);
        }
    }
    None
}

/// Гауссово исключение с частичным выбором ведущего элемента (n×n).
pub fn solve_linear(a: &[Vec<f64>], b: &[f64]) -> Option<Vec<f64>> {
    let n = b.len();
    let mut m: Vec<Vec<f64>> = a
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let mut r = row.clone();
            r.push(b[i]);
            r
        })
        .collect();
    for col in 0..n {
        // ведущий элемент
        let mut piv = col;
        for r in col + 1..n {
            if m[r][col].abs() > m[piv][col].abs() {
                piv = r;
            }
        }
        if m[piv][col].abs() < 1e-12 {
            return None;
        }
        m.swap(col, piv);
        let d = m[col][col];
        for j in col..=n {
            m[col][j] /= d;
        }
        for r in 0..n {
            if r != col && m[r][col] != 0.0 {
                let k = m[r][col];
                for j in col..=n {
                    m[r][j] -= k * m[col][j];
                }
            }
        }
    }
    Some((0..n).map(|i| m[i][n]).collect())
}

/// Численная производная (центральная разность).
fn dnum(f: &dyn Fn(f64) -> f64, x: f64) -> f64 {
    let h = 1e-7 * (1.0 + x.abs());
    (f(x + h) - f(x - h)) / (2.0 * h)
}

/// Решить f(x) = 0. Стратегия: полином → Дюран–Кернер; иначе Ньютон
/// мультстарт + бисекция на найденных знакопеременных интервалах.
pub fn solve_real(f: &dyn Fn(f64) -> f64) -> SolveOutcome {
    // 1) распознавание полинома (до степени 16)
    match try_poly_fit(f, 16) {
        Some(coeffs) if coeffs.is_empty() => return SolveOutcome::Identity,
        Some(coeffs) if coeffs.len() == 1 => {
            return SolveOutcome::Contradiction(coeffs[0]);
        }
        Some(coeffs) => {
            // нормируем к monic и ищем корни
            let roots = durand_kerner(&coeffs, 200);
            // отфильтровываем «бесконечные» (расходящиеся) корни
            let roots: Vec<Complex> = roots
                .into_iter()
                .filter(|r| r.abs().is_finite() && r.abs() < 1e12)
                .collect();
            if roots.is_empty() {
                return SolveOutcome::Contradiction(0.0);
            }
            return SolveOutcome::Roots(sort_roots(roots), "полином (Дюран–Кернер)");
        }
        None => {}
    }

    // 2) численно: мультстарт-Ньютон
    let mut roots: Vec<f64> = Vec::new();
    // цикл N: был ли отклонён кандидат из зоны underflow (exp-плато)
    let mut asymptotic_hit = false;
    let starts: Vec<f64> = (-20..=20)
        .map(|i| i as f64 * 10.0)
        .chain((-40..=40).map(|i| i as f64 * 0.25))
        .collect();
    'starts: for &x0 in &starts {
        let mut x = x0;
        for _ in 0..80 {
            let fx = f(x);
            if !fx.is_finite() {
                continue 'starts;
            }
            if fx.abs() < 1e-12 {
                break;
            }
            let d = dnum(f, x);
            if !d.is_finite() || d.abs() < 1e-14 {
                continue 'starts;
            }
            let dx = fx / d;
            let nx = x - dx;
            if !nx.is_finite() {
                continue 'starts;
            }
            x = nx;
            if dx.abs() < 1e-12 * (1.0 + x.abs()) {
                break;
            }
        }
        if f(x).abs() < 1e-9 {
            // цикл N — ОТСЕВ ЛОЖНЫХ КОРНЕЙ В ЗОНЕ UNDERFLOW:
            // настоящий корень = смена знака в окрестности ИЛИ касание
            // нуля (|f| на 2 порядка меньше соседей — кратные корни);
            // экспоненциальное плато (f(x±h) ≈ f(x) ≠ 0) — НЕ корень.
            // h больше ньютоновской точности (1e-6): для кратных корней
            // fx = ε² при ε ≤ 1e-6 нужен h ≳ 1e-4, чтобы соседи выросли.
            let h = 1e-4 * (1.0 + x.abs());
            let (fl, fr) = (f(x - h), f(x + h));
            let fx = f(x);
            let sign_cross = (fl <= 0.0 && fr >= 0.0) || (fr <= 0.0 && fl >= 0.0);
            let touch = fx.abs() < 1e-12
                && fl.abs() > 100.0 * fx.abs().max(1e-300)
                && fr.abs() > 100.0 * fx.abs().max(1e-300);
            if sign_cross || touch {
                // дедупликация
                if !roots.iter().any(|&r| (r - x).abs() < 1e-6 * (1.0 + x.abs())) {
                    roots.push(x);
                }
            } else if fx.abs() < 1e-12 {
                // малое, но ненулевое плато — метка асимптотического нуля
                asymptotic_hit = true;
            }
        }
    }

    // 3) бисекция на сетке (ловит корни с чётной кратностью/пропущенные)
    let mut prev_x = -100.0f64;
    let mut prev_y = f(prev_x);
    let mut x = prev_x;
    for _ in 0..4000 {
        x += 0.05;
        let y = f(x);
        if prev_y.is_finite() && y.is_finite() && prev_y * y < 0.0 {
            let (mut lo, mut hi) = (prev_x, x);
            for _ in 0..80 {
                let mid = 0.5 * (lo + hi);
                let fm = f(mid);
                if fm == 0.0 {
                    lo = mid;
                    hi = mid;
                    break;
                }
                if f(lo) * fm < 0.0 {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            let r = 0.5 * (lo + hi);
            if !roots.iter().any(|&q| (q - r).abs() < 1e-6 * (1.0 + r.abs())) {
                roots.push(r);
            }
        }
        prev_x = x;
        prev_y = y;
        if x > 100.0 {
            break;
        }
    }
    roots.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    if roots.is_empty() {
        if asymptotic_hit {
            // exp(x) = 0: числитель под e^x уходит в underflow — корней нет,
            // но |f| плато-малое; сообщаем асимптотическую правду
            return SolveOutcome::AsymptoticZero;
        }
        // последний шанс: может, f нигде не определена/нет корней
        SolveOutcome::Roots(Vec::new(), "численный поиск: вещественных корней не найдено")
    } else {
        SolveOutcome::Roots(
            roots.into_iter().map(|r| Complex::new(r, 0.0)).collect(),
            "численно (Ньютон + бисекция), диапазон ±100",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn complex_arith() {
        let a = Complex::new(3.0, 4.0);
        let b = Complex::new(1.0, -2.0);
        assert!((a.abs() - 5.0).abs() < 1e-15);
        let s = a.add(b);
        assert_eq!((s.re, s.im), (4.0, 2.0));
        let p = a.mul(b);
        assert!((p.re - 11.0).abs() < 1e-12 && (p.im + 2.0).abs() < 1e-12);
        let q = a.div(b);
        // (3+4i)/(1−2i) = (3+4i)(1+2i)/5 = (3−8 + i(6+4))/5 = (−5+10i)/5 = −1+2i
        assert!((q.re + 1.0).abs() < 1e-12 && (q.im - 2.0).abs() < 1e-12);
        let i2 = Complex::I.mul(Complex::I);
        assert!((i2.re + 1.0).abs() < 1e-15 && i2.im.abs() < 1e-15);
    }

    #[test]
    fn complex_display() {
        assert_eq!(Complex::new(2.5, 0.0).to_string(), "2.5");
        assert_eq!(Complex::new(0.0, 1.0).to_string(), "i");
        assert_eq!(Complex::new(0.0, -1.0).to_string(), "-i");
        assert_eq!(Complex::new(1.0, 2.0).to_string(), "1.0 + 2.0i");
        assert_eq!(Complex::new(1.0, -1.0).to_string(), "1.0 - i");
    }

    #[test]
    fn durand_kerner_quadratic() {
        // x² − 5x + 6 = 0 → 2, 3
        let roots = sort_roots(durand_kerner(&[1.0, -5.0, 6.0], 200));
        assert_eq!(roots.len(), 2);
        assert!(close(roots[0].re, 2.0, 1e-9));
        assert!(close(roots[1].re, 3.0, 1e-9));
    }

    #[test]
    fn durand_kerner_complex_pair() {
        // x² + 1 = 0 → ±i
        let roots = sort_roots(durand_kerner(&[1.0, 0.0, 1.0], 200));
        assert_eq!(roots.len(), 2);
        assert!(roots[0].im.abs() > 0.9 && close(roots[0].re, 0.0, 1e-9));
        assert!((roots[0].im + roots[1].im).abs() < 1e-9);
    }

    #[test]
    fn durand_kerner_quartic() {
        // (x−1)(x−2)(x−3)(x+7) = x⁴+x³−19x²+11x+42? проверим прямым перемножением
        // (x−1)(x−2)=x²−3x+2; (x−3)(x+7)=x²+4x−21
        // произведение: x⁴+4x³−21x²−3x³−12x²+63x+2x²+8x−42 = x⁴+x³−31x²+71x−42
        let roots = sort_roots(durand_kerner(&[1.0, 1.0, -31.0, 71.0, -42.0], 300));
        let rs: Vec<f64> = roots.iter().map(|r| r.re).collect();
        assert!(rs.iter().all(|r| close(*r, r.round(), 1e-6)));
        let want = vec![-7.0, 1.0, 2.0, 3.0];
        for w in want {
            assert!(rs.iter().any(|r| close(*r, w, 1e-6)), "нет корня {w} в {rs:?}");
        }
    }

    #[test]
    fn poly_fit_detection() {
        // f(x) = x³ − 6x² + 11x − 6 → корни 1, 2, 3
        let f = |x: f64| x.powi(3) - 6.0 * x.powi(2) + 11.0 * x - 6.0;
        match solve_real(&f) {
            SolveOutcome::Roots(rs, how) => {
                assert!(how.contains("Дюран"), "ожидался полином, got {how}");
                let rs: Vec<f64> = rs.iter().map(|r| r.re).collect();
                for w in [1.0, 2.0, 3.0] {
                    assert!(rs.iter().any(|r| close(*r, w, 1e-6)), "{rs:?}");
                }
            }
            other => panic!("ожидались корни, got {other:?}"),
        }
    }

    #[test]
    fn identity_and_contradiction() {
        // f(x) = x − x → 0 везде
        match solve_real(&|x| x - x) {
            SolveOutcome::Identity => {}
            other => panic!("ожидалось тождество, got {other:?}"),
        }
        // f(x) = x² + 1 (нет вещественных, но полином → комплексные)
        match solve_real(&|x| x * x + 1.0) {
            SolveOutcome::Roots(rs, _) => {
                assert!(rs.iter().all(|r| r.im.abs() > 0.9));
            }
            other => panic!("ожидались комплексные корни, got {other:?}"),
        }
        // f(x) = 5 (константа) — противоречие
        match solve_real(&|_| 5.0) {
            SolveOutcome::Contradiction(c) => assert!((c - 5.0).abs() < 1e-9),
            other => panic!("ожидалось противоречие, got {other:?}"),
        }
    }

    #[test]
    fn numeric_transcendental() {
        // sin(x) = 0.5 → x ≈ π/6 + 2πk и 5π/6 + 2πk; в ±100 их 64,
        // проверим ближайшие к нулю
        let f = |x: f64| x.sin() - 0.5;
        match solve_real(&f) {
            SolveOutcome::Roots(rs, how) => {
                assert!(how.contains("Ньютон") || how.contains("численн"), "{how}");
                assert!(rs.len() >= 2);
                let rs: Vec<f64> = rs.iter().map(|r| r.re).collect();
                assert!(
                    rs.iter().any(|r| close(*r, std::f64::consts::FRAC_PI_6, 1e-5)),
                    "нет π/6 в {rs:?}"
                );
            }
            other => panic!("ожидались корни, got {other:?}"),
        }
    }

    // ГЛАВНАЯ регрессия цикла N: exp(x) = 0 — корней нет, но старый
    // решатель возвращал ложные [-200, -90] (зона машинного underflow,
    // где e^x < 1e-12 ломает критерий сходимости Ньютона).
    #[test]
    fn underflow_asymptotic_zero() {
        let f = |x: f64| x.exp();
        match solve_real(&f) {
            SolveOutcome::AsymptoticZero => {}
            other => panic!("ожидался AsymptoticZero, got {other:?}"),
        }
        // родственный случай: 2^x = 0 — та же асимптотика
        let g = |x: f64| (2.0f64).powf(x);
        match solve_real(&g) {
            SolveOutcome::AsymptoticZero => {}
            other => panic!("ожидался AsymptoticZero, got {other:?}"),
        }
        // контроль: exp(x) = 2 по-прежнему решается
        let h = |x: f64| x.exp() - 2.0;
        match solve_real(&h) {
            SolveOutcome::Roots(rs, _) => {
                assert!(rs.iter().any(|r| close(r.re, 2.0f64.ln(), 1e-6)));
            }
            other => panic!("ожидались корни, got {other:?}"),
        }
    }

    #[test]
    fn linear_solver() {
        // x + y = 3; 2x − y = 0 → x = 1, y = 2
        let a = vec![vec![1.0, 1.0], vec![2.0, -1.0]];
        let b = vec![3.0, 0.0];
        let s = solve_linear(&a, &b).unwrap();
        assert!(close(s[0], 1.0, 1e-12) && close(s[1], 2.0, 1e-12));
        // вырожденная
        assert!(solve_linear(&vec![vec![1.0, 2.0], vec![2.0, 4.0]], &vec![1.0, 2.0]).is_none());
    }
}
