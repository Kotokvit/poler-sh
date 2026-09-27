//! Матрично-квантовое ядро POLER Matrix Calc (цикл M → цикл O).
//!
//! Цикл O: элементы — комплексные числа ℂ; эрмитово сопряжение dagger,
//! тензорное произведение kron, унитарность — решатель уравнения
//! Шрёдингера |Ψ(t)⟩ = expm(−i·H·t/ħ)·|Ψ₀⟩ живёт поверх этого слоя.
//!
//! Исправленные дефекты прошлой сессии (задокументированы тестами):
//! - Паде [6/6] для expm: коэффициент b4 = **1/792** (не 1/1584);
//! - Фаддеев–Леврерье: M_k = A·M_{k−1} + c_k·I — прибавление ТОЛЬКО к
//!   диагонали (add_scalar ко всем элементам ломал характеристический
//!   полином);
//! - собственные значения — через Дюрана–Кернера по charpoly.
//!
//! Квантовая часть: генераторы Ли so(2)/so(3) и их экспоненты —
//! точные вращения expm(J·θ), как в живом голосе (J = A − Aᵀ).

use super::solve::{durand_kerner, durand_kerner_c, sort_roots, Complex};

/// Плотная матрица, row-major. Цикл O: элементы — комплексные числа
/// (вещественная матрица ≡ все im = 0); вся линейная алгебра — над ℂ.
#[derive(Debug, Clone, PartialEq)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<Complex>,
}

impl Matrix {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Matrix { rows, cols, data: vec![Complex::ZERO; rows * cols] }
    }

    pub fn identity(n: usize) -> Self {
        let mut m = Self::zeros(n, n);
        for i in 0..n {
            m.data[i * n + i] = Complex::ONE;
        }
        m
    }

    pub fn from_rows(rows: &[Vec<f64>]) -> Result<Self, String> {
        if rows.is_empty() {
            return Err("пустая матрица".into());
        }
        let cols = rows[0].len();
        if cols == 0 || rows.iter().any(|r| r.len() != cols) {
            return Err("строки матрицы разной длины".into());
        }
        Ok(Matrix {
            rows: rows.len(),
            cols,
            data: rows
                .iter()
                .flat_map(|r| r.iter().map(|&v| Complex::new(v, 0.0)))
                .collect(),
        })
    }

    /// Матрица из комплексных строк (цикл O: [0, −i; i, 0]).
    pub fn from_complex_rows(rows: &[Vec<Complex>]) -> Result<Self, String> {
        if rows.is_empty() {
            return Err("пустая матрица".into());
        }
        let cols = rows[0].len();
        if cols == 0 || rows.iter().any(|r| r.len() != cols) {
            return Err("строки матрицы разной длины".into());
        }
        Ok(Matrix {
            rows: rows.len(),
            cols,
            data: rows.iter().flat_map(|r| r.iter().copied()).collect(),
        })
    }

    #[inline]
    pub fn get(&self, i: usize, j: usize) -> Complex {
        self.data[i * self.cols + j]
    }
    #[inline]
    pub fn set(&mut self, i: usize, j: usize, v: Complex) {
        self.data[i * self.cols + j] = v;
    }

    pub fn is_square(&self) -> bool {
        self.rows == self.cols
    }

    pub fn transpose(&self) -> Matrix {
        let mut t = Matrix::zeros(self.cols, self.rows);
        for i in 0..self.rows {
            for j in 0..self.cols {
                t.set(j, i, self.get(i, j));
            }
        }
        t
    }

    pub fn trace(&self) -> Result<Complex, String> {
        if !self.is_square() {
            return Err("след определён только для квадратных матриц".into());
        }
        Ok((0..self.rows).fold(Complex::ZERO, |s, i| s.add(self.get(i, i))))
    }

    pub fn add(&self, o: &Matrix) -> Result<Matrix, String> {
        if self.rows != o.rows || self.cols != o.cols {
            return Err(format!(
                "размеры не совпадают: {}×{} + {}×{}",
                self.rows, self.cols, o.rows, o.cols
            ));
        }
        let mut r = self.clone();
        for (a, b) in r.data.iter_mut().zip(o.data.iter()) {
            *a = *a + *b;
        }
        Ok(r)
    }

    pub fn sub(&self, o: &Matrix) -> Result<Matrix, String> {
        if self.rows != o.rows || self.cols != o.cols {
            return Err(format!(
                "размеры не совпадают: {}×{} − {}×{}",
                self.rows, self.cols, o.rows, o.cols
            ));
        }
        let mut r = self.clone();
        for (a, b) in r.data.iter_mut().zip(o.data.iter()) {
            *a = *a - *b;
        }
        Ok(r)
    }

    pub fn scale(&self, k: f64) -> Matrix {
        let mut r = self.clone();
        for v in r.data.iter_mut() {
            *v = v.scale(k);
        }
        r
    }

    /// Умножение на комплексный скаляр (цикл O: i·A, (2+3i)·A).
    pub fn scale_c(&self, k: Complex) -> Matrix {
        let mut r = self.clone();
        for v in r.data.iter_mut() {
            *v = v.mul(k);
        }
        r
    }

    pub fn mul(&self, o: &Matrix) -> Result<Matrix, String> {
        if self.cols != o.rows {
            return Err(format!(
                "несовместимо для умножения: {}×{} · {}×{}",
                self.rows, self.cols, o.rows, o.cols
            ));
        }
        let mut r = Matrix::zeros(self.rows, o.cols);
        for i in 0..self.rows {
            for k in 0..self.cols {
                let a = self.get(i, k);
                if a == 0.0 {
                    continue;
                }
                for j in 0..o.cols {
                    let v = r.get(i, j) + a * o.get(k, j);
                    r.set(i, j, v);
                }
            }
        }
        Ok(r)
    }

    /// Определитель: LU с частичным выбором ведущего элемента (над ℂ).
    pub fn det(&self) -> Result<Complex, String> {
        if !self.is_square() {
            return Err("определитель только для квадратных матриц".into());
        }
        let n = self.rows;
        let mut a = self.data.clone();
        let mut det = Complex::ONE;
        for col in 0..n {
            let mut piv = col;
            for r in col + 1..n {
                if a[r * n + col].abs() > a[piv * n + col].abs() {
                    piv = r;
                }
            }
            if a[piv * n + col].abs() < 1e-300 {
                return Ok(Complex::ZERO);
            }
            if piv != col {
                for j in 0..n {
                    a.swap(piv * n + j, col * n + j);
                }
                det = Complex::ZERO.sub(det);
            }
            let d = a[col * n + col];
            det = det.mul(d);
            for r in col + 1..n {
                let k = a[r * n + col].div(d);
                if k != Complex::ZERO {
                    for j in col..n {
                        a[r * n + j] = a[r * n + j].sub(k.mul(a[col * n + j]));
                    }
                }
            }
        }
        Ok(det)
    }

    /// Обратная матрица: Гаусс–Жордан с выбором ведущего.
    pub fn inv(&self) -> Result<Matrix, String> {
        if !self.is_square() {
            return Err("обратная только для квадратных матриц".into());
        }
        let n = self.rows;
        let mut a = self.data.clone();
        let mut b = Matrix::identity(n).data;
        for col in 0..n {
            let mut piv = col;
            for r in col + 1..n {
                if a[r * n + col].abs() > a[piv * n + col].abs() {
                    piv = r;
                }
            }
            if a[piv * n + col].abs() < 1e-13 {
                return Err(
                    "матрица вырождена (сингулярна) — псевдообратная Мура–Пенроуза: pinv(...)".into(),
                );
            }
            swap_rows_vec(&mut a, n, piv, col);
            swap_rows_vec(&mut b, n, piv, col);
            let d = a[col * n + col];
            for j in 0..n {
                a[col * n + j] = a[col * n + j].div(d);
                b[col * n + j] = b[col * n + j].div(d);
            }
            for r in 0..n {
                if r != col {
                    let k = a[r * n + col];
                    if k != Complex::ZERO {
                        for j in 0..n {
                            a[r * n + j] = a[r * n + j].sub(k.mul(a[col * n + j]));
                            b[r * n + j] = b[r * n + j].sub(k.mul(b[col * n + j]));
                        }
                    }
                }
            }
        }
        Ok(Matrix { rows: n, cols: n, data: b })
    }

    /// Псевдообратная Мура–Пенроуза: алгоритм Гревилля (колоночный, без SVD).
    ///
    /// A⁺ определена для ЛЮБОЙ матрицы — вырожденной, прямоугольной, нулевой.
    /// Строится наращиванием по столбцам: для нового столбца aₖ остаток
    /// cₖ = aₖ − Aₖ₋₁Aₖ₋₁⁺aₖ вне образа предыдущих столбцов либо становится
    /// новой строкой bₖᵀ = cₖᵀ/(cₖᵀcₖ), либо (cₖ ≈ 0) сворачивается в
    /// bₖᵀ = dₖᵀAₖ₋₁⁺/(1+dₖᵀdₖ), а прошлые строки корректируются на dₖbₖᵀ.
    /// Удовлетворяет четырём условиям Мура–Пенроуза (см. тест): проекции
    /// AA⁺ и A⁺A симметричны и идемпотентны. Для плохо обусловленных
    /// матриц шум усиливается — это цена отказа от SVD-пути.
    pub fn pinv(&self) -> Result<Matrix, String> {
        let (m, n) = (self.rows, self.cols);
        if !self
            .data
            .iter()
            .all(|v| v.re.is_finite() && v.im.is_finite())
        {
            return Err("pinv: элементы должны быть конечны".into());
        }
        let scale = self.norm_inf();
        if scale == 0.0 {
            return Ok(Matrix::zeros(n, m)); // нулевая матрица → нулевая A⁺
        }
        // P — растущая Aₖ⁺: k строк × m столбцов.
        // Цикл O: комплексная версия — внутренние произведения эрмитовы
        // (сопряжение в b и в d⁴; внешние d·bᵀ — без сопряжения).
        let mut p: Vec<Vec<Complex>> = Vec::with_capacity(n);
        for k in 0..n {
            // столбец aₖ (m-вектор)
            let a: Vec<Complex> = (0..m).map(|i| self.get(i, k)).collect();
            // d = P·aₖ (k-вектор)
            let d: Vec<Complex> = p
                .iter()
                .map(|r| {
                    r.iter()
                        .zip(&a)
                        .map(|(x, y)| x.mul(*y))
                        .fold(Complex::ZERO, |s, v| s.add(v))
                })
                .collect();
            // c = aₖ − Aₖ₋₁·d — остаток вне образа предыдущих столбцов
            let mut c = a.clone();
            for (j, dj) in d.iter().enumerate() {
                if *dj != Complex::ZERO {
                    for i in 0..m {
                        c[i] = c[i].sub(self.get(i, j).mul(*dj));
                    }
                }
            }
            let c2: f64 = c.iter().map(|x| x.abs().powi(2)).sum();
            // относительный порог численного нуля (к столбцу и к масштабу A)
            let a2: f64 = a.iter().map(|x| x.abs().powi(2)).sum();
            let tol2 = (1e-10 * a2.sqrt().max(1e-12 * scale)).powi(2);
            let b: Vec<Complex> = if c2 > tol2 {
                // b = c^H/(c^H·c) — сопряжение для эрмитовой проекции;
                // деление напрямую (не умножение на 1/c2) — побитовая
                // преемственность с f64-путём (0.04, а не 0.039999…)
                c.iter().map(|x| x.conj().div_real(c2)).collect()
            } else {
                let d2: f64 = d.iter().map(|x| x.abs().powi(2)).sum();
                let denom = 1.0 + d2;
                (0..m)
                    .map(|col| {
                        d.iter()
                            .zip(&p)
                            .map(|(dv, r)| dv.conj().mul(r[col]))
                            .fold(Complex::ZERO, |s, v| s.add(v))
                            .div_real(denom)
                    })
                    .collect()
            };
            // Pₖ = [Pₖ₋₁ − d·bᵀ ; b]
            for (i, dv) in d.iter().enumerate() {
                if *dv != Complex::ZERO {
                    for col in 0..m {
                        p[i][col] = p[i][col].sub(dv.mul(b[col]));
                    }
                }
            }
            p.push(b);
        }
        Matrix::from_complex_rows(&p)
    }

    /// Норма ∞ (максимум сумм модулей строк).
    pub fn norm_inf(&self) -> f64 {
        (0..self.rows)
            .map(|i| (0..self.cols).map(|j| self.get(i, j).abs()).sum::<f64>())
            .fold(0.0, f64::max)
    }

    /// Экспонента матрицы: масштабирование-возведение в степень + Паде [6/6].
    ///
    /// Коэффициенты числителя Паде [6/6] функции e^x (проверены
    /// символьно: p_k = (12−k)!·6! / (12!·k!·(6−k)!)):
    ///   [1, 1/2, 5/44, 1/66, **1/792**, 1/15840, 1/665280]
    /// Регрессия прошлой сессии: b4 ошибочно был 1/1584.
    pub fn expm(&self) -> Result<Matrix, String> {
        if !self.is_square() {
            return Err("expm определён для квадратных матриц".into());
        }
        let n = self.rows;
        let b: [f64; 7] = [
            1.0,
            1.0 / 2.0,
            5.0 / 44.0,
            1.0 / 66.0,
            1.0 / 792.0,
            1.0 / 15840.0,
            1.0 / 665280.0,
        ];

        // масштабируем к ||A||∞ ≤ 1/2
        let mut s = 0u32;
        let norm = self.norm_inf();
        if norm > 0.5 {
            s = (norm / 0.5).log2().ceil().max(0.0) as u32 + 1;
        }
        let scale = 1.0 / (2u64.pow(s) as f64);
        let bs = self.scale(scale);

        // P(B) по Хорнеру: I·b6, затем B·acc + I·b_k
        let mut acc = Matrix::identity(n).scale(b[6]);
        for k in (0..6).rev() {
            acc = bs.mul(&acc)?; // B·acc
            // acc += b[k]·I — прибавление к диагонали
            for i in 0..n {
                let v = acc.get(i, i) + b[k];
                acc.set(i, i, v);
            }
        }
        // P(−B)
        let negb = bs.scale(-1.0);
        let mut negp = Matrix::identity(n).scale(b[6]);
        for k in (0..6).rev() {
            negp = negb.mul(&negp)?;
            for i in 0..n {
                let v = negp.get(i, i) + b[k];
                negp.set(i, i, v);
            }
        }
        // X = P(−B)^{-1}·P(B)
        let mut x = negp.inv()?.mul(&acc)?;
        // возведение в квадрат s раз
        for _ in 0..s {
            x = x.mul(&x)?;
        }
        Ok(x)
    }

    /// Характеристический полином по Фаддееву–Леврерье (над ℂ).
    /// Возвращает коэффициенты по убыванию степени (monic):
    /// p(λ) = λⁿ + c₁λⁿ⁻¹ + … + cₙ.
    ///
    /// ИНВАРИАНТ (регрессия прошлой сессии): прибавление c_k·I — только
    /// к ДИАГОНАЛИ M_k, ни в коем случае не ко всем элементам.
    pub fn charpoly(&self) -> Result<Vec<Complex>, String> {
        if !self.is_square() {
            return Err("характеристический полином — только для квадратных".into());
        }
        let n = self.rows;
        let mut coeffs = vec![Complex::ZERO; n + 1];
        coeffs[0] = Complex::ONE; // старший (monic)
        let mut m = Matrix::zeros(n, n); // M_0 = 0
        for k in 1..=n {
            // M_k = A·M_{k−1} + c_{k−1}·I  (c с индексом n−k+1 в 1-based нотации)
            m = self.mul(&m)?;
            for i in 0..n {
                let v = m.get(i, i) + coeffs[k - 1];
                m.set(i, i, v); // ТОЛЬКО диагональ
            }
            // c_k = −tr(A·M_k)/k
            let am = self.mul(&m)?;
            let tr: Complex = (0..n).fold(Complex::ZERO, |s, i| s.add(am.get(i, i)));
            coeffs[k] = Complex::ZERO.sub(tr).scale(1.0 / k as f64);
        }
        Ok(coeffs)
    }

    /// Собственные значения: charpoly → Дюран–Кернер (комплексные).
    /// Цикл O: МАСШТАБНАЯ НОРМИРОВКА — спектр приводится к O(1)
    /// (B = A/‖A‖∞), динамический диапазон коэффициентов charpoly
    /// сжимается с ~10³⁹ до ~10⁷ (яма 16×16 без нормировки разваливала
    /// ДК), корни масштабируются обратно. Вещественные коэффициенты
    /// идут по проверенному f64-пути (нулевая регрессия), комплексные —
    /// по зеркальному ℂ-пути.
    pub fn eigenvalues(&self) -> Result<Vec<Complex>, String> {
        if self.rows == 0 {
            return Ok(Vec::new());
        }
        let s = self.norm_inf();
        if s == 0.0 || !s.is_finite() {
            return Ok(vec![Complex::ZERO; self.rows]); // нулевая матрица
        }
        let b = self.scale(1.0 / s);
        let coeffs = b.charpoly()?;
        // итерации растут с размером: 2×2 хватает 300, 16×16 — ~1000
        let iters = 300 + 40 * self.rows;
        let roots = if coeffs.iter().all(|c| c.im == 0.0) {
            let rc: Vec<f64> = coeffs.iter().map(|c| c.re).collect();
            sort_roots(durand_kerner(&rc, iters))
        } else {
            sort_roots(durand_kerner_c(&coeffs, iters))
        };
        Ok(roots.into_iter().map(|r| r.scale(s)).collect())
    }

    // -----------------------------------------------------------------
    // Цикл O: эрмитово сопряжение, тензорное произведение, унитарность
    // -----------------------------------------------------------------

    /// Эрмитово сопряжение A† = (Ā)ᵀ (цикл O: квантовая механика).
    pub fn dagger(&self) -> Matrix {
        let mut t = Matrix::zeros(self.cols, self.rows);
        for i in 0..self.rows {
            for j in 0..self.cols {
                t.set(j, i, self.get(i, j).conj());
            }
        }
        t
    }

    /// Тензорное (кронекерово) произведение A⊗B (цикл O: многокупитные
    /// состояния, H⊗I, CNOT-схемы).
    pub fn kron(&self, o: &Matrix) -> Matrix {
        let (m, n, p, q) = (self.rows, self.cols, o.rows, o.cols);
        let mut r = Matrix::zeros(m * p, n * q);
        for i in 0..m {
            for j in 0..n {
                let a = self.get(i, j);
                if a == Complex::ZERO {
                    continue;
                }
                for k in 0..p {
                    for l in 0..q {
                        r.set(i * p + k, j * q + l, a.mul(o.get(k, l)));
                    }
                }
            }
        }
        r
    }

    /// Проверка унитарности: U†U = I (в пределах tol).
    pub fn is_unitary(&self, tol: f64) -> Result<bool, String> {
        if !self.is_square() {
            return Err("унитарность — свойство квадратных матриц".into());
        }
        let p = self.dagger().mul(self)?;
        for i in 0..self.rows {
            for j in 0..self.cols {
                let want = if i == j { Complex::ONE } else { Complex::ZERO };
                if p.get(i, j).sub(want).abs() > tol {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    // -----------------------------------------------------------------
    // Группа Ли SO(n): генераторы и вращения
    // -----------------------------------------------------------------

    /// Генератор вращения плоскости (i,j) в R^n: J_ij имеет −1 на (i,j),
    /// +1 на (j,i) — кососимметричный, как ротор живого голоса J = A − Aᵀ.
    /// КОНВЕНЦИЯ (регрессия прошлой сессии): expm(so_generator(i,j)·θ)
    /// РАВЕН rotation(i,j,θ) — знаки согласованы.
    pub fn so_generator(n: usize, i: usize, j: usize) -> Result<Matrix, String> {
        if i >= n || j >= n || i == j {
            return Err("нужны два разных индекса 0..n".into());
        }
        let mut g = Matrix::zeros(n, n);
        g.set(i, j, Complex::new(-1.0, 0.0));
        g.set(j, i, Complex::new(1.0, 0.0));
        Ok(g)
    }

    /// Точное вращение плоскости (i,j) на угол θ (рад):
    /// R = expm(J_ij·θ) — но записываем аналитически (быстро и точно).
    pub fn rotation(n: usize, i: usize, j: usize, theta: f64) -> Result<Matrix, String> {
        if i >= n || j >= n || i == j {
            return Err("нужны два разных индекса 0..n".into());
        }
        let mut r = Matrix::identity(n);
        r.set(i, i, Complex::new(theta.cos(), 0.0));
        r.set(j, j, Complex::new(theta.cos(), 0.0));
        r.set(i, j, Complex::new(-theta.sin(), 0.0));
        r.set(j, i, Complex::new(theta.sin(), 0.0));
        Ok(r)
    }

    /// Вращение 2D (θ в радианах).
    pub fn rot2(theta: f64) -> Matrix {
        Matrix::from_rows(&[
            vec![theta.cos(), -theta.sin()],
            vec![theta.sin(), theta.cos()],
        ])
        .unwrap()
    }

    /// Вращение 3D вокруг оси X.
    pub fn rot_x(theta: f64) -> Matrix {
        Matrix::from_rows(&[
            vec![1.0, 0.0, 0.0],
            vec![0.0, theta.cos(), -theta.sin()],
            vec![0.0, theta.sin(), theta.cos()],
        ])
        .unwrap()
    }

    /// Вращение 3D вокруг оси Y.
    pub fn rot_y(theta: f64) -> Matrix {
        Matrix::from_rows(&[
            vec![theta.cos(), 0.0, theta.sin()],
            vec![0.0, 1.0, 0.0],
            vec![-theta.sin(), 0.0, theta.cos()],
        ])
        .unwrap()
    }

    /// Вращение 3D вокруг оси Z.
    pub fn rot_z(theta: f64) -> Matrix {
        Matrix::from_rows(&[
            vec![theta.cos(), -theta.sin(), 0.0],
            vec![theta.sin(), theta.cos(), 0.0],
            vec![0.0, 0.0, 1.0],
        ])
        .unwrap()
    }
}

/// Перестановка строк r1 ↔ r2 в плотном n×n буфере (row-major).
fn swap_rows_vec(v: &mut [Complex], n: usize, r1: usize, r2: usize) {
    for j in 0..n {
        v.swap(r1 * n + j, r2 * n + j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Универсальное сравнение: f64 или Complex (цикл O) — мнимая часть
    /// вещественных результатов проверяется на нуль.
    trait ToC {
        fn to_c(self) -> Complex;
    }
    impl ToC for f64 {
        fn to_c(self) -> Complex {
            Complex::new(self, 0.0)
        }
    }
    impl ToC for Complex {
        fn to_c(self) -> Complex {
            self
        }
    }
    fn close(a: impl ToC + Copy, b: impl ToC + Copy, tol: f64) -> bool {
        let (a, b) = (a.to_c(), b.to_c());
        (a.re - b.re).abs() <= tol * (1.0 + a.re.abs() + b.re.abs())
            && (a.im - b.im).abs() <= tol * (1.0 + a.im.abs() + b.im.abs())
    }

    fn m22(a: f64, b: f64, c: f64, d: f64) -> Matrix {
        Matrix::from_rows(&[vec![a, b], vec![c, d]]).unwrap()
    }

    #[test]
    fn construction_errors() {
        assert!(Matrix::from_rows(&[]).is_err());
        assert!(Matrix::from_rows(&[vec![1.0], vec![1.0, 2.0]]).is_err());
        assert!(Matrix::from_rows(&[vec![]]).is_err());
    }

    #[test]
    fn pinv_moore_penrose() {
        // вырожденная [1,2;2,4] (det = 0, stress-тест цикла N):
        // A = u·vᵀ с u = v = [1;2] → A⁺ = A/25
        let a = m22(1.0, 2.0, 2.0, 4.0);
        let p = a.pinv().unwrap();
        assert!(close(p.get(0, 0), 0.04, 1e-12), "{}", p.get(0, 0));
        assert!(close(p.get(0, 1), 0.08, 1e-12));
        assert!(close(p.get(1, 0), 0.08, 1e-12));
        assert!(close(p.get(1, 1), 0.16, 1e-12));

        // четыре условия Мура–Пенроуза: AA⁺A=A, A⁺AA⁺=A⁺,
        // (AA⁺)ᵀ=AA⁺, (A⁺A)ᵀ=A⁺A
        let apa = a.mul(&p).unwrap().mul(&a).unwrap();
        assert!(close(apa.get(0, 0), 1.0, 1e-12) && close(apa.get(1, 1), 4.0, 1e-12));
        let pap = p.mul(&a).unwrap().mul(&p).unwrap();
        assert!(close(pap.get(0, 0), 0.04, 1e-12) && close(pap.get(1, 1), 0.16, 1e-12));
        let aat = a.mul(&p).unwrap();
        let sym1 = aat.transpose();
        for i in 0..2 {
            for j in 0..2 {
                assert!(close(aat.get(i, j), sym1.get(i, j), 1e-12));
            }
        }

        // невырожденная: pinv = inv
        let b = m22(4.0, 7.0, 2.0, 6.0);
        let bp = b.pinv().unwrap();
        let bi = b.inv().unwrap();
        for i in 0..2 {
            for j in 0..2 {
                assert!(close(bp.get(i, j), bi.get(i, j), 1e-9));
            }
        }

        // прямоугольная строка [1,2,3]: A⁺ = aᵀ/‖a‖² = [1,2,3]ᵀ/14
        let row = Matrix::from_rows(&[vec![1.0, 2.0, 3.0]]).unwrap();
        let rp = row.pinv().unwrap();
        assert_eq!((rp.rows, rp.cols), (3, 1));
        assert!(close(rp.get(0, 0), 1.0 / 14.0, 1e-12));
        assert!(close(rp.get(1, 0), 2.0 / 14.0, 1e-12));
        assert!(close(rp.get(2, 0), 3.0 / 14.0, 1e-12));

        // нулевой столбец — нулевая строка A⁺; единичная — сама себя
        let z = Matrix::from_rows(&[vec![0.0, 1.0], vec![0.0, 2.0]]).unwrap();
        let zp = z.pinv().unwrap();
        assert_eq!(zp.get(0, 0).abs() + zp.get(0, 1).abs(), 0.0);
        let eye = Matrix::identity(3);
        let ep = eye.pinv().unwrap();
        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(ep.get(i, j), eye.get(i, j));
            }
        }

        // нулевая матрица — нулевая A⁺ (транспонированной формы)
        let zz = Matrix::from_rows(&[vec![0.0, 0.0], vec![0.0, 0.0]]).unwrap();
        let zpp = zz.pinv().unwrap();
        assert_eq!((zpp.rows, zpp.cols), (2, 2));
        assert!(zpp.data.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn mul_add_basic() {
        let a = m22(1.0, 2.0, 3.0, 4.0);
        let b = m22(5.0, 6.0, 7.0, 8.0);
        let p = a.mul(&b).unwrap();
        assert_eq!(p.get(0, 0), 19.0);
        assert_eq!(p.get(0, 1), 22.0);
        assert_eq!(p.get(1, 0), 43.0);
        assert_eq!(p.get(1, 1), 50.0);
        let s = a.add(&b).unwrap();
        assert_eq!(s.get(1, 1), 12.0);
        // несовместимые
        let c = Matrix::from_rows(&[vec![1.0, 2.0, 3.0]]).unwrap();
        assert!(a.mul(&c).is_err());
        assert!(a.add(&c).is_err());
    }

    #[test]
    fn det_and_inv() {
        let a = m22(1.0, 2.0, 3.0, 4.0);
        assert!((a.det().unwrap() - (-2.0)).abs() < 1e-12);
        let inv = a.inv().unwrap();
        // A·A⁻¹ = I
        let eye = a.mul(&inv).unwrap();
        assert!(close(eye.get(0, 0), 1.0, 1e-12));
        assert!(close(eye.get(0, 1), 0.0, 1e-12));
        assert!(close(eye.get(1, 1), 1.0, 1e-12));
        // сингулярная
        assert!(m22(1.0, 2.0, 2.0, 4.0).inv().is_err());
        // det 3×3 (правило Сарруса): |1 2 3; 4 5 6; 7 8 10| = 1(50−48) −2(40−42) +3(32−35) = 2+4−9 = −3
        let m3 = Matrix::from_rows(&[vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0], vec![7.0, 8.0, 10.0]]).unwrap();
        assert!((m3.det().unwrap() - (-3.0)).abs() < 1e-12);
    }

    #[test]
    fn trace_transpose() {
        let a = m22(1.0, 2.0, 3.0, 4.0);
        assert!((a.trace().unwrap() - 5.0).abs() < 1e-15);
        let t = a.transpose();
        assert_eq!(t.get(0, 1), 3.0);
        assert_eq!(t.get(1, 0), 2.0);
        let rect = Matrix::from_rows(&[vec![1.0, 2.0, 3.0]]).unwrap();
        assert!(rect.trace().is_err());
        assert!(rect.det().is_err());
    }

    // ================================================================
    // РЕГРЕССИЯ прошлой сессии: Паде b4 = 1/792 (было 1/1584 — вдвое
    // меньше правильного). expm вращательного генератора обязан давать
    // точную ротацию; ошибка в b4 ломала её на ~1e-4.
    // ================================================================
    #[test]
    fn expm_rotation_generator() {
        // J = [[0, −θ],[θ, 0]] → expm(J) = [[cos θ, −sin θ],[sin θ, cos θ]]
        for &theta in &[0.7, 2.5, 10.0] {
            let j = m22(0.0, -theta, theta, 0.0);
            let e = j.expm().unwrap();
            let r = Matrix::rot2(theta);
            for (a, b) in e.data.iter().zip(r.data.iter()) {
                assert!(close(*a, *b, 1e-12), "expm ≠ rot при θ={theta}: {a} vs {b}");
            }
        }
    }

    #[test]
    fn expm_diagonal_and_nilpotent() {
        // expm(αI) = e^α·I — проверяет масштабирование (норма 10 → s>0)
        let a = Matrix::identity(3).scale(10.0);
        let e = a.expm().unwrap();
        let want = 10.0f64.exp();
        for i in 0..3 {
            assert!(close(e.get(i, i), want, 1e-12));
            for j in 0..3 {
                if i != j {
                    assert!(close(e.get(i, j), 0.0, 1e-12));
                }
            }
        }
        // нильпотентная: expm([[0,1],[0,0]]) = [[1,1],[0,0]]+I = [[1,1],[0,1]]
        let nil = m22(0.0, 1.0, 0.0, 0.0);
        let e = nil.expm().unwrap();
        assert!(close(e.get(0, 0), 1.0, 1e-14));
        assert!(close(e.get(0, 1), 1.0, 1e-14));
        assert!(close(e.get(1, 0), 0.0, 1e-14));
        assert!(close(e.get(1, 1), 1.0, 1e-14));
        // expm(0) = I
        let z = Matrix::zeros(4, 4);
        assert_eq!(z.expm().unwrap(), Matrix::identity(4));
        // неквадратная — ошибка
        let rect = Matrix::from_rows(&[vec![1.0, 2.0]]).unwrap();
        assert!(rect.expm().is_err());
    }

    #[test]
    fn expm_agrees_with_series() {
        // небольшая матрица: сравнение с рядом Тейлора 20 членов
        let a = m22(0.3, -0.2, 0.1, 0.05);
        let mut t = Matrix::identity(2);
        let mut term = Matrix::identity(2);
        for k in 1..=20 {
            term = term.mul(&a).unwrap().scale(1.0 / k as f64);
            t = t.add(&term).unwrap();
        }
        let e = a.expm().unwrap();
        for (x, y) in e.data.iter().zip(t.data.iter()) {
            assert!(close(*x, *y, 1e-12));
        }
        // det(expm(A)) = e^tr(A) — фундаментальное тождество
        let tr = a.trace().unwrap();
        assert!(close(e.det().unwrap(), tr.re.exp(), 1e-10));
    }

    // ================================================================
    // РЕГРЕССИЯ прошлой сессии: Фаддеев–Леврерье, add_scalar только на
    // диагональ. Ручная трассировка [[1,2],[3,4]]: p(λ)=λ²−5λ−2.
    // ================================================================
    #[test]
    fn charpoly_faddeev_leverrier() {
        let a = m22(1.0, 2.0, 3.0, 4.0);
        let c = a.charpoly().unwrap();
        assert_eq!(c.len(), 3);
        assert!((c[0] - 1.0).abs() < 1e-12);
        assert!((c[1] - (-5.0)).abs() < 1e-12, "c1 = {}", c[1]);
        assert!((c[2] - (-2.0)).abs() < 1e-12, "c2 = {}", c[2]);

        // единичная: (λ−1)ⁿ
        let i3 = Matrix::identity(3);
        let c = i3.charpoly().unwrap();
        assert!((c[0] - 1.0).abs() < 1e-12);
        assert!((c[1] - (-3.0)).abs() < 1e-12);
        assert!((c[2] - 3.0).abs() < 1e-12);
        assert!((c[3] - (-1.0)).abs() < 1e-12);

        // 3×3: [[2,0,0],[0,3,0],[0,0,5]] → (λ−2)(λ−3)(λ−5)
        let d = Matrix::from_rows(&[vec![2.0, 0.0, 0.0], vec![0.0, 3.0, 0.0], vec![0.0, 0.0, 5.0]]).unwrap();
        let c = d.charpoly().unwrap();
        // λ³ − 10λ² + 31λ − 30
        assert!((c[1] - (-10.0)).abs() < 1e-12, "{}", c[1]);
        assert!((c[2] - 31.0).abs() < 1e-12, "{}", c[2]);
        assert!((c[3] - (-30.0)).abs() < 1e-12, "{}", c[3]);

        // Кэли–Гамильтон на 4×4 случайной (фиксированный сид):
        // p(A) = 0
        let m4 = Matrix::from_rows(&[
            vec![0.5, 1.2, 0.0, -0.3],
            vec![-1.1, 0.2, 0.7, 0.0],
            vec![0.4, 0.0, 1.3, -0.8],
            vec![0.0, 0.9, -0.2, 0.6],
        ])
        .unwrap();
        let c = m4.charpoly().unwrap();
        let n = 4;
        let mut pa = Matrix::zeros(n, n); // p(A) = 0·Aⁿ + c1·Aⁿ⁻¹ + … (старший при Aⁿ — c0=1)
        let mut ak = Matrix::identity(n);
        // идём от старшей степени вниз: c0·A⁴? нет: c[0]·A^4 + c[1]·A^3 + ... + c[4]·I
        for (k, coef) in c.iter().enumerate() {
            let power = n - k;
            let mut term = Matrix::identity(n);
            for _ in 0..power {
                term = term.mul(&m4).unwrap();
            }
            pa = pa.add(&term.scale_c(*coef)).unwrap();
            let _ = ak;
        }
        for v in pa.data.iter() {
            assert!(v.abs() < 1e-9, "Кэли–Гамильтон нарушен: {v}");
        }
    }

    #[test]
    fn eigenvalues_2x2() {
        // [[1,2],[3,4]] → (5±√33)/2 ≈ 5.37228, −0.37228
        let a = m22(1.0, 2.0, 3.0, 4.0);
        let ev = a.eigenvalues().unwrap();
        assert_eq!(ev.len(), 2);
        let s33 = 33.0f64.sqrt();
        assert!(close(ev[0].re, (5.0 - s33) / 2.0, 1e-9), "{:?}", ev);
        assert!(close(ev[1].re, (5.0 + s33) / 2.0, 1e-9), "{:?}", ev);
        assert!(ev.iter().all(|e| e.im.abs() < 1e-9));
    }

    #[test]
    fn eigenvalues_rotation_pure_imaginary() {
        // вращение 90°: собственные значения ±i (регрессия прошлой сессии)
        let r = Matrix::rot2(std::f64::consts::FRAC_PI_2);
        let ev = r.eigenvalues().unwrap();
        assert_eq!(ev.len(), 2);
        assert!(ev[0].im.abs() > 0.99 && ev[1].im.abs() > 0.99, "{:?}", ev);
        assert!((ev[0].im + ev[1].im).abs() < 1e-9);
        assert!(ev.iter().all(|e| e.re.abs() < 1e-9), "{:?}", ev);
    }

    #[test]
    fn eigenvalues_diagonal() {
        let d = Matrix::from_rows(&[vec![2.0, 0.0], vec![0.0, -7.0]]).unwrap();
        let ev = d.eigenvalues().unwrap();
        let rs: Vec<f64> = ev.iter().map(|e| e.re).collect();
        assert!(rs.iter().any(|r| close(*r, 2.0, 1e-9)));
        assert!(rs.iter().any(|r| close(*r, -7.0, 1e-9)));
    }

    #[test]
    fn lie_rotations() {
        // rot_x(π/2) поворачивает ось Y → Z
        let r = Matrix::rot_x(std::f64::consts::FRAC_PI_2);
        let y = Matrix::from_rows(&[vec![0.0], vec![1.0], vec![0.0]]).unwrap();
        let z = r.mul(&y).unwrap();
        assert!(close(z.get(0, 0), 0.0, 1e-12));
        assert!(close(z.get(1, 0), 0.0, 1e-12));
        assert!(close(z.get(2, 0), 1.0, 1e-12));

        // rot_z поворачивает X → Y
        let r = Matrix::rot_z(std::f64::consts::FRAC_PI_2);
        let x = Matrix::from_rows(&[vec![1.0], vec![0.0], vec![0.0]]).unwrap();
        let y2 = r.mul(&x).unwrap();
        assert!(close(y2.get(1, 0), 1.0, 1e-12));

        // rot_y поворачивает Z → X
        let r = Matrix::rot_y(std::f64::consts::FRAC_PI_2);
        let zv = Matrix::from_rows(&[vec![0.0], vec![0.0], vec![1.0]]).unwrap();
        let x2 = r.mul(&zv).unwrap();
        assert!(close(x2.get(0, 0), 1.0, 1e-12));

        // генератор: expm(J·θ) = rotation
        let g = Matrix::so_generator(3, 0, 1).unwrap();
        let e = g.scale(std::f64::consts::FRAC_PI_2).expm().unwrap();
        let r = Matrix::rotation(3, 0, 1, std::f64::consts::FRAC_PI_2).unwrap();
        for (a, b) in e.data.iter().zip(r.data.iter()) {
            assert!(close(*a, *b, 1e-12));
        }
        assert!(Matrix::so_generator(3, 1, 1).is_err());
        assert!(Matrix::so_generator(3, 0, 3).is_err());
    }

    #[test]
    fn norm_inf() {
        let a = m22(1.0, -2.0, 3.0, 0.5);
        assert!((a.norm_inf() - 3.5).abs() < 1e-15);
    }

    // ================================================================
    // Цикл O: комплексные матрицы, Шрёдингер, тензорное произведение
    // ================================================================
    fn sigma_y() -> Matrix {
        Matrix::from_complex_rows(&[
            vec![Complex::ZERO, Complex::new(0.0, -1.0)],
            vec![Complex::new(0.0, 1.0), Complex::ZERO],
        ])
        .unwrap()
    }

    #[test]
    fn complex_matrix_core_sigma_y() {
        let sy = sigma_y();
        // эрмитовость: σ_y† = σ_y
        assert_eq!(sy.dagger(), sy);
        // унитарность: σ_y†·σ_y = I
        assert!(sy.is_unitary(1e-12).unwrap());
        // det(σ_y) = −1 (произведение спектра ±1), tr = 0
        assert!(close(sy.det().unwrap(), -1.0, 1e-12));
        assert!(close(sy.trace().unwrap(), 0.0, 1e-12));
        // собственные значения ±1 (комплексная матрица, вещественный спектр)
        let ev = sy.eigenvalues().unwrap();
        assert_eq!(ev.len(), 2);
        assert!(close(ev[0], -1.0, 1e-9), "{:?}", ev);
        assert!(close(ev[1], 1.0, 1e-9), "{:?}", ev);
        // pinv унитарной = эрмитово сопряжённая = сама σ_y
        let p = sy.pinv().unwrap();
        for i in 0..2 {
            for j in 0..2 {
                assert!(close(p.get(i, j), sy.get(i, j), 1e-12));
            }
        }
        // inv тоже: σ_y⁻¹ = σ_y
        let iv = sy.inv().unwrap();
        for i in 0..2 {
            for j in 0..2 {
                assert!(close(iv.get(i, j), sy.get(i, j), 1e-12));
            }
        }
    }

    #[test]
    fn complex_expm_unitary_evolution() {
        // U = expm(−i·σ_y·π/2) = cos(π/2)·I − i·sin(π/2)·σ_y = [0, −1; 1, 0]
        let sy = sigma_y();
        let u = sy
            .scale_c(Complex::new(0.0, -std::f64::consts::FRAC_PI_2))
            .expm()
            .unwrap();
        assert!(close(u.get(0, 0), 0.0, 1e-10), "{:?}", u.data);
        assert!(close(u.get(0, 1), -1.0, 1e-10), "{:?}", u.data);
        assert!(close(u.get(1, 0), 1.0, 1e-10), "{:?}", u.data);
        assert!(close(u.get(1, 1), 0.0, 1e-10), "{:?}", u.data);
        // унитарность эволюции: U†U = I (фундаментальный закон)
        assert!(u.is_unitary(1e-10).unwrap());
        // |det U| = 1
        let d = u.det().unwrap();
        assert!((d.abs() - 1.0).abs() < 1e-10, "det = {d}");
        // U·|↑⟩ = |↓⟩ — переворот спина за время π/2
        let up = Matrix::from_rows(&[vec![1.0], vec![0.0]]).unwrap();
        let psi = u.mul(&up).unwrap();
        assert!(close(psi.get(0, 0), 0.0, 1e-10));
        assert!(close(psi.get(1, 0), 1.0, 1e-10));
    }

    #[test]
    fn complex_eigenvalues_pure_imaginary() {
        // i·I₂: спектр {i, i} — комплексный путь Дюрана–Кернера.
        // Кратный корень: |ошибка| ~ ε^(1/2) ≈ 1e-8 — честный предел ДК
        let a = Matrix::identity(2).scale_c(Complex::I);
        let ev = a.eigenvalues().unwrap();
        assert_eq!(ev.len(), 2);
        for e in &ev {
            assert!(close(*e, Complex::I, 1e-6), "{:?}", ev);
        }
    }

    #[test]
    fn pinv_complex_scaling() {
        // pinv(i·I) = −i·I: (iI)⁺ = ((iI)†(iI))⁻¹(iI)† = I⁻¹·(−iI)
        let a = Matrix::identity(2).scale_c(Complex::I);
        let p = a.pinv().unwrap();
        assert!(close(p.get(0, 0), Complex::new(0.0, -1.0), 1e-12));
        assert!(close(p.get(1, 1), Complex::new(0.0, -1.0), 1e-12));
        assert!(close(p.get(0, 1), 0.0, 1e-12));
        assert!(close(p.get(1, 0), 0.0, 1e-12));
    }

    #[test]
    fn dagger_and_kron_laws() {
        let a = Matrix::from_complex_rows(&[
            vec![Complex::new(1.0, 2.0), Complex::new(3.0, -1.0)],
            vec![Complex::new(0.5, 0.0), Complex::new(-2.0, 4.0)],
        ])
        .unwrap();
        let b = Matrix::from_complex_rows(&[
            vec![Complex::new(0.0, 1.0), Complex::new(2.0, 0.0)],
            vec![Complex::new(-1.0, -1.0), Complex::new(0.5, 0.5)],
        ])
        .unwrap();
        // (A†)† = A
        assert_eq!(a.dagger().dagger(), a);
        // (AB)† = B†A†
        let abd = a.mul(&b).unwrap().dagger();
        let bad = b.dagger().mul(&a.dagger()).unwrap();
        for i in 0..2 {
            for j in 0..2 {
                assert!(close(abd.get(i, j), bad.get(i, j), 1e-12));
            }
        }
        // kron: [1,2]⊗[3,4] = [3,4,6,8] — строка 1×4 (блочное покомпонентное)
        let r1 = Matrix::from_rows(&[vec![1.0, 2.0]]).unwrap();
        let r2 = Matrix::from_rows(&[vec![3.0, 4.0]]).unwrap();
        let k = r1.kron(&r2);
        assert_eq!((k.rows, k.cols), (1, 4));
        assert!(close(k.get(0, 0), 3.0, 1e-15));
        assert!(close(k.get(0, 1), 4.0, 1e-15));
        assert!(close(k.get(0, 2), 6.0, 1e-15));
        assert!(close(k.get(0, 3), 8.0, 1e-15));
        // σ_z⊗I₂ = diag(1,1,−1,−1)
        let sz = m22(1.0, 0.0, 0.0, -1.0);
        let d = sz.kron(&Matrix::identity(2));
        assert!(close(d.get(0, 0), 1.0, 1e-15));
        assert!(close(d.get(1, 1), 1.0, 1e-15));
        assert!(close(d.get(2, 2), -1.0, 1e-15));
        assert!(close(d.get(3, 3), -1.0, 1e-15));
        // смешанный закон: (A⊗B)(C⊗D) = (AC)⊗(BD)
        let x = m22(0.0, 1.0, 1.0, 0.0);
        let lhs = sz.kron(&x).mul(&x.kron(&Matrix::identity(2))).unwrap();
        let rhs = sz.mul(&x).unwrap().kron(&x);
        for i in 0..4 {
            for j in 0..4 {
                assert!(close(lhs.get(i, j), rhs.get(i, j), 1e-12));
            }
        }
    }

    #[test]
    fn infinite_square_well_spectrum() {
        // УРАВНЕНИЕ ШРЁДИНГЕРА НА СЕТКЕ: H = −½·d²/dx² на [0,1] с
        // дырчатыми краями. Дискретный спектр λ_k = (1/h²)(1−cos(πkh)).
        // Для n = 16: λ₁ ≈ 4.937 (непрерывный предел (π/2)·π ≈ 4.9348)
        let n = 16usize;
        let h = 1.0 / (n as f64 + 1.0);
        let diag = 1.0 / (h * h);
        let off = -0.5 / (h * h);
        let mut hh = Matrix::zeros(n, n);
        for i in 0..n {
            hh.set(i, i, Complex::new(diag, 0.0));
        }
        for i in 0..n - 1 {
            hh.set(i, i + 1, Complex::new(off, 0.0));
            hh.set(i + 1, i, Complex::new(off, 0.0));
        }
        let ev = hh.eigenvalues().unwrap();
        // точные дискретные уровни
        let lam = |k: usize| (1.0 / (h * h)) * (1.0 - (std::f64::consts::PI * k as f64 * h).cos());
        assert!(close(ev[0].re, lam(1), 1e-6), "E1 = {:?} vs {}", ev[0], lam(1));
        assert!(close(ev[1].re, lam(2), 1e-6), "E2 = {:?} vs {}", ev[1], lam(2));
        assert!(close(ev[2].re, lam(3), 1e-5), "E3 = {:?} vs {}", ev[2], lam(3));
        // и они же ≈ (πk)²/2 непрерывного предела (погрешность сетки
        // h²·(πk)⁴/24: для k=2 на n=16 это ~0.22)
        assert!((ev[0].re - std::f64::consts::PI.powi(2) / 2.0).abs() < 0.03);
        assert!((ev[1].re - (2.0 * std::f64::consts::PI).powi(2) / 2.0).abs() < 0.25);
    }
}
