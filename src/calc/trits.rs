//! Триты POLER — сбалансированная троичная арифметика (цикл M, v0.48.0).
//!
//! Цифры {−1, 0, +1} (тритная щель живого голоса, цикл K). Диапазон
//! n-тритного числа: ±(3ⁿ−1)/2.
//!
//! РЕГРЕССИЯ прошлой сессии: вычитание/перенос. При сумме цифр вне
//! диапазона перенос определяется через ОСТАТОК: sum = 3·carry + digit,
//! где digit ∈ {−1,0,+1}: sum=2 → digit=−1, carry=+1; sum=−2 → digit=+1,
//! carry=−1. Прошлая версия теряла заём при остатке +2.

/// Значение одного трита.
pub type Trit = i8; // −1 | 0 | +1

/// Число в сбалансированной троичной записи.
/// `digits[0]` — СТАРШАЯ цифра (человекочитательный порядок), без ведущих нулей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trits {
    pub digits: Vec<Trit>,
}

impl Trits {
    /// Ноль (пустая запись).
    pub fn zero() -> Self {
        Trits { digits: vec![0] }
    }

    /// Из целого со знаком (|v| ≤ (3^24−1)/2).
    pub fn from_i64(v: i64) -> Result<Self, String> {
        if v == 0 {
            return Ok(Self::zero());
        }
        let mut n = v;
        let mut rev: Vec<Trit> = Vec::new(); // младшие в конце… нет: пишем с младшей
        let mut guard = 0;
        while n != 0 {
            let r = n.rem_euclid(3); // {0,1,2} всегда (усечённый % давал −2 → unreachable)
            match r {
                0 => {
                    rev.push(0);
                    n /= 3;
                }
                1 => {
                    rev.push(1);
                    n = (n - 1) / 3;
                }
                _ => {
                    // 2 ≡ −1 (mod 3): цифра −1, перенос +1
                    rev.push(-1);
                    n = (n + 1) / 3;
                }
            }
            guard += 1;
            if guard > 40 {
                return Err("trits: переполнение разрядности".into());
            }
        }
        rev.reverse(); // старшая — первой
        Ok(Trits { digits: rev })
    }

    /// В целое со знаком.
    pub fn to_i64(&self) -> i64 {
        let mut v: i64 = 0;
        for &d in &self.digits {
            v = v * 3 + d as i64;
        }
        v
    }

    /// Количество значащих тритов.
    pub fn len(&self) -> usize {
        self.digits.len()
    }
    pub fn is_zero(&self) -> bool {
        self.digits.iter().all(|&d| d == 0)
    }

    /// Унарный минус (поразрядная инверсия).
    pub fn neg(&self) -> Self {
        Trits { digits: self.digits.iter().map(|&d| -d).collect() }
    }

    /// Сложение с правильными переносами.
    pub fn add(&self, other: &Trits) -> Result<Trits, String> {
        let n = self.len().max(other.len()) + 1;
        let mut rev: Vec<Trit> = Vec::with_capacity(n);
        let mut carry: i32 = 0;
        for i in 0..n {
            let s = digit_from_end(&self.digits, i) + digit_from_end(&other.digits, i) + carry;
            let (digit, c) = balance(s);
            rev.push(digit);
            carry = c;
        }
        if carry != 0 {
            rev.push(carry as Trit);
        }
        rev.reverse();
        Ok(Trits { digits: trim(&rev) })
    }

    /// Вычитание: a + (−b).
    pub fn sub(&self, other: &Trits) -> Result<Trits, String> {
        self.add(&other.neg())
    }

    /// Умножение школьное.
    pub fn mul(&self, other: &Trits) -> Result<Trits, String> {
        let mut acc = Trits::zero();
        let nb = other.len();
        for (shift, &bd) in other.digits.iter().enumerate() {
            if bd == 0 {
                continue;
            }
            // сдвиг влево = умножение на 3^pad: нули ДОПИСЫВАЮТСЯ в конец
            // (младшая сторона); версия с нулями в начале теряла сдвиг
            let pad = nb - 1 - shift;
            let mut shifted = self.digits.clone();
            shifted.extend(std::iter::repeat(0).take(pad));
            let term = Trits { digits: shifted };
            let t = if bd == 1 { term } else { term.neg() };
            acc = acc.add(&t)?;
        }
        Ok(acc)
    }

    /// Тритные вентили Клини (поразрядные): T=ложь, 0=неизвестно, 1=истина.
    /// AND = min, OR = max, NOT = инверсия. Выравнивание — по младшему
    /// разряду, старшие добираются нулями.
    pub fn t_and(a: &Trits, b: &Trits) -> Trits {
        let n = a.len().max(b.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let x = digit_from_end(&a.digits, i);
            let y = digit_from_end(&b.digits, i);
            out.push(x.min(y) as Trit);
        }
        out.reverse();
        Trits { digits: trim(&out) }
    }

    /// OR = max (трёхзначная логика Клини).
    pub fn t_or(a: &Trits, b: &Trits) -> Trits {
        let n = a.len().max(b.len());
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let x = digit_from_end(&a.digits, i);
            let y = digit_from_end(&b.digits, i);
            out.push(x.max(y) as Trit);
        }
        out.reverse();
        Trits { digits: trim(&out) }
    }

    /// NOT = поразрядная инверсия (совпадает с арифметическим минусом).
    pub fn t_not(a: &Trits) -> Trits {
        a.neg()
    }

    /// Отображение: старшая цифра слева, −1 → 'T', 0 → '0', +1 → '1'.
    pub fn to_string_bal(&self) -> String {
        self.digits
            .iter()
            .map(|&d| match d {
                -1 => 'T',
                0 => '0',
                _ => '1',
            })
            .collect()
    }

    /// Разбор из строки "1T0…" (T/N = −1; допускается 'N').
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut digits = Vec::with_capacity(s.len());
        for (i, ch) in s.chars().enumerate() {
            let d = match ch {
                '1' | '+' => 1,
                '0' => 0,
                'T' | 't' | 'N' | 'n' | '-' => -1,
                other => return Err(format!("символ {other:?} на позиции {} не трит", i + 1)),
            };
            digits.push(d);
        }
        if digits.is_empty() {
            return Err("пустая тритная запись".into());
        }
        Ok(Trits { digits: trim(&digits) })
    }
}

/// Цифра на позиции i при нумерации с МЛАДШЕГО разряда (i = 0 — последний
/// элемент вектора); за пределами записи — 0.
fn digit_from_end(digits: &[Trit], i: usize) -> i32 {
    if i < digits.len() {
        digits[digits.len() - 1 - i] as i32
    } else {
        0
    }
}

/// Приведение суммы цифр к триту + переносу.
/// sum = 3·carry + digit, digit ∈ {−1, 0, +1}.
/// РЕГРЕССИЯ: sum = +2 → digit = −1, carry = +1 (заём!).
fn balance(sum: i32) -> (Trit, i32) {
    match sum {
        -2 => (1, -1),  // −2 = 3·(−1) + 1
        -1 => (-1, 0),
        0 => (0, 0),
        1 => (1, 0),
        2 => (-1, 1),   // 2 = 3·1 + (−1)
        3 => (0, 1),
        -3 => (0, -1),
        4 => (1, 1),
        -4 => (-1, -1),
        _ => (sum.clamp(-1, 1) as Trit, (sum - sum.clamp(-1, 1)) / 3),
    }
}

fn trim(digits: &[Trit]) -> Vec<Trit> {
    if digits.is_empty() {
        return vec![0];
    }
    // срезаем ТОЛЬКО ведущие нули (старшая сторона): «T00» = −9 обязан
    // сохранять хвостовые нули — это младшие значимые разряды
    match digits.iter().position(|&d| d != 0) {
        Some(first) => digits[first..].to_vec(),
        None => vec![0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(v: i64) -> Trits {
        Trits::from_i64(v).unwrap()
    }

    #[test]
    fn roundtrip() {
        for v in [-40, -13, -9, -5, -3, -2, -1, 0, 1, 2, 3, 5, 8, 13, 40, 121] {
            let tr = t(v as i64);
            assert_eq!(tr.to_i64(), v as i64, "roundtrip {v}");
            // повторный парс строки
            let s = tr.to_string_bal();
            assert_eq!(Trits::parse(&s).unwrap().to_i64(), v as i64, "parse {s}");
        }
        // большая разрядность
        let big = (3i64.pow(12) - 1) / 2; // 265720
        assert_eq!(t(big).to_i64(), big);
        assert_eq!(t(-big).to_i64(), -big);
        assert!(Trits::from_i64(3i64.pow(20)).is_err() == false);
    }

    #[test]
    fn known_representations() {
        // 5 = 1T−? вычислим: 5 = 9 − 3 − 1 → 1 T T? 1·9 + (−1)·3 + (−1)·1 = 5 → «1TT»
        assert_eq!(t(5).to_string_bal(), "1TT");
        // 8 = 9 − 1 → «10T»
        assert_eq!(t(8).to_string_bal(), "10T");
        // −4 = −3 − 1 → «TT»
        assert_eq!(t(-4).to_string_bal(), "TT");
        // 6 = 9 − 3 → «10T»? нет: 9−3 = 6 → «1T0»
        assert_eq!(t(6).to_string_bal(), "1T0");
        assert_eq!(t(0).to_string_bal(), "0");
        assert_eq!(t(1).to_string_bal(), "1");
        assert_eq!(t(2).to_string_bal(), "1T");
        assert_eq!(t(3).to_string_bal(), "10");
        assert_eq!(t(4).to_string_bal(), "11");
    }

    // ================================================================
    // РЕГРЕССИЯ прошлой сессии: заём при сумме цифр = 2.
    // 1 + 1 = 2 → «1» + «1» = «1T» (не «2», не «10»).
    // ================================================================
    #[test]
    fn addition_with_borrow() {
        assert_eq!(t(1).add(&t(1)).unwrap().to_i64(), 2);
        assert_eq!(t(1).add(&t(1)).unwrap().to_string_bal(), "1T");
        assert_eq!(t(1).add(&t(1)).unwrap().len(), 2);
        // цепочка переносов: 4 + 1 = 5 («11» + «1» = «1TT»)
        assert_eq!(t(4).add(&t(1)).unwrap().to_string_bal(), "1TT");
        assert_eq!(t(4).add(&t(1)).unwrap().to_i64(), 5);
        // 13 + 13 = 26
        assert_eq!(t(13).add(&t(13)).unwrap().to_i64(), 26);
        // крайние: (3^6−1)/2 = 364; 364 + 364 = 728
        let m = 364;
        assert_eq!(t(m).add(&t(m)).unwrap().to_i64(), 728);
    }

    #[test]
    fn subtraction_with_borrow() {
        // 0 − 1 = −1; 1 − 2 = −1; 5 − 5 = 0
        assert_eq!(t(0).sub(&t(1)).unwrap().to_i64(), -1);
        assert_eq!(t(1).sub(&t(2)).unwrap().to_i64(), -1);
        assert_eq!(t(5).sub(&t(5)).unwrap().to_i64(), 0);
        assert!(t(5).sub(&t(5)).unwrap().is_zero());
        // отрицательный результат с заёмом: 3 − 4 = −1
        assert_eq!(t(3).sub(&t(4)).unwrap().to_i64(), -1);
        // большая разность
        assert_eq!(t(200).sub(&t(-200)).unwrap().to_i64(), 400);
        for (a, b) in [(17, 5), (100, 99), (0, 121), (121, 122)] {
            assert_eq!(t(a).sub(&t(b)).unwrap().to_i64(), a - b, "{a}−{b}");
        }
    }

    #[test]
    fn multiplication() {
        assert_eq!(t(5).mul(&t(7)).unwrap().to_i64(), 35);
        assert_eq!(t(-5).mul(&t(7)).unwrap().to_i64(), -35);
        assert_eq!(t(-5).mul(&t(-7)).unwrap().to_i64(), 35);
        assert_eq!(t(0).mul(&t(99)).unwrap().to_i64(), 0);
        assert_eq!(t(13).mul(&t(13)).unwrap().to_i64(), 169);
        // перемножение через сложение сверяется
        for (a, b) in [(9, 8), (20, 20), (121, 3), (7, 13)] {
            assert_eq!(t(a).mul(&t(b)).unwrap().to_i64(), a * b, "{a}·{b}");
        }
    }

    #[test]
    fn negation() {
        assert_eq!(t(7).neg().to_i64(), -7);
        assert_eq!(t(-13).neg().to_i64(), 13);
        assert!(t(0).neg().is_zero());
    }

    #[test]
    fn parse_errors_and_aliases() {
        assert!(Trits::parse("12").is_err());
        assert!(Trits::parse("").is_err());
        // N = −1 алиас
        assert_eq!(Trits::parse("1N").unwrap().to_i64(), 2);
        assert_eq!(Trits::parse("+").unwrap().to_i64(), 1);
    }

    #[test]
    fn kleene_gates() {
        let a = t(5);  // 1TT
        let b = t(8);  // 10T
        // Клини: min поразрядно (младшие выровнены): a=1TT b=10T
        let and = Trits::t_and(&a, &b);
        let or = Trits::t_or(&a, &b);
        // цифры a (младшие→старшие): T,T,1 ; b: T,0,1
        // AND (min): T,T,1 → «1TT» = 5
        assert_eq!(and.to_string_bal(), "1TT");
        // OR (max): T,0,1 → «10T» = 8
        assert_eq!(or.to_string_bal(), "10T");
        // NOT: инверсия
        assert_eq!(Trits::t_not(&t(5)).to_i64(), -5);
        // однотритная таблица истинности Клини
        let t1 = t(1);
        let z = t(0);
        let f = t(-1);
        assert_eq!(Trits::t_and(&t1, &z).to_i64(), 0);
        assert_eq!(Trits::t_and(&f, &t1).to_i64(), -1);
        assert_eq!(Trits::t_or(&z, &t1).to_i64(), 1);
        assert_eq!(Trits::t_or(&z, &f).to_i64(), 0);
    }
}
