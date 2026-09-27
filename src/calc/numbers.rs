//! Теория чисел (цикл M, v0.48.0).
//!
//! - `is_prime`: детерминированный Миллер–Рабин для u64 (12 свидетелей —
//!   доказано Sorenson/Webster для всего диапазона u64);
//! - `factorize`: пробное деление + ρ-Полларда (Брент) с рекурсией;
//! - `next_prime`/`prev_prime`: строгие (регрессия прошлой сессии —
//!   граничные случаи);
//! - фибоначчи удвоением, биномиальный коэффициент, каталанцы.

/// a·b mod m без переполнения (русский крестьянин).
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    let mut a = a % m;
    let mut b = b % m;
    let mut r: u64 = 0;
    while b > 0 {
        if b & 1 == 1 {
            r = (r + a) % m;
        }
        a = (a << 1) % m; // a < m ≤ 2^63 гарантирует отсутствие переполнения при m < 2^63
        b >>= 1;
    }
    r
}

/// a^e mod m (быстрое возведение).
fn pow_mod(mut a: u64, mut e: u64, m: u64) -> u64 {
    let mut r: u64 = 1 % m;
    a %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = mul_mod(r, a, m);
        }
        a = mul_mod(a, a, m);
        e >>= 1;
    }
    r
}

/// Детерминированный Миллер–Рабин для u64.
pub fn is_prime_u64(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for &p in &[2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n % p == 0 {
            return n == p;
        }
    }
    // n > 37, нечётное, без малых делителей
    let mut d = n - 1;
    let mut s = 0u32;
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    let witnesses: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    'w: for &a in witnesses.iter() {
        if a >= n {
            continue;
        }
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'w;
            }
        }
        return false;
    }
    true
}

/// is_prime для f64 (целые до 2^53 точно; выше — отказ).
pub fn is_prime(v: f64) -> Result<bool, String> {
    let n = to_u64(v)?;
    Ok(is_prime_u64(n))
}

fn to_u64(v: f64) -> Result<u64, String> {
    if !v.is_finite() || v < 0.0 || v.fract() != 0.0 || v > 9.007_199_254_740_992e15 {
        return Err("ожидалось неотрицательное целое ≤ 2^53".into());
    }
    Ok(v as u64)
}

/// Наименьшее простое СТРОГО БОЛЬШЕЕ n.
pub fn next_prime(v: f64) -> Result<f64, String> {
    let mut n = to_u64(v)?;
    if n < 2 {
        return Ok(2.0);
    }
    loop {
        n += 1;
        if n == 2 || n == 3 {
            return Ok(n as f64);
        }
        if n % 2 == 0 {
            continue;
        }
        if is_prime_u64(n) {
            return Ok(n as f64);
        }
    }
}

/// Наибольшее простое СТРОГО МЕНЬШЕЕ n (или ошибка, если n ≤ 2).
pub fn prev_prime(v: f64) -> Result<f64, String> {
    let mut n = to_u64(v)?;
    if n <= 2 {
        return Err("простых меньше 2 не существует".into());
    }
    loop {
        n -= 1;
        if n <= 1 {
            return Err("простых меньше 2 не существует".into());
        }
        if n == 2 || (n % 2 == 1 && is_prime_u64(n)) {
            return Ok(n as f64);
        }
    }
}

/// gcd / lcm.
pub fn gcd(a: f64, b: f64) -> Result<f64, String> {
    let (mut a, mut b) = (to_u64(a)?, to_u64(b)?);
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    Ok(a as f64)
}

pub fn lcm(a: f64, b: f64) -> Result<f64, String> {
    let g = gcd(a, b)?;
    if g == 0.0 {
        return Ok(0.0);
    }
    let l = (a / g) * b;
    if l > 9.007_199_254_740_992e15 {
        return Err("lcm переполняет точный целочисленный диапазон".into());
    }
    Ok(l)
}

/// Брент-модификация ρ-Полларда: находит нетривиальный делитель
/// составного нечётного n.
fn pollard_brent(n: u64) -> Option<u64> {
    if n % 2 == 0 {
        return Some(2);
    }
    // детерминированные сиды — воспроизводимость
    for (ci, &c) in [1u64, 2, 3, 5, 7, 11].iter().enumerate() {
        let _ = ci;
        let mut x: u64 = 2;
        let mut y: u64 = 2;
        let mut d: u64 = 1;
        // ограничиваем итерации (для больших простых факторов)
        let mut iterations = 0u64;
        while d == 1 && iterations < 500_000 {
            x = (mul_mod(x, x, n) + c) % n;
            y = (mul_mod(y, y, n) + c) % n;
            y = (mul_mod(y, y, n) + c) % n;
            let diff = if x > y { x - y } else { y - x };
            d = gcd_u64(diff, n);
            iterations += 1;
        }
        if d != 1 && d != n {
            return Some(d);
        }
    }
    None
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Разложение на простые множители (отсортированные, с кратностями).
/// Возвращает Vec<(p, k)>.
pub fn factorize(v: f64) -> Result<Vec<(f64, f64)>, String> {
    let mut n = to_u64(v)?;
    if n < 2 {
        return Ok(Vec::new());
    }
    if n > u32::MAX as u64 * 4096 {
        return Err("слишком большое число для факторизации (лимит ~2^44)".into());
    }
    let mut factors: Vec<(u64, u32)> = Vec::new();
    let push = |p: u64, fs: &mut Vec<(u64, u32)>| {
        if let Some(last) = fs.last_mut() {
            if last.0 == p {
                last.1 += 1;
                return;
            }
        }
        fs.push((p, 1));
    };

    // пробное деление малыми
    for p in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        while n % p == 0 {
            push(p, &mut factors);
            n /= p;
        }
    }
    // 6k±1 до 10^5
    let mut d = 41u64;
    while d <= 100_000 && d * d <= n {
        while n % d == 0 {
            push(d, &mut factors);
            n /= d;
        }
        let d2 = d + 2;
        while n % d2 == 0 {
            push(d2, &mut factors);
            n /= d2;
        }
        d += 6;
    }
    // осталась большая полупростая часть
    if n > 1 {
        let mut stack = vec![n];
        while let Some(m) = stack.pop() {
            if m == 1 {
                continue;
            }
            if is_prime_u64(m) {
                push(m, &mut factors);
                continue;
            }
            match pollard_brent(m) {
                Some(d) => {
                    stack.push(d);
                    stack.push(m / d);
                }
                None => {
                    // не смогли — оставляем как есть (лучше честно, чем зациклиться)
                    push(m, &mut factors);
                }
            }
        }
        factors.sort();
    }
    Ok(factors.into_iter().map(|(p, k)| (p as f64, k as f64)).collect())
}

/// Все делители числа (отсортированные).
pub fn divisors(v: f64) -> Result<Vec<f64>, String> {
    let fs = factorize(v)?;
    let mut divs: Vec<u64> = vec![1];
    for (p, k) in fs {
        let p = p as u64;
        let k = k as u64;
        let mut new_divs = Vec::with_capacity(divs.len() * (k as usize + 1));
        for d in &divs {
            let mut pk = 1u64;
            for _ in 0..=k {
                new_divs.push(d * pk);
                if pk > u64::MAX / p {
                    break;
                }
                pk *= p;
            }
        }
        divs = new_divs;
    }
    divs.sort();
    divs.dedup();
    Ok(divs.into_iter().map(|d| d as f64).collect())
}

/// Фибоначчи (быстрое удвоение). Точно до F(78).
pub fn fib(n: f64) -> Result<f64, String> {
    if !n.is_finite() || n.fract() != 0.0 {
        return Err("fib: ожидается целое".into());
    }
    if n < 0.0 {
        return Err("fib: ожидается неотрицательное (реализация без негафибоначчи)".into());
    }
    if n > 78.0 {
        return Err("fib(n>78) переполняет f64-точность — используйте матричный путь в bigint (не в калькуляторе)".into());
    }
    if n == 0.0 {
        return Ok(0.0);
    }
    if n == 1.0 {
        return Ok(1.0);
    }
    let n = n as u64;
    // (F(k), F(k+1)) удвоением
    let (mut a, mut b) = (0u64, 1u64); // F(0), F(1)
    for bit in (0..n.ilog2() + 1).rev() {
        // F(2k) = F(k)·(2F(k+1) − F(k)); F(2k+1) = F(k)² + F(k+1)²
        let c = a * (2 * b - a);
        let d = a * a + b * b;
        if (n >> bit) & 1 == 1 {
            a = d;
            b = c + d;
        } else {
            a = c;
            b = d;
        }
    }
    Ok(a as f64)
}

/// Биномиальный коэффициент C(n, k).
pub fn binomial(n: f64, k: f64) -> Result<f64, String> {
    if n.fract() != 0.0 || k.fract() != 0.0 {
        return Err("binomial: ожидается целые".into());
    }
    if k < 0.0 || n < 0.0 {
        return Err("binomial: n, k ≥ 0".into());
    }
    let n = n as u64;
    let k = k as u64;
    if k > n {
        return Ok(0.0);
    }
    let k = k.min(n - k);
    let mut r: u128 = 1;
    for i in 0..k {
        r = r * (n - k + 1 + i) as u128 / (i + 1) as u128;
        if r > 9.007_199_254_740_992e15 as u128 {
            return Err("binomial переполняет точный диапазон".into());
        }
    }
    Ok(r as f64)
}

/// Числа Каталана: C_n = C(2n, n)/(n+1).
pub fn catalan(n: f64) -> Result<f64, String> {
    let b = binomial(2.0 * n, n)?;
    let r = b / (n + 1.0);
    if r.fract() != 0.0 {
        return Err("catalan: ожидается целое n ≥ 0".into());
    }
    Ok(r)
}

// =====================================================================
// ТОЧНЫЕ БОЛЬШИЕ ЦЕЛЫЕ (цикл N: «невозможное → возможное»).
// Десятичное строковое представление (возможен ведущий '-'), школьные
// алгоритмы O(n²) — для калькуляторных масштабов (до ~100 тыс. цифр)
// этого достаточно, а точность — абсолютная.
// =====================================================================

/// Разобрать строку в (знак, модуль-цифры). Гарантирует отсутствие
/// ведущих нулей в модуле (кроме "0").
fn big_parts(s: &str) -> (bool, &str) {
    let neg = s.starts_with('-');
    let mag = if neg { &s[1..] } else { s };
    let mag = mag.trim_start_matches('0');
    (neg, if mag.is_empty() { "0" } else { mag })
}

/// Собрать строку из знака и модуля.
fn big_from(neg: bool, mag: &str) -> String {
    let mag = mag.trim_start_matches('0');
    if mag.is_empty() {
        return "0".into();
    }
    if neg {
        format!("-{mag}")
    } else {
        mag.into()
    }
}

/// Школьное сложение модулей.
fn mag_add(a: &str, b: &str) -> String {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut out = Vec::with_capacity(ab.len().max(bb.len()) + 1);
    let (mut i, mut j, mut carry) = (ab.len(), bb.len(), 0u32);
    while i > 0 || j > 0 || carry > 0 {
        let da = if i > 0 { (ab[i - 1] - b'0') as u32 } else { 0 };
        let db = if j > 0 { (bb[j - 1] - b'0') as u32 } else { 0 };
        let s = da + db + carry;
        out.push(b'0' + (s % 10) as u8);
        carry = s / 10;
        i -= (i > 0) as usize;
        j -= (j > 0) as usize;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "0".into())
}

/// Школьное вычитание модулей (требует a ≥ b, иначе None).
fn mag_sub(a: &str, b: &str) -> Option<String> {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut out = Vec::with_capacity(ab.len());
    let (mut i, mut j, mut borrow) = (ab.len(), bb.len(), 0i32);
    while i > 0 {
        let da = (ab[i - 1] - b'0') as i32;
        let db = if j > 0 { (bb[j - 1] - b'0') as i32 } else { 0 };
        let mut d = da - db - borrow;
        if d < 0 {
            d += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(b'0' + d as u8);
        i -= 1;
        j -= (j > 0) as usize;
    }
    if borrow != 0 {
        return None; // a < b
    }
    while out.len() > 1 && *out.last().unwrap() == b'0' {
        out.pop();
    }
    out.reverse();
    Some(String::from_utf8(out).unwrap_or_else(|_| "0".into()))
}

/// Сравнение модулей.
fn mag_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    let (a, b) = (if a.is_empty() { "0" } else { a }, if b.is_empty() { "0" } else { b });
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Школьное умножение модулей (O(n·m), устойчивые переносы).
fn mag_mul(a: &str, b: &str) -> String {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    if a.is_empty() || b.is_empty() {
        return "0".into();
    }
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut acc = vec![0u32; ab.len() + bb.len() + 1];
    for (i, &da) in ab.iter().enumerate().rev() {
        if da == b'0' {
            continue;
        }
        let da = (da - b'0') as u32;
        let mut carry = 0u32;
        let mut k = acc.len() - 1 - (ab.len() - 1 - i);
        for &db in bb.iter().rev() {
            let cur = acc[k] + da * (db - b'0') as u32 + carry;
            acc[k] = cur % 10;
            carry = cur / 10;
            k -= 1;
        }
        while carry > 0 {
            let cur = acc[k] + carry;
            acc[k] = cur % 10;
            carry = cur / 10;
            if k == 0 {
                break;
            }
            k -= 1;
        }
    }
    let mut s: String = acc.iter().map(|&d| (b'0' + d as u8) as char).collect();
    while s.len() > 1 && s.starts_with('0') {
        s.remove(0);
    }
    s
}

/// Знаковое сложение больших целых.
pub fn big_add(a: &str, b: &str) -> String {
    let (na, ma) = big_parts(a);
    let (nb, mb) = big_parts(b);
    if na == nb {
        big_from(na, &mag_add(ma, mb))
    } else {
        match mag_cmp(ma, mb) {
            std::cmp::Ordering::Equal => "0".into(),
            std::cmp::Ordering::Greater => {
                let d = mag_sub(ma, mb).unwrap_or_else(|| "0".into());
                big_from(na, &d)
            }
            std::cmp::Ordering::Less => {
                let d = mag_sub(mb, ma).unwrap_or_else(|| "0".into());
                big_from(nb, &d)
            }
        }
    }
}

/// Знаковое вычитание больших целых.
pub fn big_sub(a: &str, b: &str) -> String {
    let (nb, mb) = big_parts(b);
    let neg_b = big_from(!nb, mb);
    big_add(a, &neg_b)
}

/// Знаковое умножение больших целых.
pub fn big_mul(a: &str, b: &str) -> String {
    let (na, ma) = big_parts(a);
    let (nb, mb) = big_parts(b);
    big_from(na != nb, &mag_mul(ma, mb))
}

/// Деление большого целого на малое (u64). Остаток отбрасывается —
/// вызовы обязаны гарантировать делимость (биномиальные схемы).
pub fn big_div_small(a: &str, d: u64) -> String {
    let (neg, mag) = big_parts(a);
    let mut out = String::with_capacity(mag.len());
    let mut rem: u64 = 0;
    for c in mag.bytes() {
        let cur = rem * 10 + (c - b'0') as u64;
        out.push((b'0' + (cur / d) as u8) as char);
        rem = cur % d;
    }
    big_from(neg, &out)
}

/// Возведение малого целого основания в большую степень — точный путь
/// для `2^10000` и т.п. (повторное возведение в квадрат).
/// Кап: ~100 тыс. цифр результата (защита от вечного счёта).
pub fn big_pow(base: i64, exp: u64) -> Result<String, String> {
    // кап по числу цифр результата (~0.3·log10(2)·exp для base=2)
    let digits = (base.unsigned_abs() as f64).log10() * exp as f64;
    if digits > 100_000.0 {
        return Err(format!(
            "big_pow: результат ≈ {digits:.0} цифр превысил бы лимит 100 000"
        ));
    }
    let neg_base = base < 0;
    let mut result = "1".to_string();
    let mut sq = base.unsigned_abs().to_string();
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = mag_mul(&result, &sq);
        }
        e >>= 1;
        if e > 0 {
            sq = mag_mul(&sq, &sq);
        }
    }
    // знак: минус ⟺ основание отрицательно И показатель нечётен
    Ok(big_from(neg_base && exp % 2 == 1, &result))
}

/// Большое целое основание в малую целую степень (fib(100)^2):
/// повторное возведение в квадрат на модулях. Кап по цифрам — как выше.
pub fn big_pow_big(a: &str, e: u64) -> Result<String, String> {
    let (neg, mag) = big_parts(a);
    let digits = mag.len() as f64 * e as f64;
    if digits > 100_000.0 {
        return Err(format!(
            "big_pow: результат ≈ {digits:.0} цифр превысил бы лимит 100 000"
        ));
    }
    let mut r = "1".to_string();
    let mut sq = mag.to_string();
    let mut k = e;
    while k > 0 {
        if k & 1 == 1 {
            r = mag_mul(&r, &sq);
        }
        k >>= 1;
        if k > 0 {
            sq = mag_mul(&sq, &sq);
        }
    }
    Ok(big_from(neg && e % 2 == 1, &r))
}

/// Точное F(n) — быстрое удвоение на больших целых.
/// F(2k) = F(k)·(2F(k+1) − F(k)); F(2k+1) = F(k)² + F(k+1)².
pub fn fib_big(n: u64) -> Result<String, String> {
    if n > 100_000 {
        return Err("fib_big: n ≤ 100 000 (F(100000) ≈ 20 899 цифр — потолок O(n²)-умножения)".into());
    }
    let (mut a, mut b) = ("0".to_string(), "1".to_string()); // F(0), F(1)
    if n == 0 {
        return Ok(a);
    }
    for bit in (0..=63 - n.leading_zeros()).rev() {
        let two_b = big_add(&b, &b);
        let t = big_sub(&two_b, &a); // 2F(k+1) − F(k) ≥ 0 всегда
        let c = big_mul(&a, &t); // F(2k)
        let d = big_add(&big_mul(&a, &a), &big_mul(&b, &b)); // F(2k+1)
        if (n >> bit) & 1 == 1 {
            let s = big_add(&c, &d);
            a = d;
            b = s;
        } else {
            a = c;
            b = d;
        }
    }
    Ok(a)
}

/// Точное n! (умножение накопителя на малые множители). Кап 10 000
/// (10 000! ≈ 35 660 цифр).
pub fn factorial_big(n: u64) -> Result<String, String> {
    if n > 10_000 {
        return Err("factorial: n ≤ 10 000 (10 000! ≈ 35 660 цифр)".into());
    }
    let mut r = "1".to_string();
    for k in 2..=n {
        r = mag_mul(&r, &k.to_string());
    }
    Ok(r)
}

/// Точный C(n, k) — мультипликативная схема с целочисленным делением
/// на каждом шаге (промежуточное значение = C(n−k+i, i), всегда целое).
pub fn binomial_big(n: u64, k: u64) -> Result<String, String> {
    if k > n {
        return Ok("0".into());
    }
    let k = k.min(n - k);
    if n > 10_000 {
        return Err("binomial_big: n ≤ 10 000".into());
    }
    let mut r = "1".to_string();
    for i in 0..k {
        // r = r·(n−k+1+i)/(i+1) — порядок: сначала умножение, потом деление
        let num = big_mul(&r, &(n - k + 1 + i).to_string());
        r = big_div_small(&num, i + 1);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primality_basics() {
        assert!(!is_prime_u64(0));
        assert!(!is_prime_u64(1));
        assert!(is_prime_u64(2));
        assert!(is_prime_u64(3));
        assert!(!is_prime_u64(4));
        assert!(is_prime_u64(97));
        // Carmichael-числа (обманывают Ферма)
        assert!(!is_prime_u64(561)); // 3·11·17
        assert!(!is_prime_u64(41041)); // 7·11·13·41
        assert!(!is_prime_u64(2465)); // 5·17·29
        // большие простые
        assert!(is_prime_u64(2_147_483_647)); // M31
        assert!(is_prime_u64(6_700_417));
        assert!(!is_prime_u64(6_700_419));
        // псевдопростые по основанию 2
        assert!(!is_prime_u64(2_047));
        assert!(!is_prime_u64(3_215_031_751)); // сильное псевдопростое по многим базам
        assert!(is_prime(2.0).unwrap());
        assert!(is_prime(2.5).is_err());
    }

    // ================================================================
    // РЕГРЕССИЯ прошлой сессии: next_prime на граничных значениях.
    // ================================================================
    #[test]
    fn next_prev_prime_strict() {
        assert_eq!(next_prime(0.0).unwrap(), 2.0);
        assert_eq!(next_prime(1.0).unwrap(), 2.0);
        assert_eq!(next_prime(2.0).unwrap(), 3.0); // строго больше!
        assert_eq!(next_prime(3.0).unwrap(), 5.0);
        assert_eq!(next_prime(7.0).unwrap(), 11.0);
        assert_eq!(next_prime(13.0).unwrap(), 17.0);
        assert_eq!(next_prime(1e6 as f64).unwrap(), 1_000_003.0);
        assert_eq!(prev_prime(3.0).unwrap(), 2.0);
        assert_eq!(prev_prime(10.0).unwrap(), 7.0);
        assert_eq!(prev_prime(2.0).is_err(), true);
        assert_eq!(prev_prime(1.0).is_err(), true);
    }

    #[test]
    fn gcd_lcm() {
        assert_eq!(gcd(12.0, 18.0).unwrap(), 6.0);
        assert_eq!(gcd(7.0, 13.0).unwrap(), 1.0);
        assert_eq!(gcd(0.0, 5.0).unwrap(), 5.0);
        assert_eq!(lcm(4.0, 6.0).unwrap(), 12.0);
        assert_eq!(lcm(21.0, 6.0).unwrap(), 42.0);
    }

    #[test]
    fn factorization() {
        assert_eq!(factorize(1.0).unwrap(), vec![]);
        assert_eq!(factorize(2.0).unwrap(), vec![(2.0, 1.0)]);
        assert_eq!(factorize(360.0).unwrap(), vec![(2.0, 3.0), (3.0, 2.0), (5.0, 1.0)]);
        assert_eq!(factorize(97.0).unwrap(), vec![(97.0, 1.0)]);
        // полупростые с большими множителями (ρ-Поллард)
        assert_eq!(factorize(1000003.0 * 1000033.0).unwrap(), vec![(1000003.0, 1.0), (1000033.0, 1.0)]);
        assert_eq!(
            factorize(1e9 + 7.0).unwrap(),
            vec![(1_000_000_007.0, 1.0)]
        );
    }

    #[test]
    fn divisors_list() {
        assert_eq!(divisors(12.0).unwrap(), vec![1.0, 2.0, 3.0, 4.0, 6.0, 12.0]);
        assert_eq!(divisors(28.0).unwrap(), vec![1.0, 2.0, 4.0, 7.0, 14.0, 28.0]); // совершенное
        assert_eq!(divisors(1.0).unwrap(), vec![1.0]);
    }

    #[test]
    fn fibonacci_doubling() {
        assert_eq!(fib(0.0).unwrap(), 0.0);
        assert_eq!(fib(1.0).unwrap(), 1.0);
        assert_eq!(fib(10.0).unwrap(), 55.0);
        assert_eq!(fib(20.0).unwrap(), 6765.0);
        assert_eq!(fib(50.0).unwrap(), 12_586_269_025.0);
        assert_eq!(fib(70.0).unwrap(), 190_392_490_709_135.0);
        assert!(fib(79.0).is_err());
        assert!(fib(-1.0).is_err());
    }

    #[test]
    fn binomials_and_catalan() {
        assert_eq!(binomial(0.0, 0.0).unwrap(), 1.0);
        assert_eq!(binomial(5.0, 2.0).unwrap(), 10.0);
        assert_eq!(binomial(20.0, 10.0).unwrap(), 184_756.0);
        assert_eq!(binomial(52.0, 5.0).unwrap(), 2_598_960.0); // покерные руки
        assert_eq!(binomial(5.0, 0.0).unwrap(), 1.0);
        assert_eq!(binomial(5.0, 6.0).unwrap(), 0.0);
        assert_eq!(catalan(0.0).unwrap(), 1.0);
        assert_eq!(catalan(5.0).unwrap(), 42.0);
        assert_eq!(catalan(10.0).unwrap(), 16_796.0);
    }

    #[test]
    fn modular_helpers() {
        assert_eq!(pow_mod(2u64, 10, 1000), 24);
        assert_eq!(mul_mod(3, 4, 10), 2);
        // большие операнды не переполняют: 2^64 mod (10^9+7)
        let v = pow_mod(2, 64, 1_000_000_007);
        let want = (2u128).pow(64) % (1_000_000_007 as u128);
        assert_eq!(v as u128, want);
    }

    // =============================================================
    // ЦИКЛ N: точные большие целые — якоря
    // =============================================================

    #[test]
    fn big_arith_basics() {
        assert_eq!(big_add("99999999999999999999", "1"), "100000000000000000000");
        assert_eq!(big_add("0", "0"), "0");
        assert_eq!(big_sub("100000000000000000000", "1"), "99999999999999999999");
        assert_eq!(big_sub("5", "7"), "-2"); // знаковый переход
        assert_eq!(big_sub("-5", "-7"), "2");
        assert_eq!(big_mul("123456789", "987654321"), "121932631112635269");
        assert_eq!(big_mul("0", "999999999999"), "0");
        assert_eq!(big_mul("-3", "7"), "-21");
        assert_eq!(big_mul("-3", "-7"), "21");
        // деление на малое с проверкой делимости
        assert_eq!(big_div_small("1267650600228229401496703205376", 2), "633825300114114700748351602688");
        assert_eq!(big_div_small("-100", 4), "-25");
    }

    #[test]
    fn big_pow_anchors() {
        assert_eq!(big_pow(2, 100).unwrap(), "1267650600228229401496703205376");
        // знак: нечётная степень отрицательного основания
        assert_eq!(big_pow(-3, 3).unwrap(), "-27");
        assert_eq!(big_pow(-3, 4).unwrap(), "81");
        assert_eq!(big_pow(-2, 63).unwrap(), "-9223372036854775808");
        assert_eq!(big_pow(10, 0).unwrap(), "1");
        // большое основание
        assert_eq!(
            big_pow_big("354224848179261915075", 2).unwrap(),
            big_mul("354224848179261915075", "354224848179261915075")
        );
        // кап: 2^400000 превышает 100 тыс. цифр
        assert!(big_pow(2, 400_000).is_err());
    }

    #[test]
    fn fib_factorial_binomial_big() {
        // F(100) — за f64-точностью (стресс-тест прошлой сессии)
        assert_eq!(fib_big(100).unwrap(), "354224848179261915075");
        // F(79) — первая за пределом
        assert_eq!(fib_big(79).unwrap(), "14472334024676221");
        // 25! точно
        assert_eq!(factorial_big(25).unwrap(), "15511210043330985984000000");
        assert_eq!(factorial_big(0).unwrap(), "1");
        assert_eq!(factorial_big(1).unwrap(), "1");
        // C(100, 50) — гигант вне f64
        assert_eq!(
            binomial_big(100, 50).unwrap(),
            "100891344545564193334812497256"
        );
        assert_eq!(binomial_big(10, 3).unwrap(), "120");
        assert_eq!(binomial_big(10, 0).unwrap(), "1");
        assert_eq!(binomial_big(10, 11).unwrap(), "0");
    }
}
