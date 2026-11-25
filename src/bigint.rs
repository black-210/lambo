//! From-scratch arbitrary-precision unsigned and signed integers (`BigUint`, `BigInt`)
//! plus number-theoretic primitives for zero-dependency cryptographic auditing.

use anyhow::{Result, bail};
use std::cmp::Ordering;

/// Arbitrary-precision unsigned integer stored in little-endian base-2^32 limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (&a, &b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            match a.cmp(&b) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    pub fn from_u64(v: u64) -> Self {
        if v == 0 {
            Self::zero()
        } else if v <= u32::MAX as u64 {
            Self {
                limbs: vec![v as u32],
            }
        } else {
            Self {
                limbs: vec![v as u32, (v >> 32) as u32],
            }
        }
    }

    pub fn from_u128(v: u128) -> Self {
        if v == 0 {
            return Self::zero();
        }
        let mut limbs = Vec::new();
        let mut rem = v;
        while rem > 0 {
            limbs.push((rem & 0xffff_ffff) as u32);
            rem >>= 32;
        }
        Self { limbs }
    }

    /// Parse decimal or `0x`-prefixed hexadecimal integer string.
    pub fn parse_auto(s: &str) -> Result<Self> {
        let s = s.trim().replace('_', "");
        if s.is_empty() {
            bail!("Empty integer string.");
        }
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Self::from_hex(hex)
        } else {
            Self::from_decimal(&s)
        }
    }

    pub fn from_decimal(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            bail!("Invalid decimal integer: {s:?}");
        }
        let mut acc = Self::zero();
        let ten = Self::from_u64(10);
        for b in s.bytes() {
            acc = acc.mul(&ten);
            acc = acc.add(&Self::from_u64((b - b'0') as u64));
        }
        Ok(acc)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.trim().strip_prefix("0x").or_else(|| s.trim().strip_prefix("0X")).unwrap_or(s.trim());
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("Invalid hexadecimal integer.");
        }
        let mut acc = Self::zero();
        for b in s.bytes() {
            let nibble = match b {
                b'0'..=b'9' => (b - b'0') as u64,
                b'a'..=b'f' => (b - b'a' + 10) as u64,
                b'A'..=b'F' => (b - b'A' + 10) as u64,
                _ => unreachable!(),
            };
            acc = acc.shl_bits(4).add(&Self::from_u64(nibble));
        }
        Ok(acc)
    }

    pub fn to_u64(&self) -> Option<u64> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0] as u64),
            2 => Some((self.limbs[0] as u64) | ((self.limbs[1] as u64) << 32)),
            _ => None,
        }
    }

    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0x0".to_owned();
        }
        let mut out = String::from("0x");
        if let Some((&top, rest)) = self.limbs.split_last() {
            out.push_str(&format!("{top:x}"));
            for &limb in rest.iter().rev() {
                out.push_str(&format!("{limb:08x}"));
            }
        }
        out
    }

    pub fn to_decimal(&self) -> String {
        if self.is_zero() {
            return "0".to_owned();
        }
        let mut digits = Vec::new();
        let mut cur = self.clone();
        while !cur.is_zero() {
            let (q, r) = cur.div_rem_u32(1_000_000_000);
            digits.push(r);
            cur = q;
        }
        let mut out = String::new();
        if let Some((&top, rest)) = digits.split_last() {
            out.push_str(&format!("{top}"));
            for &d in rest.iter().rev() {
                out.push_str(&format!("{d:09}"));
            }
        }
        out
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    pub fn is_even(&self) -> bool {
        self.limbs.first().is_none_or(|&l| l & 1 == 0)
    }

    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    pub fn bit(&self, idx: usize) -> bool {
        let limb_idx = idx / 32;
        let bit_idx = idx % 32;
        self.limbs
            .get(limb_idx)
            .is_some_and(|&l| ((l >> bit_idx) & 1) == 1)
    }

    pub fn set_bit(&mut self, idx: usize) {
        let limb_idx = idx / 32;
        let bit_idx = idx % 32;
        if limb_idx >= self.limbs.len() {
            self.limbs.resize(limb_idx + 1, 0);
        }
        self.limbs[limb_idx] |= 1u32 << bit_idx;
    }

    pub fn shl1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let mut out = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u32;
        for &l in &self.limbs {
            out.push((l << 1) | carry);
            carry = l >> 31;
        }
        if carry != 0 {
            out.push(carry);
        }
        Self { limbs: out }
    }

    pub fn shr1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0u32; self.limbs.len()];
        let mut carry = 0u32;
        for i in (0..self.limbs.len()).rev() {
            let l = self.limbs[i];
            out[i] = (l >> 1) | carry;
            carry = (l & 1) << 31;
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn shl_bits(&self, shift: usize) -> Self {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }
        let word_shift = shift / 32;
        let bit_shift = shift % 32;
        let mut out = vec![0u32; word_shift];
        let mut carry = 0u32;
        for &l in &self.limbs {
            if bit_shift == 0 {
                out.push(l);
            } else {
                out.push((l << bit_shift) | carry);
                carry = l >> (32 - bit_shift);
            }
        }
        if carry != 0 {
            out.push(carry);
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;
        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u64;
            let sum = a + b + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    /// Panics only if `self < other`; callers check ordering or use `checked_sub`.
    pub fn sub(&self, other: &Self) -> Self {
        self.checked_sub(other)
            .expect("BigUint::sub underflow")
    }

    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self < other {
            return None;
        }
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for (i, &a_u32) in self.limbs.iter().enumerate() {
            let a = a_u32 as i64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(diff as u32);
        }
        let mut res = Self { limbs: out };
        res.trim();
        Some(res)
    }

    pub fn abs_diff(&self, other: &Self) -> Self {
        if self >= other {
            self.sub(other)
        } else {
            other.sub(self)
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0u32; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let prod = (a as u64) * (b as u64) + (out[i + j] as u64) + carry;
                out[i + j] = prod as u32;
                carry = prod >> 32;
            }
            out[i + other.limbs.len()] = ((out[i + other.limbs.len()] as u64) + carry) as u32;
        }
        let mut res = Self { limbs: out };
        res.trim();
        res
    }

    pub fn div_rem_u32(&self, divisor: u32) -> (Self, u32) {
        if divisor == 0 {
            panic!("Division by zero");
        }
        let mut q = vec![0u32; self.limbs.len()];
        let mut rem = 0u64;
        let d = divisor as u64;
        for i in (0..self.limbs.len()).rev() {
            let cur = (rem << 32) | (self.limbs[i] as u64);
            q[i] = (cur / d) as u32;
            rem = cur % d;
        }
        let mut res = Self { limbs: q };
        res.trim();
        (res, rem as u32)
    }

    pub fn div_rem(&self, divisor: &Self) -> Result<(Self, Self)> {
        if divisor.is_zero() {
            bail!("Division by zero in BigUint");
        }
        if self < divisor {
            return Ok((Self::zero(), self.clone()));
        }
        if let Some(d32) = divisor.limbs.first().filter(|_| divisor.limbs.len() == 1) {
            let (q, r) = self.div_rem_u32(*d32);
            return Ok((q, Self::from_u64(r as u64)));
        }
        let mut q = Self::zero();
        let mut r = Self::zero();
        for bit_idx in (0..self.bits()).rev() {
            r = r.shl1();
            if self.bit(bit_idx) {
                if r.limbs.is_empty() {
                    r.limbs.push(1);
                } else {
                    r.limbs[0] |= 1;
                }
            }
            if r >= *divisor {
                r = r.sub(divisor);
                q.set_bit(bit_idx);
            }
        }
        q.trim();
        r.trim();
        Ok((q, r))
    }

    pub fn rem(&self, modulus: &Self) -> Result<Self> {
        Ok(self.div_rem(modulus)?.1)
    }

    pub fn div(&self, divisor: &Self) -> Result<Self> {
        Ok(self.div_rem(divisor)?.0)
    }

    pub fn mod_mul(&self, other: &Self, modulus: &Self) -> Result<Self> {
        self.mul(other).rem(modulus)
    }

    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Result<Self> {
        if modulus.is_zero() {
            bail!("Modulus must be non-zero.");
        }
        if modulus.is_one() {
            return Ok(Self::zero());
        }
        let mut result = Self::one();
        let mut base = self.rem(modulus)?;
        for bit_idx in 0..exp.bits() {
            if exp.bit(bit_idx) {
                result = result.mul(&base).rem(modulus)?;
            }
            if bit_idx + 1 < exp.bits() {
                base = base.mul(&base).rem(modulus)?;
            }
        }
        Ok(result)
    }

    pub fn gcd(mut a: Self, mut b: Self) -> Self {
        while !b.is_zero() {
            let (_, r) = a.div_rem(&b).expect("b is non-zero");
            a = b;
            b = r;
        }
        a
    }

    /// Exact integer square root `floor(sqrt(self))` using binary shift-and-Newton.
    pub fn isqrt(&self) -> Self {
        if self.is_zero() || self.is_one() {
            return self.clone();
        }
        let mut x = Self::one().shl_bits(self.bits().div_ceil(2));
        loop {
            let (q, _) = self.div_rem(&x).unwrap();
            let next = x.add(&q).shr1();
            if next >= x {
                return x;
            }
            x = next;
        }
    }

    /// Miller-Rabin primality test using fixed deterministic witness bases.
    pub fn is_probable_prime(&self) -> bool {
        if self < &Self::from_u64(2) {
            return false;
        }
        let small_primes = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
        for &p in &small_primes {
            let bp = Self::from_u64(p);
            if self == &bp {
                return true;
            }
            if self.rem(&bp).map(|r| r.is_zero()).unwrap_or(false) {
                return false;
            }
        }
        let one = Self::one();
        let n_minus_1 = self.sub(&one);
        let mut d = n_minus_1.clone();
        let mut s = 0usize;
        while d.is_even() {
            d = d.shr1();
            s += 1;
        }
        'witness: for &a in &small_primes {
            let base = Self::from_u64(a);
            if &base >= self {
                continue;
            }
            let mut x = match base.mod_pow(&d, self) {
                Ok(v) => v,
                Err(_) => return false,
            };
            if x == one || x == n_minus_1 {
                continue;
            }
            for _ in 1..s {
                x = match x.mod_mul(&x, self) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                if x == n_minus_1 {
                    continue 'witness;
                }
            }
            return false;
        }
        true
    }
}

/// Minimal signed arbitrary-precision integer for extended GCD & Bezout identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt {
    pub negative: bool,
    pub mag: BigUint,
}

impl BigInt {
    pub fn zero() -> Self {
        Self {
            negative: false,
            mag: BigUint::zero(),
        }
    }

    pub fn from_uint(mag: BigUint) -> Self {
        Self {
            negative: false,
            mag,
        }
    }

    pub fn normalize(mut self) -> Self {
        if self.mag.is_zero() {
            self.negative = false;
        }
        self
    }

    pub fn neg(&self) -> Self {
        if self.mag.is_zero() {
            Self::zero()
        } else {
            Self {
                negative: !self.negative,
                mag: self.mag.clone(),
            }
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        if self.negative == other.negative {
            Self {
                negative: self.negative,
                mag: self.mag.add(&other.mag),
            }
            .normalize()
        } else if self.mag >= other.mag {
            Self {
                negative: self.negative,
                mag: self.mag.sub(&other.mag),
            }
            .normalize()
        } else {
            Self {
                negative: other.negative,
                mag: other.mag.sub(&self.mag),
            }
            .normalize()
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self {
            negative: self.negative ^ other.negative,
            mag: self.mag.mul(&other.mag),
        }
        .normalize()
    }

    pub fn to_string_signed(&self) -> String {
        if self.mag.is_zero() {
            "0".to_owned()
        } else if self.negative {
            format!("-{}", self.mag.to_decimal())
        } else {
            self.mag.to_decimal()
        }
    }
}

/// Extended Euclidean algorithm returning `(gcd, x, y)` such that `a*x + b*y = gcd`.
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigInt, BigInt) {
    let mut old_r = a.clone();
    let mut r = b.clone();
    let mut old_s = BigInt::from_uint(BigUint::one());
    let mut s = BigInt::zero();
    let mut old_t = BigInt::zero();
    let mut t = BigInt::from_uint(BigUint::one());

    while !r.is_zero() {
        let (q, rem) = old_r.div_rem(&r).expect("r non-zero");
        old_r = r;
        r = rem;

        let qb = BigInt::from_uint(q);
        let next_s = old_s.sub(&qb.mul(&s));
        old_s = s;
        s = next_s;

        let next_t = old_t.sub(&qb.mul(&t));
        old_t = t;
        t = next_t;
    }
    (old_r, old_s, old_t)
}

/// Modular inverse `a^{-1} mod m` if `gcd(a, m) == 1`.
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() {
        return None;
    }
    let (g, x, _) = extended_gcd(a, m);
    if !g.is_one() {
        return None;
    }
    let r = x.mag.rem(m).ok()?;
    if x.negative && !r.is_zero() {
        Some(m.sub(&r))
    } else {
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biguint_arithmetic_and_pow_match_known_values() {
        let a = BigUint::parse_auto("123456789012345678901234567890").unwrap();
        let b = BigUint::parse_auto("98765432109876543210").unwrap();
        let prod = a.mul(&b);
        let (q, r) = prod.div_rem(&a).unwrap();
        assert_eq!(q, b);
        assert!(r.is_zero());

        let m = BigUint::from_u64(3233);
        let base = BigUint::from_u64(65);
        let e = BigUint::from_u64(17);
        let d = BigUint::from_u64(2753);
        let ct = base.mod_pow(&e, &m).unwrap();
        assert_eq!(ct.to_u64(), Some(2790));
        let pt = ct.mod_pow(&d, &m).unwrap();
        assert_eq!(pt, base);
    }

    #[test]
    fn extended_gcd_and_mod_inverse_work() {
        let a = BigUint::from_u64(17);
        let m = BigUint::from_u64(3120);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!(inv.to_u64(), Some(2753));
        assert_eq!(BigUint::from_u64(144).isqrt().to_u64(), Some(12));
    }
}
