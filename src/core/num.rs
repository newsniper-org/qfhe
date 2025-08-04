use std::ops::{Add, Mul, Rem, Sub};
use std::cmp::{Ordering, Ord};

pub trait SafeModuloArith<M = Self> : Add<Self> + Sub<Self> + Mul<Self> + Rem<M> {
    const MAXVAL: Self;

    // (a * b) mod m
    const fn safe_mul_mod(self, rhs: Self, m: M) -> Self;

    // (a + b) mod m
    const fn safe_add_mod(self, rhs: Self, m: M) -> Self;

    // (a - b) mod m
    const fn safe_sub_mod(self, rhs: Self, m: M) -> Self;
}

impl SafeModuloArith<Self> for u64 {
    const MAXVAL: Self = u64::MAX;

    // (a * b) mod m
    const fn safe_mul_mod(self, rhs: Self, m: Self) -> Self {
        let (low, high) = a.widening_mul(b);

        let two_pow_64_mod_m = ((Self::MAXVAL % m) + 1u64) % m;
        (((high % m) * two_pow_64_mod_m) % m + (low % m)) % m
    }
    // (a + b) mod m
    const fn safe_add_mod(self, rhs: Self, m: Self) -> Self {
        let a_mod_m = self % m;
        let b_mod_m = rhs % m;
        let (wrapped, is_overflowing) = a_mod_m.overflowing_add(b_mod_m);
        let processed_overflow = if is_overflowing {
            ((u64::MAX % m) + 1u64) % m
        } else { 0 };
        ((wrapped % m) + processed_overflow) % m
    }
    // (a - b) mod m
    const fn safe_sub_mod(self, rhs: Self, m: Self) -> Self {
        let a_mod_m = self % m;
        let b_mod_m = rhs % m;
        let result = match a_mod_m.cmp(&b_mod_m) {
            Ordering::Equal => 0u64,
            Ordering::Greater => a_mod_m - b_mod_m,
            Ordering::Less => (m - b_mod_m) + a_mod_m
        };
        result
    }
}

#[inline(always)]
pub fn concat64x2((low, high): (u64, u64)) -> u128 {
    ((high as u128) << 64) | (low as u128)
}