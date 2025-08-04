use std::ops::{Add, Mul, Rem, Sub};
use std::cmp::{Ordering, Ord};

pub trait SafeModuloArith<M = Self> : Add<Self> + Sub<Self> + Mul<Self> + Rem<M> where Self : Sized {
    const MAXVAL: Self;

    // (a * b) mod m
    fn safe_mul_mod(self, rhs: Self, m: M) -> Self;

    // (a + b) mod m
    fn safe_add_mod(self, rhs: Self, m: M) -> Self;

    // (a - b) mod m
    fn safe_sub_mod(self, rhs: Self, m: M) -> Self;
}

impl SafeModuloArith<Self> for u64 {
    const MAXVAL: Self = u64::MAX;

    // (a * b) mod m
    fn safe_mul_mod(self, rhs: Self, m: Self) -> Self {
        (concat64x2(self.widening_mul(rhs)) % (m as u128)) as u64        
    }
    // (a + b) mod m
    fn safe_add_mod(self, rhs: Self, m: Self) -> Self {
        let a_mod_m = self % m;
        let b_mod_m = rhs % m;
        let (wrapped, is_overflowing) = a_mod_m.overflowing_add(b_mod_m);
        let processed_overflow = if is_overflowing {
            ((u64::MAX % m) + 1u64) % m
        } else { 0 };
        ((wrapped % m) + processed_overflow) % m
    }
    // (a - b) mod m
    fn safe_sub_mod(self, rhs: Self, m: Self) -> Self {
        let a_mod_m = self % m;
        let b_mod_m = rhs % m;
        let result = if a_mod_m > b_mod_m { a_mod_m - b_mod_m } else if a_mod_m < b_mod_m { (m - b_mod_m) + a_mod_m } else { 0u64 };
        result
    }
}

#[inline(always)]
pub fn concat64x2((low, high): (u64, u64)) -> u128 {
    ((high as u128) << 64) | (low as u128)
}