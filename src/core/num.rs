// src/core/num.rs

use std::ops::{Add, Mul, Rem, Sub};

pub trait SafeModuloArith<M = Self>: Add<Self> + Sub<Self> + Mul<Self> + Rem<M> where Self: Sized {
    fn safe_mul_mod(self, rhs: Self, m: M) -> Self;
    fn safe_add_mod(self, rhs: Self, m: M) -> Self;
    fn safe_sub_mod(self, rhs: Self, m: M) -> Self;
}

impl SafeModuloArith<Self> for u64 {
    /// (a * b) mod m. Widens to u128 to prevent overflow.
    #[inline(always)]
    fn safe_mul_mod(self, rhs: Self, m: Self) -> Self {
        ((self as u128 * rhs as u128) % m as u128) as u64
    }
    
    /// (a + b) mod m. Widens to u128 to prevent overflow.
    /// First, reduces inputs modulo m to prevent (a+b) from overflowing u128.
    #[inline(always)]
    fn safe_add_mod(self, rhs: Self, m: Self) -> Self {
        let a128 = self as u128;
        let b128 = rhs as u128;
        let m128 = m as u128;
        ((a128 % m128 + b128 % m128) % m128) as u64
    }

    /// (a - b) mod m. Widens to u128 to prevent overflow.
    /// The classic (a + m - b) % m trick for unsigned integers.
    #[inline(always)]
    fn safe_sub_mod(self, rhs: Self, m: Self) -> Self {
        let a128 = self as u128;
        let b128 = rhs as u128;
        let m128 = m as u128;
        ((a128 % m128 + m128 - (b128 % m128)) % m128) as u64
    }
}

/// Helper to combine two u64 into a u128.
#[inline(always)]
pub fn concat64x2((low, high): (u64, u64)) -> u128 {
    ((high as u128) << 64) | (low as u128)
}