//! Widening arithmetic operations for SIMD emulation.

use std::simd::{cmp::SimdPartialOrd, u64x8, Mask, Simd};

/// A trait for widening arithmetic operations.
pub trait WideningAdd : Sized {

    /// Performs addition that returns the full result in a wider type.
    fn widening_add(self, rhs: Self) -> (Self, Self);
}

impl WideningAdd for u64 {
    #[inline(always)]
    fn widening_add(self, rhs: Self) -> (u64, u64) {
        let sum = (self as u128) + (rhs as u128);
        (sum as u64, (sum >> 64) as u64)
    }
}

impl WideningAdd for u128 { // (low, high)

    #[inline(always)]
    fn widening_add(self, rhs: Self) -> (u128, u128) {
        let (low, carry) = self.carrying_add(rhs, false);
        (low, carry as u128)
    }
}

pub trait WideningSimdMul : Sized {
    fn widening_mul(self, rhs: Self) -> (Self, Self);
}

impl WideningSimdMul for u64x8 {
    /// 두 u64x8 벡터를 곱하여 128비트 결과 (low, high)를 반환하는 헬퍼 함수입니다.
    #[inline(always)]
    fn widening_mul(self, rhs: u64x8) -> (u64x8, u64x8) {
        // 64비트 곱셈을 32비트 단위로 분해하여 128비트 결과를 계산 (Karatsuba와 유사)
        // self = self_hi * 2^32 + self_lo
        // rhs = rhs_hi * 2^32 + rhs_lo
        // self*rhs = (self_hi*rhs_hi)*2^64 + (self_hi*rhs_lo + self_lo*rhs_hi)*2^32 + (self_lo*rhs_lo)
        const MASK32: u64 = 0xFFFFFFFF;
        let mask32_simd = u64x8::splat(MASK32);

        let self_lo = self & mask32_simd;
        let self_hi = self >> 32;
        let rhs_lo = rhs & mask32_simd;
        let rhs_hi = rhs >> 32;

        let p0 = self_lo * rhs_lo;
        let p1 = self_lo * rhs_hi;
        let p2 = self_hi * rhs_lo;
        let p3 = self_hi * rhs_hi;

        let (mid_sum, mid_carry) = p1.overflowing_add(p2);
        let mid_carry_as_u64 = mid_carry.select(u64x8::splat(1), u64x8::splat(0));
        
        let (low, low_carry) = p0.overflowing_add(mid_sum << 32);
        let low_carry_as_u64 = low_carry.select(u64x8::splat(1), u64x8::splat(0));

        let high = p3 + (mid_sum >> 32) + (mid_carry_as_u64 << 32) + low_carry_as_u64;
        
        (low, high)
    }
}

/// SIMD 덧셈 시 캐리(carry)를 반환하는 트레이트
pub trait OverflowingSimdAdd : Sized {
    type Output;
    fn overflowing_add(self, rhs: Self) -> (Self, Self::Output) where Self: Sized;
}

/// SIMD 뺄셈 시 빌림(borrow)을 반환하는 트레이트
pub trait OverflowingSimdSub : Sized {
    type Output;
    fn overflowing_sub(self, rhs: Self) -> (Self, Self::Output) where Self: Sized;
}

impl OverflowingSimdAdd for u64x8 {
    type Output = Mask<i64, 8>; // 각 레인별 carry flag (true if overflowed)

    #[inline(always)]
    fn overflowing_add(self, rhs: u64x8) -> (u64x8, Self::Output) {
        let sum = self + rhs;
        // 덧셈 결과가 두 피연산자 중 하나보다 작으면 오버플로우 발생
        let carry = sum.simd_lt(self) | sum.simd_lt(rhs);
        (sum, carry)
    }
}

impl OverflowingSimdSub for u64x8 {
    type Output = Mask<i64, 8>; // 각 레인별 borrow flag (true if underflowed)

    #[inline(always)]
    fn overflowing_sub(self, rhs: u64x8) -> (u64x8, Self::Output) {
        let diff = self - rhs;
        // 뺄셈 결과가 피감수(self)보다 크면 언더플로우 발생
        let borrow = diff.simd_gt(self);
        (diff, borrow)
    }
}