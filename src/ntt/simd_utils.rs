
use crate::core::wide_arith::{WideningSimdMul, OverflowingSimdAdd, OverflowingSimdSub};

use crate::core::num::{SafeModuloArith, concat64x2};

use super::{Ntt, BarrettReducer64};

// SIMD 연산을 위해 추가
use std::simd::{Simd, u64x8, cmp::*};

use std::ops::Add;


/// 128비트 SIMD 벡터에 대한 Barrett Reduction을 수행합니다.
#[inline(always)]
pub(crate) fn reduce_simd((low, high): (u64x8, u64x8), reducer: &BarrettReducer64) -> u64x8 {
    let m_simd = u64x8::splat(reducer.m);
    let zero_simd = u64x8::splat(0);
    let one_simd = u64x8::splat(1);
    
    // --- 1. 몫 추정: q ≈ floor(x / m) ---
    // q_approx = (x * m_inv) >> 128
    let m_inv_low = u64x8::splat(reducer.m_inv as u64);
    let m_inv_high = u64x8::splat((reducer.m_inv >> 64) as u64);

    let (mid1_low, mid1_high) = low.widening_mul(m_inv_high);
    let (mid2_low, mid2_high) = high.widening_mul(m_inv_low);
    let (_, high_high) = high.widening_mul(m_inv_high);
    
    let (mid_sum, carry1) = mid1_high.overflowing_add(mid2_high);
    let (q_approx, carry2) = mid_sum.overflowing_add(high_high);
    let q_approx = q_approx + carry1.select(one_simd, zero_simd) + carry2.select(one_simd, zero_simd);

    // --- 2. 나머지 계산: r = x - q * m ---
    // q*m 계산
    let (qm_low, qm_high) = q_approx.widening_mul(m_simd);
    
    // 128비트 뺄셈 r = x - qm
    let (r_low, borrow1) = low.overflowing_sub(qm_low);
    let (mut r_high, borrow2) = high.overflowing_sub(qm_high);
    r_high = r_high - borrow1.select(one_simd, zero_simd); // borrow 전파

    // --- 3. 오차 보정 ---
    let mut final_r = r_low;
    // 보정 조건: r >= m  <=>  r_high > 0 or (r_high == 0 and r_low >= m)
    let mask = r_high.simd_ne(zero_simd) | final_r.simd_ge(m_simd);
    final_r = mask.select(final_r - m_simd, final_r);
    
    // 근사 오차가 2m에 가까운 경우를 대비해 한 번 더 보정
    let mask2 = final_r.simd_ge(m_simd);
    final_r = mask2.select(final_r - m_simd, final_r);

    final_r
}

pub(crate) fn element_wise_add<T1 : Add<T1>, T2 : Add<T2>>((a1, a2): (T1, T2), (b1, b2): (T1, T2)) -> (T1::Output, T2::Output) {
    (a1+b1, a2+b2)
}