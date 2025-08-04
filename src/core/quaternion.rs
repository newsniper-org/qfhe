// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/core/quaternion.rs

use std::ops::{Add, Sub, Mul};

// 각 쿼터니언 성분이 RNS 표현을 가집니다.
#[derive(Clone, Debug, Default)]
pub struct Quaternion {
    pub w: Vec<u64>,
    pub x: Vec<u64>,
    pub y: Vec<u64>,
    pub z: Vec<u64>,
}

impl Quaternion {
    // RNS 기저 크기에 맞춰 0으로 초기화
    pub fn zero(rns_basis_size: usize) -> Self {
        Self {
            w: vec![0; rns_basis_size],
            x: vec![0; rns_basis_size],
            y: vec![0; rns_basis_size],
            z: vec![0; rns_basis_size],
        }
    }
}
