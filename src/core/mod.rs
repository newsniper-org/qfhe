pub mod quaternion;
pub use crate::core::quaternion::Quaternion;

pub mod polynominal;
pub use crate::core::polynominal::Polynomial;

// src/core/mod.rs

use rand::prelude::*;

// --- 암호화 파라미터 정의 ---
pub const N_DIM: usize = 1024; // 모듈 차원 (비밀키 벡터의 길이)
pub const T_MOD: i64 = 257;   // 평문(plaintext)을 위한 소수 모듈러스
pub const NOISE_STD_DEV: f64 = 3.2; // 오류(noise) 생성을 위한 표준 편차
pub const Q_MOD: u64 = 4294967291; // 모듈러스 (32비트 최대 소수)
pub const SCALING_FACTOR_DELTA: u64 = Q_MOD / 16; // 메시지 인코딩을 위한 스케일링 인자

// --- 새로운 데이터 구조 ---

/// 비밀키는 4원수들의 벡터입니다.
pub struct SecretKey(pub Polynomial);

/// LWE 암호문은 (a, b) 쌍으로 구성됩니다.
/// a는 4원수들의 벡터이고, b는 단일 4원수입니다.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub polynomials: Vec<Polynomial>
}

/// 암호화, 복호화, 동형 연산을 위한 핵심 트레이트(trait)입니다.
pub trait QfheEngine {
    fn encrypt(&self, secret_key: &SecretKey, message: u64) -> Ciphertext;
    fn decrypt(&self, secret_key: &SecretKey, ciphertext: &Ciphertext) -> u64;
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
}

// --- 유틸리티 함수 ---

/// 정규 분포를 따르는 작은 오류 4원수를 샘플링합니다.
pub fn sample_error_quaternion() -> Quaternion {
    let mut rng = rand::rng();

    // 박스-뮬러 변환을 이용한 간단한 정규 분포 샘플링
    let u1: f64 = rng.random::<f64>();
    let u2: f64 = rng.random::<f64>();
    let mag = NOISE_STD_DEV * (-2.0 * u1.ln()).sqrt();
    let z1 = mag * (2.0 * std::f64::consts::PI * u2).cos();
    let z2 = mag * (2.0 * std::f64::consts::PI * u2).sin();
    
    Quaternion {
        w: z1.round() as u64,
        x: z2.round() as u64,
        y: 0, // 단순화를 위해 두 요소만 사용
        z: 0
    }
}

/// 균등 분포를 따르는 랜덤 4원수를 샘플링합니다.
pub fn sample_uniform_quaternion() -> Quaternion {
    let mut rng = rand::rng();
    Quaternion::new (
        rng.random_range(0..Q_MOD),
        rng.random_range(0..Q_MOD),
        rng.random_range(0..Q_MOD),
        rng.random_range(0..Q_MOD)
    )
}
