pub mod quaternion;
pub use crate::core::quaternion::Quaternion;

pub mod polynominal;
pub use crate::core::polynominal::Polynomial;


// --- 암호화 파라미터 정의 ---
// --- 64비트 메시지 공간을 위한 파라미터 재조정 ---
pub const POLYNOMIAL_DEGREE: usize = 2048; // 보안 강화를 위해 차수 증가
pub const MODULUS_Q: u128 = 340282366920938463463374607431768211293; // 125-bit prime: (1 << 125) - 159
pub const PLAINTEXT_MODULUS: u128 = 1 << 64; // 64비트 메시지 공간
pub const SCALING_FACTOR_DELTA: u128 = MODULUS_Q / PLAINTEXT_MODULUS;
pub const NOISE_STD_DEV: f64 = 3.2; // 오차 분포는 유지 (더 큰 파라미터로 인해 상대적으로 작아짐)

// --- 새로운 데이터 구조 ---

/// 비밀키는 4원수들의 벡터입니다.
#[repr(C)]
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
    fn encrypt(&self, message: u64) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext) -> u64;
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
}
