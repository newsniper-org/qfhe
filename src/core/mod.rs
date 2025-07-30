pub mod quaternion;
pub use crate::core::quaternion::Quaternion;

pub mod polynominal;
pub use crate::core::polynominal::Polynomial;

/// C FFI에서 사용할 보안 수준 열거형입니다.
#[repr(C)]
pub enum SecurityLevel {
    L128,
    L160,
    L192,
    L224,
    L256,
}

/// 각 보안 수준에 맞는 파라미터 세트를 담는 구조체입니다.
#[derive(Debug, Clone)]
pub struct QfheParameters {
    pub polynomial_degree: usize,
    pub modulus_q: u128,
    pub plaintext_modulus: u128,
    pub scaling_factor_delta: u128,
    pub noise_std_dev: f64,
    pub module_dimension_k: usize,
    pub relin_key_base: u128, // 재선형화 키를 위한 분해 기준
    pub relin_key_len: usize,   // 재선형화 키의 길이
}

impl SecurityLevel {
    /// 선택된 보안 수준에 맞는 MLWE 파라미터 세트를 반환합니다.
    pub fn get_params(&self) -> QfheParameters {
        match self {
            // 128-bit quantum security (NIST Level 1)
            SecurityLevel::L128 => {
                let n = 1024;
                let q: u128 = 1152921504606584833; // 60-bit prime, q = 1 (mod 2048)
                QfheParameters {
                    module_dimension_k: 2,
                    polynomial_degree: n,
                    modulus_q: q,
                    plaintext_modulus: 1 << 32,
                    scaling_factor_delta: q / (1 << 32),
                    noise_std_dev: 3.2,
                    relin_key_base: 1 << 30,
                    relin_key_len: 2,
                }
            },
            // ~160-bit quantum security (Intermediate)
            SecurityLevel::L160 => {
                let n = 1024;
                let q: u128 = 1180591620717411303425; // 70-bit prime, q = 1 (mod 2048)
                QfheParameters {
                    module_dimension_k: 2,
                    polynomial_degree: n,
                    modulus_q: q,
                    plaintext_modulus: 1 << 32,
                    scaling_factor_delta: q / (1 << 32),
                    noise_std_dev: 3.2,
                    relin_key_base: 1 << 35,
                    relin_key_len: 2,
                }
            },
            // 192-bit quantum security (NIST Level 3)
            SecurityLevel::L192 => {
                let n = 1024;
                let q: u128 = 1180591620717411303425; // 70-bit prime, q = 1 (mod 2048)
                QfheParameters {
                    module_dimension_k: 3,
                    polynomial_degree: n,
                    modulus_q: q,
                    plaintext_modulus: 1 << 32,
                    scaling_factor_delta: q / (1 << 32),
                    noise_std_dev: 3.2,
                    relin_key_base: 1 << 35,
                    relin_key_len: 2,
                }
            },
            // ~224-bit quantum security (Intermediate)
            SecurityLevel::L224 => {
                let n = 2048;
                // u128 범위 내의 120-bit prime, q = 1 (mod 4096)
                let q: u128 = 1329227995784915872903807060280344577;
                QfheParameters {
                    module_dimension_k: 3,
                    polynomial_degree: n,
                    modulus_q: q,
                    plaintext_modulus: 1 << 60, // plaintext 공간 조정
                    scaling_factor_delta: q / (1 << 60),
                    noise_std_dev: 3.2,
                    relin_key_base: 1 << 60,
                    relin_key_len: 2,
                }
            },
            // 256-bit quantum security (NIST Level 5)
            SecurityLevel::L256 => {
                let n = 2048;
                 // u128 범위 내의 120-bit prime, q = 1 (mod 4096)
                let q: u128 = 1329227995784915872903807060280344577;
                QfheParameters {
                    module_dimension_k: 4,
                    polynomial_degree: n,
                    modulus_q: q,
                    plaintext_modulus: 1 << 60, // plaintext 공간 조정
                    scaling_factor_delta: q / (1 << 60),
                    noise_std_dev: 3.2,
                    relin_key_base: 1 << 60,
                    relin_key_len: 2,
                }
            },
        }
    }
}

/// 비밀키는 s와 s^2을 모두 포함합니다.
pub struct SecretKey {
    pub s: Vec<Polynomial>,
    pub s_squared: Vec<Polynomial>, // For MLWE, s^2 becomes a matrix of polynomials
}

/// 재선형화 키는 암호문들의 벡터입니다.
pub struct RelinearizationKey(pub Vec<Ciphertext>);


/// LWE 암호문은 (a, b) 쌍으로 구성됩니다.
/// a는 4원수들의 벡터이고, b는 단일 4원수입니다.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub a_vec: Vec<Polynomial>, // k개의 다항식 벡터
    pub b: Polynomial,          // 1개의 다항식
}

/// 암호화, 복호화, 동형 연산을 위한 핵심 트레이트(trait)입니다.
pub trait QfheEngine {
    fn encrypt(&self, message: u64) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext) -> u64;
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
}