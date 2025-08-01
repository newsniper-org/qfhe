pub mod quaternion;
pub use crate::core::quaternion::Quaternion;

pub mod polynominal;
pub use crate::core::polynominal::Polynomial;

pub mod keys;
pub use crate::core::keys::{SecretKey, RelinearizationKey};

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
    pub module_dimension_k: usize
}

impl SecurityLevel {
    /// 선택된 보안 수준에 맞는 MLWE 파라미터 세트를 반환합니다.
    /// 이 파라미터들은 표준 FHE 및 PQC 문헌을 참고한 예시 값입니다.
    pub fn get_params(&self) -> QfheParameters {
        match self {
            // 128-bit quantum security (NIST Level 1)
            SecurityLevel::L128 => QfheParameters {
                module_dimension_k: 2,
                polynomial_degree: 1024,
                modulus_q: 1152921504606846883, // ~60-bit prime
                plaintext_modulus: 1 << 32,
                scaling_factor_delta: 1152921504606846883 / (1 << 32),
                noise_std_dev: 3.2,
            },
            // ~160-bit quantum security (Intermediate)
            SecurityLevel::L160 => QfheParameters {
                module_dimension_k: 2,
                polynomial_degree: 1024,
                modulus_q: 1180591620717411303423, // ~70-bit prime
                plaintext_modulus: 1 << 32,
                scaling_factor_delta: 1180591620717411303423 / (1 << 32),
                noise_std_dev: 3.2,
            },
            // 192-bit quantum security (NIST Level 3)
            SecurityLevel::L192 => QfheParameters {
                module_dimension_k: 3,
                polynomial_degree: 1024,
                modulus_q: 1180591620717411303423, // ~70-bit prime
                plaintext_modulus: 1 << 32,
                scaling_factor_delta: 1180591620717411303423 / (1 << 32),
                noise_std_dev: 3.2,
            },
            // ~224-bit quantum security (Intermediate)
            SecurityLevel::L224 => QfheParameters {
                module_dimension_k: 3,
                polynomial_degree: 2048,
                modulus_q: 340282366920938463463374607431768211293, // 125-bit prime
                plaintext_modulus: 1 << 64,
                scaling_factor_delta: 340282366920938463463374607431768211293 / (1 << 64),
                noise_std_dev: 3.2,
            },
            // 256-bit quantum security (NIST Level 5)
            SecurityLevel::L256 => QfheParameters {
                module_dimension_k: 4,
                polynomial_degree: 2048,
                modulus_q: 340282366920938463463374607431768211293, // 125-bit prime
                plaintext_modulus: 1 << 64,
                scaling_factor_delta: 340282366920938463463374607431768211293 / (1 << 64),
                noise_std_dev: 3.2,
            },
        }
    }
}



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
