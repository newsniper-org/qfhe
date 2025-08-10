pub mod quaternion;
pub use crate::core::quaternion::Quaternion;

pub mod polynomial;
pub use crate::core::polynomial::Polynomial;

pub mod keys;

use crate::ntt::{power, primitive_root, BarrettReducer64};

pub mod rns;

pub use crate::core::rns::{
    Q_128_BASIS, Q_192_BASIS, Q_256_BASIS,
    converter::{integer_to_rns, rns_to_integer},
    REDUCERS_128, REDUCERS_192, REDUCERS_256
};

pub mod consts;

pub use crate::core::consts::{n2048, n4096, n8192};

pub mod num;
pub use crate::core::num::{SafeModuloArith, concat64x2};

pub(crate) mod wide_arith;
pub(crate) use crate::core::wide_arith::WideningArith;

use serde::{Serialize, Deserialize};

use crypto_bigint::{U256, U512};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct U512Wrapper(U512);

impl U512Wrapper {
    const ONE: Self = Self(U512::ONE);

    fn widening_mul(&self, rhs: &U256) -> Self {
        Self(self.0.widening_mul(rhs).resize())
    }

    fn div_rem(&self, rhs: &U256) -> (Self, U256) {
        let (q, r) = self.0.div_rem(&crypto_bigint::NonZero::new(rhs.resize()).unwrap());
        (Self(q), r.resize())
    }

    fn to_words(&self) -> [u64; 8] {
        self.0.to_words()
    }
}



/// C FFI에서 사용할 보안 수준 열거형입니다.
/// 
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum SecurityLevel {
    L128,
    L192,
    L256,
}

/// 각 보안 수준에 맞는 파라미터 세트를 담는 구조체입니다.
#[derive(Debug, Clone)]
pub struct QfheParameters<'a> {
    pub polynomial_degree: usize,
    pub log2_of_polynomial_degree: usize,
    pub modulus_q: &'a [u64],
    pub plaintext_modulus: u128,
    pub scaling_factor_delta: u128,
    pub noise_std_dev: f64,
    pub gadget_base_b: u128,
    pub gadget_levels_l: usize,
    pub reducers: &'a [BarrettReducer64]
}

#[derive(Debug, Clone)]
pub struct QfheMinimalParameters<'a> {
    pub log2_of_polynomial_degree: usize,
    pub modulus_q: &'a [u64],
    pub plaintext_modulus: u128,
    pub noise_std_dev: f64,
    pub gadget_base_b: u128,
    pub gadget_levels_l: usize,
    pub reducers: &'a [BarrettReducer64]
}

impl<'a> QfheMinimalParameters<'a> {
    pub fn get_full_params(self) -> QfheParameters<'a> {
        let one: usize = 1;
        // ✅ FIX: `scaling_factor_delta`를 `modulus_q`로부터 동적으로 계산합니다.
        let q_product = self.modulus_q.iter().fold(U512Wrapper::ONE, |acc, &m| {
            acc.widening_mul(&U256::from_u64(m))
        });
        
        let scaling_factor_delta = q_product.div_rem(&U256::from(self.plaintext_modulus)).0.to_words()[0] as u128;
        QfheParameters {
            polynomial_degree: (one << self.log2_of_polynomial_degree),
            log2_of_polynomial_degree: self.log2_of_polynomial_degree,
            modulus_q: self.modulus_q,
            plaintext_modulus: self.plaintext_modulus,
            scaling_factor_delta,
            noise_std_dev: self.noise_std_dev,
            gadget_base_b: self.gadget_base_b,
            gadget_levels_l: self.gadget_levels_l,
            reducers: self.reducers
        }
    }
    

}


impl SecurityLevel {

    /// 선택된 보안 수준에 맞는 MLWE 파라미터 세트를 반환합니다.
    /// 이 파라미터들은 표준 FHE 및 PQC 문헌을 참고한 예시 값입니다.
    pub fn get_params(&self) -> QfheParameters<'static> {
        let minimal: QfheMinimalParameters<'static> = match self {
            // 128-bit quantum security (NIST Level 1)
            SecurityLevel::L128 => QfheMinimalParameters {
                log2_of_polynomial_degree: 11,
                modulus_q: &Q_128_BASIS,
                plaintext_modulus: 1 << 32,
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 14,
                reducers: &REDUCERS_128
            },
            // 192-bit quantum security (NIST Level 3)
            SecurityLevel::L192 => QfheMinimalParameters {
                log2_of_polynomial_degree: 12,
                modulus_q: &Q_192_BASIS,
                plaintext_modulus: 1 << 32,
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 28,
                reducers: &REDUCERS_192
            },
            // 256-bit quantum security (NIST Level 5)
            SecurityLevel::L256 => QfheMinimalParameters {
                log2_of_polynomial_degree: 13,
                modulus_q: &Q_256_BASIS,
                plaintext_modulus: 1 << 64,
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 55,
                reducers: &REDUCERS_256
            }
        };
        minimal.get_full_params()
    }
}

/// ✅ RLWE: 암호문은 (c0, c1) 쌍으로 구성됩니다.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ciphertext {
    pub c0: Polynomial,
    pub c1: Polynomial,
    pub modulus_level: usize,
}

/// GGSW 암호문은 부트스트래핑의 핵심 요소입니다.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GgswCiphertext {
    pub levels: Vec<Ciphertext>,
}

/// 암호화, 복호화, 동형 연산을 위한 핵심 트레이트(trait)입니다.
pub trait EncryptionEngine {
    fn encrypt(&self, message: u64) -> Ciphertext;
}

pub trait DecryptionEngine {
    fn decrypt(&self, ciphertext: &Ciphertext) -> u64;
}

pub trait EvaluationEngine {
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_conjugate(&self, ct: &Ciphertext) -> Ciphertext; // 예시 오토모피즘 연산
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial) -> Ciphertext;
    fn modulus_switch(&self, ct: &Ciphertext) -> Ciphertext;
}
