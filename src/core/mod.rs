pub mod quaternion;
pub use crate::core::quaternion::Quaternion;

pub mod polynomial;
pub use crate::core::polynomial::Polynomial;

pub mod keys;
pub use crate::core::keys::{SecretKey, RelinearizationKey, KeySwitchingKey, BootstrapKey};

use crate::ntt::{power, primitive_root, BarrettReducer64};

pub mod rns;

pub use crate::core::rns::{
    Q_128_BASIS, Q_160_BASIS, Q_192_BASIS, Q_224_BASIS, Q_256_BASIS,
    MODULUS_CHAIN_128, MODULUS_CHAIN_160, MODULUS_CHAIN_192, MODULUS_CHAIN_224, MODULUS_CHAIN_256,
    converter::{integer_to_rns, rns_to_integer},
    REDUCERS_128, REDUCERS_160, REDUCERS_192, REDUCERS_224, REDUCERS_256
};

pub mod consts;

pub use crate::core::consts::{n1024, n2048};

pub mod num;
pub use crate::core::num::{SafeModuloArith, concat64x2};

pub(crate) mod u256;
pub(crate) use crate::core::u256::U256;

pub(crate) mod wide_arith;
pub(crate) use crate::core::wide_arith::{WideningAdd, WideningSimdMul, OverflowingSimdAdd, OverflowingSimdSub};

/// C FFI에서 사용할 보안 수준 열거형입니다.
#[repr(C)]
pub enum SecurityLevel {
    L128,
    L160,
    L192,
    L224,
    L256,
}

/// 미리 계산된 NTT 관련 파라미터를 저장하는 구조체
#[derive(Debug, Clone)]
pub struct NttParameters<'a> {
    pub w_primitive: u128,
    pub w_inv_primitive: u128,
    pub twiddle_lut_n1: &'a [u128],
    pub twiddle_lut_n2: &'a [u128],
    pub inv_twiddle_lut_n1: &'a [u128],
    pub inv_twiddle_lut_n2: &'a [u128],
}

const L128_NTT_PARAMS: NttParameters<'static> = NttParameters {
    w_primitive: 68238162691450256,
    w_inv_primitive: 707747518257109193,
    twiddle_lut_n1: &n1024::TWIDDLE_LUT_N1_1024,
    twiddle_lut_n2: &n1024::TWIDDLE_LUT_N2_1024,
    inv_twiddle_lut_n1: &n1024::INV_TWIDDLE_LUT_N1_1024,
    inv_twiddle_lut_n2: &n1024::INV_TWIDDLE_LUT_N2_1024
};

const L160_NTT_PARAMS: NttParameters<'static> = NttParameters {
    w_primitive: 1089679529145525629180,
    w_inv_primitive: 95788525767978893246,
    twiddle_lut_n1: &n1024::TWIDDLE_LUT_N1_1024,
    twiddle_lut_n2: &n1024::TWIDDLE_LUT_N2_1024,
    inv_twiddle_lut_n1: &n1024::INV_TWIDDLE_LUT_N1_1024,
    inv_twiddle_lut_n2: &n1024::INV_TWIDDLE_LUT_N2_1024
};

const L192_NTT_PARAMS: NttParameters<'static> = NttParameters {
    w_primitive: 1089679529145525629180,
    w_inv_primitive: 95788525767978893246,
    twiddle_lut_n1: &n1024::TWIDDLE_LUT_N1_1024,
    twiddle_lut_n2: &n1024::TWIDDLE_LUT_N2_1024,
    inv_twiddle_lut_n1: &n1024::INV_TWIDDLE_LUT_N1_1024,
    inv_twiddle_lut_n2: &n1024::INV_TWIDDLE_LUT_N2_1024
};

const L224_NTT_PARAMS: NttParameters<'static> = NttParameters {
    w_primitive: 24679949381292746831263984413215061718,
    w_inv_primitive: 127677392777263148763617266660004723698,
    twiddle_lut_n1: &n2048::TWIDDLE_LUT_N1_2048,
    twiddle_lut_n2: &n2048::TWIDDLE_LUT_N2_2048,
    inv_twiddle_lut_n1: &n2048::INV_TWIDDLE_LUT_N1_2048,
    inv_twiddle_lut_n2: &n2048::INV_TWIDDLE_LUT_N2_2048
};

const L256_NTT_PARAMS: NttParameters<'static> = NttParameters {
    w_primitive: 24679949381292746831263984413215061718,
    w_inv_primitive: 127677392777263148763617266660004723698,
    twiddle_lut_n1: &n2048::TWIDDLE_LUT_N1_2048,
    twiddle_lut_n2: &n2048::TWIDDLE_LUT_N2_2048,
    inv_twiddle_lut_n1: &n2048::INV_TWIDDLE_LUT_N1_2048,
    inv_twiddle_lut_n2: &n2048::INV_TWIDDLE_LUT_N2_2048
};


/// 각 보안 수준에 맞는 파라미터 세트를 담는 구조체입니다.
#[derive(Debug, Clone)]
pub struct QfheParameters<'a, 'b, 'c> {
    pub polynomial_degree: usize,
    pub log2_of_polynomial_degree: usize,
    pub modulus_q: &'b [u64],
    pub modulus_chain: &'a [u128],
    pub plaintext_modulus: u128,
    pub scaling_factor_delta: u128,
    pub noise_std_dev: f64,
    pub module_dimension_k: usize,
    pub gadget_base_b: u128,
    pub gadget_levels_l: usize,
    pub ntt_params: NttParameters<'c>,
    pub reducers: &'b [BarrettReducer64]
}

#[derive(Debug, Clone)]
pub struct QfheMinimalParameters<'a, 'b, 'c> {
    pub log2_of_polynomial_degree: usize,
    pub modulus_q: &'b [u64],
    pub modulus_chain: &'a [u128],
    pub plaintext_modulus: u128,
    pub scaling_factor_delta: u128,
    pub noise_std_dev: f64,
    pub module_dimension_k: usize,
    pub gadget_base_b: u128,
    pub gadget_levels_l: usize,
    pub ntt_params: NttParameters<'c>,
    pub reducers: &'b [BarrettReducer64]
}

impl<'a, 'b, 'c> QfheMinimalParameters<'a, 'b, 'c> {
    pub const fn get_full_params(self) -> QfheParameters<'a, 'b, 'c> {
        let one: usize = 1;
        QfheParameters {
            ntt_params: self.ntt_params,
            polynomial_degree: (one << self.log2_of_polynomial_degree),
            log2_of_polynomial_degree: self.log2_of_polynomial_degree,
            modulus_q: self.modulus_q,
            modulus_chain: self.modulus_chain,
            plaintext_modulus: self.plaintext_modulus,
            scaling_factor_delta: self.scaling_factor_delta,
            noise_std_dev: self.noise_std_dev,
            module_dimension_k: self.module_dimension_k,
            gadget_base_b: self.gadget_base_b,
            gadget_levels_l: self.gadget_levels_l,
            reducers: self.reducers
        }
    }
    

}

impl SecurityLevel {

    /// 선택된 보안 수준에 맞는 MLWE 파라미터 세트를 반환합니다.
    /// 이 파라미터들은 표준 FHE 및 PQC 문헌을 참고한 예시 값입니다.
    pub fn get_params(&self) -> QfheParameters<'static, 'static, 'static> {
        let minimal: QfheMinimalParameters<'static, 'static, 'static> = match self {
            // 128-bit quantum security (NIST Level 1)
            SecurityLevel::L128 => QfheMinimalParameters {
                module_dimension_k: 2,
                log2_of_polynomial_degree: 10,
                modulus_q: &Q_128_BASIS,
                modulus_chain: &MODULUS_CHAIN_128,
                plaintext_modulus: 1 << 32,
                scaling_factor_delta: 1152921504606846883 / (1 << 32),
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 8, // 8 levels * 8 bits = 64 bits coverage
                ntt_params: L128_NTT_PARAMS,
                reducers: &REDUCERS_128
            },
            // ~160-bit quantum security (Intermediate)
            SecurityLevel::L160 => QfheMinimalParameters {
                module_dimension_k: 2,
                log2_of_polynomial_degree: 10,
                modulus_q: &Q_160_BASIS,
                modulus_chain: &MODULUS_CHAIN_160,
                plaintext_modulus: 1 << 32,
                scaling_factor_delta: 1180591620717411303423 / (1 << 32),
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 9, // 9 levels * 8 bits = 72 bits coverage
                ntt_params: L160_NTT_PARAMS,
                reducers: &REDUCERS_160
            },
            // 192-bit quantum security (NIST Level 3)
            SecurityLevel::L192 => QfheMinimalParameters {
                module_dimension_k: 3,
                log2_of_polynomial_degree: 10,
                modulus_q: &Q_192_BASIS,
                modulus_chain: &MODULUS_CHAIN_192,
                plaintext_modulus: 1 << 32,
                scaling_factor_delta: 1180591620717411303423 / (1 << 32),
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 9, // 9 levels * 8 bits = 72 bits coverage
                ntt_params: L192_NTT_PARAMS,
                reducers: &REDUCERS_192
            },
            // ~224-bit quantum security (Intermediate)
            SecurityLevel::L224 => QfheMinimalParameters {
                module_dimension_k: 3,
                log2_of_polynomial_degree: 11,
                modulus_q: &Q_224_BASIS,
                modulus_chain: &MODULUS_CHAIN_224,
                plaintext_modulus: 1 << 64,
                scaling_factor_delta: 340282366920938463463374607431768211293 / (1 << 64),
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 16, // 16 levels * 8 bits = 128 bits coverage
                ntt_params: L224_NTT_PARAMS,
                reducers: &REDUCERS_224
            },
            // 256-bit quantum security (NIST Level 5)
            SecurityLevel::L256 => QfheMinimalParameters {
                module_dimension_k: 4,
                log2_of_polynomial_degree: 11,
                modulus_q: &Q_256_BASIS,
                modulus_chain: &MODULUS_CHAIN_256,
                plaintext_modulus: 1 << 64,
                scaling_factor_delta: 340282366920938463463374607431768211293 / (1 << 64),
                noise_std_dev: 3.2,
                gadget_base_b: 1 << 8,
                gadget_levels_l: 16, // 16 levels * 8 bits = 128 bits coverage
                ntt_params: L256_NTT_PARAMS,
                reducers: &REDUCERS_256
            }
        };
        minimal.get_full_params()
    }
}



/// LWE 암호문은 (a, b) 쌍으로 구성됩니다.
/// a는 4원수들의 벡터이고, b는 단일 4원수입니다.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub a_vec: Vec<Polynomial>, // k개의 다항식 벡터
    pub b: Polynomial,          // 1개의 다항식
    pub modulus_level: usize,   // 현재 모듈러스 레벨 추적 필드
}

/// GGSW 암호문은 부트스트래핑의 핵심 요소입니다.
#[derive(Clone, Debug)]
pub struct GgswCiphertext {
    pub levels: Vec<Ciphertext>,
}

/// 암호화, 복호화, 동형 연산을 위한 핵심 트레이트(trait)입니다.
pub trait QfheEngine {
    fn encrypt(&self, message: u64) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext) -> u64;
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;

    fn homomorphic_mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn bootstrap(&self, ct: &Ciphertext, test_poly: &Polynomial) -> Ciphertext;

    fn modulus_switch(&self, ct: &Ciphertext) -> Ciphertext;
}