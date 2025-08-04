// newsniper-org/qfhe/qfhe-wip-cpu-simple/src/core/rns.rs

//! RNS 기저(basis)와 관련된 상수들을 정의합니다.
//! 이 값들은 FHE 표준 및 논문을 참고하여 선정된 예시 NTT 친화 소수(NTT-friendly primes)입니다.

// --- L128 Security Level ---
// 전체 모듈러스 Q ~= 60 bits
pub const Q_128_BASIS: [u64; 1] = [
    1152921504606584833, // 60-bit prime
];
pub const MODULUS_CHAIN_128: [u128; 2] = [1125899906842597, 1099511627749];

// --- L160 Security Levels ---
// 전체 모듈러스 Q ~= 70 bits
pub const Q_160_BASIS: [u64; 2] = [
    9223372036854775783, // 63-bit prime
    13835058055282163713, // 64-bit prime
];
pub const MODULUS_CHAIN_160: [u128; 2] = [1152921504606846883, 1125899906842597];


// --- L160 & L192 Security Levels ---
// 전체 모듈러스 Q ~= 70 bits
pub const Q_192_BASIS: [u64; 2] = [
    9223372036854775783, // 63-bit prime
    13835058055282163713, // 64-bit prime
];
pub const MODULUS_CHAIN_192: [u128; 2] = [1152921504606846883, 1125899906842597];


// --- L224 Security Level ---
// 전체 모듈러스 Q ~= 125 bits
pub const Q_224_BASIS: [u64; 2] = [
    9223372036854775783,  // 63-bit prime
    18446744073709551557, // 64-bit prime
];
pub const MODULUS_CHAIN_224: [u128; 2] = [
    340282366920938463463374607431768210431, // ~128-bit
    170141183460469231731687303715884105727, // ~127-bit
];


// --- L256 Security Level ---
// 전체 모듈러스 Q ~= 125 bits (L224와 동일한 모듈러스를 사용하나, 다른 파라미터로 보안성 확보)
pub const Q_256_BASIS: [u64; 2] = [
    9223372036854775783,  // 63-bit prime
    18446744073709551557, // 64-bit prime
];
// L256은 L224와 동일한 모듈러스 체인을 공유할 수 있습니다.
pub const MODULUS_CHAIN_256: [u128; 2] = [
    340282366920938463463374607431768210431, // ~128-bit
    170141183460469231731687303715884105727, // ~127-bit
];


pub const REDUCERS_128: [BarrettReducer64; 1] = [BarrettReducer64::new(1152921504606584833)];
pub const REDUCERS_160: [BarrettReducer64; 2] = [
    BarrettReducer64::new(9223372036854775783),
    BarrettReducer64::new(13835058055282163713)
];
pub const REDUCERS_192: [BarrettReducer64; 2] = [
    BarrettReducer64::new(9223372036854775783),
    BarrettReducer64::new(13835058055282163713)
];
pub const REDUCERS_224: [BarrettReducer64; 2] = [
    BarrettReducer64::new(9223372036854775783),
    BarrettReducer64::new(18446744073709551557)
];
pub const REDUCERS_256: [BarrettReducer64; 2] = [
    BarrettReducer64::new(9223372036854775783),
    BarrettReducer64::new(18446744073709551557)
];


pub mod converter;
pub use converter::{integer_to_rns, rns_to_integer};

use crate::ntt::BarrettReducer64;