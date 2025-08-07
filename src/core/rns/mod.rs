// src/core/rns/mod.rs

//! RNS 기저(basis)와 관련된 상수들을 정의합니다.
//! 이 값들은 Homomorphic Encryption Security Standard를 준수하는
//! RLWE 친화적인 NTT 소수(NTT-friendly primes)들입니다.

use crate::ntt::BarrettReducer64;

// --- ✅ NEW (RLWE Standard): 128-bit Security Level (n=2048, logQ ≈ 109) ---
pub const Q_128_BASIS: [u64; 2] = [
    36028797018963969,  // 55-bit prime (2^55 - 2^11 + 1)
    35184371884033,     // 55-bit prime (2^55 - 2^23 + 1) - Example prime
];
pub const REDUCERS_128: [BarrettReducer64; 2] = [
    BarrettReducer64::new(Q_128_BASIS[0]),
    BarrettReducer64::new(Q_128_BASIS[1]),
];

// --- ✅ NEW (RLWE Standard): 192-bit Security Level (n=4096, logQ ≈ 218) ---
pub const Q_192_BASIS: [u64; 4] = [
    288230376151748609, // 58-bit
    288230376152698881, // 58-bit
    288230376154009601, // 58-bit
    288230376154501121, // 58-bit
];
pub const REDUCERS_192: [BarrettReducer64; 4] = [
    BarrettReducer64::new(Q_192_BASIS[0]),
    BarrettReducer64::new(Q_192_BASIS[1]),
    BarrettReducer64::new(Q_192_BASIS[2]),
    BarrettReducer64::new(Q_192_BASIS[3]),
];

// --- ✅ NEW (RLWE Standard): 256-bit Security Level (n=8192, logQ ≈ 438) ---
pub const Q_256_BASIS: [u64; 8] = [
    288230376151748609, // 58-bit
    288230376152698881, // 58-bit
    288230376154009601, // 58-bit
    288230376154501121, // 58-bit
    288230376154566657, // 58-bit
    288230376155287553, // 58-bit
    288230376155779073, // 58-bit
    288230376156172289, // 58-bit
];
pub const REDUCERS_256: [BarrettReducer64; 8] = [
    BarrettReducer64::new(Q_256_BASIS[0]),
    BarrettReducer64::new(Q_256_BASIS[1]),
    BarrettReducer64::new(Q_256_BASIS[2]),
    BarrettReducer64::new(Q_256_BASIS[3]),
    BarrettReducer64::new(Q_256_BASIS[4]),
    BarrettReducer64::new(Q_256_BASIS[5]),
    BarrettReducer64::new(Q_256_BASIS[6]),
    BarrettReducer64::new(Q_256_BASIS[7]),
];

pub mod converter;
pub use converter::{integer_to_rns, rns_to_integer};
