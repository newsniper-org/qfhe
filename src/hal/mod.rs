// src/hal/mod.rs

use crate::{core::{Ciphertext, SecretKey}, Polynomial};

/// 모든 하드웨어 백엔드가 구현해야 하는 공통 연산 트레이트입니다.
pub trait HardwareBackend {
    fn homomorphic_add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn homomorphic_sub(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
    fn polynomial_add(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial;
    fn polynomial_sub(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial;
    fn polynomial_mul(&self, p1: &Polynomial, p2: &Polynomial) -> Polynomial;
    fn encrypt(&self, message: u64, secret_key: &SecretKey) -> Ciphertext;
    fn decrypt(&self, ciphertext: &Ciphertext, secret_key: &SecretKey) -> u64;
}

pub mod cpu;
pub use cpu::CpuBackend;
