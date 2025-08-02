#![feature(portable_simd)]

// 라이브러리의 각 모듈을 선언합니다.
pub mod core;
pub mod hal;
pub mod ffi;
pub mod ntt;

// --- Public API ---
// 라이브러리 사용자가 직접 접근할 수 있는 핵심 기능들을 공개(re-export)합니다.
pub use crate::core::{QfheEngine, Ciphertext, SimdPolynomial, Quaternion, SecretKey,
    QfheParameters};
pub use crate::ffi::QfheContext;
pub use crate::ntt::{BarrettReducer, Ntt, qntt::{SplitSimdPolynomial,split,merge,qntt_forward,qntt_pointwise_mul,qntt_inverse}};