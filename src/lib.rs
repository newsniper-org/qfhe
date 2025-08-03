#![feature(bigint_helper_methods)]
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
pub use crate::ntt::{BarrettReducer, Ntt, qntt::{SplitPolynomial, split, merge, qntt_forward, qntt_inverse, qntt_pointwise_mul}};
pub use crate::hal::{HardwareBackend, CpuBackend};

// --- 테스트 모듈 ---
// `cargo test` 명령어를 실행할 때만 컴파일되고 실행됩니다.
#[cfg(test)]
mod tests {
    use super::QfheContext; 
    use super::ffi::{qfhe_context_create, qfhe_context_destroy};
    
    #[test]
    fn test_encryption_decryption_large_numbers() {
        println!("--- 64비트 암호화/복호화 정확성 테스트 시작 ---");
        
        let context_ptr = unsafe { qfhe_context_create(crate::core::SecurityLevel::L128) };
        let context = unsafe { &*(context_ptr as *mut QfheContext) };
        println!("테스트 컨텍스트 생성 완료.");

        let messages: [u64; 3] = [42, 100, u64::MAX / 2];

        for &message in &messages {
            println!("테스트 메시지: {}", message);
            let ciphertext = context.encrypt(message);
            println!("메시지 암호화 완료.");
            let decrypted_message = context.decrypt(&ciphertext);
            println!("암호문 복호화 완료. 복호화된 메시지: {}", decrypted_message);
            assert_eq!(message, decrypted_message, "메시지 {}에 대한 암복호화 실패!", message);
            println!("메시지 {} 검증 성공!", message);
        }
        
        unsafe { qfhe_context_destroy(context_ptr) };
        println!("--- 64비트 암호화/복호화 정확성 테스트 종료 ---\n");
    }

    #[test]
    fn test_homomorphic_addition_large_numbers() {
        println!("--- 64비트 동형 덧셈 정확성 테스트 시작 ---");

        let context_ptr = unsafe { qfhe_context_create(crate::core::SecurityLevel::L128) };
        let context = unsafe { &*(context_ptr as *mut QfheContext) };
        println!("테스트 컨텍스트 생성 완료.");

        let msg1: u64 = 42;
        let msg2: u64 = 100;
        // 64비트 공간에서는 모듈러 연산 없이 단순 덧셈
        let expected_sum = msg1 + msg2;
        println!("메시지 1: {}, 메시지 2: {}. 예상 결과: {}", msg1, msg2, expected_sum);

        let ct1 = context.encrypt(msg1);
        let ct2 = context.encrypt(msg2);
        println!("두 메시지 암호화 완료.");

        let ct_sum = context.homomorphic_add(&ct1, &ct2);
        println!("동형 덧셈 완료.");

        let decrypted_sum = context.decrypt(&ct_sum);
        println!("결과 암호문 복호화 완료. 복호화된 합계: {}", decrypted_sum);

        assert_eq!(expected_sum, decrypted_sum, "동형 덧셈 실패!");
        println!("동형 덧셈 검증 성공!");

        unsafe { qfhe_context_destroy(context_ptr) };
        println!("--- 64비트 동형 덧셈 정확성 테스트 종료 ---");
    }

    #[test]
    fn test_homomorphic_subtraction_large_numbers() {
        println!("--- 64비트 동형 뺄셈 정확성 테스트 시작 ---");

        let context_ptr = unsafe { qfhe_context_create(crate::core::SecurityLevel::L128) };
        let context = unsafe { &*(context_ptr as *mut QfheContext) };
        println!("테스트 컨텍스트 생성 완료.");

        let msg1: u64 = 100;
        let msg2: u64 = 42;
        let expected_sub = msg1 - msg2;
        println!("메시지 1: {}, 메시지 2: {}. 예상 결과: {}", msg1, msg2, expected_sub);

        let ct1 = context.encrypt(msg1);
        let ct2 = context.encrypt(msg2);
        println!("두 메시지 암호화 완료.");

        let ct_sub = context.homomorphic_sub(&ct1, &ct2);
        println!("동형 뺄셈 완료.");

        let decrypted_sub = context.decrypt(&ct_sub);
        println!("결과 암호문 복호화 완료. 복호화된 차: {}", decrypted_sub);

        assert_eq!(expected_sub, decrypted_sub, "동형 뺄셈 실패!");
        println!("동형 뺄셈 검증 성공!");

        unsafe { qfhe_context_destroy(context_ptr) };
        println!("--- 64비트 동형 뺄셈 정확성 테스트 종료 ---");
    }
}
