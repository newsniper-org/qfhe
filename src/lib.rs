// 라이브러리의 각 모듈을 선언합니다.
pub mod core;
pub mod hal;
pub mod ffi;

// --- Public API ---
// 라이브러리 사용자가 직접 접근할 수 있는 핵심 기능들을 공개(re-export)합니다.
pub use crate::core::{QfheEngine, Ciphertext, Polynomial, Quaternion};
pub use crate::ffi::QfheContext;


// --- 테스트 모듈 ---
// `cargo test` 명령어를 실행할 때만 컴파일되고 실행됩니다.
#[cfg(test)]
mod tests {
    // 라이브러리의 공개 API를 직접 사용합니다.
    use super::{QfheContext}; 
    use super::ffi::qfhe_context_create; // 컨텍스트 생성은 FFI 함수를 통해 수행
    
    /// 암호화와 복호화가 정확히 동작하는지 테스트합니다.
    #[test]
    fn test_encryption_decryption() {
        println!("--- 암호화/복호화 정확성 테스트 시작 ---");
        
        // 1. 컨텍스트(비밀키 포함)를 생성합니다.
        // FFI를 통해 생성된 컨텍스트를 안전한 Rust 타입으로 변환합니다.
        let context_ptr = qfhe_context_create();
        let context = unsafe { &*(context_ptr as *mut QfheContext) };
        println!("테스트 컨텍스트 생성 완료.");

        // 2. 테스트할 메시지를 정의합니다. (0부터 15까지)
        for message in 0..16 {
            println!("테스트 메시지: {}", message);

            // 3. 메시지를 암호화합니다. (안전한 Rust API 호출)
            let ciphertext = context.encrypt(message);
            println!("메시지 암호화 완료.");

            // 4. 암호문을 복호화합니다. (안전한 Rust API 호출)
            let decrypted_message = context.decrypt(&ciphertext);
            println!("암호문 복호화 완료. 복호화된 메시지: {}", decrypted_message);

            // 5. 원본 메시지와 복호화된 메시지가 일치하는지 확인합니다.
            assert_eq!(message, decrypted_message, "메시지 {}에 대한 암복호화 실패!", message);
            println!("메시지 {} 검증 성공!", message);
        }
        
        // 컨텍스트 메모리 해제
        crate::ffi::qfhe_context_destroy(context as *const _ as *mut _);
        println!("--- 암호화/복호화 정확성 테스트 종료 ---\n");
    }

    /// 동형 덧셈이 정확히 동작하는지 테스트합니다.
    #[test]
    fn test_homomorphic_addition() {
        println!("--- 동형 덧셈 정확성 테스트 시작 ---");

        // 1. 컨텍스트를 생성합니다.
        let context_ptr = qfhe_context_create();
        let context = unsafe { &*(context_ptr as *mut QfheContext) };
        println!("테스트 컨텍스트 생성 완료.");

        // 2. 테스트할 두 메시지를 정의합니다.
        let msg1: u64 = 5;
        let msg2: u64 = 7;
        let expected_sum = (msg1 + msg2) % 16; // 4비트 메시지 공간에서의 덧셈
        println!("메시지 1: {}, 메시지 2: {}. 예상 결과: {}", msg1, msg2, expected_sum);

        // 3. 각 메시지를 암호화합니다.
        let ct1 = context.encrypt(msg1);
        let ct2 = context.encrypt(msg2);
        println!("두 메시지 암호화 완료.");

        // 4. 두 암호문을 동형적으로 더합니다.
        let ct_sum = context.homomorphic_add(&ct1, &ct2);
        println!("동형 덧셈 완료.");

        // 5. 결과 암호문을 복호화합니다.
        let decrypted_sum = context.decrypt(&ct_sum);
        println!("결과 암호문 복호화 완료. 복호화된 합계: {}", decrypted_sum);

        // 6. 복호화된 결과가 예상 결과와 일치하는지 확인합니다.
        assert_eq!(expected_sum, decrypted_sum, "동형 덧셈 실패!");
        println!("동형 덧셈 검증 성공!");

        // 컨텍스트 메모리 해제
        crate::ffi::qfhe_context_destroy(context as *const _ as *mut _);
        println!("--- 동형 덧셈 정확성 테스트 종료 ---");
    }
}