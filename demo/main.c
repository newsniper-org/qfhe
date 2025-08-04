// newsniper-org/qfhe/qfhe-wip-cpu-simple/demo/main.c

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h> // For PRIu64 macro
#include "../include/qfhe.h"

typedef void QfheContext;
typedef void Ciphertext;

// 각 보안 수준에 대한 테스트를 실행하는 함수
void run_demo_for_level(SecurityLevel level, const char* level_name) {
    printf("\n--- Running Demo for %s Security Level ---\n", level_name);

    // 1. 컨텍스트 생성
    // Rust FFI에서 'static 라이프타임을 가진 컨텍스트를 반환합니다.
    QfheContext* context = qfhe_context_create(level);
    if (!context) {
        printf("Error: Failed to create context.\n");
        return;
    }
    printf("1. Context created successfully.\n");

    // 2. 평문 메시지 준비
    uint64_t msg1 = 25;
    uint64_t msg2 = 10;
    printf("2. Plaintext messages: msg1 = %" PRIu64 ", msg2 = %" PRIu64 "\n", msg1, msg2);

    // 3. 메시지 암호화
    Ciphertext* ct1 = qfhe_encrypt(context, msg1);
    Ciphertext* ct2 = qfhe_encrypt(context, msg2);
    if (!ct1 || !ct2) {
        printf("Error: Encryption failed.\n");
        qfhe_context_destroy(context);
        return;
    }
    printf("3. Messages encrypted successfully.\n");

    // 4. 동형 덧셈
    Ciphertext* ct_add = qfhe_homomorphic_add(context, ct1, ct2);
    if (!ct_add) {
        printf("Error: Homomorphic addition failed.\n");
        // Clean up before returning
        qfhe_ciphertext_destroy(ct1);
        qfhe_ciphertext_destroy(ct2);
        qfhe_context_destroy(context);
        return;
    }
    printf("4. Homomorphic addition completed.\n");
    
    // 5. 동형 곱셈
    Ciphertext* ct_mul = qfhe_homomorphic_mul(context, ct1, ct2);
    if (!ct_mul) {
        printf("Error: Homomorphic multiplication failed.\n");
        // Clean up before returning
        qfhe_ciphertext_destroy(ct1);
        qfhe_ciphertext_destroy(ct2);
        qfhe_ciphertext_destroy(ct_add);
        qfhe_context_destroy(context);
        return;
    }
    printf("5. Homomorphic multiplication completed.\n");

    // 6. 결과 복호화
    uint64_t decrypted_add = qfhe_decrypt(context, ct_add);
    uint64_t decrypted_mul = qfhe_decrypt(context, ct_mul);
    printf("6. Results decrypted.\n");

    // 7. 결과 검증
    printf("\n--- Verification ---\n");
    uint64_t expected_add = msg1 + msg2;
    printf("Addition: Expected %" PRIu64 " + %" PRIu64 " = %" PRIu64 ", Got %" PRIu64 "\n", msg1, msg2, expected_add, decrypted_add);
    if (decrypted_add == expected_add) {
        printf(" -> Addition VERIFIED! ✅\n");
    } else {
        printf(" -> Addition FAILED! ❌\n");
    }

    uint64_t expected_mul = msg1 * msg2;
    printf("Multiplication: Expected %" PRIu64 " * %" PRIu64 " = %" PRIu64 ", Got %" PRIu64 "\n", msg1, msg2, expected_mul, decrypted_mul);
    if (decrypted_mul == expected_mul) {
        printf(" -> Multiplication VERIFIED! ✅\n");
    } else {
        printf(" -> Multiplication FAILED! ❌\n");
    }

    // 8. 메모리 해제
    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_add);
    qfhe_ciphertext_destroy(ct_mul);
    qfhe_context_destroy(context);
    printf("8. Memory freed successfully.\n");
}

int main() {
    // 현재 L128 보안 수준에 대한 파라미터만 완전하게 정의되어 있으므로, L128만 테스트합니다.
    run_demo_for_level(L128, "L128");
    
    // 다른 보안 수준들은 get_params 함수에서 완전하게 구현된 후 활성화할 수 있습니다.
    // run_demo_for_level(L160, "L160");
    // run_demo_for_level(L192, "L192");
    // run_demo_for_level(L224, "L224");
    // run_demo_for_level(L256, "L256");

    return 0;
}
