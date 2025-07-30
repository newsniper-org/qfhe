// demo/main.c

#include <stdio.h>
#include <stdint.h>
#include "../include/qfhe.h"

void run_demo_for_level(SecurityLevel level, const char* level_name) {
    printf("\n--- %s 보안 수준으로 데모 실행 ---\n", level_name);
    QfheContext* context = qfhe_context_create(level);
    if (!context) { /* ... error handling ... */ return; }
    printf("1. 컨텍스트 생성 완료\n");

    uint64_t msg1 = 7;
    uint64_t msg2 = 6;
    printf("2. 평문 메시지: %llu, %llu\n", (unsigned long long)msg1, (unsigned long long)msg2);

    Ciphertext* ct1 = qfhe_encrypt(context, msg1);
    Ciphertext* ct2 = qfhe_encrypt(context, msg2);
    printf("3. 메시지 암호화 완료\n");

    printf("4. 동형 연산 수행 중...\n");
    Ciphertext* ct_sum = qfhe_homomorphic_add(context, ct1, ct2);
    Ciphertext* ct_mul = qfhe_homomorphic_mul(context, ct1, ct2);

    printf("5. 결과 복호화 중...\n");
    uint64_t decrypted_sum = qfhe_decrypt(context, ct_sum);
    uint64_t decrypted_mul = qfhe_decrypt(context, ct_mul);

    printf("\n--- 검증 ---\n");
    uint64_t expected_sum = msg1 + msg2;
    uint64_t expected_mul = msg1 * msg2;

    printf("복호화된 합계: %llu (예상: %llu)\n", (unsigned long long)decrypted_sum, (unsigned long long)expected_sum);
    if (decrypted_sum == expected_sum) { printf(" -> 덧셈 검증 성공!\n"); } 
    else { printf(" -> 덧셈 검증 실패!\n"); }
    
    printf("복호화된 곱셈: %llu (예상: %llu)\n", (unsigned long long)decrypted_mul, (unsigned long long)expected_mul);
    if (decrypted_mul == expected_mul) { printf(" -> 곱셈 검증 성공!\n"); }
    else { printf(" -> 곱셈 검증 실패!\n"); }

    printf("\n6. 모든 객체 메모리 해제 중...\n");
    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_sum);
    qfhe_ciphertext_destroy(ct_mul);
    qfhe_context_destroy(context);
}

int main() {
    run_demo_for_level(L128, "128-bit");
    // Other levels are computationally intensive and may be slow
    // run_demo_for_level(L192, "192-bit");
    return 0;
}
