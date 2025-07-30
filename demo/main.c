// demo/main.c

#include <stdio.h>
#include <stdint.h>
#include "../include/qfhe.h"

void run_demo_for_level(SecurityLevel level, const char* level_name) {
    printf("\n--- %s 보안 수준으로 데모 실행 ---\n", level_name);

    QfheContext* context = qfhe_context_create(level);
    if (!context) {
        printf("오류: 컨텍스트 생성 실패\n");
        return;
    }
    printf("1. 컨텍스트 생성 완료\n");

    uint64_t msg1 = 100;
    uint64_t msg2 = 42;
    printf("2. 평문 메시지: %llu, %llu\n", (unsigned long long)msg1, (unsigned long long)msg2);

    Ciphertext* ct1 = qfhe_encrypt(context, msg1);
    Ciphertext* ct2 = qfhe_encrypt(context, msg2);
    printf("3. 메시지 암호화 완료\n");

    Ciphertext* ct_sum = qfhe_homomorphic_add(context, ct1, ct2);
    printf("4. 동형 덧셈 완료\n");

    uint64_t decrypted_sum = qfhe_decrypt(context, ct_sum);
    printf("5. 결과 복호화 완료\n");

    printf("\n--- 검증 ---\n");
    uint64_t expected_sum = msg1 + msg2;
    printf("복호화된 합계: %llu (예상: %llu)\n", (unsigned long long)decrypted_sum, (unsigned long long)expected_sum);
    if (decrypted_sum == expected_sum) {
        printf(" -> 검증 성공!\n");
    } else {
        printf(" -> 검증 실패!\n");
    }

    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_sum);
    qfhe_context_destroy(context);
    printf("6. 메모리 해제 완료\n");
}

int main() {
    run_demo_for_level(L128, "128-bit");
    run_demo_for_level(L160, "160-bit");
    run_demo_for_level(L192, "192-bit");
    run_demo_for_level(L224, "224-bit");
    run_demo_for_level(L256, "256-bit");

    return 0;
}
