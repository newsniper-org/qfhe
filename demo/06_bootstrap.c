// demo/06_bootstrap.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define CHECK_STATUS(status, message) \
    do { \
        if (status != Success) { \
            fprintf(stderr, "Error: %s (status code: %d)\n", message, status); \
            exit(1); \
        } \
    } while (0)

int main(int argc, char* argv[]) {
    if (argc != 6) {
        // Usage: <noisy_ct> <sk_file> <bk_FILE_PATH> <output_ct>
        fprintf(stderr, "Usage: %s <noisy_ct_file> <sk_file> <bk_file_path> <bk_index_file_path> <output_ct_file>\n", argv[0]);
        return 1;
    }
    
    char* noisy_ct_file = argv[1];
    char* sk_file = argv[2];
    char* bk_file_path = argv[3]; // 이제 파일 경로를 직접 받습니다.
    char* bk_idx_file_path = argv[4]; // 이제 파일 경로를 직접 받습니다.
    char* output_ct_file = argv[5];

    void* noisy_ct = NULL;
    QfheResult status = qfhe_deserialize_object_from_file(&noisy_ct, noisy_ct_file);
    CHECK_STATUS(status, "Failed to load noisy ciphertext");

    void* temp_sk_ptr = NULL;
    status = qfhe_deserialize_object_from_file(&temp_sk_ptr, sk_file);
    CHECK_STATUS(status, "Failed to load secret key");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;

    SecurityLevel level = L128;

    printf("Creating evaluation context with memory-mapped bootstrap key from '%s'...\n", bk_file_path);
    // 컨텍스트 생성 시 더 이상 bk 포인터가 아닌 파일 경로를 전달합니다.
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, NULL, bk_file_path, bk_idx_file_path, NULL);
    if (!eval_ctx) {
        fprintf(stderr, "Error: Failed to create evaluation context with memory-mapped key.\n");
        exit(1);
    }

    Polynomial* test_poly = qfhe_create_test_poly_f_2x(level);

    printf("Bootstrapping noisy ciphertext with f(x)=2x...\n");
    Ciphertext* bootstrapped_ct = qfhe_bootstrap(eval_ctx, noisy_ct, test_poly);
    
    status = qfhe_serialize_object_to_file(bootstrapped_ct, CT, level, output_ct_file);
    if (status == Success) {
        printf(" -> Result saved to %s\n", output_ct_file);
    } else {
        fprintf(stderr, "Error: Failed to save bootstrapped ciphertext (status code: %d)\n", status);
    }

    DecryptionContext* dec_ctx = qfhe_create_decryption_context(level, sk);
    uint64_t final_msg = qfhe_decrypt(dec_ctx, bootstrapped_ct);
    printf(" -> Decrypted bootstrapped message: %" PRIu64 "\n", final_msg);

    qfhe_ciphertext_destroy(noisy_ct);
    qfhe_secret_key_destroy(sk);
    // BootstrapKey 객체는 더 이상 C에서 관리하지 않으므로 destroy 호출이 필요 없습니다.
    qfhe_polynomial_destroy(test_poly);
    qfhe_ciphertext_destroy(bootstrapped_ct);
    qfhe_destroy_evaluation_context(eval_ctx);
    qfhe_destroy_decryption_context(dec_ctx);
    
    return 0;
}