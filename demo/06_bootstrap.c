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
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <noisy_ct_file> <sk_file> <bk_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* noisy_ct = NULL;
    QfheResult status = qfhe_deserialize_ciphertext_from_file(&noisy_ct, argv[1]);
    CHECK_STATUS(status, "Failed to load noisy ciphertext");

    void* temp_sk_ptr = NULL;
    status = qfhe_deserialize_key_from_file_binary(&temp_sk_ptr, argv[2]);
    CHECK_STATUS(status, "Failed to load secret key");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;

    printf("Loading bootstrap key (binary) from %s...\n", argv[3]);
    void* temp_bk_ptr = NULL;
    status = qfhe_deserialize_key_from_file_binary(&temp_bk_ptr, argv[3]);
    CHECK_STATUS(status, "Failed to load bootstrap key from binary file");
    BootstrapKey* bk = (BootstrapKey*)temp_bk_ptr;

    SecurityLevel level = L128;
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, NULL, bk, NULL); 

    Polynomial* test_poly = qfhe_create_test_poly_f_2x(level);

    printf("Bootstrapping noisy ciphertext with f(x)=2x...\n");
    Ciphertext* bootstrapped_ct = qfhe_bootstrap(eval_ctx, noisy_ct, test_poly);
    
    status = qfhe_serialize_ciphertext_to_file(bootstrapped_ct, level, argv[4]);
    if (status == Success) {
        printf(" -> Result saved to %s\n", argv[4]);
    } else {
        fprintf(stderr, "Error: Failed to save bootstrapped ciphertext (status code: %d)\n", status);
    }

    DecryptionContext* dec_ctx = qfhe_create_decryption_context(level, sk);
    uint64_t final_msg = qfhe_decrypt(dec_ctx, bootstrapped_ct);
    printf(" -> Decrypted bootstrapped message: %" PRIu64 "\n", final_msg);

    qfhe_ciphertext_destroy(noisy_ct);
    qfhe_secret_key_destroy(sk);
    qfhe_bootstrap_key_destroy(bk);
    qfhe_polynomial_destroy(test_poly);
    qfhe_ciphertext_destroy(bootstrapped_ct);
    qfhe_destroy_evaluation_context(eval_ctx);
    qfhe_destroy_decryption_context(dec_ctx);
    
    return 0;
}