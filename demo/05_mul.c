// demo/05_mul.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK_STATUS(status, message) \
    do { \
        if (status != Success) { \
            fprintf(stderr, "Error: %s (status code: %d)\n", message, status); \
            exit(1); \
        } \
    } while (0)

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <rlk_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* ct1 = NULL;
    QfheResult status = qfhe_deserialize_ciphertext_from_file(&ct1, argv[1]);
    CHECK_STATUS(status, "Failed to load first ciphertext");

    Ciphertext* ct2 = NULL;
    status = qfhe_deserialize_ciphertext_from_file(&ct2, argv[2]);
    CHECK_STATUS(status, "Failed to load second ciphertext");

    void* temp_rlk_ptr = NULL;
    status = qfhe_deserialize_key_from_file_binary(&temp_rlk_ptr, argv[3]);
    CHECK_STATUS(status, "Failed to load relinearization key");
    RelinearizationKey* rlk = (RelinearizationKey*)temp_rlk_ptr;

    SecurityLevel level = L128;
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, rlk, NULL, NULL); 

    printf("Performing homomorphic multiplication...\n");
    Ciphertext* ct_mul = qfhe_homomorphic_mul(eval_ctx, ct1, ct2);
    
    status = qfhe_serialize_ciphertext_to_file(ct_mul, level, argv[4]);
    if (status == Success) {
        printf(" -> Result saved to %s\n", argv[4]);
    } else {
        fprintf(stderr, "Error: Failed to save result ciphertext (status code: %d)\n", status);
    }

    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_relinearization_key_destroy(rlk);
    qfhe_ciphertext_destroy(ct_mul);
    qfhe_destroy_evaluation_context(eval_ctx);
    
    return 0;
}