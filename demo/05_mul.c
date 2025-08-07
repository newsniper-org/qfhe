// demo/05_mul.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <rlk_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* ct1 = qfhe_deserialize_ciphertext_from_file(argv[1]);
    Ciphertext* ct2 = qfhe_deserialize_ciphertext_from_file(argv[2]);
    RelinearizationKey* rlk = (RelinearizationKey*)qfhe_deserialize_key_from_file(RLK, argv[3]);
    if (!ct1 || !ct2 || !rlk) {
        fprintf(stderr, "Error loading inputs.\n");
        return 1;
    }

    SecurityLevel level = L128;
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, rlk, NULL, NULL); // Mul only needs RLK

    printf("Performing homomorphic multiplication with relinearization...\n");
    Ciphertext* ct_mul = qfhe_homomorphic_mul(eval_ctx, ct1, ct2);
    
    qfhe_serialize_ciphertext_to_file(ct_mul, level, argv[4]);
    printf(" -> Result saved to %s\n", argv[4]);

    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_relinearization_key_destroy(rlk);
    qfhe_ciphertext_destroy(ct_mul);
    qfhe_destroy_evaluation_context(eval_ctx);
    
    return 0;
}
