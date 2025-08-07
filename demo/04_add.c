// demo/04_add.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* ct1 = qfhe_deserialize_ciphertext_from_file(argv[1]);
    Ciphertext* ct2 = qfhe_deserialize_ciphertext_from_file(argv[2]);
    if (!ct1 || !ct2) {
        fprintf(stderr, "Error loading ciphertexts.\n");
        return 1;
    }

    SecurityLevel level = L128;
    // Note: For addition, a full EvaluationContext is not strictly necessary
    // but we use the direct FFI function for simplicity.
    
    printf("Performing homomorphic addition...\n");
    Ciphertext* ct_add = qfhe_homomorphic_add(ct1, ct2, level);
    
    qfhe_serialize_ciphertext_to_file(ct_add, level, argv[3]);
    printf(" -> Result saved to %s\n", argv[3]);

    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_add);
    
    return 0;
}
