// demo/04_add.c
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
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* ct1 = NULL;
    QfheResult status = qfhe_deserialize_ciphertext_from_file(&ct1, argv[1]);
    CHECK_STATUS(status, "Failed to load first ciphertext");

    Ciphertext* ct2 = NULL;
    status = qfhe_deserialize_ciphertext_from_file(&ct2, argv[2]);
    CHECK_STATUS(status, "Failed to load second ciphertext");

    SecurityLevel level = L128;
    
    printf("Performing homomorphic addition...\n");
    Ciphertext* ct_add = qfhe_homomorphic_add(ct1, ct2, level);
    
    status = qfhe_serialize_ciphertext_to_file(ct_add, level, argv[3]);
    if (status == Success) {
        printf(" -> Result saved to %s\n", argv[3]);
    } else {
        fprintf(stderr, "Error: Failed to save result ciphertext (status code: %d)\n", status);
    }

    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_add);
    
    return 0;
}