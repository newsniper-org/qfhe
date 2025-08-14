// demo/01b_generate_conjugation_key.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK_STATUS(status, message) \
    do { \
        if (status != Success) { \
            fprintf(stderr, "Error: %s (code: %d)\n", message, status); \
            exit(1); \
        } \
    } while (0)

#define SAVE_KEY_BINARY(obj_ptr, object_type, level, suffix) \
    do { \
        char filename[64]; \
        sprintf(filename, "demo_output/qfhe128.%s.qkey", suffix); \
        QfheResult status = qfhe_serialize_object_to_file(obj_ptr, object_type, level, filename); \
        if (status == Success) { printf(" -> Key saved to '%s'\n", filename); } \
        else { fprintf(stderr, "Error saving '%s'\n", filename); exit(1); } \
    } while(0)

int main(void) {
    SecurityLevel level = L128;
    char sk_filename[64];
    sprintf(sk_filename, "demo_output/qfhe128.sk.qkey");

    printf("--- Step 2: Generating Conjugation Key (EVK_conj) ---\n");
    printf("Loading secret key from '%s'...\n", sk_filename);

    void* temp_sk_ptr = NULL;
    QfheResult status = qfhe_deserialize_object_from_file(&temp_sk_ptr, sk_filename);
    CHECK_STATUS(status, "Failed to load secret key. Run '01a' first.");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;

    EvaluationKey* evk_conj = NULL;
    qfhe_generate_conjugation_key(level, sk, &evk_conj);
    printf("Conjugation key generated. Saving key...\n");

    SAVE_KEY_BINARY(evk_conj, EVK, level, "evk_conj");

    qfhe_secret_key_destroy(sk);
    qfhe_evaluation_key_destroy(evk_conj);

    printf("Conjugation key generation complete.\n");
    return 0;
}