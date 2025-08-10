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

#define SAVE_KEY(key_ptr, key_type_enum, level, level_num, suffix) \
    do { \
        char filename[64]; \
        sprintf(filename, "demo_output/qfhe%d.%s", level_num, suffix); \
        QfheResult status = qfhe_serialize_key_to_file((const void*)key_ptr, key_type_enum, level, filename); \
        if (status == Success) { \
            printf(" -> %s saved.\n", filename); \
        } else { \
            fprintf(stderr, "Error: Failed to save %s (code: %d)\n", filename, status); \
        } \
    } while (0)

int main(void) {
    SecurityLevel level = L128;
    int level_num = 128;
    char sk_filename[64];
    sprintf(sk_filename, "demo_output/qfhe%d.sk", level_num);

    printf("--- Step 2: Generating Conjugation Key (EVK_conj) ---\n");
    printf("Loading secret key from %s...\n", sk_filename);

    void* temp_sk_ptr = NULL;
    QfheResult status = qfhe_deserialize_key_from_file_binary(&temp_sk_ptr, sk_filename);
    CHECK_STATUS(status, "Failed to load secret key. Run '01a_generate_essential_keys' first.");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;

    EvaluationKey* evk_conj = NULL;
    qfhe_generate_conjugation_key(level, sk, &evk_conj);
    printf("Conjugation key generated. Saving key...\n");

    SAVE_KEY(evk_conj, EVK, level, level_num, "evk_conj");

    qfhe_secret_key_destroy(sk);
    qfhe_evaluation_key_destroy(evk_conj);

    printf("Conjugation key generation complete.\n");
    return 0;
}