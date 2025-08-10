// demo/01a_generate_essential_keys.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

#define SAVE_KEY(key_ptr, key_type_enum, level, level_num, suffix) \
    do { \
        char filename[64]; \
        sprintf(filename, "demo_output/qfhe%d.%s", level_num, suffix); \
        QfheResult status = qfhe_serialize_key_to_file_binary((const void*)key_ptr, key_type_enum, level, filename); \
        if (status == Success) { \
            printf(" -> %s saved.\n", filename); \
        } else { \
            fprintf(stderr, "Error: Failed to save %s (code: %d)\n", filename, status); \
        } \
    } while (0)

int main(void) {
    SecurityLevel level = L128;
    int level_num = 128;
    unsigned char master_key[32] = {0};
    unsigned char salt[24] = {0};

    SecretKey* sk = NULL;
    PublicKey* pk = NULL;
    RelinearizationKey* rlk = NULL;

    printf("--- Step 1: Generating Essential Keys (SK, PK, RLK) ---\n");
    qfhe_generate_essential_keys(level, master_key, salt, &sk, &pk, &rlk);

    SAVE_KEY(sk, SK, level, level_num, "sk");
    SAVE_KEY(pk, PK, level, level_num, "pk");
    SAVE_KEY(rlk, RLK, level, level_num, "rlk");

    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk);
    qfhe_relinearization_key_destroy(rlk);

    printf("Essential key generation complete.\n");
    return 0;
}