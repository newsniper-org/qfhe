// demo/01a_generate_essential_keys.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

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
    unsigned char master_key[32] = {0};
    unsigned char salt[24] = {0};

    SecretKey* sk = NULL;
    PublicKey* pk = NULL;
    RelinearizationKey* rlk = NULL;

    printf("--- Step 1: Generating Essential Keys (SK, PK, RLK) ---\n");
    qfhe_generate_essential_keys(level, master_key, salt, &sk, &pk, &rlk);

    SAVE_KEY_BINARY(sk, SK, level, "sk");
    SAVE_KEY_BINARY(pk, PK, level, "pk");
    SAVE_KEY_BINARY(rlk, RLK, level, "rlk");

    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk);
    qfhe_relinearization_key_destroy(rlk);

    printf("Essential key generation complete.\n");
    return 0;
}