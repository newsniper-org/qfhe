// demo/01c_generate_bootstrap_key.c
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

int main(void) {
    SecurityLevel level = L128;
    char sk_filename[64];
    char pk_filename[64];
    char bk_filename[64];
    char bk_idx_filename[64];
    sprintf(sk_filename, "demo_output/qfhe128.sk.qkey");
    sprintf(pk_filename, "demo_output/qfhe128.pk.qkey");
    sprintf(bk_filename, "demo_output/qfhe128.bk.qkey");
    sprintf(bk_idx_filename, "demo_output/qfhe128.bk.idx");

    printf("--- Step 3: Generating Bootstrap Key (BK) ---\n");

    printf("Loading secret key from '%s'...\n", sk_filename);
    void* temp_sk_ptr = NULL;
    QfheResult status = qfhe_deserialize_object_from_file(&temp_sk_ptr, sk_filename);
    CHECK_STATUS(status, "Failed to load secret key. Run '01a' first.");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;

    printf("Loading public key from '%s'...\n", pk_filename);
    void* temp_pk_ptr = NULL;
    status = qfhe_deserialize_object_from_file(&temp_pk_ptr, pk_filename);
    CHECK_STATUS(status, "Failed to load public key. Run '01a' first.");
    PublicKey* pk = (PublicKey*)temp_pk_ptr;
    
    printf("\n❗ WARNING: Generating bootstrap key directly to file '%s'.\n", bk_filename);
    printf("This will be slow due to disk I/O, but will use minimal memory.\n");

    status = qfhe_generate_bootstrap_key_to_file(level, sk, pk, bk_filename, bk_idx_filename);
    CHECK_STATUS(status, "Failed to generate bootstrap key to file.");

    printf("\nBootstrap key generation complete.\n");
    printf(" -> Key saved to '%s'\n", bk_filename);

    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk);

    return 0;
}