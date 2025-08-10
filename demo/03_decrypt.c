// demo/03_decrypt.c
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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ciphertext_file> <secret_key_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* ct = NULL;
    QfheResult status = qfhe_deserialize_ciphertext_from_file(&ct, argv[1]);
    CHECK_STATUS(status, "Failed to load ciphertext");

    void* temp_sk_ptr = NULL;
    status = qfhe_deserialize_key_from_file_binary(&temp_sk_ptr, argv[2]);
    CHECK_STATUS(status, "Failed to load secret key");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;
    
    SecurityLevel level = L128;
    DecryptionContext* dec_ctx = qfhe_create_decryption_context(level, sk);
    
    printf("Decrypting...\n");
    uint64_t decrypted_message = qfhe_decrypt(dec_ctx, ct);
    printf(" -> Decrypted Message: %" PRIu64 "\n", decrypted_message);

    qfhe_secret_key_destroy(sk);
    qfhe_ciphertext_destroy(ct);
    qfhe_destroy_decryption_context(dec_ctx);

    return 0;
}