// demo/02_encrypt.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <public_key_file> <message> <output_ct_file>\n", argv[0]);
        return 1;
    }
    
    PublicKey* pk = (PublicKey*)qfhe_deserialize_key_from_file(PK, argv[1]);
    if (!pk) {
        fprintf(stderr, "Error: Failed to load public key from %s\n", argv[1]);
        return 1;
    }
    
    uint64_t message = strtoull(argv[2], NULL, 10);
    SecurityLevel level = L128;

    EncryptionContext* enc_ctx = qfhe_create_encryption_context(level, pk);

    printf("Encrypting %" PRIu64 " with RLWE scheme...\n", message);
    Ciphertext* ct = qfhe_encrypt(enc_ctx, message);

    if (qfhe_serialize_ciphertext_to_file(ct, level, argv[3]) == 0) {
        printf(" -> Ciphertext saved to %s\n", argv[3]);
    } else {
        fprintf(stderr, "Error: Failed to save ciphertext to %s\n", argv[3]);
    }

    qfhe_public_key_destroy(pk);
    qfhe_ciphertext_destroy(ct);
    qfhe_destroy_encryption_context(enc_ctx);

    return 0;
}
