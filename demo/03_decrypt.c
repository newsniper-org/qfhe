// demo/03_decrypt.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ciphertext_file> <secret_key_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* ct = qfhe_deserialize_ciphertext_from_file(argv[1]);
    SecretKey* sk = (SecretKey*)qfhe_deserialize_key_from_file(SK, argv[2]);
    if (!ct || !sk) {
        fprintf(stderr, "Error: Failed to load ciphertext or secret key.\n");
        return 1;
    }
    
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
