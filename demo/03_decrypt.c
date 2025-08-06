// demo/03_decrypt.c
#include "include/qfhe.h"
#include "demo/file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ciphertext_file> <private_key_file>\n", argv[0]);
        return 1;
    }

    char* ct_json = read_file_to_string(argv[1]);
    char* sk_json = read_file_to_string(argv[2]);

    Ciphertext* ct = qfhe_deserialize_ciphertext_from_json_str(ct_json);
    SecretKey* sk = qfhe_deserialize_sk_from_json_str(sk_json);
    SecurityLevel level = L128;

    DecryptionContext* dec_ctx = qfhe_create_decryption_context(level, sk);
    
    printf("Decrypting...\n");
    uint64_t decrypted_message = qfhe_decrypt(dec_ctx, ct);
    printf(" -> Decrypted Message: %" PRIu64 "\n", decrypted_message);

    free(ct_json);
    free(sk_json);
    qfhe_secret_key_destroy(sk);
    qfhe_ciphertext_destroy(ct);
    qfhe_destroy_decryption_context(dec_ctx);

    return 0;
}