// demo/02_encrypt.c
#include "include/qfhe.h"
#include "demo/file_io.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <public_key_file> <message>\n", argv[0]);
        return 1;
    }
    
    char* pk_json = read_file_to_string(argv[1]);
    uint64_t message = strtoull(argv[2], NULL, 10);
    
    PublicKey* pk = qfhe_deserialize_pk_from_json_str(pk_json);
    SecurityLevel level = L128; // JSON에서 읽어오도록 FFI 확장 가능

    EncryptionContext* enc_ctx = qfhe_create_encryption_context(level, pk);

    printf("Encrypting %llu...\n", message);
    Ciphertext* ct = qfhe_encrypt(enc_ctx, message);

    char* ct_json = qfhe_serialize_ciphertext_to_json_str(ct, level);
    write_string_to_file("ciphertext.ct", ct_json);
    printf(" -> Ciphertext saved to ciphertext.ct\n");

    free(pk_json);
    qfhe_free_string(ct_json);
    qfhe_public_key_destroy(pk);
    qfhe_ciphertext_destroy(ct);
    qfhe_destroy_encryption_context(enc_ctx);

    return 0;
}