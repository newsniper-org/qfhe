// demo/02_encrypt.c
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
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <public_key_file> <message> <output_ct_file>\n", argv[0]);
        return 1;
    }
    
    // 1. 역직렬화를 위해 void* 임시 포인터 사용
    void* temp_pk_ptr = NULL;
    QfheResult status = qfhe_deserialize_key_from_file_binary(&temp_pk_ptr, argv[1]);
    CHECK_STATUS(status, "Failed to load public key");
    // 2. 실제 타입으로 형변환
    PublicKey* pk = (PublicKey*)temp_pk_ptr;
    
    uint64_t message = strtoull(argv[2], NULL, 10);
    SecurityLevel level = L128;

    EncryptionContext* enc_ctx = qfhe_create_encryption_context(level, pk);

    printf("Encrypting %" PRIu64 " with RLWE scheme...\n", message);
    Ciphertext* ct = qfhe_encrypt(enc_ctx, message);

    status = qfhe_serialize_ciphertext_to_file(ct, level, argv[3]);
    if (status == Success) {
        printf(" -> Ciphertext saved to %s\n", argv[3]);
    } else {
        fprintf(stderr, "Error: Failed to save ciphertext to %s (status code: %d)\n", argv[3], status);
    }

    qfhe_public_key_destroy(pk);
    qfhe_ciphertext_destroy(ct);
    qfhe_destroy_encryption_context(enc_ctx);

    return 0;
}