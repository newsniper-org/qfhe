// demo/02_encrypt.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <public_key_file> <message> <output_ct_file>\n", argv[0]);
        return 1;
    }
    
    // 1. 공개키 파일로부터 직접 PublicKey 객체 생성
    PublicKey* pk = (PublicKey*)qfhe_deserialize_key_from_file(PK, argv[1]);
    if (!pk) {
        fprintf(stderr, "Error: Failed to load public key from %s\n", argv[1]);
        return 1;
    }
    
    uint64_t message = strtoull(argv[2], NULL, 10);
    SecurityLevel level = L128; // 실제로는 키 파일 헤더에서 읽어와야 함

    // 2. EncryptionContext 생성
    EncryptionContext* enc_ctx = qfhe_create_encryption_context(level, pk);

    printf("Encrypting %llu...\n", message);
    Ciphertext* ct = qfhe_encrypt(enc_ctx, message);

    // 3. 암호문을 파일에 직접 직렬화
    if (qfhe_serialize_ciphertext_to_file(ct, level, argv[3]) == 0) {
        printf(" -> Ciphertext saved to %s\n", argv[3]);
    } else {
        fprintf(stderr, "Error: Failed to save ciphertext to %s\n", argv[3]);
    }

    // 4. 메모리 해제
    qfhe_public_key_destroy(pk);
    qfhe_ciphertext_destroy(ct);
    qfhe_destroy_encryption_context(enc_ctx);

    return 0;
}