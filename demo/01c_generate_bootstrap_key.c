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

#define SAVE_KEY(key_ptr, key_type_enum, level, level_num, suffix) \
    do { \
        char filename[64]; \
        sprintf(filename, "demo_output/qfhe%d.%s", level_num, suffix); \
        QfheResult status = qfhe_serialize_key_to_file((const void*)key_ptr, key_type_enum, level, filename); \
        if (status == Success) { \
            printf(" -> %s saved.\n", filename); \
        } else { \
            fprintf(stderr, "Error: Failed to save %s (code: %d)\n", filename, status); \
        } \
    } while (0)

#define SAVE_KEY_CUSTOM(key_ptr, key_type, level, suffix) \
    do { \
        char filename[64]; \
        sprintf(filename, "demo_output/qfhe128.%s.qkey", suffix); \
        /* level 파라미터를 serialize 함수에 전달 */ \
        QfheResult status = qfhe_serialize_key_to_file_binary(key_ptr, key_type, level, filename); \
        if (status == Success) { printf(" -> Custom key '%s' saved.\n", filename); } \
        else { fprintf(stderr, "Error saving '%s'\n", filename); } \
    } while(0)

int main(void) {
    SecurityLevel level = L128;
    int level_num = 128;
    char sk_filename[64]; sprintf(sk_filename, "demo_output/qfhe%d.sk", level_num);
    char pk_filename[64]; sprintf(pk_filename, "demo_output/qfhe%d.pk", level_num);

    printf("--- Step 3: Generating Bootstrap Key (BK) ---\n");
    printf("Loading secret key from %s...\n", sk_filename);

    // ... (비밀키 로드) ...
    void* temp_sk_ptr = NULL;
    QfheResult status = qfhe_deserialize_key_from_file_binary(&temp_sk_ptr, sk_filename); // JSON으로 로드
    CHECK_STATUS(status, "Failed to load secret key.");
    SecretKey* sk = (SecretKey*)temp_sk_ptr;
    
    // ✅ 공개키 로드 (JSON)
    printf("Loading public key from %s...\n", pk_filename);
    void* temp_pk_ptr = NULL;
    status = qfhe_deserialize_key_from_file_binary(&temp_pk_ptr, pk_filename);
    CHECK_STATUS(status, "Failed to load public key.");
    PublicKey* pk = (PublicKey*)temp_pk_ptr;

    BootstrapKey* bk = NULL;
    
    printf("\n❗ WARNING: Generating bootstrap key is a very slow and memory-intensive process.\n");
    printf("This may take several minutes and consume a large amount of RAM...\n");

    qfhe_generate_bootstrap_key(level, sk, pk, &bk);
    
    printf("\nBootstrap key generated. Saving key in custom binary format...\n");
    SAVE_KEY_CUSTOM(bk, BK, level, "bk"); // ✅ 새로운 저장 매크로 사용

    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk); // ✅ pk 메모리 해제
    qfhe_bootstrap_key_destroy(bk);

    printf("Bootstrap key generation complete.\n");
    return 0;
}