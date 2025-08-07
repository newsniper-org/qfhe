// demo/01_generate_keys.c

#include "include/qfhe.h"
// #include "demo/file_io.h" // 더 이상 필요 없음
#include <stdio.h>

// 헬퍼 매크로
#define GENERATE_AND_SAVE_KEY(key_ptr, key_type_enum, level, level_num, suffix) \
    do { \
        char filename[64]; \
        sprintf(filename, "demo_output/qfhe%d.%s", level_num, suffix); \
        if (qfhe_serialize_key_to_file((const void*)key_ptr, key_type_enum, level, filename) == 0) { \
            printf(" -> %s saved.\n", filename); \
        } else { \
            fprintf(stderr, "Error: Failed to save %s\n", filename); \
        } \
    } while (0)

int main(void) {
    SecurityLevel level = L128;
    int level_num = 128;
    unsigned char master_key[32] = {0};
    unsigned char salt[24] = {0};

    SecretKey* sk = NULL;
    PublicKey* pk = NULL;
    RelinearizationKey* rlk = NULL;
    KeySwitchingKey* ksk = NULL;
    BootstrapKey* bk = NULL;

    printf("Generating all keys for L%d...\n", level_num);
    qfhe_generate_keys(level, master_key, salt, &sk, &pk, &rlk, &ksk, &bk);

    // ❗ 새로운 FFI 함수를 사용하여 파일에 직접 저장
    GENERATE_AND_SAVE_KEY(sk, SK, level, level_num, "prv");
    GENERATE_AND_SAVE_KEY(pk, PK, level, level_num, "pub");
    GENERATE_AND_SAVE_KEY(rlk, RLK, level, level_num, "rlk");
    GENERATE_AND_SAVE_KEY(ksk, KSK, level, level_num, "ksk");
    GENERATE_AND_SAVE_KEY(bk, BK, level, level_num, "bk");

    // 메모리 해제
    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk);
    qfhe_relinearization_key_destroy(rlk);
    qfhe_key_switching_key_destroy(ksk);
    qfhe_bootstrap_key_destroy(bk);

    return 0;
}