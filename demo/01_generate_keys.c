// demo/01_generate_keys.c
#include "include/qfhe.h"
#include <stdio.h>

// 헬퍼 매크로
#define SAVE_KEY(key_ptr, key_type_enum, level, level_num, suffix) \
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
    // 실제 사용 시에는 안전한 방식으로 마스터 키와 솔트를 생성해야 합니다.
    unsigned char master_key[32] = {0}; 
    unsigned char salt[24] = {0};

    SecretKey* sk = NULL;
    PublicKey* pk = NULL;
    RelinearizationKey* rlk = NULL;
    EvaluationKey* evk_conj = NULL; // 동형 켤레를 위한 평가 키
    BootstrapKey* bk = NULL;

    printf("Generating all keys for L%d (RLWE Scheme)...\n", level_num);
    qfhe_generate_keys(level, master_key, salt, &sk, &pk, &rlk, &evk_conj, &bk);

    // 새로운 RLWE 키들을 파일에 저장
    SAVE_KEY(sk, SK, level, level_num, "sk");
    SAVE_KEY(pk, PK, level, level_num, "pk");
    SAVE_KEY(rlk, RLK, level, level_num, "rlk");
    SAVE_KEY(evk_conj, EVK, level, level_num, "evk_conj");
    SAVE_KEY(bk, BK, level, level_num, "bk");

    // 메모리 해제
    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk);
    qfhe_relinearization_key_destroy(rlk);
    qfhe_evaluation_key_destroy(evk_conj);
    qfhe_bootstrap_key_destroy(bk);

    printf("Key generation complete.\n");
    return 0;
}
