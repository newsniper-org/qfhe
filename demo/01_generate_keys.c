#include "include/qfhe.h"
#include "demo/file_io.h"
#include <stdio.h>
#include <stdlib.h>

// 헬퍼 매크로
#define SAVE_KEY(filename, json_str) \
    do { \
        write_string_to_file(filename, json_str); \
        printf(" -> %s saved.\n", filename); \
        qfhe_free_string(json_str); \
    } while (0)















int main(void) {
    // 예시: L128
    SecurityLevel level = L128;
    int level_num = 128;

    printf("Generating all keys for L%d...\n", level_num);
    QfheContext* context = qfhe_context_create(level);

    const SecretKey* sk = qfhe_context_get_sk(context);
    const PublicKey* pk = qfhe_context_get_pk(context);
    const RelinearizationKey* rlk = qfhe_context_get_rlk(context);
    const BootstrapKey* bk = qfhe_context_get_bk(context);
    const KeySwitchingKey* ksk = qfhe_context_get_ksk(context);

    char* sk_json_str = qfhe_serialize_sk_to_json_str((const void*)sk, level);
    char* pk_json_str = qfhe_serialize_pk_to_json_str((const void*)pk, level);
    char* rlk_json_str = qfhe_serialize_rlk_to_json_str((const void*)rlk, level);
    char* bk_json_str = qfhe_serialize_bk_to_json_str((const void*)bk, level);
    char* ksk_json_str = qfhe_serialize_ksk_to_json_str((const void*)ksk, level);

    char sk_filename[64];
    sprintf(sk_filename, "qfhe%d.prv", level_num);
    char pk_filename[64];
    sprintf(pk_filename, "qfhe%d.pub", level_num);
    char rlk_filename[64];
    sprintf(rlk_filename, "qfhe%d.rlk", level_num);
    char bk_filename[64];
    sprintf(bk_filename, "qfhe%d.bk", level_num);
    char ksk_filename[64];
    sprintf(ksk_filename, "qfhe%d.ksk", level_num);

    SAVE_KEY(sk_filename, sk_json_str);
    SAVE_KEY(pk_filename, pk_json_str);
    SAVE_KEY(rlk_filename, rlk_json_str);
    SAVE_KEY(bk_filename, bk_json_str);
    SAVE_KEY(ksk_filename, ksk_json_str);

    qfhe_context_destroy(context);
    return 0;
}