#include "include/qfhe.h"
#include "demo/file_io.h"
#include "demo/run.h"
#include <stdio.h>

typedef char* cstr;

void free_json_ptrs(cstr arr_ptr[5]) {
    int i;
    for (i = 0; i < 5; i++) {
        if(!(arr_ptr[i])) {
            free(arr_ptr[i]);
        }
    }
}

QfheContext* load_context() {
    SecurityLevel level = L128;

    cstr alloc_json_ptr[5] = {NULL, NULL, NULL, NULL, NULL};

    // 비밀키 파일 읽기
    printf("Reading private key from %s...\n", "qfhe128.prv");
    char* sk_json = read_file_to_string("qfhe128.prv");
    if (!sk_json) {
        fprintf(stderr, "Error: Could not read private key file.\n");
        free_json_ptrs(alloc_json_ptr);
        return NULL;
    }
    alloc_json_ptr[0] = sk_json;
    SecretKey* sk = (SecretKey*)qfhe_deserialize_sk_from_json_str(sk_json);

    // 공개키 파일 읽기
    printf("Reading private key from %s...\n", "qfhe128.pub");
    char* pk_json = read_file_to_string("qfhe128.pub");
    if (!pk_json) {
        fprintf(stderr, "Error: Could not read private key file.\n");
        free_json_ptrs(alloc_json_ptr);
        return NULL;
    }
    alloc_json_ptr[1] = pk_json;
    PublicKey* pk = (PublicKey*)qfhe_deserialize_pk_from_json_str(pk_json);

    // 재선형화키 파일 읽기
    printf("Reading relinearization key from %s...\n", "qfhe128.rlk");
    char* rlk_json = read_file_to_string("qfhe128.rlk");
    if (!rlk_json) {
        fprintf(stderr, "Error: Could not read relinearization key file.\n");
        free_json_ptrs(alloc_json_ptr);
        return NULL;
    }
    alloc_json_ptr[2] = rlk_json;
    RelinearizationKey* rlk = (RelinearizationKey*)qfhe_deserialize_rlk_from_json_str(rlk_json);


    // 부트스트래핑키 파일 읽기
    printf("Reading bootstrap key from %s...\n", "qfhe128.bk");
    char* bk_json = read_file_to_string("qfhe128.bk");
    if (!bk_json) {
        fprintf(stderr, "Error: Could not read bootstrap key file.\n");
        free_json_ptrs(alloc_json_ptr);
        return NULL;
    }
    alloc_json_ptr[3] = bk_json;
    BootstrapKey* bk = (BootstrapKey*)qfhe_deserialize_bk_from_json_str(bk_json);


    // 키스위칭키 파일 읽기
    printf("Reading keyswitching key from %s...\n", "qfhe128.ksk");
    char* ksk_json = read_file_to_string("qfhe128.ksk");
    if (!ksk_json) {
        fprintf(stderr, "Error: Could not read keyswitching key file.\n");
        free_json_ptrs(alloc_json_ptr);
        return NULL;
    }
    alloc_json_ptr[4] = ksk_json;
    KeySwitchingKey* ksk = (KeySwitchingKey*)qfhe_deserialize_ksk_from_json_str(ksk_json);

    return qfhe_context_load(level, sk, pk, rlk, bk, ksk);
}