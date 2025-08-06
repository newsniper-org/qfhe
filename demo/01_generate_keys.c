// demo/01_generate_key_s.c
#include "include/qfhe.h"
#include "demo/file_io.h"
#include <stdio.h>

int main(void) {
    SecurityLevel level = L128;
    int level_num = 128;

    // 예시 마스터 키와 솔트 (실제 사용 시에는 안전한 난수 소스에서 생성해야 함)
    unsigned char master_key[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    unsigned char salt[24] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    SecretKey* sk = NULL;
    PublicKey* pk = NULL;
    RelinearizationKey* rlk = NULL;
    KeySwitchingKey* ksk = NULL;
    BootstrapKey* bk = NULL;

    printf("Generating all keys for L%d...\n", level_num);
    qfhe_generate_key_s(level, master_key, salt, &sk, &pk, &rlk, &ksk, &bk);

    char filename[64];

    // 각 키를 JSON으로 직렬화하여 파일에 저장
    sprintf(filename, "qfhe%d.prv", level_num);
    char* sk_json = qfhe_serialize_sk_to_json_str(sk, level);
    write_string_to_file(filename, sk_json);
    printf(" -> Secret Key saved to %s\n", filename);

    sprintf(filename, "qfhe%d.pub", level_num);
    char* pk_json = qfhe_serialize_pk_to_json_str(pk, level);
    write_string_to_file(filename, pk_json);
    printf(" -> Public Key saved to %s\n", filename);
    
    // ... rlk, ksk, bk에 대해서도 동일하게 직렬화 및 저장 ...

    // 메모리 해제
    qfhe_free_string(sk_json);
    qfhe_free_string(pk_json);
    // ...
    qfhe_secret_key_destroy(sk);
    qfhe_public_key_destroy(pk);
    qfhe_relinearization_key_destroy(rlk);
    qfhe_key_switching_key_destroy(ksk);
    qfhe_bootstrap_key_destroy(bk);

    return 0;
}