// demo/04_add.c
#include "include/qfhe.h"
#include "demo/file_io.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    // 1. 암호문 파일 읽기
    char* ct1_json = read_file_to_string(argv[1]);
    char* ct2_json = read_file_to_string(argv[2]);
    Ciphertext* ct1 = qfhe_deserialize_ciphertext_from_json_str(ct1_json);
    Ciphertext* ct2 = qfhe_deserialize_ciphertext_from_json_str(ct2_json);

    // 2. 연산에 필요한 모든 키 파일 읽기
    char* rlk_json = read_file_to_string("demo_output/qfhe128.rlk");
    char* bk_json = read_file_to_string("demo_output/qfhe128.bk");
    char* ksk_json = read_file_to_string("demo_output/qfhe128.ksk");
    RelinearizationKey* rlk = qfhe_deserialize_rlk_from_json_str(rlk_json);
    BootstrapKey* bk = qfhe_deserialize_bk_from_json_str(bk_json);
    KeySwitchingKey* ksk = qfhe_deserialize_ksk_from_json_str(ksk_json);

    // 3. EvaluationContext 생성
    SecurityLevel level = L128;
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, rlk, bk, ksk);

    // 4. 동형 덧셈 수행
    printf("Performing homomorphic addition...\n");
    Ciphertext* ct_add = qfhe_homomorphic_add(eval_ctx, ct1, ct2);
    
    // 5. 결과 저장 및 메모리 해제
    char* result_json = qfhe_serialize_ciphertext_to_json_str(ct_add, level);
    write_string_to_file(argv[3], result_json);
    printf(" -> Result saved to %s\n", argv[3]);

    // ... 모든 할당된 메모리 free 및 destroy 호출 ...
    
    return 0;
}