// demo/05_sub.c

#include "include/qfhe.h"
#include "demo/file_io.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    const char* ct1_file = argv[1];
    const char* ct2_file = argv[2];
    const char* output_file = argv[3];

    // 1. 암호문 파일 읽기
    char* ct1_json = read_file_to_string(ct1_file);
    char* ct2_json = read_file_to_string(ct2_file);
    if (!ct1_json || !ct2_json) {
        fprintf(stderr, "Error: Could not read ciphertext files.\n");
        free(ct1_json); free(ct2_json);
        return 1;
    }

    // 2. 연산에 필요한 모든 키 파일 읽기
    char* rlk_json = read_file_to_string("demo_output/qfhe128.rlk");
    char* bk_json = read_file_to_string("demo_output/qfhe128.bk");
    char* ksk_json = read_file_to_string("demo_output/qfhe128.ksk");

    // 3. JSON 문자열로부터 Rust 객체 역직렬화
    Ciphertext* ct1 = qfhe_deserialize_ciphertext_from_json_str(ct1_json);
    Ciphertext* ct2 = qfhe_deserialize_ciphertext_from_json_str(ct2_json);
    RelinearizationKey* rlk = qfhe_deserialize_rlk_from_json_str(rlk_json);
    BootstrapKey* bk = qfhe_deserialize_bk_from_json_str(bk_json);
    KeySwitchingKey* ksk = qfhe_deserialize_ksk_from_json_str(ksk_json);

    // 4. 동형 연산 전용 EvaluationContext 생성
    SecurityLevel level = L128; // 실제로는 JSON에서 레벨을 읽어오는 것이 더 좋음
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, rlk, bk, ksk);

    // 5. 동형 뺄셈 수행
    printf("Performing homomorphic subtraction...\n");
    Ciphertext* ct_sub = qfhe_homomorphic_sub(eval_ctx, ct1, ct2);

    // 6. 결과 직렬화 및 파일 저장
    char* result_json = qfhe_serialize_ciphertext_to_json_str(ct_sub, level);
    write_string_to_file(output_file, result_json);
    printf(" -> Result saved to %s\n", output_file);

    // 7. 모든 할당된 메모리 해제
    free(ct1_json); free(ct2_json); free(rlk_json); free(bk_json); free(ksk_json);
    qfhe_free_string(result_json);
    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_sub);
    qfhe_relinearization_key_destroy(rlk);
    qfhe_bootstrap_key_destroy(bk);
    qfhe_key_switching_key_destroy(ksk);
    qfhe_destroy_evaluation_context(eval_ctx);

    return 0;
}