// demo/05_mul.c

#include "include/qfhe.h"
#include "demo/file_io.h"
#include "demo/run.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <ct1_file> <ct2_file> <relinearization_key_file> <output_ct_file>\n", argv[0]);
        return 1;
    }
    const char* ct1_file = argv[1];
    const char* ct2_file = argv[2];
    const char* rlk_file = argv[3];
    const char* output_file = argv[4];

    // 1. 파일 읽기
    printf("Reading ciphertext 1 from %s...\n", ct1_file);
    char* ct1_json = read_file_to_string(ct1_file);
    printf("Reading ciphertext 2 from %s...\n", ct2_file);
    char* ct2_json = read_file_to_string(ct2_file);

    // 2. 역직렬화
    Ciphertext* ct1 = qfhe_deserialize_ciphertext_from_json_str(ct1_json);
    Ciphertext* ct2 = qfhe_deserialize_ciphertext_from_json_str(ct2_json);
    SecurityLevel level = L128;

    // 3. 컨텍스트 로드
    QfheContext* context = load_context();

    // 4. 동형 곱셈 수행
    printf("Performing homomorphic multiplication...\n");
    Ciphertext* ct_mul = qfhe_homomorphic_mul(context, ct1, ct2); // 이 함수는 컨텍스트의 rlk를 사용

    // 5. 결과 직렬화 및 저장
    char* result_json = qfhe_serialize_ciphertext_to_json_str(ct_mul, level);
    write_string_to_file(output_file, result_json);
    printf(" -> Result saved to %s\n", output_file);

    // 6. 메모리 해제
    free(ct1_json);
    free(ct2_json);
    qfhe_free_string(result_json);
    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_mul);
    qfhe_context_destroy(context);

    return 0;
}