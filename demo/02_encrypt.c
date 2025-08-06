#include "include/qfhe.h"
#include "demo/file_io.h"
#include "demo/run.h"
#include <stdio.h>

int main(void) {
    // 예시: L128, 평문 12345
    SecurityLevel level = L128;
    uint64_t message = 12345;
    
    // 컨텍스트 로드
    QfheContext* context = load_context();
    if (!context) {
        fprintf(stderr, "Error: Could not load context.\n");
        return 1;
    }
    
    printf("Encrypting %llu...\n", message);
    Ciphertext* ct = qfhe_encrypt(context, message); // encrypt는 컨텍스트의 pk를 사용

    // 암호문 파일로 저장
    char* ct_json = qfhe_serialize_ciphertext_to_json_str(ct, level);
    write_string_to_file("ciphertext.ct", ct_json);
    printf(" -> Ciphertext saved to ciphertext.ct\n");

    qfhe_free_string(ct_json);
    qfhe_ciphertext_destroy(ct);
    qfhe_context_destroy(context);
    return 0;
}