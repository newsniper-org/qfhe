// demo/03_decrypt.c

#include "include/qfhe.h"
#include "demo/file_io.h"
#include "demo/run.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h> // PRIu64
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ciphertext_file>\n", argv[0]);
        return 1;
    }

    const char* ciphertext_file = argv[1];
    // 1. 암호문 파일을 JSON 문자열로 읽기
    printf("Reading ciphertext from %s...\n", ciphertext_file);
    char* ct_json = read_file_to_string(ciphertext_file);
    if (!ct_json) {
        fprintf(stderr, "Error: Could not read ciphertext file.\n");
        return 1;
    }

    // 2. JSON 문자열로부터 Rust 객체 역직렬화
    Ciphertext* ct = qfhe_deserialize_ciphertext_from_json_str(ct_json);

    // 3. 컨텍스트 로드
    QfheContext* context = load_context();

    // 4. 복호화 수행
    printf("Decrypting...\n");
    uint64_t decrypted_message = qfhe_decrypt(context, ct);

    printf("\n--- Decryption Result ---\n");
    printf(" -> Decrypted Message: %" PRIu64 "\n", decrypted_message);

    // 5. 메모리 해제
    free(ct_json);
    qfhe_ciphertext_destroy(ct);
    qfhe_context_destroy(context);
    return 0;
}