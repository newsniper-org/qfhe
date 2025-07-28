#ifndef QFHE_H
#define QFHE_H

#include <stdint.h> // uint64_t와 같은 고정 너비 정수형을 사용하기 위해 포함합니다.

#ifdef __cplusplus
extern "C" {
#endif

// Opaque pointers to hide Rust's internal structures
typedef void QfheContext;
typedef void Ciphertext;

/**
 * @brief QFHE 연산을 위한 새로운 컨텍스트를 생성하고 초기화합니다.
 *
 * 이 컨텍스트는 암호화에 필요한 모든 파라미터와 비밀키를 포함합니다.
 * 사용이 끝난 후에는 반드시 qfhe_context_destroy를 호출하여 메모리를 해제해야 합니다.
 *
 * @return 성공 시 생성된 컨텍스트에 대한 포인터, 실패 시 NULL.
 */
QfheContext* qfhe_context_create(void);

/**
 * @brief qfhe_context_create로 생성된 컨텍스트의 메모리를 안전하게 해제합니다.
 *
 * @param context_ptr 해제할 컨텍스트에 대한 포인터.
 */
void qfhe_context_destroy(QfheContext* context_ptr);

/**
 * @brief 주어진 메시지를 암호화하여 암호문을 생성합니다.
 *
 * @param context_ptr 유효한 QFHE 컨텍스트에 대한 포인터.
 * @param message 암호화할 64비트 부호 없는 정수 메시지.
 * @return 생성된 암호문에 대한 포인터. 사용 후에는 qfhe_ciphertext_destroy로 해제해야 합니다.
 */
Ciphertext* qfhe_encrypt(QfheContext* context_ptr, uint64_t message);

/**
 * @brief 암호문을 복호화하여 원본 메시지를 복원합니다.
 *
 * @param context_ptr 유효한 QFHE 컨텍스트에 대한 포인터.
 * @param ciphertext_ptr 복호화할 암호문에 대한 포인터.
 * @return 복호화된 64비트 부호 없는 정수 메시지.
 */
uint64_t qfhe_decrypt(QfheContext* context_ptr, Ciphertext* ciphertext_ptr);

/**
 * @brief 두 개의 암호문에 대해 동형 덧셈 연산을 수행합니다.
 *
 * 결과 암호문은 두 원본 메시지의 합을 암호화한 값입니다.
 *
 * @param context_ptr 유효한 QFHE 컨텍스트에 대한 포인터.
 * @param ciphertext1_ptr 첫 번째 피연산자 암호문에 대한 포인터.
 * @param ciphertext2_ptr 두 번째 피연산자 암호문에 대한 포인터.
 * @return 덧셈 결과가 담긴 새로운 암호문에 대한 포인터. 사용 후에는 qfhe_ciphertext_destroy로 해제해야 합니다.
 */
void* qfhe_homomorphic_add(QfheContext* context_ptr, Ciphertext* ciphertext1_ptr, Ciphertext* ciphertext2_ptr);

/**
 * @brief qfhe_encrypt 또는 qfhe_homomorphic_add로 생성된 암호문의 메모리를 안전하게 해제합니다.
 *
 * @param ciphertext_ptr 해제할 암호문에 대한 포인터.
 */
void qfhe_ciphertext_destroy(Ciphertext* ciphertext_ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QFHE_H
