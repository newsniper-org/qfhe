/* Auto-generated by cbindgen */

#ifndef QFHE_H
#define QFHE_H

/* Do not edit this file manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C FFI에서 사용할 보안 수준 열거형입니다.
 */
typedef enum {
  L128,
  L160,
  L192,
  L224,
  L256,
} SecurityLevel;

/**
 * LWE 암호문은 (a, b) 쌍으로 구성됩니다.
 * a는 4원수들의 벡터이고, b는 단일 4원수입니다.
 */
typedef struct Ciphertext Ciphertext;

typedef struct QfheContext QfheContext;

QfheContext *qfhe_context_create(SecurityLevel level);

void qfhe_context_destroy(QfheContext *context_ptr);

Ciphertext *qfhe_encrypt(QfheContext *context_ptr, uint64_t message);

uint64_t qfhe_decrypt(QfheContext *context_ptr, Ciphertext *ciphertext_ptr);

Ciphertext *qfhe_homomorphic_add(QfheContext *context_ptr,
                                 Ciphertext *ct1_ptr,
                                 Ciphertext *ct2_ptr);

Ciphertext *qfhe_homomorphic_sub(QfheContext *context_ptr,
                                 Ciphertext *ct1_ptr,
                                 Ciphertext *ct2_ptr);

Ciphertext *qfhe_homomorphic_mul(QfheContext *context_ptr,
                                 Ciphertext *ct1_ptr,
                                 Ciphertext *ct2_ptr);

void qfhe_ciphertext_destroy(Ciphertext *ciphertext_ptr);

#endif  /* QFHE_H */
