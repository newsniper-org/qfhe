#include <stdio.h>
#include <stdint.h>
#include "include/qfhe.h"

int main() {
    printf("--- QFHE Software Stack Demo ---\n\n");

    // 1. Create a QFHE context
    printf("1. Creating QFHE context...\n");
    QfheContext* context = qfhe_context_create();
    if (!context) {
        printf("Error: Failed to create context.\n");
        return 1;
    }

    // 2. Define plaintexts
    uint64_t msg1 = 42;
    uint64_t msg2 = 100;
    printf("2. Plaintext messages: %llu and %llu\n", (unsigned long long)msg1, (unsigned long long)msg2);

    // 3. Encrypt plaintexts
    printf("3. Encrypting messages...\n");
    Ciphertext* ct1 = qfhe_encrypt(context, msg1);
    Ciphertext* ct2 = qfhe_encrypt(context, msg2);

    // 4. Perform homomorphic addition
    printf("4. Performing homomorphic addition...\n");
    Ciphertext* ct_sum = qfhe_homomorphic_add(context, ct1, ct2);

    // 5. Decrypt the result
    printf("5. Decrypting the result...\n");
    uint64_t decrypted_sum = qfhe_decrypt(context, ct_sum);

    // 6. Verify and print the result
    printf("\n--- Verification ---\n");
    printf("Decrypted sum: %llu\n", (unsigned long long)decrypted_sum);
    printf("Expected sum:  %llu\n", (unsigned long long)(msg1 + msg2));

    if (decrypted_sum == (msg1 + msg2)) {
        printf("\nSUCCESS: The homomorphic addition was correct!\n");
    } else {
        printf("\nFAILURE: The result is incorrect.\n");
    }

    // 7. Clean up resources
    printf("\n7. Cleaning up resources...\n");
    qfhe_ciphertext_destroy(ct1);
    qfhe_ciphertext_destroy(ct2);
    qfhe_ciphertext_destroy(ct_sum);
    qfhe_context_destroy(context);

    printf("\n--- Demo Finished ---\n");

    return 0;
}