// demo/06_bootstrap.c
#include "include/qfhe.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <noisy_ct_file> <sk_file> <bk_file> <output_ct_file>\n", argv[0]);
        return 1;
    }

    Ciphertext* noisy_ct = qfhe_deserialize_ciphertext_from_file(argv[1]);
    SecretKey* sk = (SecretKey*)qfhe_deserialize_key_from_file(SK, argv[2]); // For context creation
    BootstrapKey* bk = (BootstrapKey*)qfhe_deserialize_key_from_file(BK, argv[3]);
    if (!noisy_ct || !sk || !bk) {
        fprintf(stderr, "Error loading inputs.\n");
        return 1;
    }

    SecurityLevel level = L128;
    // PBS requires a full context
    EvaluationContext* eval_ctx = qfhe_create_evaluation_context(level, NULL, bk, NULL); 

    // Create a test polynomial for f(x) = 2*x
    Polynomial* test_poly = qfhe_create_test_poly_f_2x(level);

    printf("Bootstrapping noisy ciphertext with f(x)=2x...\n");
    Ciphertext* bootstrapped_ct = qfhe_bootstrap(eval_ctx, noisy_ct, test_poly);
    
    qfhe_serialize_ciphertext_to_file(bootstrapped_ct, level, argv[4]);
    printf(" -> Result saved to %s\n", argv[4]);

    // Decrypt to verify
    DecryptionContext* dec_ctx = qfhe_create_decryption_context(level, sk);
    uint64_t final_msg = qfhe_decrypt(dec_ctx, bootstrapped_ct);
    printf(" -> Decrypted bootstrapped message: %llu\n", final_msg);


    qfhe_ciphertext_destroy(noisy_ct);
    qfhe_secret_key_destroy(sk);
    qfhe_bootstrap_key_destroy(bk);
    qfhe_polynomial_destroy(test_poly);
    qfhe_ciphertext_destroy(bootstrapped_ct);
    qfhe_destroy_evaluation_context(eval_ctx);
    qfhe_destroy_decryption_context(dec_ctx);
    
    return 0;
}
