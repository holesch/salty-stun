#ifndef KDF_H_
#define KDF_H_

#include <stddef.h>
#include <stdint.h>

enum {
    KDF_KEY_SIZE = 32,
    KDF_OUTPUT_SIZE = 32,
};

struct kdf_state {
    uint8_t hmac_key[KDF_OUTPUT_SIZE];
    uint8_t previous_output[KDF_OUTPUT_SIZE];
    uint8_t hmac_input[1];
};

void kdf_init(struct kdf_state *state, const uint8_t *key, const uint8_t *input,
        size_t input_len);
void kdf_expand(struct kdf_state *state, uint8_t *output);

#endif // KDF_H_
