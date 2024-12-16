#include "wireguard/kdf.h"

#include <stdint.h>
#include <string.h>

#include "wireguard/hmac.h"

// Kdfn(key, input)
//     Sets τ0 := Hmac(key, input), τ1 := Hmac(τ0, 0x1), τi := Hmac(τ0, τi−1 ‖
//     i), and returns an n-tuple of 32 byte values, (τ1, . . . , τn). This is
//     the HKDF [15] function.

void kdf_init(struct kdf_state *state, const uint8_t *key, const uint8_t *input,
        size_t input_len) {
    // τ0 := Hmac(key, input)
    hmac(state->hmac_key, input, input_len, key, KDF_KEY_SIZE);
    state->hmac_input[0] = 0x1;
}

void kdf_expand(struct kdf_state *state, uint8_t *output) {
    // τ1 := Hmac(τ0, 0x1)
    // τi := Hmac(τ0, τi−1 ‖ i)
    struct hmac_state hmac_state;

    hmac_init(&hmac_state, state->hmac_key, sizeof(state->hmac_key));
    if (state->hmac_input[0] != 0x1) {
        hmac_update(
                &hmac_state, state->previous_output, sizeof(state->previous_output));
    }
    hmac_update(&hmac_state, state->hmac_input, sizeof(state->hmac_input));
    hmac_final(&hmac_state, output);
    memcpy(state->previous_output, output, sizeof(state->previous_output));
    state->hmac_input[0]++;
}
