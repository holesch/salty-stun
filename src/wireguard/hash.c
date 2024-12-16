#include "wireguard/hash.h"

#include <blake2.h>
#include <stdint.h>

// Hash(input)
//     Blake2s(input, 32), returning 32 bytes of output.

void hash_init(hash_state *state) {
    blake2s_init(state, BLAKE2S_OUTBYTES);
}

void hash_update(hash_state *state, const uint8_t *in, size_t inlen) {
    blake2s_update(state, in, inlen);
}

void hash_final(hash_state *state, uint8_t *out) {
    blake2s_final(state, out, BLAKE2S_OUTBYTES);
}

void hash_mix(uint8_t *hash, const uint8_t *in, size_t inlen) {
    hash_mix_to(hash, hash, in, inlen);
}

void hash_mix_to(
        uint8_t *hash_out, const uint8_t *hash_in, const uint8_t *in, size_t inlen) {
    hash_state state;
    hash_init(&state);
    hash_update(&state, hash_in, BLAKE2S_OUTBYTES);
    hash_update(&state, in, inlen);
    hash_final(&state, hash_out);
}
