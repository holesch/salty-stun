#ifndef MAC_H_
#define MAC_H_

#include <blake2.h>
#include <stdint.h>

// Mac(key, input)
//     Keyed-Blake2s(key, input, 16), the keyed MAC variant of the BLAKE2s hash
//     function, returning 16 bytes of output.

enum {
    MAC_KEY_SIZE_MAX = 32,
    MAC_SIZE = 16,
};

struct mac_state {
    blake2s_state b2_state;
};

static inline void mac_calculate(
        uint8_t *out, const void *in, size_t inlen, const void *key, size_t keylen) {
    blake2s(out, in, key, MAC_SIZE, inlen, keylen);
}

static inline void mac_init(struct mac_state *state, const void *key, size_t keylen) {
    blake2s_init_key(&state->b2_state, MAC_SIZE, key, keylen);
}

static inline void mac_update(struct mac_state *state, const void *in, size_t inlen) {
    blake2s_update(&state->b2_state, in, inlen);
}

static inline void mac_final(struct mac_state *state, uint8_t *out) {
    blake2s_final(&state->b2_state, out, MAC_SIZE);
}

#endif // MAC_H_
