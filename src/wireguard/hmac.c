// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "wireguard/hmac.h"

#include <blake2.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>

// Hmac(key, input)
//     Hmac-Blake2s(key, input, 32), the ordinary BLAKE2s hash function used in
//     an HMAC construction, returning 32 bytes of output.

void hmac_init(struct hmac_state *state, const uint8_t *key) {
    uint8_t pad[BLAKE2S_BLOCKBYTES];
    uint8_t khash[BLAKE2S_OUTBYTES];

    blake2s_init(&state->ictx, BLAKE2S_OUTBYTES);
    const uint8_t ipad_value = 0x36;
    memset(pad, ipad_value, BLAKE2S_BLOCKBYTES);
    for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
        pad[i] ^= key[i];
    }
    blake2s_update(&state->ictx, pad, sizeof(pad));

    blake2s_init(&state->octx, BLAKE2S_OUTBYTES);
    const uint8_t opad_value = 0x5c;
    memset(pad, opad_value, BLAKE2S_BLOCKBYTES);
    for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
        pad[i] ^= key[i];
    }
    blake2s_update(&state->octx, pad, sizeof(pad));

    sodium_memzero((void *)pad, sizeof(pad));
    sodium_memzero((void *)khash, sizeof(khash));
}

void hmac_update(struct hmac_state *state, const uint8_t *in, size_t inlen) {
    blake2s_update(&state->ictx, in, inlen);
}

void hmac_final(struct hmac_state *state, uint8_t *out) {
    uint8_t hash[BLAKE2S_OUTBYTES];

    blake2s_final(&state->ictx, hash, sizeof(hash));
    blake2s_update(&state->octx, hash, sizeof(hash));
    blake2s_final(&state->octx, out, BLAKE2S_OUTBYTES);

    sodium_memzero((void *)hash, sizeof(hash));
}

void hmac(uint8_t *out, const uint8_t *in, size_t inlen, const uint8_t *key) {
    struct hmac_state state;

    hmac_init(&state, key);
    hmac_update(&state, in, inlen);
    hmac_final(&state, out);
}
