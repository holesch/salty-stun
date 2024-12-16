#ifndef HASH_H_
#define HASH_H_

#include <blake2.h>
#include <stddef.h>
#include <stdint.h>

enum {
    HASH_SIZE = BLAKE2S_OUTBYTES,
};

typedef blake2s_state hash_state;

void hash_init(hash_state *state);
void hash_update(hash_state *state, const uint8_t *in, size_t inlen);
void hash_final(hash_state *state, uint8_t *out);

void hash_mix(uint8_t *hash, const uint8_t *in, size_t inlen);
void hash_mix_to(
        uint8_t *hash_out, const uint8_t *hash_in, const uint8_t *in, size_t inlen);

#endif // HASH_H_
