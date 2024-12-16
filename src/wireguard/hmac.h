#ifndef HMAC_H_
#define HMAC_H_

#include <blake2.h>
#include <stdint.h>

struct hmac_state {
    blake2s_state ictx;
    blake2s_state octx;
};

void hmac_init(struct hmac_state *state, const uint8_t *key, size_t keylen);
void hmac_update(struct hmac_state *state, const uint8_t *in, size_t inlen);
void hmac_final(struct hmac_state *state, uint8_t *out);
void hmac(uint8_t *out, const uint8_t *in, size_t inlen, const uint8_t *key,
        size_t keylen);

#endif // HMAC_H_
