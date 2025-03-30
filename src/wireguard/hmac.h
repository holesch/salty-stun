#ifndef HMAC_H_
#define HMAC_H_

#include <blake2.h>
#include <stdint.h>

enum {
    HMAC_KEY_SIZE = 32,
};

struct hmac_state {
    blake2s_state ictx;
    blake2s_state octx;
};

void hmac_init(struct hmac_state *state, const uint8_t *key);
void hmac_update(struct hmac_state *state, const uint8_t *in, size_t inlen);
void hmac_final(struct hmac_state *state, uint8_t *out);
void hmac(uint8_t *out, const uint8_t *in, size_t inlen, const uint8_t *key);

#endif // HMAC_H_
