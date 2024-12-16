#ifndef DH_H_
#define DH_H_

#include <sodium.h>
#include <stdint.h>

enum {
    DH_PUBLIC_KEY_SIZE = crypto_scalarmult_BYTES,
    DH_PRIVATE_KEY_SIZE = crypto_scalarmult_SCALARBYTES,
    DH_SHARED_SECRET_SIZE = crypto_scalarmult_BYTES,
};

static inline void dh_generate_private_key(uint8_t *private_key) {
    randombytes_buf(private_key, DH_PRIVATE_KEY_SIZE);
}

static inline void dh_derive_public_key(
        uint8_t *public_key, const uint8_t *private_key) {
    crypto_scalarmult_base(public_key, private_key);
}

static inline int dh_shared_secret(
        uint8_t *shared_secret, const uint8_t *private_key, const uint8_t *public_key) {
    return crypto_scalarmult(shared_secret, private_key, public_key);
}

#endif // DH_H_
