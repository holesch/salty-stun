#ifndef AEAD_H_
#define AEAD_H_

#include <endian.h>
#include <sodium.h>
#include <stdint.h>

// Aead(key, counter, plain text, auth text)
//     ChaCha20Poly1305 AEAD, as specified in RFC7539 [17], with its nonce
//     being composed of 32 bits of zeros followed by the 64-bit little-endian
//     value of counter.

enum {
    AEAD_KEY_SIZE = crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    AEAD_NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
    AEAD_TAG_SIZE = crypto_aead_chacha20poly1305_ietf_ABYTES,
};

union aead_nonce {
    struct {
        uint32_t _padding1;
        uint32_t zero;
        uint64_t counter;
    };
    struct {
        uint32_t _padding2;
        uint8_t bytes[AEAD_NONCE_SIZE];
    };
};

static inline void aead_encrypt(uint8_t *ciphertext, const uint8_t *key,
        uint64_t counter, const uint8_t *plaintext, uint32_t plaintext_len,
        const uint8_t *ad, uint32_t ad_len) {
    union aead_nonce nonce = { .counter = htole64(counter) };

    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
            plaintext_len, ad, ad_len, NULL, nonce.bytes, key);
}

static inline int aead_decrypt(uint8_t *plaintext, const uint8_t *key, uint64_t counter,
        const uint8_t *ciphertext, uint32_t ciphertext_len, const uint8_t *ad,
        uint32_t ad_len) {
    union aead_nonce nonce = { .counter = htole64(counter) };

    return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL, ciphertext,
            ciphertext_len, ad, ad_len, nonce.bytes, key);
}

#endif // AEAD_H_
