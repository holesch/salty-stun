#ifndef XAEAD_H_
#define XAEAD_H_

#include <sodium.h>
#include <stdint.h>

// Xaead(key, nonce, plain text, auth text)
//     XChaCha20Poly1305 AEAD, with a 24-byte random nonce, instantiated using
//     HChaCha20 and ChaCha20Poly1305.

enum {
    XAEAD_KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    XAEAD_NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    XAEAD_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES,
};

static inline void xaead_encrypt(uint8_t *ciphertext, const uint8_t *key,
        const uint8_t *nonce, const uint8_t *plaintext, uint32_t plaintext_len,
        const uint8_t *ad, uint32_t ad_len) {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, NULL, plaintext, plaintext_len, ad, ad_len, NULL, nonce, key);
}

static inline int xaead_decrypt(uint8_t *plaintext, const uint8_t *key,
        const uint8_t *nonce, const uint8_t *ciphertext, uint32_t ciphertext_len,
        const uint8_t *ad, uint32_t ad_len) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext, NULL, NULL, ciphertext, ciphertext_len, ad, ad_len, nonce, key);
}

#endif // XAEAD_H_
