#ifndef MAC_H_
#define MAC_H_

#include <blake2.h>
#include <stdint.h>

// Mac(key, input)
//     Keyed-Blake2s(key, input, 16), the keyed MAC variant of the BLAKE2s hash
//     function, returning 16 bytes of output.

enum {
    MAC_KEY_SIZE = 32,
    MAC_SIZE = 16,
};

static inline void mac_calculate(
        uint8_t *out, const void *in, size_t inlen, const void *key) {
    blake2s(out, in, key, MAC_SIZE, inlen, MAC_KEY_SIZE);
}

#endif // MAC_H_
