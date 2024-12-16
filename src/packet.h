#ifndef PACKET_H_
#define PACKET_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ALIGNED_BUFFER(name, size) \
    union { \
        uint64_t words[((size) + 7) / 8]; \
        uint8_t bytes[size]; \
    } name

struct packet {
    uint8_t *head;
    size_t len;
};

static inline void packet_shrink(struct packet *packet, size_t len) {
    packet->head += len;
    packet->len -= len;
}

static inline void packet_expand(struct packet *packet, size_t len) {
    packet->head -= len;
    packet->len += len;
}

static inline void packet_reserve(struct packet *packet, size_t len) {
    packet->head += len;
}

static inline void packet_pad(struct packet *packet, size_t n) {
    size_t pad = (n - (packet->len % n)) % n;
    memset(packet->head + packet->len, 0, pad);
    packet->len += pad;
}

#endif // PACKET_H_
