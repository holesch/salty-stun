#ifndef PACKET_H_
#define PACKET_H_

#include <stddef.h>
#include <stdint.h>

#define ALIGNED_BUFFER(name, size) \
    union { \
        uint64_t words[((size) + 7) / 8]; \
        uint8_t bytes[size]; \
    } name

struct packet {
    uint8_t *head;
    size_t len;
};

#endif // PACKET_H_
