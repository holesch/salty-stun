#include "checksum.h"

#include <limits.h>

static uint32_t fold_sum(uint32_t sum);

uint16_t inet_checksum(const void *data, size_t len) {
    uint32_t sum = 0;
    const uint16_t *data16 = data;
    while (len >= sizeof(*data16)) {
        sum += *data16++;
        len -= sizeof(*data16);
    }
    if (len) {
        sum += *(const uint8_t *)data16;
    }

    // folding twice to cover the worst case
    sum = fold_sum(sum);
    sum = fold_sum(sum);

    return ~sum;
}

static uint32_t fold_sum(uint32_t sum) {
    return (sum & UINT16_MAX) + (sum >> (CHAR_BIT * sizeof(uint16_t)));
}
