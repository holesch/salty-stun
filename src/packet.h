// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef PACKET_H_
#define PACKET_H_

#include <assert.h>
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

static inline void packet_init(struct packet *packet, void *head, size_t len) {
    packet->head = head;
    packet->len = len;
}

static inline void *packet_pop_head(struct packet *packet, size_t len) {
    if (packet->len < len) {
        return NULL;
    }

    void *head = packet->head;
    packet->head += len;
    packet->len -= len;
    return head;
}

static inline void *packet_peak_head(struct packet *packet, size_t len) {
    if (packet->len < len) {
        return NULL;
    }

    return packet->head;
}

static inline void packet_reserve(struct packet *packet, size_t len) {
    void *head = packet_pop_head(packet, len);
    assert(head);
    (void)head;
}

static inline void *packet_push_head(struct packet *packet, size_t len) {
    packet->head -= len;
    packet->len += len;
    return packet->head;
}

static inline void *packet_set_len(struct packet *packet, size_t len) {
    assert(packet->len >= len);
    packet->len = len;
    return packet->head;
}

static inline void packet_pop_tail(struct packet *packet, size_t len) {
    assert(packet->len >= len);
    packet->len -= len;
}

static inline void packet_push_tail(struct packet *packet, size_t len) {
    packet->len += len;
}

static inline void packet_pad(struct packet *packet, size_t n) {
    size_t pad = (n - (packet->len % n)) % n;
    memset(packet->head + packet->len, 0, pad);
    packet->len += pad;
}

#endif // PACKET_H_
