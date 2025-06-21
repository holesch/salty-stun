// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef RATE_LIMIT_H_
#define RATE_LIMIT_H_

#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "hashtable.h"

enum {
    // assuming a single user has access to one IPv4 address, but also to a /56
    // block of IPv6 addresses (see RFC 6177).
    IPV6_END_SITE_PREFIX_LEN = 7,
};

struct rate_limit_entry {
    struct hashtable_node node;
    union {
        struct {
            uint8_t count;
            uint8_t ip_prefix[IPV6_END_SITE_PREFIX_LEN];
        };
        struct {
            uint32_t count_magic;
            uint32_t ipv4_addr;
        };
    };
};

struct rate_limiter {
    uint32_t max_total;
    uint32_t max_per_ip;
    uint32_t attempts;
    uint32_t allowed;
    time_t interval;
    time_t reset_time;
    time_t under_load_until;
    struct hashtable ip_count_map;
    struct rate_limit_entry *entries;
    size_t next_entry_index;
};

void rate_limit_init(struct rate_limiter *rl, time_t interval, size_t max_total,
        size_t max_per_ip, struct rate_limit_entry *entries,
        struct hashtable_node **buckets);
bool rate_limit_is_allowed_unverified(struct rate_limiter *rl, time_t now);
bool rate_limit_is_allowed_verified(
        struct rate_limiter *rl, struct sockaddr_storage *addr);

#endif // RATE_LIMIT_H_
