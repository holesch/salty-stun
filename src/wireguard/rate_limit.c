// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rate_limit.h"

#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "log.h"

enum {
    IPV6_MULTICAST_MARK = 0xff,
};

static bool allow_verified(struct rate_limiter *rl, struct rate_limit_entry *entry);
static void init_ipv4_entry(struct rate_limit_entry *entry, struct sockaddr_in *addr4);
static void init_ipv6_entry(struct rate_limit_entry *entry, struct sockaddr_in6 *addr6);
static void ip_count_map_reset(struct rate_limiter *rl);
static struct rate_limit_entry *entry_from_node(struct hashtable_node *node);

void rate_limit_init(struct rate_limiter *rl, time_t interval, size_t max_total,
        size_t max_per_ip, struct rate_limit_entry *entries,
        struct hashtable_node **buckets) {
    rl->max_total = max_total;
    rl->max_per_ip = max_per_ip;
    rl->attempts = 0;
    rl->allowed = 0;
    rl->interval = interval;
    rl->reset_time = 0;
    rl->under_load_until = 0;
    rl->entries = entries;
    rl->next_entry_index = 0;

    hashtable_new(&rl->ip_count_map, buckets, max_total);
}

bool rate_limit_is_allowed_unverified(struct rate_limiter *rl, time_t now) {
    if (now >= rl->reset_time) {
        log_debug("rate limit reset");
        rl->reset_time = now + rl->interval;
        rl->attempts = 0;
        rl->allowed = 0;
        ip_count_map_reset(rl);
    } else if (rl->attempts >= rl->max_total) {
        rl->under_load_until = now + (2 * rl->interval);
        return false;
    }

    rl->attempts++;

    if (now < rl->under_load_until) {
        return false;
    }

    rl->allowed++;
    log_debug("rate limit allow unverified: allowed=%zu", rl->allowed);
    return true;
}

bool rate_limit_is_allowed_verified(
        struct rate_limiter *rl, struct sockaddr_storage *addr) {
    if (rl->allowed >= rl->max_total) {
        log_debug("rate limit allow verified failed: allowed=%zu, max=%zu", rl->allowed,
                rl->max_total);
        return false;
    }

    struct rate_limit_entry *entry = &rl->entries[rl->next_entry_index];

    if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            struct sockaddr_in addr4;
            static const size_t mapped_addr_offset =
                    sizeof(addr6->sin6_addr) - sizeof(addr4.sin_addr);
            memcpy(&addr4.sin_addr, &addr6->sin6_addr.s6_addr[mapped_addr_offset],
                    sizeof(addr4.sin_addr));
            init_ipv4_entry(entry, &addr4);
        } else {
            init_ipv6_entry(entry, addr6);
        }
    } else {
        assert(addr->ss_family == AF_INET);
        init_ipv4_entry(entry, (struct sockaddr_in *)addr);
    }

    size_t bucket_index = hashtable_bucket_index(
            &rl->ip_count_map, entry->ip_prefix, IPV6_END_SITE_PREFIX_LEN);

    struct hashtable_node *node = NULL;
    hashtable_for_each_possible(&rl->ip_count_map, node, bucket_index) {
        struct rate_limit_entry *existing_entry = entry_from_node(node);
        if (memcmp(existing_entry->ip_prefix, entry->ip_prefix,
                    IPV6_END_SITE_PREFIX_LEN) == 0) {
            // Found an existing entry for this IP prefix
            if (existing_entry->count >= rl->max_per_ip) {
                log_debug(
                        "rate limit allow verified failed: count > max_per_ip, max_per_ip=%zu",
                        rl->max_per_ip);
                return false;
            }
            existing_entry->count++;
            return allow_verified(rl, existing_entry);
        }
    }

    hashtable_add(&rl->ip_count_map, bucket_index, &entry->node);
    rl->next_entry_index++;

    return allow_verified(rl, entry);
}

static bool allow_verified(struct rate_limiter *rl, struct rate_limit_entry *entry) {
    rl->allowed++;
    log_debug("rate limit allow verified: count=%u, max_per_ip=%zu", entry->count,
            rl->max_per_ip);
    return true;
}

static void init_ipv4_entry(struct rate_limit_entry *entry, struct sockaddr_in *addr4) {
    entry->count = 1;
    // Use IPv6 multicast prefix to represent IPv4 addresses, because multicast
    // addresses can't appear as source addresses.
    entry->ip_prefix[0] = IPV6_MULTICAST_MARK;
    entry->ip_prefix[1] = 0x01; // Interface-Local scope, doesn't matter
    entry->ip_prefix[2] = 0x00;
    entry->ipv4_addr = addr4->sin_addr.s_addr;
}

static void init_ipv6_entry(
        struct rate_limit_entry *entry, struct sockaddr_in6 *addr6) {
    entry->count = 1;
    memcpy(entry->ip_prefix, &addr6->sin6_addr, sizeof(entry->ip_prefix));
}

static void ip_count_map_reset(struct rate_limiter *rl) {
    rl->next_entry_index = 0;
    hashtable_remove_all(&rl->ip_count_map);
}

static struct rate_limit_entry *entry_from_node(struct hashtable_node *node) {
    return (struct rate_limit_entry *)((char *)node -
            offsetof(struct rate_limit_entry, node));
}
