#include "rate_limit.h"

#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

enum {
    IPV6_MULTICAST_MARK = 0xff,
};

static void init_ipv4_entry(struct rate_limit_entry *entry, struct sockaddr_in *addr4);
static void ip_count_map_reset(struct rate_limiter *rl);
static size_t hash(const void *key);
static int entry_equals(const void *key, const HashTableNode *node);
static void entry_collide(
        HashTableNode *old_node, HashTableNode *new_node, void *auxiliary_data);
static const struct rate_limit_entry *entry_from_node_const(const HashTableNode *node);
static struct rate_limit_entry *entry_from_node(HashTableNode *node);

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static uint8_t g_hash_key[crypto_shorthash_KEYBYTES];

void rate_limit_init(struct rate_limiter *rl, time_t interval, size_t max_total,
        size_t max_per_ip, struct rate_limit_entry *entries, HashTableNode **buckets) {
    rl->max_total = max_total;
    rl->max_per_ip = max_per_ip;
    rl->attempts = 0;
    rl->allowed = 0;
    rl->interval = interval;
    rl->reset_time = 0;
    rl->under_load_until = 0;
    rl->entries = entries;

    hashtable_fast_init(&rl->ip_count_map, buckets, RATE_LIMIT_NUM_BUCKETS(max_total),
            hash, entry_equals,
            (void (*)(
                    const HashTableNode *, const HashTableNode *, void *))entry_collide,
            rl);

    HashTableNode *first = HASHTABLE_POISON_NEXT;
    for (size_t i = 0; i < max_total; ++i) {
        struct rate_limit_entry *entry = &entries[i];
        entry->node.next = first;
        first = &entry->node;
    }
    rl->next_node = first;

    crypto_shorthash_keygen(g_hash_key);
}

bool rate_limit_allow_unverified(struct rate_limiter *rl, time_t now) {
    if (now >= rl->reset_time) {
        rl->reset_time = now + rl->interval;
        rl->attempts = 0;
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
    return true;
}

bool rate_limit_allow_verified(struct rate_limiter *rl, struct sockaddr_storage *addr) {
    if (rl->allowed >= rl->max_total) {
        return false;
    }

    HashTableNode *node = rl->next_node;
    assert(node != HASHTABLE_POISON_NEXT);
    rl->next_node = node->next;
    struct rate_limit_entry *entry = entry_from_node(node);

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
            entry->count = 1;
            memcpy(entry->ip_prefix, &addr6->sin6_addr, sizeof(entry->ip_prefix));
        }
    } else {
        assert(addr->ss_family == AF_INET);
        init_ipv4_entry(entry, (struct sockaddr_in *)addr);
    }

    hashtable_insert(&rl->ip_count_map, entry->ip_prefix, &entry->node);

    if (entry->count > rl->max_per_ip) {
        return false;
    }

    rl->allowed++;
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

static void ip_count_map_reset(struct rate_limiter *rl) {
    HashTableNode *node = NULL;
    HashTableNode *backup_node = NULL;
    size_t bucket_index = 0;
    HashTableNode *first = rl->next_node;

    hashtable_for_each_safe(node, backup_node, bucket_index, &rl->ip_count_map) {
        node->next = first;
        first = node;
    }
    hashtable_remove_all(&rl->ip_count_map);

    rl->next_node = first;
}

static size_t hash(const void *key) {
    static_assert(crypto_shorthash_BYTES == sizeof(uint64_t),
            "crypto_shorthash_BYTES must be 8 bytes");
    union {
        uint8_t bytes[crypto_shorthash_BYTES];
        uint64_t u64;
    } result;

    crypto_shorthash(result.bytes, key, IPV6_END_SITE_PREFIX_LEN, g_hash_key);
    return (size_t)result.u64;
}

static int entry_equals(const void *key, const HashTableNode *node) {
    const struct rate_limit_entry *entry = entry_from_node_const(node);
    return memcmp(key, entry->ip_prefix, IPV6_END_SITE_PREFIX_LEN);
}

static void entry_collide(
        HashTableNode *old_node, HashTableNode *new_node, void *auxiliary_data) {
    struct rate_limiter *rl = (struct rate_limiter *)auxiliary_data;
    struct rate_limit_entry *old_entry = entry_from_node(old_node);
    struct rate_limit_entry *new_entry = entry_from_node(new_node);

    if (old_entry->count < UINT8_MAX) {
        new_entry->count = old_entry->count + 1;
    } else {
        new_entry->count = old_entry->count;
    }

    HashTableNode *next = rl->next_node;
    rl->next_node = old_node;
    old_node->next = next;
}

static const struct rate_limit_entry *entry_from_node_const(const HashTableNode *node) {
    return (const struct rate_limit_entry *)((const char *)node -
            offsetof(struct rate_limit_entry, node));
}

static struct rate_limit_entry *entry_from_node(HashTableNode *node) {
    return (struct rate_limit_entry *)((char *)node -
            offsetof(struct rate_limit_entry, node));
}
