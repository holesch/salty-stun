// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "hashtable.h"

#include <assert.h>
#include <sodium.h>
#include <string.h>

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static uint8_t g_hash_key[crypto_shorthash_KEYBYTES];

void hashtable_init(void) {
    crypto_shorthash_keygen(g_hash_key);
}

void hashtable_new(struct hashtable *table, struct hashtable_node **bucket_array,
        size_t expected_count) {
    table->bucket_array = bucket_array;
    table->num_buckets = HASHTABLE_BUCKET_COUNT(expected_count);
}

size_t hashtable_bucket_index(
        const struct hashtable *table, const uint8_t *key, size_t key_length) {
    static_assert(crypto_shorthash_BYTES == sizeof(uint64_t),
            "crypto_shorthash_BYTES must be 8 bytes");
    union {
        uint8_t bytes[crypto_shorthash_BYTES];
        uint64_t u64;
    } result;

    crypto_shorthash(result.bytes, key, key_length, g_hash_key);
    return hashtable_hash_to_bucket_index(table, (uint32_t)result.u64);
}

// Fast alternative to modulo reduction:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
size_t hashtable_hash_to_bucket_index(
        const struct hashtable *table, uint32_t key_hash) {
    return (size_t)(((uint64_t)key_hash * (uint64_t)table->num_buckets) >>
            (CHAR_BIT * sizeof(uint32_t)));
}

void hashtable_add(
        struct hashtable *table, size_t bucket_index, struct hashtable_node *node) {
    struct hashtable_node *first = table->bucket_array[bucket_index];
    node->next = first;
    table->bucket_array[bucket_index] = node;
}

void hashtable_remove(
        struct hashtable *table, size_t bucket_index, struct hashtable_node *node) {
    struct hashtable_node **current = &table->bucket_array[bucket_index];
    while (*current) {
        if (*current == node) {
            *current = node->next;
            return;
        }
        current = &(*current)->next;
    }
}

void hashtable_remove_all(struct hashtable *table) {
    memset((void *)table->bucket_array, 0,
            table->num_buckets * sizeof(struct hashtable_node *));
}
