// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef HASHTABLE_H_
#define HASHTABLE_H_

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define HASHTABLE_BUCKET_COUNT(expected_count) \
    ((expected_count) + ((expected_count) / 3))

struct hashtable;
struct hashtable_node;

struct hashtable_node {
    struct hashtable_node *next;
};

struct hashtable {
    struct hashtable_node **bucket_array;
    size_t num_buckets;
};

void hashtable_init(void);
void hashtable_new(struct hashtable *table, struct hashtable_node **bucket_array,
        size_t expected_count);
size_t hashtable_bucket_index(
        const struct hashtable *table, const uint8_t *key, size_t key_length);
size_t hashtable_hash_to_bucket_index(const struct hashtable *table, uint32_t key_hash);
void hashtable_add(
        struct hashtable *table, size_t bucket_index, struct hashtable_node *node);
void hashtable_remove(
        struct hashtable *table, size_t bucket_index, struct hashtable_node *node);
void hashtable_remove_all(struct hashtable *table);

#define hashtable_for_each_possible(table, node, bucket_index) \
    for ((node) = (table)->bucket_array[bucket_index]; (node); (node) = (node)->next)

#endif
