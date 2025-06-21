// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "state_mem.h"

#include <time.h>

#include "log.h"

#define INVALID_TIME INT64_MAX

static int store_new_session(
        struct wireguard_state *state, struct wireguard_session *session);
static struct wireguard_session *get_session_by_local_index(
        struct wireguard_state *state, uint32_t local_index);
static size_t calculate_bucket_index(struct state_mem *state_mem, uint32_t local_index);
static struct state_mem_session *session_from_node(struct hashtable_node *node);

struct wireguard_state *state_mem_init(struct state_mem *state_mem,
        struct state_mem_session *sessions, size_t session_count,
        struct hashtable_node **index_buckets) {
    hashtable_new(&state_mem->index_session_map, index_buckets, session_count);

    state_mem->sessions = sessions;
    state_mem->session_count = session_count;
    state_mem->next_session_index = 0;

    state_mem->state.store_new_session = store_new_session;
    state_mem->state.get_session_by_local_index = get_session_by_local_index;

    for (size_t i = 0; i < session_count; i++) {
        state_mem->sessions[i].session.created_at = INVALID_TIME;
    }

    return &state_mem->state;
}

static int store_new_session(
        struct wireguard_state *state, struct wireguard_session *session) {
    struct state_mem *state_mem = (struct state_mem *)state;
    time_t now = session->created_at;

    struct state_mem_session *state_session =
            &state_mem->sessions[state_mem->next_session_index];

    if (state_session->session.created_at != INVALID_TIME) {
        double age = difftime(now, state_session->session.created_at);
        if (age < WIREGUARD_REJECT_AFTER_TIME) {
            log_warn("Cannot store more than %d active WireGuard sessions",
                    state_mem->session_count);
            return 1;
        }

        // Remove the old session from the hashtable
        size_t bucket_index =
                calculate_bucket_index(state_mem, state_session->session.local_index);
        hashtable_remove(
                &state_mem->index_session_map, bucket_index, &state_session->node);
    }

    state_mem->next_session_index =
            (state_mem->next_session_index + 1) % state_mem->session_count;

    state_session->session = *session;
    size_t bucket_index = calculate_bucket_index(state_mem, session->local_index);
    hashtable_add(&state_mem->index_session_map, bucket_index, &state_session->node);

    return 0;
}

static struct wireguard_session *get_session_by_local_index(
        struct wireguard_state *state, uint32_t local_index) {
    struct state_mem *state_mem = (struct state_mem *)state;

    struct hashtable_node *node = NULL;
    size_t bucket_index = calculate_bucket_index(state_mem, local_index);

    hashtable_for_each_possible(&state_mem->index_session_map, node, bucket_index) {
        struct state_mem_session *session = session_from_node(node);
        if (session->session.local_index == local_index) {
            return &session->session;
        }
    }

    return NULL;
}

static size_t calculate_bucket_index(
        struct state_mem *state_mem, uint32_t local_index) {
    // Since local_index is a locally generated random number, its value can be
    // used as is. There's no need to calculate a hash.
    return hashtable_hash_to_bucket_index(&state_mem->index_session_map, local_index);
}

static struct state_mem_session *session_from_node(struct hashtable_node *node) {
    return (struct state_mem_session *)((char *)node -
            offsetof(struct state_mem_session, node));
}
