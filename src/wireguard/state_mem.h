// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef STATE_MEM_H_
#define STATE_MEM_H_

#include <stddef.h>

#include "hashtable.h"
#include "wireguard.h"

struct state_mem_session {
    struct hashtable_node node;
    struct wireguard_session session;
};

struct state_mem {
    struct wireguard_state state;
    struct hashtable index_session_map;
    struct state_mem_session *sessions;
    size_t session_count;
    size_t next_session_index;
};

struct wireguard_state *state_mem_init(struct state_mem *state_mem,
        struct state_mem_session *sessions, size_t session_count,
        struct hashtable_node **index_buckets);

#endif // STATE_MEM_H_
