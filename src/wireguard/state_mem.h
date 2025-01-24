#ifndef STATE_MEM_H_
#define STATE_MEM_H_

#include <stddef.h>

#include "cdsa/hashtable.h"
#include "wireguard.h"

#define STATE_MEM_NUM_BUCKETS(session_count) ((session_count) + ((session_count) / 3))

struct state_mem_session {
    struct wireguard_session session;
    HashTableNode node;
};

struct state_mem {
    struct wireguard_state state;
    HashTable index_session_map;
    struct state_mem_session *sessions;
    size_t session_count;
    size_t next_session_index;
};

struct wireguard_state *state_mem_init(struct state_mem *state_mem,
        struct state_mem_session *sessions, size_t session_count,
        HashTableNode **index_buckets);

#endif // STATE_MEM_H_
