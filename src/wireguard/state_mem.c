#include "state_mem.h"

#include <time.h>

#include "log.h"

#define SESSION_FROM_NODE(node_) \
    ((struct state_mem_session *)((char *)(node_) - \
            offsetof(struct state_mem_session, node)))
#define CONST_SESSION_FROM_NODE(node_) \
    ((const struct state_mem_session *)((const char *)(node_) - \
            offsetof(struct state_mem_session, node)))

#define INVALID_TIME INT64_MAX

static int store_new_session(
        struct wireguard_state *state, struct wireguard_session *session);
static struct wireguard_session *get_session_by_local_index(
        struct wireguard_state *state, uint32_t local_index);
static size_t index_hash(const void *key);
static int index_equals(const void *key, const HashTableNode *node);

struct wireguard_state *state_mem_init(struct state_mem *state_mem,
        struct state_mem_session *sessions, size_t session_count,
        HashTableNode **index_buckets) {
    hashtable_fast_init(&state_mem->index_session_map, index_buckets,
            STATE_MEM_NUM_BUCKETS(session_count), index_hash, index_equals, NULL, NULL);

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

        hashtable_remove_key(
                &state_mem->index_session_map, &state_session->session.local_index);
    }

    state_mem->next_session_index =
            (state_mem->next_session_index + 1) % state_mem->session_count;

    state_session->session = *session;

    hashtable_insert(
            &state_mem->index_session_map, &session->local_index, &state_session->node);

    return 0;
}

static struct wireguard_session *get_session_by_local_index(
        struct wireguard_state *state, uint32_t local_index) {
    struct state_mem *state_mem = (struct state_mem *)state;
    HashTableNode *node =
            hashtable_lookup_key(&state_mem->index_session_map, &local_index);
    if (node == NULL) {
        return NULL;
    }

    return &SESSION_FROM_NODE(node)->session;
}

static size_t index_hash(const void *key) {
    // Since local_index is a locally generated random number, its value can be
    // used as is. There's no need to calculate a hash.
    return *(const uint32_t *)key;
}

static int index_equals(const void *key, const HashTableNode *node) {
    return *(const uint32_t *)key == CONST_SESSION_FROM_NODE(node)->session.local_index;
}
