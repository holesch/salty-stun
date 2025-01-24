#ifndef WIREGUARD_H_
#define WIREGUARD_H_

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "context.h"
#include "wireguard/aead.h"
#include "wireguard/dh.h"
#include "wireguard/hash.h"
#include "wireguard/mac.h"

#define WIREGUARD_REJECT_AFTER_TIME 180

struct wireguard_session {
    uint32_t local_index;
    uint32_t remote_index;
    uint8_t recv_key[AEAD_KEY_SIZE];
    uint8_t send_key[AEAD_KEY_SIZE];
    uint64_t recv_counter;
    uint64_t send_counter;
    time_t created_at;
};

struct wireguard_state {
    int (*store_new_session)(
            struct wireguard_state *state, struct wireguard_session *session);
    struct wireguard_session *(*get_session_by_local_index)(
            struct wireguard_state *state, uint32_t local_index);
};

typedef time_t (*now_func_t)(void);

struct wireguard {
    const uint8_t *private_key;
    uint8_t public_key[DH_PUBLIC_KEY_SIZE];
    uint8_t mac1_key[MAC_KEY_SIZE];
    uint8_t initial_hash[HASH_SIZE];
    FILE *key_log;
    struct wireguard_state *state;
    now_func_t now;
};

int wireguard_init(struct wireguard *wg, const uint8_t *private_key, FILE *key_log,
        struct wireguard_state *state, now_func_t now);
int wireguard_handle_request(struct wireguard *wg, struct context *ctx);

#endif // WIREGUARD_H_
