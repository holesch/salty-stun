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
#include "wireguard/sliding_window.h"

#define WIREGUARD_REJECT_AFTER_TIME 180
#define WIREGUARD_RATE_LIMIT_RESET_TIME 5

struct wireguard_session {
    uint32_t local_index;
    uint32_t remote_index;
    uint8_t recv_key[AEAD_KEY_SIZE];
    uint8_t send_key[AEAD_KEY_SIZE];
    struct sliding_window recv_counter;
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
    uint8_t mac1_key[HASH_SIZE];
    uint8_t initial_hash[HASH_SIZE];
    uint8_t cookie_encryption_key[HASH_SIZE];
    uint8_t cookie_secret[MAC_KEY_SIZE_MAX];
    time_t cookie_secret_expiration_time;
    FILE *key_log;
    struct wireguard_state *state;
    now_func_t now;
    size_t rate;
    size_t rate_limit;
    time_t rate_limit_reset_time;
};

int wireguard_init(struct wireguard *wg, const uint8_t *private_key, FILE *key_log,
        struct wireguard_state *state, now_func_t now, size_t rate_limit);
int wireguard_handle_request(struct wireguard *wg, struct context *ctx);

#endif // WIREGUARD_H_
