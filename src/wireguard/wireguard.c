// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "wireguard.h"

#include <endian.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "context.h"
#include "inet/ip.h"
#include "log.h"
#include "packet.h"
#include "wireguard/aead.h"
#include "wireguard/dh.h"
#include "wireguard/hash.h"
#include "wireguard/kdf.h"
#include "wireguard/mac.h"
#include "wireguard/xaead.h"

enum wg_type {
    WG_TYPE_INITIATION = 1,
    WG_TYPE_RESPONSE = 2,
    WG_TYPE_COOKIE = 3,
    WG_TYPE_TRANSPORT = 4,
};

enum {
    TAI64N_SIZE = 12,
    COOKIE_SECRET_EXPIRATION_TIME = 120,
};

struct handshake_request {
    uint32_t type;
    uint32_t sender;
    uint8_t ephemeral[DH_PUBLIC_KEY_SIZE];
    uint8_t static_tagged[DH_PUBLIC_KEY_SIZE + AEAD_TAG_SIZE];
    uint8_t timestamp_tagged[TAI64N_SIZE + AEAD_TAG_SIZE];
    uint8_t mac1[MAC_SIZE];
    uint8_t mac2[MAC_SIZE];
};

struct handshake_response {
    uint32_t type;
    uint32_t sender;
    uint32_t receiver;
    uint8_t ephemeral[DH_PUBLIC_KEY_SIZE];
    uint8_t empty_tagged[AEAD_TAG_SIZE];
    uint8_t mac1[MAC_SIZE];
    uint8_t mac2[MAC_SIZE];
};

struct cookie_reply {
    uint32_t type;
    uint32_t receiver;
    uint8_t nonce[XAEAD_NONCE_SIZE];
    uint8_t cookie_tagged[MAC_SIZE + XAEAD_TAG_SIZE];
};

struct transport_data {
    uint32_t type;
    uint32_t receiver;
    uint64_t counter;
    uint8_t packet[];
};

static int wireguard_handle_handshake(struct wireguard *wg, struct context *ctx);
static void calculate_cookie(
        struct wireguard *wg, struct context *ctx, uint8_t *cookie);
static void send_cookie_reply(struct wireguard *wg, struct context *ctx,
        struct handshake_request *req, uint8_t *cookie);
static int wireguard_handle_data(struct wireguard *wg, struct context *ctx);
static void write_key(FILE *file, const char *name, const uint8_t *key);

// Label-Mac1
//     The UTF-8 string literal “mac1----”, 8 bytes of output.
static const uint8_t LABEL_MAC1[] = { 'm', 'a', 'c', '1', '-', '-', '-', '-' };
// Label-Cookie
//     The UTF-8 string literal “cookie--”, 8 bytes of output.
static const uint8_t LABEL_COOKIE[] = { 'c', 'o', 'o', 'k', 'i', 'e', '-', '-' };
// 2^64 - 2^13 - 1
static const uint64_t REJECT_AFTER_MESSAGES = 0xffffffffffffdfff;

int wireguard_init(struct wireguard *wg, const uint8_t *private_key, FILE *key_log,
        struct wireguard_state *state, now_func_t now,
        struct rate_limiter *rate_limiter) {
    struct hash_state hash_state;

    wg->private_key = private_key;
    dh_derive_public_key(wg->public_key, private_key);

    wg->key_log = key_log;
    wg->state = state;
    wg->now = now;
    wg->rate_limiter = rate_limiter;
    wg->cookie_secret_expiration_time = 0;

    // pre-calculate mac1 key
    // msg.mac1 := Mac(Hash(Label-Mac1 ‖ Spub m′ ), msgα)
    hash_init(&hash_state);
    hash_update(&hash_state, LABEL_MAC1, sizeof(LABEL_MAC1));
    hash_update(&hash_state, wg->public_key, sizeof(wg->public_key));
    hash_final(&hash_state, wg->mac1_key);

    // pre-calculate cookie encryption key
    // Hash(Label-Cookie ‖ Spub m)
    hash_init(&hash_state);
    hash_update(&hash_state, LABEL_COOKIE, sizeof(LABEL_COOKIE));
    hash_update(&hash_state, wg->public_key, sizeof(wg->public_key));
    hash_final(&hash_state, wg->cookie_encryption_key);

    // Ci := Hash(Construction)
    // Construction
    //     The UTF-8 string literal “Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s”, 37
    //     bytes of output.
    // Hi := Hash(Ci ‖ Identifier)
    // Identifier
    //     The UTF-8 string literal “WireGuard v1 zx2c4 Jason@zx2c4.com”, 34 bytes
    //     of output.
    static const uint8_t initial_hash[] = { 0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5,
        0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32, 0x2d, 0x9c, 0x6c, 0x66,
        0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3 };

    // Hi := Hash(Hi ‖ Spub r )
    hash_mix_to(wg->initial_hash, initial_hash, wg->public_key, sizeof(wg->public_key));

    return 0;
}

int wireguard_handle_request(struct wireguard *wg, struct context *ctx) {
    uint32_t *type_head = packet_peak_head(&ctx->request, sizeof(*type_head));
    if (!type_head) {
        log_warn("wireguard message is too short");
        return 1;
    }

    uint32_t type = le32toh(*type_head);

    switch (type) {
    case WG_TYPE_INITIATION:
        log_debug("received initiation packet");
        return wireguard_handle_handshake(wg, ctx);
    case WG_TYPE_TRANSPORT:
        log_debug("received transport packet");
        return wireguard_handle_data(wg, ctx);
    default:
        log_warn("unknown packet type: %d", type);
        return 1;
    }
}

static int wireguard_handle_handshake(struct wireguard *wg, struct context *ctx) {
    struct hash_state hash_state;
    struct kdf_state kdf_state;
    uint8_t hash[HASH_SIZE];
    uint8_t chaining_key[KDF_KEY_SIZE];
    uint8_t shared_secret[DH_SHARED_SECRET_SIZE];
    uint8_t encryption_key[AEAD_KEY_SIZE];
    struct wireguard_session session;

    struct handshake_request *req = packet_pop_head(&ctx->request, sizeof(*req));
    if (!req) {
        log_warn("wireguard message is too short");
        return 1;
    }

    if (ctx->request.len != 0) {
        log_warn("unexpected data after handshake message");
        return 1;
    }

    // msg.mac1 := Mac(Hash(Label-Mac1 ‖ Spub m′ ), msgα)
    uint8_t mac1[MAC_SIZE];
    size_t in_len = sizeof(*req) - sizeof(req->mac1) - sizeof(req->mac2);
    mac_calculate(mac1, req, in_len, wg->mac1_key, sizeof(wg->mac1_key));

    if (sodium_memcmp(mac1, req->mac1, sizeof(mac1)) != 0) {
        log_warn("mac1 mismatch");
        return 1;
    }

    time_t now = wg->now();

    if (!rate_limit_is_allowed_unverified(wg->rate_limiter, now)) {
        log_warn("under load");
        uint8_t cookie[MAC_SIZE];

        // The secret variable, Rm, changes every two minutes to a random value
        if (wg->cookie_secret_expiration_time <= now) {
            log_debug("cookie secret expired, generating new one");
            wg->cookie_secret_expiration_time = now + COOKIE_SECRET_EXPIRATION_TIME;
            randombytes_buf(wg->cookie_secret, sizeof(wg->cookie_secret));

            calculate_cookie(wg, ctx, cookie);

            // no need to check mac2, since we have a new secret
            send_cookie_reply(wg, ctx, req, cookie);
            return 0;
        }

        log_debug("cookie secret still valid, using it");
        calculate_cookie(wg, ctx, cookie);

        // msg.mac2 := Mac(Lm, msgβ)
        // The latest cookie received is represented by Lm
        uint8_t mac2[MAC_SIZE];
        in_len = sizeof(*req) - sizeof(req->mac2);
        mac_calculate(mac2, req, in_len, cookie, sizeof(cookie));

        if (sodium_memcmp(mac2, req->mac2, sizeof(mac2)) != 0) {
            log_warn("cookie mac2 mismatch");
            send_cookie_reply(wg, ctx, req, cookie);
            return 0;
        }

        // source IP address is now verified, it can be used to rate limit
        if (!rate_limit_is_allowed_verified(
                    wg->rate_limiter, &ctx->outer_remote_addr)) {
            log_warn("rate limit exceeded");
            return 1;
        }
    }

    // msg.sender := Ii
    session.remote_index = req->sender;

    // Ci := Hash(Construction)
    // Construction
    //     The UTF-8 string literal “Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s”, 37
    //     bytes of output.
    static const uint8_t initial_chaining_key[] = { 0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27,
        0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42,
        0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36 };

    // msg.ephemeral := Epub i
    // Ci := Kdf1(Ci, Epub i )
    kdf_init(&kdf_state, initial_chaining_key, req->ephemeral, sizeof(req->ephemeral));
    kdf_expand(&kdf_state, chaining_key);

    // Hi := Hash(Hi ‖ msg.ephemeral)
    hash_mix_to(hash, wg->initial_hash, req->ephemeral, sizeof(req->ephemeral));

    // (Ci, κ) := Kdf2(Ci, DH(Epriv i , Spub r ))
    // here: (Ci, κ) := Kdf2(Ci, DH(Spriv r , Epub i ))
    int err = dh_shared_secret(shared_secret, wg->private_key, req->ephemeral);
    if (err) {
        log_warn("error deriving shared secret");
        return 1;
    }
    kdf_init(&kdf_state, chaining_key, shared_secret, sizeof(shared_secret));
    kdf_expand(&kdf_state, chaining_key);
    kdf_expand(&kdf_state, encryption_key);

    // msg.static := Aead(κ, 0, Spub i , Hi)
    uint8_t remote_public_key[DH_PUBLIC_KEY_SIZE];
    err = aead_decrypt(remote_public_key, encryption_key, 0, req->static_tagged,
            sizeof(req->static_tagged), hash, sizeof(hash));
    if (err) {
        log_warn("error decrypting remote public key");
        return 1;
    }

    // Hi := Hash(Hi ‖ msg.static)
    hash_mix(hash, req->static_tagged, sizeof(req->static_tagged));

    // (Ci, κ) := Kdf2(Ci, DH(Spriv i , Spub r ))
    // here: (Ci, κ) := Kdf2(Ci, DH(Spriv r , Spub i ))
    err = dh_shared_secret(shared_secret, wg->private_key, remote_public_key);
    if (err) {
        log_warn("error deriving shared secret");
        return 1;
    }
    kdf_init(&kdf_state, chaining_key, shared_secret, sizeof(shared_secret));
    kdf_expand(&kdf_state, chaining_key);
    kdf_expand(&kdf_state, encryption_key);

    // msg.timestamp := Aead(κ, 0, Timestamp(), Hi)
    uint8_t timestamp[sizeof(req->timestamp_tagged) - AEAD_TAG_SIZE];
    err = aead_decrypt(timestamp, encryption_key, 0, req->timestamp_tagged,
            sizeof(req->timestamp_tagged), hash, sizeof(hash));
    if (err) {
        log_warn("error decrypting timestamp");
        return 1;
    }

    // Hi := Hash(Hi ‖ msg.timestamp)
    hash_mix(hash, req->timestamp_tagged, sizeof(req->timestamp_tagged));

    // TODO check timestamp

    struct handshake_response *resp = packet_set_len(&ctx->response, sizeof(*resp));
    resp->type = htole32(WG_TYPE_RESPONSE);

    // msg.sender := Ir
    session.local_index = randombytes_random();
    resp->sender = session.local_index;

    // msg.receiver := Ii
    resp->receiver = session.remote_index;

    // (Epriv r , Epub r) := DH-Generate()
    // msg.ephemeral := Epub r
    uint8_t ephemeral_private_key[DH_PRIVATE_KEY_SIZE];
    dh_generate_private_key(ephemeral_private_key);
    dh_derive_public_key(resp->ephemeral, ephemeral_private_key);

    // Cr := Kdf1(Cr , Epub r)
    kdf_init(&kdf_state, chaining_key, resp->ephemeral, sizeof(resp->ephemeral));
    kdf_expand(&kdf_state, chaining_key);

    // Hr := Hash(Hr ‖ msg.ephemeral)
    hash_mix(hash, resp->ephemeral, sizeof(resp->ephemeral));

    // Cr := Kdf1(Cr , DH(Epriv r , Epub i))
    err = dh_shared_secret(shared_secret, ephemeral_private_key, req->ephemeral);
    if (err) {
        log_warn("error deriving shared secret");
        return 1;
    }
    kdf_init(&kdf_state, chaining_key, shared_secret, sizeof(shared_secret));
    kdf_expand(&kdf_state, chaining_key);

    // Cr := Kdf1(Cr , DH(Epriv r , Spub i))
    err = dh_shared_secret(shared_secret, ephemeral_private_key, remote_public_key);
    if (err) {
        log_warn("error deriving shared secret");
        return 1;
    }
    kdf_init(&kdf_state, chaining_key, shared_secret, sizeof(shared_secret));
    kdf_expand(&kdf_state, chaining_key);

    // (Cr , τ, κ) := Kdf3(Cr , Q)
    static const uint8_t pre_shared_key[32] = { 0 };
    uint8_t hash_input[KDF_OUTPUT_SIZE];
    kdf_init(&kdf_state, chaining_key, pre_shared_key, sizeof(pre_shared_key));
    kdf_expand(&kdf_state, chaining_key);
    kdf_expand(&kdf_state, hash_input);
    kdf_expand(&kdf_state, encryption_key);

    // Hr := Hash(Hr ‖ τ )
    hash_mix(hash, hash_input, sizeof(hash_input));

    // msg.empty := Aead(κ, 0, ϵ, Hr )
    aead_encrypt(resp->empty_tagged, encryption_key, 0, NULL, 0, hash, sizeof(hash));

    // Hr := Hash(Hr ‖ msg.empty)
    hash_mix(hash, resp->empty_tagged, sizeof(resp->empty_tagged));

    // msg.mac1 := Mac(Hash(Label-Mac1 ‖ Spub m′ ), msgα)
    uint8_t mac1_key[HASH_SIZE];
    hash_init(&hash_state);
    hash_update(&hash_state, LABEL_MAC1, sizeof(LABEL_MAC1));
    hash_update(&hash_state, remote_public_key, sizeof(remote_public_key));
    hash_final(&hash_state, mac1_key);
    in_len = sizeof(*resp) - sizeof(resp->mac1) - sizeof(resp->mac2);
    mac_calculate(resp->mac1, resp, in_len, mac1_key, sizeof(mac1_key));

    // msg.mac2 := 0
    memset(resp->mac2, 0, sizeof(resp->mac2));

    // (T send i = T recv r , T recv i = T send r) := Kdf2(Ci = Cr , ϵ)
    kdf_init(&kdf_state, chaining_key, NULL, 0);
    kdf_expand(&kdf_state, session.recv_key);
    kdf_expand(&kdf_state, session.send_key);

    // N send i = N recv r = N recv i = N send r := 0
    session.recv_counter = SLIDING_WINDOW_INIT;
    session.send_counter = 0;

    session.created_at = now;

    // store session
    err = wg->state->store_new_session(wg->state, &session);
    if (err) {
        return 1;
    }

    if (wg->key_log) {
        write_key(wg->key_log, "LOCAL_STATIC_PRIVATE_KEY", wg->private_key);
        write_key(wg->key_log, "REMOTE_STATIC_PUBLIC_KEY", remote_public_key);
        write_key(wg->key_log, "LOCAL_EPHEMERAL_PRIVATE_KEY", ephemeral_private_key);
        write_key(wg->key_log, "PRE_SHARED_KEY", pre_shared_key);
    }

    // Epriv i = Epub i = Epriv r = Epub r = Ci = Cr := ϵ
    sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
    sodium_memzero(chaining_key, sizeof(chaining_key));
    sodium_memzero(shared_secret, sizeof(shared_secret));
    sodium_memzero(encryption_key, sizeof(encryption_key));

    return 0;
}

static void calculate_cookie(
        struct wireguard *wg, struct context *ctx, uint8_t *cookie) {
    // τ := Mac(Rm, Am′)
    // Am′ represents a concatenation of the subscript’s external IP source
    // address and UDP source port
    struct mac_state mac_state;
    mac_init(&mac_state, wg->cookie_secret, sizeof(wg->cookie_secret));
    if (ctx->outer_remote_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ctx->outer_remote_addr;
        mac_update(&mac_state, &addr6->sin6_addr, sizeof(addr6->sin6_addr));
        mac_update(&mac_state, &addr6->sin6_port, sizeof(addr6->sin6_port));
        mac_update(&mac_state, &addr6->sin6_scope_id, sizeof(addr6->sin6_scope_id));
    } else {
        assert(ctx->outer_remote_addr.ss_family == AF_INET);
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&ctx->outer_remote_addr;
        mac_update(&mac_state, &addr4->sin_addr, sizeof(addr4->sin_addr));
        mac_update(&mac_state, &addr4->sin_port, sizeof(addr4->sin_port));
    }
    mac_final(&mac_state, cookie);
}

static void send_cookie_reply(struct wireguard *wg, struct context *ctx,
        struct handshake_request *req, uint8_t *cookie) {
    struct cookie_reply *resp = packet_set_len(&ctx->response, sizeof(*resp));
    resp->type = htole32(WG_TYPE_COOKIE);

    // receiver := Im′
    resp->receiver = req->sender;

    // msg.nonce := ρ24
    randombytes_buf(resp->nonce, sizeof(resp->nonce));

    // msg.cookie := Xaead(Hash(Label-Cookie ‖ Spub m), msg.nonce, τ, M)
    // M represents the msg.mac1 value of the message to which this is in reply
    xaead_encrypt(resp->cookie_tagged, wg->cookie_encryption_key, resp->nonce, cookie,
            MAC_SIZE, req->mac1, sizeof(req->mac1));
}

static int wireguard_handle_data(struct wireguard *wg, struct context *ctx) {
    (void)wg;
    struct transport_data *req = packet_pop_head(&ctx->request, sizeof(*req));
    if (!req) {
        log_warn("wireguard message is too short");
        return 1;
    }

    // msg.receiver := Im′
    uint32_t local_index = req->receiver;

    struct wireguard_session *session =
            wg->state->get_session_by_local_index(wg->state, local_index);
    if (!session) {
        log_warn("unknown session");
        return 1;
    }

    // check session age
    if (wg->now() - session->created_at > WIREGUARD_REJECT_AFTER_TIME) {
        log_warn("session expired");
        return 1;
    }

    // msg.counter := N send m
    uint64_t msg_counter = le64toh(req->counter);

    // limit messages per session
    if (msg_counter >= REJECT_AFTER_MESSAGES) {
        log_warn("too many messages for session");
        return 1;
    }

    // prevent replay attacks
    struct sliding_window new_counter = { 0 };
    if (sliding_window_is_replay(&session->recv_counter, msg_counter, &new_counter)) {
        log_warn("dropping already seen packet");
        return 1;
    }

    // msg.packet := Aead(T send m , N send m , P, ϵ)
    size_t ciphertext_len = ctx->request.len;
    int err = aead_decrypt(req->packet, session->recv_key, msg_counter, req->packet,
            ciphertext_len, NULL, 0);
    if (err) {
        log_warn("error decrypting packet");
        return 1;
    }
    packet_pop_tail(&ctx->request, AEAD_TAG_SIZE);

    // N send m := N send m + 1
    session->recv_counter = new_counter;

    packet_reserve(&ctx->response, sizeof(struct transport_data));

    if (ctx->request.len == 0) {
        log_debug("received keepalive packet");
        return 1;
    }

    err = ip_handle_request(ctx);
    if (err) {
        // send keepalive packet
        packet_set_len(&ctx->response, 0);
    }

    struct transport_data *resp = packet_push_head(&ctx->response, sizeof(*resp));
    resp->type = htole32(WG_TYPE_TRANSPORT);

    // receiver := Im′
    resp->receiver = session->remote_index;

    // pad packet to multiple of 16 bytes
    // P := P ‖0^16·⎡‖P‖/16⎤−‖P‖
    packet_pad(&ctx->response, sizeof(*resp));

    // msg.counter := N send m
    resp->counter = htole64(session->send_counter);

    // msg.packet := Aead(T send m , N send m , P, ϵ)
    size_t plaintext_len = ctx->response.len - sizeof(*resp);
    packet_push_tail(&ctx->response, AEAD_TAG_SIZE);
    aead_encrypt(resp->packet, session->send_key, session->send_counter, resp->packet,
            plaintext_len, NULL, 0);

    // N send m := N send m + 1
    session->send_counter++;

    return 0;
}

static void write_key(FILE *file, const char *name, const uint8_t *key) {
    char b64[sodium_base64_ENCODED_LEN(
            DH_PRIVATE_KEY_SIZE, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(
            b64, sizeof(b64), key, DH_PRIVATE_KEY_SIZE, sodium_base64_VARIANT_ORIGINAL);
    (void)fprintf(file, "%s = %s\n", name, b64);
    (void)fflush(file);
}
