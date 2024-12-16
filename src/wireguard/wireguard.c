#include "wireguard.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "wireguard/aead.h"
#include "wireguard/dh.h"
#include "wireguard/hash.h"
#include "wireguard/kdf.h"
#include "wireguard/mac.h"

enum wg_type {
    WG_TYPE_INITIATION = 1,
    WG_TYPE_RESPONSE = 2,
    WG_TYPE_COOKIE = 3,
    WG_TYPE_TRANSPORT = 4,
};

enum {
    TAI64N_SIZE = 12,
};

struct handshake_request {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t sender;
    uint8_t ephemeral[DH_PUBLIC_KEY_SIZE];
    uint8_t static_tagged[DH_PUBLIC_KEY_SIZE + AEAD_TAG_SIZE];
    uint8_t timestamp_tagged[TAI64N_SIZE + AEAD_TAG_SIZE];
    uint8_t mac1[MAC_SIZE];
    uint8_t mac2[MAC_SIZE];
};

struct handshake_response {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t sender;
    uint32_t receiver;
    uint8_t ephemeral[DH_PUBLIC_KEY_SIZE];
    uint8_t empty_tagged[AEAD_TAG_SIZE];
    uint8_t mac1[MAC_SIZE];
    uint8_t mac2[MAC_SIZE];
};

struct transport_data {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t receiver;
    uint64_t counter;
    uint8_t packet[];
};

struct session {
    uint32_t local_index;
    uint32_t remote_index;
    uint8_t recv_key[AEAD_KEY_SIZE];
    uint8_t send_key[AEAD_KEY_SIZE];
    uint64_t recv_counter;
    uint64_t send_counter;
};

static int wireguard_handle_handshake(struct wireguard *wg,
        struct packet *request_bytes, struct packet *response_bytes);
static int wireguard_handle_data(
        struct wireguard *wg, struct packet *request, struct packet *response);
static void dump_bytes(const uint8_t *bytes, size_t len);

// Label-Mac1
//     The UTF-8 string literal “mac1----”, 8 bytes of output.
static const uint8_t LABEL_MAC1[] = { 'm', 'a', 'c', '1', '-', '-', '-', '-' };
static struct session
        g_sessions[1]; // NOLINT: will be replaced when multiple sessions are supported

int wireguard_init(struct wireguard *wg, const uint8_t *private_key) {
    hash_state hash_state;

    wg->private_key = private_key;
    dh_derive_public_key(wg->public_key, private_key);

    // pre-calculate mac1 key
    // msg.mac1 := Mac(Hash(Label-Mac1 ‖ Spub m′ ), msgα)
    hash_init(&hash_state);
    hash_update(&hash_state, LABEL_MAC1, sizeof(LABEL_MAC1));
    hash_update(&hash_state, wg->public_key, sizeof(wg->public_key));
    hash_final(&hash_state, wg->mac1_key);

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

int wireguard_handle_request(
        struct wireguard *wg, struct packet *request, struct packet *response) {
    uint8_t type = request->head[0];
    switch (type) {
    case WG_TYPE_INITIATION:
        printf("initiation\n");
        return wireguard_handle_handshake(wg, request, response);
    case WG_TYPE_TRANSPORT:
        printf("transport\n");
        return wireguard_handle_data(wg, request, response);
    default:
        printf("unknown packet type: %d\n", type);
        return 1;
    }
}

static int wireguard_handle_handshake(struct wireguard *wg,
        struct packet *request_bytes, struct packet *response_bytes) {
    hash_state hash_state;
    struct kdf_state kdf_state;
    uint8_t hash[HASH_SIZE];
    uint8_t chaining_key[KDF_KEY_SIZE];
    uint8_t shared_secret[DH_SHARED_SECRET_SIZE];
    uint8_t encryption_key[AEAD_KEY_SIZE];
    struct handshake_request *req = (struct handshake_request *)request_bytes->head;

    // msg.mac1 := Mac(Hash(Label-Mac1 ‖ Spub m′ ), msgα)
    uint8_t mac1[MAC_SIZE];
    size_t in_len = sizeof(*req) - sizeof(req->mac1) - sizeof(req->mac2);
    mac_calculate(mac1, request_bytes->head, in_len, wg->mac1_key);

    if (sodium_memcmp(mac1, req->mac1, sizeof(mac1)) != 0) {
        printf("mac1 mismatch\n");
        return 1;
    }

    // TODO support multiple sessions
    struct session *session = &g_sessions[0];

    // msg.sender := Ii
    session->remote_index = req->sender;

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
        printf("error deriving shared secret\n");
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
        printf("error decrypting remote public key\n");
        return 1;
    }

    // Hi := Hash(Hi ‖ msg.static)
    hash_mix(hash, req->static_tagged, sizeof(req->static_tagged));

    // (Ci, κ) := Kdf2(Ci, DH(Spriv i , Spub r ))
    // here: (Ci, κ) := Kdf2(Ci, DH(Spriv r , Spub i ))
    err = dh_shared_secret(shared_secret, wg->private_key, remote_public_key);
    if (err) {
        printf("error deriving shared secret\n");
        return 1;
    }
    kdf_init(&kdf_state, chaining_key, shared_secret, sizeof(shared_secret));
    kdf_expand(&kdf_state, chaining_key);
    kdf_expand(&kdf_state, encryption_key);

    // msg.timestamp := Aead(κ, 0, Timestamp(), Hi)
    uint8_t timestamp[sizeof(req->timestamp_tagged) - AEAD_TAG_SIZE];
    aead_decrypt(timestamp, encryption_key, 0, req->timestamp_tagged,
            sizeof(req->timestamp_tagged), hash, sizeof(hash));
    if (err) {
        printf("error decrypting timestamp\n");
        return 1;
    }

    // Hi := Hash(Hi ‖ msg.timestamp)
    hash_mix(hash, req->timestamp_tagged, sizeof(req->timestamp_tagged));

    // TODO check timestamp

    struct handshake_response *resp = (struct handshake_response *)response_bytes->head;
    resp->type = WG_TYPE_RESPONSE;
    memset(resp->reserved, 0, sizeof(resp->reserved));

    // msg.sender := Ir
    session->local_index = randombytes_random();
    resp->sender = session->local_index;

    // msg.receiver := Ii
    resp->receiver = session->remote_index;

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
        printf("error deriving shared secret from ephemeral\n");
        return 1;
    }
    kdf_init(&kdf_state, chaining_key, shared_secret, sizeof(shared_secret));
    kdf_expand(&kdf_state, chaining_key);

    // Cr := Kdf1(Cr , DH(Epriv r , Spub i))
    err = dh_shared_secret(shared_secret, ephemeral_private_key, remote_public_key);
    if (err) {
        printf("error deriving shared secret from remote public key\n");
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
    uint8_t mac1_key[MAC_KEY_SIZE];
    hash_init(&hash_state);
    hash_update(&hash_state, LABEL_MAC1, sizeof(LABEL_MAC1));
    hash_update(&hash_state, remote_public_key, sizeof(remote_public_key));
    hash_final(&hash_state, mac1_key);
    in_len = sizeof(*resp) - sizeof(resp->mac1) - sizeof(resp->mac2);
    mac_calculate(resp->mac1, response_bytes->head, in_len, mac1_key);

    // msg.mac2 := 0
    memset(resp->mac2, 0, sizeof(resp->mac2));

    // (T send i = T recv r , T recv i = T send r) := Kdf2(Ci = Cr , ϵ)
    kdf_init(&kdf_state, chaining_key, NULL, 0);
    kdf_expand(&kdf_state, session->recv_key);
    kdf_expand(&kdf_state, session->send_key);

    // N send i = N recv r = N recv i = N send r := 0
    session->recv_counter = 0;
    session->send_counter = 0;

    // Epriv i = Epub i = Epriv r = Epub r = Ci = Cr := ϵ
    sodium_memzero(ephemeral_private_key, sizeof(ephemeral_private_key));
    sodium_memzero(chaining_key, sizeof(chaining_key));
    sodium_memzero(shared_secret, sizeof(shared_secret));
    sodium_memzero(encryption_key, sizeof(encryption_key));

    response_bytes->len = sizeof(*resp);
    return 0;
}

static int wireguard_handle_data(
        struct wireguard *wg, struct packet *request, struct packet *response) {
    (void)wg;
    struct transport_data *req = (struct transport_data *)request->head;

    // TODO support multiple sessions
    struct session *session = &g_sessions[0];

    // msg.receiver := Im′
    if (req->receiver != session->local_index) {
        printf("receiver mismatch\n");
        return 1;
    }

    // msg.counter := N send m
    // TODO sliding window
    if (req->counter != session->recv_counter) {
        printf("counter mismatch: expected %lu, got %lu\n", session->recv_counter,
                req->counter);
        // return 1;
    }

    // msg.packet := Aead(T send m , N send m , P, ϵ)
    size_t packet_len = request->len - sizeof(*req);
    int err = aead_decrypt(req->packet, session->recv_key, req->counter, req->packet,
            packet_len, NULL, 0);
    if (err) {
        printf("error decrypting packet\n");
        return 1;
    }
    packet_len -= AEAD_TAG_SIZE;

    // N send m := N send m + 1
    session->recv_counter++;

    printf("received packet: ");
    dump_bytes(req->packet, packet_len);

    // TODO send response
    response->len = 0;
    return 0;
}

static void dump_bytes(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        // printf("%02x", bytes[i]);
        // printf("%d ", bytes[i]);
        printf("0x%02x, ", bytes[i]);
    }
    printf("\n");
}