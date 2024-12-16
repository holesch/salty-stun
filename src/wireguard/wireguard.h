#ifndef WIREGUARD_H_
#define WIREGUARD_H_

#include <stdint.h>

#include "packet.h"
#include "wireguard/dh.h"
#include "wireguard/hash.h"
#include "wireguard/mac.h"

struct wireguard {
    const uint8_t *private_key;
    uint8_t public_key[DH_PUBLIC_KEY_SIZE];
    uint8_t mac1_key[MAC_KEY_SIZE];
    uint8_t initial_hash[HASH_SIZE];
};

int wireguard_init(struct wireguard *wg, const uint8_t *private_key);
int wireguard_handle_request(
        struct wireguard *wg, struct packet *request, struct packet *response);

#endif // WIREGUARD_H_
