// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef KDF_H_
#define KDF_H_

#include <blake2.h>
#include <stddef.h>
#include <stdint.h>

#include "wireguard/hmac.h"

enum {
    KDF_KEY_SIZE = HMAC_KEY_SIZE,
    KDF_OUTPUT_SIZE = BLAKE2S_OUTBYTES,
};

struct kdf_state {
    uint8_t hmac_key[KDF_OUTPUT_SIZE];
    uint8_t previous_output[KDF_OUTPUT_SIZE];
    uint8_t hmac_input[1];
};

void kdf_init(struct kdf_state *state, const uint8_t *key, const uint8_t *input,
        size_t input_len);
void kdf_expand(struct kdf_state *state, uint8_t *output);

#endif // KDF_H_
