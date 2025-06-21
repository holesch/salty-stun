// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <stdbool.h>
#include <stdint.h>

#define SLIDING_WINDOW_INIT ((struct sliding_window){ 0 })

struct sliding_window {
    uint64_t bitmap;
    uint64_t last_counter;
};

bool sliding_window_is_replay(
        struct sliding_window *swin, uint64_t counter, struct sliding_window *swin_new);
