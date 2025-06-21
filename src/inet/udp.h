// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef INET_UDP_H_
#define INET_UDP_H_

#include <stdint.h>

#include "context.h"

int udp_handle_request(struct context *ctx, uint32_t ip_header_sum);

#endif // INET_UDP_H_
