// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef INET_ICMP_H_
#define INET_ICMP_H_

#include "context.h"

int icmp_handle_request(struct context *ctx);
int icmpv6_handle_request(struct context *ctx, uint32_t ip_header_sum);

#endif // INET_ICMP_H_
