// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef STUN_H_
#define STUN_H_

#include "context.h"

int stun_handle_request(struct context *ctx);

#endif // STUN_H_
