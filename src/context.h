// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef CONTEXT_H_
#define CONTEXT_H_

#include <netinet/in.h>

#include "packet.h"

struct context {
    struct packet request;
    struct packet response;
    struct sockaddr_storage outer_remote_addr;
};

#endif // CONTEXT_H_
