// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef INET_CHECKSUM_H_
#define INET_CHECKSUM_H_

#include <stddef.h>
#include <stdint.h>

uint16_t inet_checksum(const void *data, size_t len, uint32_t initial_sum);

#endif // INET_CHECKSUM_H_
