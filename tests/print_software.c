// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <stdio.h>

#include "version.h"

int main(void) {
    (void)printf("salty-stun %s (%s)\n", SALTY_STUN_VERSION, SALTY_STUN_SOURCE_URL);
    return 0;
}
