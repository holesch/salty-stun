// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include "args.h"

int main(int argc, char **argv) {
    struct args args = { 0 };
    parse_args(argc, argv, &args);

    printf("%" PRIu16 "\n", args.port);

    for (int i = 0; i < DH_PRIVATE_KEY_SIZE; i++) {
        printf("%02" PRIx8 " ", args.private_key[i]);
    }
    printf("\n");

    printf("%d\n", (int)args.level);

    printf("%zu\n", args.max_sessions);

    printf("%d\n", args.sockfd);

    printf("%d\n", args.plain);

    if (args.key_log) {
        (void)fprintf(args.key_log, "key log\n");
        (void)fflush(args.key_log);
    }
}
