// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "wireguard/rate_limit.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

#include "log.h"

enum {
    MAX_TOTAL = 10,
    MAX_PER_IP = 2,
    RESET_TIME = 5,
    MAX_LINE_LENGTH = 1024,
};

int main(void) {
    log_init(LOG_DEBUG);

    struct rate_limiter rl;
    static struct rate_limit_entry entries[MAX_TOTAL];
    static struct hashtable_node *buckets[HASHTABLE_BUCKET_COUNT(MAX_TOTAL)];
    rate_limit_init(&rl, RESET_TIME, MAX_TOTAL, MAX_PER_IP, entries, buckets);

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), stdin)) {
        time_t timestamp = 0;
        char addr_str[INET6_ADDRSTRLEN]; // Enough for IPv6 addresses

        // Parse the timestamp and IP address from the line
        // <timestamp> <ip_address>
        // NOLINTNEXTLINE(cert-err34-c)
        int num_matched = sscanf(line, "%ld %s", &timestamp, addr_str);
        if (num_matched != 2) {
            (void)fprintf(stderr, "Invalid input format: %s\n", line);
            return 1;
        }

        struct sockaddr_storage addr;
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        if (inet_pton(AF_INET6, addr_str, &addr6->sin6_addr) == 1) {
            addr.ss_family = AF_INET6;
        } else if (inet_pton(AF_INET, addr_str, &addr4->sin_addr) == 1) {
            addr.ss_family = AF_INET;
        } else {
            (void)fprintf(stderr, "Invalid IP address: %s\n", addr_str);
            return 1;
        }

        if (rate_limit_is_allowed_unverified(&rl, timestamp)) {
            (void)fprintf(stdout, "allowed unverified\n");
        } else {
            if (rate_limit_is_allowed_verified(&rl, &addr)) {
                (void)fprintf(stdout, "allowed verified\n");
            } else {
                (void)fprintf(stdout, "denied\n");
            }
        }
        (void)fflush(stdout);
    }
}
