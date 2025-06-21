#ifndef ARGS_H_
#define ARGS_H_

#include <stdbool.h>
#include <stdint.h>

#include "log.h"
#include "wireguard/dh.h"

struct args {
    uint16_t port;
    uint8_t private_key[DH_PRIVATE_KEY_SIZE];
    FILE *key_log;
    enum log_level level;
    size_t max_sessions;
    int sockfd;
    bool plain;
};

void parse_args(int argc, char *argv[], struct args *args);

#endif
