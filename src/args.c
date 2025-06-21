// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "args.h"

#include <errno.h>
#include <limits.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include "version.h"

static FILE *open_key_log_file(const char *path);
static void read_key(const char *path, unsigned char *key);
static void read_key_from_file(FILE *file, const char *path, unsigned char *key);
static bool is_lone_dash(const char *str);
static enum log_level handle_log_level_option(const char *arg);
static unsigned long handle_ulong_option(const char *arg, unsigned long min_value,
        unsigned long max_value, const char *error_msg);
static int parse_ulong(const char *str, unsigned long *val, int base);
_Noreturn static void usage_error(const char *fmt, ...);
_Noreturn static void usage_error_errnum(const char *fmt, ...);

static const char USAGE[] =
        "usage: salty-stun [-hV] [-p PORT] [-k KEY_FILE] [-K KEY_LOG] [-l LEVEL]\n"
        "                  [-n MAX_SESSIONS]\n";
static const char HELP[] =
        "\n"
        "A STUN server running inside a WireGuard tunnel, returning the transport\n"
        "address of the WireGuard endpoint to enable P2P VPN tunnels through NATs.\n"
        "\n"
        "optional arguments:\n"
        "  -h               show this help message and exit\n"
        "  -V               output version information and exit\n"
        "  -p PORT          listen on UDP port PORT (default %d or %d in plain\n"
        "                   mode)\n"
        "  -k KEY_FILE      read private key from KEY_FILE (default\n"
        "                   %s)\n"
        "  -K KEY_LOG       write keys to KEY_LOG, which can be used to decrypt the\n"
        "                   traffic later\n"
        "  -l LEVEL         set log level to LEVEL (error, warning, info or debug,\n"
        "                   default is info)\n"
        "  -n MAX_SESSIONS  maximum number of WireGuard sessions (default %zu)\n"
        "  -f FD            listen on socket FD instead of creating a new socket\n"
        "  -P               run in plain STUN mode, without WireGuard tunneling\n"
        "";
static const char VERSION[] = "salty-stun " SALTY_STUN_VERSION "\n";
static const char OPTSTRING[] = ":hVp:k:K:l:n:f:P";

static const char DEFAULT_KEY_FILE[] = "/etc/salty-stun/private-key";
static const uint16_t DEFAULT_PORT = 51820;
static const uint16_t DEFAULT_PORT_PLAIN = 3478;
static const size_t DEFAULT_MAX_SESSIONS = 1024;

void parse_args(int argc, char *argv[], struct args *args) {
    bool has_key_file = false;
    args->port = 0;
    args->key_log = NULL;
    args->level = LOG_INFO;
    args->max_sessions = DEFAULT_MAX_SESSIONS;
    args->sockfd = -1;
    args->plain = false;

    int opt = 0;
    while ((opt = getopt(argc, argv, OPTSTRING)) != -1) {
        switch (opt) {
        case 'h':
            (void)fprintf(stdout, USAGE);
            (void)fprintf(stdout, HELP, DEFAULT_PORT, DEFAULT_PORT_PLAIN,
                    DEFAULT_KEY_FILE, DEFAULT_MAX_SESSIONS);
            exit(0);
            break;
        case 'V':
            (void)fprintf(stdout, VERSION);
            exit(0);
            break;
        case 'p': {
            const unsigned long min_port = 1;
            const unsigned long max_port = UINT16_MAX;
            args->port =
                    handle_ulong_option(optarg, min_port, max_port, "-p: invalid port");
            break;
        }
        case 'k':
            read_key(optarg, args->private_key);
            has_key_file = true;
            break;
        case 'K':
            args->key_log = open_key_log_file(optarg);
            break;
        case 'l':
            args->level = handle_log_level_option(optarg);
            break;
        case 'n': {
            const unsigned long min_sessions = 1;
            const unsigned long max_sessions = 0x800000;
            args->max_sessions = handle_ulong_option(optarg, min_sessions, max_sessions,
                    "-n: invalid number of sessions");
            break;
        }
        case 'f': {
            const unsigned long min_fd = 0;
            const unsigned long max_fd = INT_MAX;
            args->sockfd = (int)handle_ulong_option(
                    optarg, min_fd, max_fd, "-f: invalid file descriptor");
            break;
        }
        case 'P':
            args->plain = true;
            break;
        case ':':
            usage_error("option -%c requires an argument", optopt);
            break;
        default:
            usage_error("unrecognized option: -%c", optopt);
        }
    }

    int remaining = argc - optind;
    if (remaining) {
        usage_error("unrecognized argument: %s", argv[optind]);
    }

    if (!args->plain && !has_key_file) {
        read_key(DEFAULT_KEY_FILE, args->private_key);
    }

    if (args->port == 0) {
        args->port = args->plain ? DEFAULT_PORT_PLAIN : DEFAULT_PORT;
    }
}

static FILE *open_key_log_file(const char *path) {
    if (is_lone_dash(path)) {
        return stdout;
    }

    FILE *file = fopen(path, "w");
    if (!file) {
        usage_error_errnum("failed to open key log file \"%s\"", path);
    }

    return file;
}

static void read_key(const char *path, unsigned char *key) {
    if (is_lone_dash(path)) {
        read_key_from_file(stdin, "<stdin>", key);
    } else {
        FILE *file = fopen(path, "r");
        if (!file) {
            usage_error_errnum("failed to open key file \"%s\"", path);
        }
        read_key_from_file(file, path, key);
        int err = fclose(file);
        if (err) {
            usage_error_errnum("failed to close key file \"%s\"", path);
        }
    }
}

static void read_key_from_file(FILE *file, const char *path, unsigned char *key) {
    char base64_key[sodium_base64_ENCODED_LEN(
            DH_PRIVATE_KEY_SIZE, sodium_base64_VARIANT_ORIGINAL)];

    size_t n_items = fread(base64_key, sizeof(base64_key) - 1, 1, file);
    if (n_items != 1) {
        if (feof(file)) {
            usage_error("not enough data in key file \"%s\"", path);
        } else {
            usage_error_errnum("failed to read key file \"%s\"", path);
        }
    }

    base64_key[sizeof(base64_key) - 1] = '\0';

    int trailing_char = 0;
    while ((trailing_char = fgetc(file)) != EOF) {
        switch (trailing_char) {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case '\v':
        case '\f':
            break;
        default:
            usage_error("found trailing character in key file \"%s\": '%c'", path,
                    trailing_char);
        }
    }

    if (ferror(file)) {
        usage_error_errnum("failed to read key file \"%s\"", path);
    }

    int err = sodium_base642bin(key, DH_PRIVATE_KEY_SIZE, base64_key,
            sizeof(base64_key) - 1, NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
    if (err) {
        usage_error("failed to decode key in \"%s\"", path);
    }
}

static bool is_lone_dash(const char *str) {
    return str[0] == '-' && str[1] == '\0';
}

static enum log_level handle_log_level_option(const char *arg) {
    const char *level_str[] = {
        [LOG_ERROR] = "error",
        [LOG_WARN] = "warning",
        [LOG_INFO] = "info",
        [LOG_DEBUG] = "debug",
    };

    for (enum log_level level = LOG_ERROR; level <= LOG_DEBUG; level++) {
        if (strcmp(arg, level_str[level]) == 0) {
            return level;
        }
    }

    usage_error("argument -l invalid log level: '%s'", arg);
}

static unsigned long handle_ulong_option(const char *arg, unsigned long min_value,
        unsigned long max_value, const char *error_msg) {
    unsigned long val = 0;
    int err = parse_ulong(arg, &val, 0);
    if (err || val < min_value || val > max_value) {
        usage_error("argument %s: '%s'", error_msg, arg);
    }

    return val;
}

static int parse_ulong(const char *str, unsigned long *val, int base) {
    char *endptr = NULL;
    errno = 0;
    *val = strtoul(str, &endptr, base);
    return endptr == str || *endptr != '\0' || (*val == ULONG_MAX && errno == ERANGE);
}

_Noreturn static void usage_error(const char *fmt, ...) {
    (void)fprintf(stderr, USAGE);
    (void)fprintf(stderr, "error: ");

    va_list args;
    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);

    (void)fprintf(stderr, "\n");
    exit(2);
}

_Noreturn static void usage_error_errnum(const char *fmt, ...) {
    (void)fprintf(stderr, USAGE);
    (void)fprintf(stderr, "error: ");

    va_list args;
    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);

    (void)fprintf(stderr, ": ");
    perror(NULL);
    exit(2);
}
