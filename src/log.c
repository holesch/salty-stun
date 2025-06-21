// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define C_RESET "\x1B[m"
#define C_RED "\x1B[31m"
#define C_YELLOW "\x1B[33m"
#define C_BRIGHT_BLACK "\x1B[90m"

enum {
    MAX_STRERROR_LEN = 80,
    SEC_IN_NSEC = 1000000000,
    MSEC_IN_NSEC = 1000000,
};

static void finish_log_message(void);
static void print_meta(enum log_level level, const char *file, int line);
static void get_local_time(struct tm *time, long *msec);
static bool is_output_enabled(enum log_level level);

// having global state keeps the logging interface simple
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static enum log_level g_log_level;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static bool g_is_color_enabled;

void log_init(enum log_level log_level) {
    g_log_level = log_level;
    g_is_color_enabled = isatty(fileno(stderr));
}

void log_force_color(void) {
    g_is_color_enabled = true;
}

void log_log(enum log_level level, const char *file, int line, const char *fmt, ...) {
    if (!is_output_enabled(level)) {
        return;
    }

    print_meta(level, file, line);

    va_list args;
    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);

    finish_log_message();
}

void log_log_errnum(
        enum log_level level, const char *file, int line, const char *fmt, ...) {
    int errnum = errno;

    if (!is_output_enabled(level)) {
        return;
    }

    print_meta(level, file, line);

    va_list args;
    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);

    char errnum_str[MAX_STRERROR_LEN];

    int err = strerror_r(errnum, errnum_str, sizeof(errnum_str));
    if (!err) {
        (void)fprintf(stderr, ": %s", errnum_str);
    } else {
        (void)fprintf(stderr, ": Unknown error %d", errnum);
    }
    finish_log_message();
}

static void print_meta(enum log_level level, const char *file, int line) {
    if (g_is_color_enabled) {
        static const struct {
            const char *name;
            const char *color;
        } level_infos[] = {
            [LOG_DEBUG] = { "DEBUG", C_BRIGHT_BLACK },
            [LOG_INFO] = { "INFO", C_RESET },
            [LOG_WARN] = { "WARN", C_YELLOW },
            [LOG_ERROR] = { "ERROR", C_RED },
        };

        // format current time
        struct tm time = { 0 };
        long msec = 0;
        get_local_time(&time, &msec);
        char time_str[sizeof("1970-12-31 23:59:59")];
        time_str[strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &time)] =
                '\0';

        // print time, file, line and set message color
        (void)fprintf(stderr, "%s.%03li " C_BRIGHT_BLACK "%s:%d:%s ", time_str, msec,
                file, line, level_infos[level].color);
    } else {
        static const struct {
            const char *name;
            const char *prefix;
        } level_prefixes[] = {
            [LOG_DEBUG] = { "DEBUG", "<7>" },
            [LOG_INFO] = { "INFO", "<6>" },
            [LOG_WARN] = { "WARN", "<4>" },
            [LOG_ERROR] = { "ERROR", "<3>" },
        };

        // print level, file and line
        (void)fprintf(stderr, "%s%s:%d: ", level_prefixes[level].prefix, file, line);
    }
}

static void get_local_time(struct tm *time, long *msec) {
    struct timespec now = { 0 };
    (void)clock_gettime(CLOCK_REALTIME, &now);

    // round nanoseconds to milliseconds
    if (now.tv_nsec >= (SEC_IN_NSEC - (MSEC_IN_NSEC / 2))) {
        now.tv_sec++;
        *msec = 0;
    } else {
        *msec = (now.tv_nsec + (MSEC_IN_NSEC / 2)) / MSEC_IN_NSEC;
    }

    (void)localtime_r(&now.tv_sec, time);
}

static void finish_log_message(void) {
    if (g_is_color_enabled) {
        (void)fputs(C_RESET "\n", stderr);
    } else {
        (void)fputs("\n", stderr);
    }
    (void)fflush(stderr);
}

static bool is_output_enabled(enum log_level level) {
    return level <= g_log_level;
}
