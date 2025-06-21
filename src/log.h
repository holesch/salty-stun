// SPDX-FileCopyrightText: 2024 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef LOG_H_
#define LOG_H_

#include <stdarg.h>

enum log_level {
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
};

#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...) log_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...) log_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#define log_errnum_debug(...) log_log_errnum(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_errnum_info(...) log_log_errnum(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_errnum_warn(...) log_log_errnum(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_errnum_error(...) log_log_errnum(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

void log_init(enum log_level log_level);
void log_force_color(void);
void log_log(enum log_level level, const char *file, int line, const char *fmt, ...);
void log_log_errnum(
        enum log_level level, const char *file, int line, const char *fmt, ...);

#endif // LOG_H_
