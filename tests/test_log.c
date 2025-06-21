// SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <errno.h>

#include "log.h"

enum {
    INVALID_ERRNO = 999999,
};

int main(void) {
    log_init(LOG_INFO);
    log_debug("Debug"); // no output
    log_info("Info");
    log_warn("Warn");
    log_error("Error");
    errno = EPERM;
    log_errnum_debug("Debug EPERM"); // no output
    errno = EPERM;
    log_errnum_error("Error EPERM");
    errno = INVALID_ERRNO;
    log_errnum_error("Unknown");
    log_force_color();
    log_warn("Warning");
}
