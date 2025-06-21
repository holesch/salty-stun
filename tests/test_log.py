# SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import subprocess


def test_log(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    test_log = builddir / "test-log"
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = subprocess.run([test_log], stderr=subprocess.PIPE, env=env, check=True)
    lines = result.stderr.decode().splitlines()

    assert lines[0] == "<6>tests/test_log.c:16: Info"
    assert lines[1] == "<4>tests/test_log.c:17: Warn"
    assert lines[2] == "<3>tests/test_log.c:18: Error"
    assert lines[3] == "<3>tests/test_log.c:22: Error EPERM: Operation not permitted"
    assert lines[4] == "<3>tests/test_log.c:24: Unknown: Unknown error 999999"
    assert "\x1b[90mtests/test_log.c:26:\x1b[33m Warning\x1b[m" in lines[5]
