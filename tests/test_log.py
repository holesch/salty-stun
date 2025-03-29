import os
import subprocess


def test_log(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    test_log = builddir / "test-log"
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = subprocess.run([test_log], stderr=subprocess.PIPE, env=env, check=True)
    lines = result.stderr.decode().splitlines()

    assert lines[0] == "<6>tests/test_log.c:12: Info"
    assert lines[1] == "<4>tests/test_log.c:13: Warn"
    assert lines[2] == "<3>tests/test_log.c:14: Error"
    assert lines[3] == "<3>tests/test_log.c:18: Error EPERM: Operation not permitted"
    assert lines[4] == "<3>tests/test_log.c:20: Unknown: Unknown error 999999"
    assert "\x1b[90mtests/test_log.c:22:\x1b[33m Warning\x1b[m" in lines[5]
