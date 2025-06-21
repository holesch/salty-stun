# SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import contextlib
import subprocess

import pytest


class RateLimit:
    def __init__(self, prog):
        self._prog = prog
        self._timestamp = 0

    def __enter__(self):
        with contextlib.ExitStack() as stack:
            proc = stack.enter_context(
                subprocess.Popen(
                    [self._prog],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    text=True,
                )
            )
            stack.callback(proc.wait)
            stack.callback(proc.stdin.close)
            self._proc = proc
            self._stack = stack.pop_all()
            self._stack.__enter__()
            return self

    def __exit__(self, exc_type, exc, tb):
        self._stack.__exit__(exc_type, exc, tb)

    def allow_unverified(self):
        self._proc.stdin.write(f"{self._timestamp} 127.0.0.1\n")
        self._proc.stdin.flush()
        out = self._proc.stdout.readline().strip()
        assert out == "allowed unverified"

    def allow_verified(self, addr):
        self._proc.stdin.write(f"{self._timestamp} {addr}\n")
        self._proc.stdin.flush()
        out = self._proc.stdout.readline().strip()
        assert out == "allowed verified"

    def denied(self, addr="127.0.0.1"):
        self._proc.stdin.write(f"{self._timestamp} {addr}\n")
        self._proc.stdin.flush()
        out = self._proc.stdout.readline().strip()
        assert out == "denied"

    def rate_limit_timeout(self):
        self._timestamp += 5

    def under_load_timeout(self):
        self._timestamp += 10


@pytest.fixture
def rate_limit(pytestconfig):
    build_dir = pytestconfig.getoption("builddir")
    with RateLimit(build_dir / "test-rate-limit") as rate_limit:
        yield rate_limit


def test_unverified(rate_limit):
    for _ in range(10):
        rate_limit.allow_unverified()
    rate_limit.denied()

    rate_limit.under_load_timeout()
    rate_limit.allow_unverified()


def test_max_per_ip(rate_limit):
    for _ in range(2):
        for _ in range(10):
            rate_limit.allow_unverified()
        rate_limit.denied()

        rate_limit.rate_limit_timeout()

        for _ in range(2):
            rate_limit.allow_verified("10.0.0.1")
        rate_limit.denied("10.0.0.1")

        # do another round to make sure the rate limit is reset
        rate_limit.rate_limit_timeout()


def test_ipv6(rate_limit):
    for _ in range(10):
        rate_limit.allow_unverified()
    rate_limit.denied()

    rate_limit.rate_limit_timeout()

    for _ in range(2):
        rate_limit.allow_verified("2001:db8::1")
    rate_limit.denied("2001:db8::1")


def test_ipv6_end_site(rate_limit):
    for _ in range(10):
        rate_limit.allow_unverified()
    rate_limit.denied()

    rate_limit.rate_limit_timeout()

    for _ in range(2):
        rate_limit.allow_verified("2001:db8::1")

    # every address in the same /56 block is considered the same end site and
    # is now blocked
    rate_limit.denied("2001:db8::2")
    rate_limit.denied("2001:db8:0000:00ff::1")
    rate_limit.allow_verified("2001:db8:0000:01ff::1")


def test_ipv4_mapped(rate_limit):
    for _ in range(10):
        rate_limit.allow_unverified()
    rate_limit.denied()

    rate_limit.rate_limit_timeout()

    for _ in range(2):
        rate_limit.allow_verified("::ffff:10.0.0.1")
    rate_limit.denied("::ffff:10.0.0.1")

    # different ipv4 mapped addresses are not treated as the same end site
    rate_limit.allow_verified("::ffff:10.0.0.2")


def test_all_different(rate_limit):
    for _ in range(2):
        for _ in range(10):
            rate_limit.allow_unverified()
        rate_limit.denied()

        rate_limit.rate_limit_timeout()

        for n in range(10):
            rate_limit.allow_verified(f"10.0.0.{n}")

        rate_limit.denied()

        # do another round to make sure the rate limit is reset
        rate_limit.under_load_timeout()
