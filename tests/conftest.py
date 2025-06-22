# SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import pathlib
import socket
import subprocess

import pytest
import testlib
import testlib.scapy_stun_backport as scapy_stun


def pytest_addoption(parser, pluginmanager):  # noqa: ARG001
    parser.addoption(
        "--builddir",
        required=True,
        type=pathlib.Path,
        help="Path to the build directory",
    )


@pytest.fixture(scope="session")
def software_attribute(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    software_string = subprocess.run(
        [builddir / "print-software"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return scapy_stun.STUNGenericTlv(type=0x8022, value=software_string.encode("utf-8"))


@pytest.fixture(scope="session")
def salty_stun(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    with testlib.SaltyStun(builddir / "salty-stun-test") as salty_stun:
        yield salty_stun


@pytest.fixture(scope="session")
def salty_stun_socket(salty_stun):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("localhost", salty_stun.port))
        yield sock


@pytest.fixture
def wireguard_session(salty_stun, salty_stun_socket):
    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        yield wg
