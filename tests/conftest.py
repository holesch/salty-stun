import pathlib
import socket

import pytest
import testlib


def pytest_addoption(parser, pluginmanager):  # noqa: ARG001
    parser.addoption(
        "--builddir",
        required=True,
        type=pathlib.Path,
        help="Path to the build directory",
    )


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
