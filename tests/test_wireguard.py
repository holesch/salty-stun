import base64
import contextlib
import socket
import struct

import pytest
import scapy.all as scapy
import scapy.contrib.wireguard as scapy_wg
import testlib


def test_wireguard_handshake(salty_stun, salty_stun_socket):
    wg = testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket)
    with wg:
        pass


@pytest.mark.parametrize("error", testlib.InjectedWireguardHandshakeErrors)
def test_wireguard_handshake_error(salty_stun, salty_stun_socket, error):
    wg = testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket)
    wg.send_handshake(error)
    assert not salty_stun_socket.recv(4096)


def test_empty_request(salty_stun_socket):
    salty_stun_socket.send(b"")
    assert not salty_stun_socket.recv(4096)


def test_invalid_message_type(salty_stun_socket):
    salty_stun_socket.send(b"\x00")
    assert not salty_stun_socket.recv(4096)


def test_empty_transport_message(salty_stun_socket):
    salty_stun_socket.send(bytes(scapy_wg.Wireguard(message_type="transport")))
    assert not salty_stun_socket.recv(4096)


@pytest.mark.parametrize("error", testlib.InjectedWireguardTransportErrors)
def test_transport_error(salty_stun_socket, wireguard_session, error):
    ping = scapy.IP() / scapy.ICMP()
    wireguard_session.send(ping, error)
    assert not salty_stun_socket.recv(4096)


def test_keepalive(salty_stun_socket, wireguard_session):
    wireguard_session.send(b"")
    assert not salty_stun_socket.recv(4096)


def test_key_log(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    with testlib.SaltyStun(
        builddir / "salty-stun-test", port=5200, key_log=True
    ) as salty_stun, udp_socket(5200) as sock, testlib.WireGuardSession(
        salty_stun.public_key, sock
    ) as wireguard_session:
        local_static_private_key = salty_stun.stdout.readline().decode()
        assert (
            local_static_private_key
            == f"LOCAL_STATIC_PRIVATE_KEY = {salty_stun.private_key_b64.decode()}\n"
        )

        remote_static_public_key = salty_stun.stdout.readline().decode()
        client_public_key = base64.b64encode(
            wireguard_session.private_key.public_key().public_bytes_raw()
        ).decode()
        assert (
            remote_static_public_key
            == f"REMOTE_STATIC_PUBLIC_KEY = {client_public_key}\n"
        )

        local_ephemeral_private_key = salty_stun.stdout.readline().decode()
        prefix = "LOCAL_EPHEMERAL_PRIVATE_KEY = "
        assert local_ephemeral_private_key.startswith(prefix)
        assert local_ephemeral_private_key.endswith("\n")
        assert len(local_ephemeral_private_key) == len(prefix + "\n") + len(
            base64.b64encode(bytes(32))
        )

        pre_shared_key = salty_stun.stdout.readline().decode()
        null_key = base64.b64encode(bytes(32)).decode()
        assert pre_shared_key == f"PRE_SHARED_KEY = {null_key}\n"


@contextlib.contextmanager
def udp_socket(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("localhost", port))
        yield sock


def test_multiple_sessions(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    ping = scapy.IP() / scapy.ICMP()

    with contextlib.ExitStack() as stack:
        salty_stun = stack.enter_context(
            testlib.SaltyStun(builddir / "salty-stun-test", port=5201, max_sessions=2)
        )
        sock = stack.enter_context(udp_socket(5201))

        wg1 = stack.enter_context(
            testlib.WireGuardSession(salty_stun.public_key, sock, my_index=1)
        )
        wg2 = stack.enter_context(
            testlib.WireGuardSession(salty_stun.public_key, sock, my_index=2)
        )

        assert wg1.request(ping)
        assert wg2.request(ping)


def test_too_many_sessions(pytestconfig):
    builddir = pytestconfig.getoption("builddir")

    with contextlib.ExitStack() as stack:
        salty_stun = stack.enter_context(
            testlib.SaltyStun(builddir / "salty-stun-test", port=5202, max_sessions=2)
        )
        sock = stack.enter_context(udp_socket(5202))

        stack.enter_context(
            testlib.WireGuardSession(salty_stun.public_key, sock, my_index=1)
        )
        stack.enter_context(
            testlib.WireGuardSession(salty_stun.public_key, sock, my_index=2)
        )

        wg = testlib.WireGuardSession(salty_stun.public_key, sock, my_index=3)
        wg.send_handshake()
        assert not sock.recv(4096)


def test_session_slot_reuse(pytestconfig):
    builddir = pytestconfig.getoption("builddir")
    ping = scapy.IP() / scapy.ICMP()

    with contextlib.ExitStack() as stack:
        salty_stun = stack.enter_context(
            testlib.SaltyStun(builddir / "salty-stun-test", port=5203, max_sessions=2)
        )
        sock = stack.enter_context(udp_socket(5203))

        with testlib.WireGuardSession(salty_stun.public_key, sock, my_index=1) as wg1:
            wg2 = stack.enter_context(
                testlib.WireGuardSession(salty_stun.public_key, sock, my_index=2)
            )

            assert wg1.request(ping)
            assert wg2.request(ping)

        wg3 = stack.enter_context(
            testlib.WireGuardSession(salty_stun.public_key, sock, my_index=3)
        )

        assert wg3.request(ping)


def test_sliding_window_accept(salty_stun, salty_stun_socket):
    ping = scapy.IP() / scapy.ICMP()

    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        assert wg.request(ping, counter=3)
        assert wg.request(ping, counter=1)
        assert wg.request(ping, counter=2)


def test_sliding_window_too_old(salty_stun, salty_stun_socket):
    ping = scapy.IP() / scapy.ICMP()

    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        assert wg.request(ping, counter=64)
        wg.send(ping, counter=0)
        assert not salty_stun_socket.recv(4096)


def test_sliding_window_already_seen(salty_stun, salty_stun_socket):
    ping = scapy.IP() / scapy.ICMP()

    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        assert wg.request(ping, counter=0)
        wg.send(ping, counter=0)
        assert not salty_stun_socket.recv(4096)


def test_sliding_window_update_error(salty_stun, salty_stun_socket):
    ping = scapy.IP() / scapy.ICMP()

    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        assert wg.request(ping, counter=3)
        assert wg.request(ping, counter=2)
        wg.send(ping, counter=3)
        assert not salty_stun_socket.recv(4096)


def test_message_counter_limit(salty_stun, salty_stun_socket):
    ping = scapy.IP() / scapy.ICMP()

    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        reject_after_messages = 2**64 - 2**13 - 1
        assert wg.request(ping, counter=reject_after_messages - 1)
        wg.send(ping, counter=reject_after_messages)
        assert not salty_stun_socket.recv(4096)


def test_session_expired(salty_stun, salty_stun_socket):
    ping = scapy.IP() / scapy.ICMP()

    def add_time(time):
        salty_stun_socket.send(struct.pack("!xxxxI", time))

    with testlib.WireGuardSession(salty_stun.public_key, salty_stun_socket) as wg:
        reject_after_time = 180
        add_time(reject_after_time)

        # just in time
        assert wg.request(ping)

        # expired
        add_time(1)
        wg.send(ping)
        assert not salty_stun_socket.recv(4096)
