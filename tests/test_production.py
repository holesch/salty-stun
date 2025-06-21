import base64
import socket
import subprocess

import pytest
import scapy.all as scapy
import testlib
import testlib.scapy_stun_backport as scapy_stun


@pytest.fixture(scope="module")
def wg_session(pytestconfig):
    port = 5400
    builddir = pytestconfig.getoption("builddir")
    result = subprocess.run(["wg", "genkey"], stdout=subprocess.PIPE, check=True)
    private_key_b64 = result.stdout.rstrip()

    result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key_b64,
        stdout=subprocess.PIPE,
        check=True,
    )
    public_key_bytes = base64.b64decode(result.stdout)
    public_key = testlib.X25519PublicKey.from_public_bytes(public_key_bytes)

    with subprocess.Popen(
        [builddir / "salty-stun", "-k", "-", "-p", str(port)],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        try:
            proc.stdin.write(private_key_b64)
            proc.stdin.close()

            for line in proc.stderr:
                if b"Listening on port " in line:
                    break

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("localhost", port))
                with testlib.WireGuardSession(public_key, sock) as wg:
                    yield wg
        finally:
            proc.terminate()


def test_production_stun(wg_session):
    request = (
        scapy.IP() / scapy.UDP() / scapy_stun.STUN(stun_message_type="Binding request")
    )
    request = scapy.IP(scapy.raw(request))
    response = wg_session.request(request)

    local_addr, local_port = wg_session.local_address
    expected_attribute = scapy_stun.STUNXorMappedAddress(
        xport=local_port, xip=local_addr
    )

    expected_response = (
        scapy.IP(id=0)
        / scapy.UDP()
        / scapy_stun.STUN(
            stun_message_type="Binding success response",
            transaction_id=request.transaction_id,
            attributes=[expected_attribute],
        )
    )
    expected_response = scapy.IP(scapy.raw(expected_response))

    assert response == expected_response


def test_production_ping(wg_session):
    ping = scapy.IP() / scapy.ICMP() / b"payload"
    response = wg_session.request(ping)
    expected_response = scapy.IP(id=0) / scapy.ICMP(type=0) / b"payload"
    expected_response = scapy.IP(scapy.raw(expected_response))
    assert response == expected_response


@pytest.fixture(scope="module")
def plain_stun_sock(pytestconfig):
    port = 3478
    builddir = pytestconfig.getoption("builddir")

    with subprocess.Popen(
        [builddir / "salty-stun", "-P"],
        stderr=subprocess.PIPE,
    ) as proc:
        try:
            for line in proc.stderr:
                if b"Listening on port " in line:
                    break

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("localhost", port))
                yield sock
        finally:
            proc.terminate()


def test_production_plain(plain_stun_sock):
    request = scapy_stun.STUN(stun_message_type="Binding request")
    request = scapy_stun.STUN(scapy.raw(request))
    plain_stun_sock.send(bytes(request))
    response = plain_stun_sock.recv(4096)
    response = scapy_stun.STUN(response)

    local_addr, local_port = plain_stun_sock.getsockname()[:2]
    expected_attribute = scapy_stun.STUNXorMappedAddress(
        xport=local_port, xip=local_addr
    )

    expected_response = scapy_stun.STUN(
        stun_message_type="Binding success response",
        transaction_id=request.transaction_id,
        attributes=[expected_attribute],
    )
    expected_response = scapy_stun.STUN(scapy.raw(expected_response))

    assert response == expected_response
