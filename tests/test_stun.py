# SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import socket

import pytest
import scapy.all as scapy
import testlib
import testlib.scapy_stun_backport as scapy_stun

# requests without the magic cookie are considered classic STUN (RFC 3489)
magic_cookie_param = pytest.mark.parametrize(
    "magic_cookie", [scapy_stun.MAGIC_COOKIE, 0xF9BC4EC0]
)


@magic_cookie_param
def test_stun(wireguard_session, magic_cookie, software_attribute):
    stun_request(wireguard_session, magic_cookie, software_attribute)


@magic_cookie_param
def test_stun_ipv6(salty_stun, magic_cookie, software_attribute):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.connect(("::1", salty_stun.port))
        with testlib.WireGuardSession(salty_stun.public_key, sock) as wg:
            stun_request(wg, magic_cookie, software_attribute)


@magic_cookie_param
def test_listening_on_ipv4(pytestconfig, magic_cookie, software_attribute):
    builddir = pytestconfig.getoption("builddir")
    with testlib.SaltyStun(
        builddir / "salty-stun-test", port=5300, address_family="IPv4"
    ) as salty_stun, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("localhost", salty_stun.port))
        with testlib.WireGuardSession(salty_stun.public_key, sock) as wg:
            stun_request(wg, magic_cookie, software_attribute)


def stun_request(wireguard_session, magic_cookie, software_attribute):
    tid = 0x36CAE9CFAB693C4320467127

    request = (
        scapy.IP()
        / scapy.UDP(sport=6200)
        / scapy_stun.STUN(
            stun_message_type="Binding request",
            magic_cookie=magic_cookie,
            transaction_id=tid,
        )
    )
    request = scapy.IP(scapy.raw(request))

    response = wireguard_session.request(request)

    local_addr, local_port = wireguard_session.local_address
    address_family = "IPv6" if ":" in local_addr else "IPv4"

    if magic_cookie == scapy_stun.MAGIC_COOKIE:
        expected_attributes = [
            scapy_stun.STUNXorMappedAddress(
                address_family=address_family, xport=local_port, xip=local_addr
            ),
        ]
    else:
        expected_attributes = [
            scapy_stun.STUNMappedAddress(
                address_family=address_family, port=local_port, ip=local_addr
            ),
        ]

    expected_attributes.append(software_attribute)

    expected_response = (
        scapy.IP(id=0)
        / scapy.UDP(dport=6200)
        / scapy_stun.STUN(
            stun_message_type="Binding success response",
            magic_cookie=magic_cookie,
            transaction_id=tid,
            attributes=expected_attributes,
        )
    )
    expected_response = scapy.IP(scapy.raw(expected_response))

    assert response == expected_response


def test_stun_too_short(wireguard_session):
    request = scapy.IP() / scapy.UDP(dport=3478) / b"\x00"
    response = wireguard_session.request(request)
    assert not response


def test_wrong_message_type(wireguard_session):
    request = (
        scapy.IP()
        / scapy.UDP()
        / scapy_stun.STUN(stun_message_type="Binding error response")
    )
    response = wireguard_session.request(request)
    assert not response


def test_stun_with_attributes(wireguard_session):
    type_software = 0x8022
    request = (
        scapy.IP()
        / scapy.UDP()
        / scapy_stun.STUN(
            stun_message_type="Binding request",
            attributes=[scapy_stun.STUNGenericTlv(type=type_software, value=b"scapy")],
        )
    )
    response = wireguard_session.request(request)

    # salty-stun doesn't support any attributes
    assert not response
