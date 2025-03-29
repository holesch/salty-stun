import scapy.all as scapy
import scapy.contrib.stun as scapy_stun
import testlib

testlib.fixup_scapy_stun()


def test_stun(salty_stun_socket, wireguard_session):
    tid = 0x36CAE9CFAB693C4320467127

    request = (
        scapy.IP()
        / scapy.UDP(sport=6200)
        / scapy_stun.STUN(stun_message_type="Binding request", transaction_id=tid)
    )
    request = scapy.IP(scapy.raw(request))

    response = wireguard_session.request(request)

    local_addr, local_port = salty_stun_socket.getsockname()
    expected_attributes = [
        scapy_stun.STUNXorMappedAddress(xport=local_port, xip=local_addr)
    ]

    expected_response = (
        scapy.IP(id=0)
        / scapy.UDP(sport=3478, dport=6200, chksum=0)
        / scapy_stun.STUN(
            stun_message_type="Binding success response",
            transaction_id=tid,
            attributes=expected_attributes,
        )
    )
    expected_response = scapy.IP(scapy.raw(expected_response))

    assert response == expected_response


def test_classic_stun(salty_stun_socket, wireguard_session):
    # requests without the magic cookie are considered classic STUN (RFC 3489)
    tid = 0x36CAE9CFAB693C4320467127
    magic_cookie = 0xF9BC4EC0

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

    local_addr, local_port = salty_stun_socket.getsockname()
    expected_attributes = [STUNMappedAddress(port=local_port, ip=local_addr)]

    expected_response = (
        scapy.IP(id=0)
        / scapy.UDP(sport=3478, dport=6200, chksum=0)
        / scapy_stun.STUN(
            stun_message_type="Binding success response",
            magic_cookie=magic_cookie,
            transaction_id=tid,
            attributes=expected_attributes,
        )
    )
    expected_response = scapy.IP(scapy.raw(expected_response))

    assert response == expected_response


class STUNMappedAddress(scapy_stun.STUNGenericTlv):
    name = "STUN Mapped Address"

    fields_desc = [  # noqa: RUF012
        scapy.XShortField("type", 0x0001),
        scapy.ShortField("length", 8),
        scapy.ByteField("RESERVED", 0),
        scapy.ByteField("address_family", 0x01),  # IPv4
        scapy.ShortField("port", 0),
        scapy.IPField("ip", 0),
    ]


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
