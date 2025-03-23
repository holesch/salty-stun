import pytest
import scapy.all as scapy
import scapy.contrib.stun as scapy_stun


def test_ping(wireguard_session):
    ping = scapy.IP(dst="100.64.0.4", src="100.64.0.5") / scapy.ICMP() / b"payload"
    response = wireguard_session.request(ping)

    expected_response = (
        scapy.IP(id=0, dst="100.64.0.5", src="100.64.0.4")
        / scapy.ICMP(type=0)
        / b"payload"
    )
    # calculate checksums
    expected_response = scapy.IP(scapy.raw(expected_response))

    assert response == expected_response


def test_ip_too_short(wireguard_session):
    response = wireguard_session.request(b"\x45")
    assert not response


def test_ip_wrong_version(wireguard_session):
    ping = scapy.IP(version=5) / scapy.ICMP() / b"payload"
    response = wireguard_session.request(ping)
    assert not response


def test_ip_wrong_checksum(wireguard_session):
    ping = scapy.IP() / scapy.ICMP() / b"payload"
    # calculate checksums
    ping = scapy.IP(scapy.raw(ping))
    ping.chksum += 1
    response = wireguard_session.request(ping)
    assert not response


def test_ip_fragmented(wireguard_session):
    ping = scapy.IP() / scapy.ICMP() / b"payload"
    packets = scapy.fragment(ping, fragsize=8)
    assert len(packets) > 1
    response = wireguard_session.request(packets[0])
    assert not response


def test_ip_wrong_total_length(wireguard_session):
    ping = scapy.IP(len=50) / scapy.ICMP() / b"payload"
    response = wireguard_session.request(ping)
    assert not response


def test_ip_unsupported_protocol(wireguard_session):
    tcp_packet = scapy.IP() / scapy.TCP()
    response = wireguard_session.request(tcp_packet)
    assert not response


def test_icmp_too_short(wireguard_session):
    ping = scapy.IP(proto=1) / b"\x08"
    response = wireguard_session.request(ping)
    assert not response


def test_icmp_unsupported_type(wireguard_session):
    ping = scapy.IP() / scapy.ICMP(type=1) / b"payload"
    response = wireguard_session.request(ping)
    assert not response


def test_icmp_unsupported_code(wireguard_session):
    ping = scapy.IP() / scapy.ICMP(code=1) / b"payload"
    response = wireguard_session.request(ping)
    assert not response


def test_icmp_wrong_checksum(wireguard_session):
    ping = scapy.IP() / scapy.ICMP() / b"payload"
    # calculate checksums
    ping = scapy.IP(scapy.raw(ping))
    ping[scapy.ICMP].chksum += 1
    response = wireguard_session.request(ping)
    assert not response


def test_udp_too_short(wireguard_session):
    request = scapy.IP(proto=17) / b"\x08"
    response = wireguard_session.request(request)
    assert not response


def test_udp_wrong_length(wireguard_session):
    request = (
        scapy.IP() / scapy.UDP() / scapy_stun.STUN(stun_message_type="Binding request")
    )
    request = scapy.IP(scapy.raw(request))
    request[scapy.UDP].len += 1
    response = wireguard_session.request(request)
    assert not response


def test_udp_unsupported_port(wireguard_session):
    request = scapy.IP() / scapy.UDP(dport=1234) / b"payload"
    response = wireguard_session.request(request)
    assert not response


@pytest.mark.xfail(reason="Checksum is not checked for UDP")
def test_udp_wrong_checksum(wireguard_session):
    request = (
        scapy.IP() / scapy.UDP() / scapy_stun.STUN(stun_message_type="Binding request")
    )
    # calculate checksums
    request = scapy.IP(scapy.raw(request))
    request[scapy.UDP].chksum += 1
    response = wireguard_session.request(request)
    assert not response
