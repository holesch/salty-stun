import scapy.all as scapy


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


def test_ip_wrong_version(salty_stun_socket, wireguard_session):
    wireguard_session.send(b"\x00")
    assert not salty_stun_socket.recv(4096)
