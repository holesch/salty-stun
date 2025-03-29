import socket
import struct

import scapy.contrib.stun as scapy_stun


# can be removed, once scapy has the following fix:
# https://github.com/secdev/scapy/pull/4700
def fixup_scapy_stun():
    def i2m(self, pkt, x):  # noqa: ARG001
        if x is None:
            return b"\x00\x00\x00\x00"
        return struct.pack(
            ">i", struct.unpack(">i", socket.inet_aton(x))[0] ^ scapy_stun.MAGIC_COOKIE
        )

    scapy_stun.XorIp.i2m = i2m
