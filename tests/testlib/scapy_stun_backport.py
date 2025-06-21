# SPDX-FileCopyrightText: 2025 Simon Holesch <simon@holesch.de>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
This includes changes from the PR https://github.com/secdev/scapy/pull/4712.
Remove this once the PR is merged.
"""

# ruff: noqa: F405, RUF012, ARG005

from scapy.contrib.stun import *  # noqa: F403
from scapy.contrib.stun import _stun_tlv_class, _xor_mapped_address_family
from scapy.fields import IP6Field, MultipleTypeField
from scapy.packet import bind_bottom_up, bind_top_down


def _fixup_xor_ip():
    def i2m(self, pkt, x):  # noqa: ARG001
        if x is None:
            return b"\x00\x00\x00\x00"
        return struct.pack(">i", struct.unpack(">i", inet_aton(x))[0] ^ MAGIC_COOKIE)

    XorIp.i2m = i2m


_fixup_xor_ip()


class XorIp6(IP6Field):

    def m2i(self, pkt, x):
        addr = self._xor_address(pkt, x)
        return super().m2i(pkt, addr)

    def i2m(self, pkt, x):
        addr = super().i2m(pkt, x)
        return self._xor_address(pkt, addr)

    def _xor_address(self, pkt, addr):
        xor_words = [pkt.parent.magic_cookie]
        xor_words += struct.unpack(
            ">III", pkt.parent.transaction_id.to_bytes(12, "big")
        )
        addr_words = struct.unpack(">IIII", addr)
        xor_addr = [a ^ b for a, b in zip(addr_words, xor_words)]
        return struct.pack(">IIII", *xor_addr)


class STUNXorMappedAddress(STUNGenericTlv):
    name = "STUN XOR Mapped Address"

    fields_desc = [
        XShortField("type", 0x0020),
        FieldLenField("length", None, length_of="xip", adjust=lambda pkt, x: x + 4),
        ByteField("RESERVED", 0),
        ByteEnumField("address_family", 1, _xor_mapped_address_family),
        XorPort("xport", 0),
        MultipleTypeField(
            [
                (XorIp("xip", "127.0.0.1"), lambda pkt: pkt.address_family == 1),
                (XorIp6("xip", "::1"), lambda pkt: pkt.address_family == 2),
            ],
            XorIp("xip", "127.0.0.1"),
        ),
    ]


class STUNMappedAddress(STUNGenericTlv):
    name = "STUN Mapped Address"

    fields_desc = [
        XShortField("type", 0x0001),
        FieldLenField("length", None, length_of="ip", adjust=lambda pkt, x: x + 4),
        ByteField("RESERVED", 0),
        ByteEnumField("address_family", 1, _xor_mapped_address_family),
        ShortField("port", 0),
        MultipleTypeField(
            [
                (IPField("ip", "127.0.0.1"), lambda pkt: pkt.address_family == 1),
                (IP6Field("ip", "::1"), lambda pkt: pkt.address_family == 2),
            ],
            IPField("ip", "127.0.0.1"),
        ),
    ]


_stun_tlv_class[0x0020] = STUNXorMappedAddress
_stun_tlv_class[0x0001] = STUNMappedAddress

bind_bottom_up(UDP, STUN, sport=3478)
bind_bottom_up(UDP, STUN, dport=3478)
bind_top_down(UDP, STUN, sport=3478, dport=3478)
