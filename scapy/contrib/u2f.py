# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Universal 2nd Factor (U2F) HID protocol
# scapy.contrib.status = loads

"""Universal 2nd Factor (U2F) HID framing and message payloads.

This module implements U2F-over-HID packets as described in the
FIDO U2F HID protocol and a basic U2F APDU request format for CMD_MSG.
"""

import struct

from scapy.fields import ByteEnumField, ByteField, FlagsField, ShortField, \
    StrLenField, XByteField, XIntField, XStrFixedLenField
from scapy.packet import Packet, Raw


U2F_HID_COMMANDS = {
    0x81: "PING",
    0x83: "MSG",
    0x84: "LOCK",
    0x86: "INIT",
    0x88: "WINK",
    0xBC: "SYNC",
    0xBF: "ERROR",
}


U2F_HID_ERRORS = {
    0x01: "invalid command",
    0x02: "invalid parameter",
    0x03: "invalid length",
    0x04: "invalid sequence",
    0x05: "message timeout",
    0x06: "channel busy",
    0x0A: "lock required",
    0x0B: "invalid channel",
    0x7F: "other",
}


U2F_INS = {
    0x01: "REGISTER",
    0x02: "AUTHENTICATE",
    0x03: "VERSION",
}


class U2FHID(Packet):
    name = "U2F HID"

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 5:
            # Command bit set => initialization frame, otherwise continuation.
            if _pkt[4] & 0x80:
                return U2FHIDInit
            return U2FHIDCont
        return cls


class U2FHIDInit(Packet):
    name = "U2F HID Init"

    fields_desc = [
        XIntField("cid", 0xFFFFFFFF),
        ByteEnumField("cmd", 0x86, U2F_HID_COMMANDS),
        ShortField("bcnt", 0),
    ]

    def post_build(self, p, pay):
        # If bcnt wasn't set by user, infer it from payload length.
        if self.bcnt == 0 and pay:
            p = p[:5] + struct.pack("!H", len(pay))
        return p + pay

    def guess_payload_class(self, payload):
        if self.cmd == 0x86:
            if len(payload) >= 17:
                return U2FHIDInitResp
            if len(payload) == 8:
                return U2FHIDInitReq
        elif self.cmd == 0x84:
            return U2FHIDLock
        elif self.cmd == 0xBF:
            return U2FHIDError
        elif self.cmd == 0x83:
            if len(payload) >= 5:
                return U2FAPDU
        return Raw


class U2FHIDCont(Packet):
    name = "U2F HID Continuation"

    fields_desc = [
        XIntField("cid", 0xFFFFFFFF),
        ByteField("seq", 0),
    ]


class U2FHIDInitReq(Packet):
    name = "U2F HID INIT request"

    fields_desc = [
        XStrFixedLenField("nonce", b"\x00" * 8, 8),
    ]


class U2FHIDInitResp(Packet):
    name = "U2F HID INIT response"

    fields_desc = [
        XStrFixedLenField("nonce", b"\x00" * 8, 8),
        XIntField("new_cid", 0xFFFFFFFF),
        XByteField("version_interface", 2),
        ByteField("version_major", 1),
        ByteField("version_minor", 0),
        ByteField("version_build", 0),
        FlagsField("cap_flags", 0, 8, ["wink", "lock", "msg"]),
    ]


class U2FHIDLock(Packet):
    name = "U2F HID LOCK"

    fields_desc = [
        ByteField("lock_time", 0),
    ]


class U2FHIDError(Packet):
    name = "U2F HID ERROR"

    fields_desc = [
        ByteEnumField("error", 0x7F, U2F_HID_ERRORS),
    ]


class U2FAPDU(Packet):
    name = "U2F APDU"

    fields_desc = [
        XByteField("cla", 0x00),
        ByteEnumField("ins", 0x03, U2F_INS),
        XByteField("p1", 0x00),
        XByteField("p2", 0x00),
        ByteField("lc", 0),
        StrLenField("data", b"", length_from=lambda pkt: pkt.lc),
    ]
