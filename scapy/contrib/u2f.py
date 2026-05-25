# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = FIDO U2F (Universal 2nd Factor)
# scapy.contrib.status = loads

"""
FIDO U2F (Universal 2nd Factor) Protocol

Implements the U2F HID transport layer and U2F application layer messages.

References:
- FIDO U2F HID Protocol Specification v1.2:
  https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/
  fido-u2f-hid-protocol-v1.2-ps-20170411.html
- FIDO U2F Raw Message Formats Specification v1.2:
  https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/
  fido-u2f-raw-message-formats-v1.2-ps-20170411.html
"""

import struct

from scapy.fields import (
    ByteEnumField,
    ByteField,
    FlagsField,
    FieldLenField,
    IntField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    XByteField,
    XIntField,
    XStrFixedLenField,
)
from scapy.packet import Packet, bind_layers

# ============================================================
# U2F HID protocol constants (FIDO U2FHID specification)
# ============================================================

# Special channel identifier used before a real CID is allocated
U2FHID_BROADCAST_CID = 0xFFFFFFFF

# HID command codes (CMD byte with bit 7 set for init packets)
_u2fhid_cmd_codes = {
    0x81: "PING",
    0x83: "MSG",
    0x84: "LOCK",
    0x86: "INIT",
    0x88: "WINK",
    0x90: "CBOR",
    0x91: "CANCEL",
    0xBB: "KEEPALIVE",
    0xBF: "ERROR",
}

# U2FHID error codes (payload of ERROR command)
_u2fhid_error_codes = {
    0x00: "ERR_NONE",
    0x01: "ERR_INVALID_CMD",
    0x02: "ERR_INVALID_PAR",
    0x03: "ERR_INVALID_LEN",
    0x04: "ERR_INVALID_SEQ",
    0x05: "ERR_MSG_TIMEOUT",
    0x06: "ERR_CHANNEL_BUSY",
    0x0A: "ERR_LOCK_REQUIRED",
    0x0B: "ERR_INVALID_CHANNEL",
    0x7F: "ERR_OTHER",
}

# U2F application command codes (INS byte of the APDU)
_u2f_ins_codes = {
    0x01: "Register",
    0x02: "Authenticate",
    0x03: "Version",
}

# U2F Authenticate control byte (P1)
_u2f_auth_p1_codes = {
    0x03: "check-only",
    0x07: "enforce-user-presence-and-sign",
    0x08: "dont-enforce-user-presence-and-sign",
}

# APDU status word SW1 values
_u2f_sw1_codes = {
    0x90: "Success",
    0x61: "More data available",
    0x67: "Wrong length",
    0x69: "Command not allowed",
    0x6A: "Wrong parameter",
    0x6D: "INS not supported",
    0x6E: "CLA not supported",
}

# Combined SW1+SW2 status codes for common U2F responses
U2F_SW_NO_ERROR = (0x90, 0x00)
U2F_SW_CONDITIONS_NOT_SATISFIED = (0x69, 0x85)
U2F_SW_WRONG_DATA = (0x6A, 0x80)
U2F_SW_WRONG_LENGTH = (0x67, 0x00)
U2F_SW_CLA_NOT_SUPPORTED = (0x6E, 0x00)
U2F_SW_INS_NOT_SUPPORTED = (0x6D, 0x00)


# ============================================================
# Custom fields
# ============================================================

class _U2FResponseDataField(StrField):
    """Field that consumes all bytes except the trailing SW1 and SW2.

    Used in U2FResponseAPDU to capture the variable-length response
    data, leaving the last two status bytes for subsequent fields.
    """

    def getfield(self, pkt, s):
        if len(s) > 2:
            return s[-2:], s[:-2]
        return s, b""

    def addfield(self, pkt, s, val):
        return s + (val if val is not None else b"")


# ============================================================
# U2F HID transport layer
# ============================================================

class U2FHIDInitializationPacket(Packet):
    """U2F HID Initialization Packet.

    The first (and possibly only) packet in a U2F HID message
    transaction.  All multi-byte integer fields are big-endian.

    USB HID frame layout (64 bytes total)::

        CID[4] | CMD[1] | BCNT[2] | DATA[up to 57]

    The CMD byte always has bit 7 set, distinguishing it from a
    continuation packet whose sequence byte has bit 7 clear.

    ``bcnt`` carries the *total* payload length across all HID packets
    for this transaction.  If the payload fits in the first 57 bytes
    this packet is self-contained; otherwise continuation packets
    follow.
    """

    name = "U2F HID Initialization Packet"
    fields_desc = [
        XIntField("cid", U2FHID_BROADCAST_CID),
        ByteEnumField("cmd", 0x86, _u2fhid_cmd_codes),
        ShortField("bcnt", None),
    ]

    def post_build(self, p, pay):
        if self.bcnt is None:
            p = p[:5] + struct.pack("!H", len(pay)) + p[7:]
        return p + pay

    def extract_padding(self, s):
        # When bcnt is known and smaller than available bytes the
        # remaining bytes are HID frame padding (zero-fill).
        if self.bcnt is not None and len(s) > self.bcnt:
            return s[:self.bcnt], s[self.bcnt:]
        return s, b""

    def guess_payload_class(self, payload):
        cmd = self.cmd
        if cmd == 0x83:  # MSG: carries a U2F APDU command
            return U2FCommandAPDU
        if cmd == 0x86:  # INIT: request (8 B) or response (17 B)
            if self.bcnt == 8:
                return U2FHIDINITRequest
            if self.bcnt == 17:
                return U2FHIDINITResponse
        if cmd == 0xBF:  # ERROR: single-byte error code
            return U2FHIDError
        return Packet.guess_payload_class(self, payload)


class U2FHIDContinuationPacket(Packet):
    """U2F HID Continuation Packet.

    Carries subsequent chunks of a multi-packet U2F HID message.

    USB HID frame layout (64 bytes total)::

        CID[4] | SEQ[1] | DATA[up to 59]

    The SEQ byte always has bit 7 clear, distinguishing it from an
    initialization packet.  Sequence numbers start at 0 and increment
    by 1 for each continuation packet within a transaction.
    """

    name = "U2F HID Continuation Packet"
    fields_desc = [
        XIntField("cid", 0),
        ByteField("seq", 0),
    ]


# ============================================================
# U2F HID command-specific payloads
# ============================================================

class U2FHIDINITRequest(Packet):
    """Payload of a U2FHID_INIT request.

    Contains an 8-byte nonce chosen by the client.  The authenticator
    echoes the nonce back in the corresponding response, allowing the
    client to match the response to this request.
    """

    name = "U2F HID INIT Request"
    fields_desc = [
        StrFixedLenField("nonce", b"\x00" * 8, length=8),
    ]

    def extract_padding(self, s):
        return b"", s


class U2FHIDINITResponse(Packet):
    """Payload of a U2FHID_INIT response.

    Returned by the authenticator after a U2FHID_INIT request.
    Allocates a new channel identifier for subsequent communication.

    Capability flags (``capabilities`` field)::

        Bit 0 (0x01)  WINK   – device supports WINK command
        Bit 2 (0x04)  CBOR   – device supports CTAP2/CBOR
        Bit 3 (0x08)  NMSG   – device does not support MSG command
    """

    name = "U2F HID INIT Response"
    fields_desc = [
        StrFixedLenField("nonce", b"\x00" * 8, length=8),
        XIntField("cid", 0),
        ByteField("protocol_version", 2),
        ByteField("major_device_version", 0),
        ByteField("minor_device_version", 0),
        ByteField("build_device_version", 0),
        FlagsField("capabilities", 0, 8,
                   ["WINK", "_b1", "CBOR", "NMSG",
                    "_b4", "_b5", "_b6", "_b7"]),
    ]

    def extract_padding(self, s):
        return b"", s


class U2FHIDError(Packet):
    """Payload of a U2FHID_ERROR response.

    A single byte indicating why the preceding request failed.
    """

    name = "U2F HID Error"
    fields_desc = [
        ByteEnumField("error_code", 0x01, _u2fhid_error_codes),
    ]

    def extract_padding(self, s):
        return b"", s


# ============================================================
# U2F APDU layer (ISO/IEC 7816-4 extended length format)
# ============================================================

class U2FCommandAPDU(Packet):
    """U2F Command APDU using ISO/IEC 7816-4 extended length encoding.

    Wire format when data is present::

        CLA(1) | INS(1) | P1(1) | P2(1) | 0x00(1) | LcH(1) | LcL(1)
        | DATA(Lc) | LeH(1) | LeL(1)

    ``lc`` (the 2-byte big-endian data length) is automatically
    computed from ``data`` during build when set to ``None``.

    ``le`` indicates the maximum number of response bytes expected
    (``0x0000`` means up to 65536 bytes, which is the U2F convention).

    The ``_ext`` byte is always ``0x00``; it serves as the ISO 7816-4
    extended length indicator.
    """

    name = "U2F Command APDU"
    fields_desc = [
        ByteEnumField("cla", 0x00, {0x00: "ISO"}),
        ByteEnumField("ins", 0x01, _u2f_ins_codes),
        ByteField("p1", 0x00),
        ByteField("p2", 0x00),
        # Extended APDU marker – always 0x00 in U2F
        ByteField("_ext", 0x00),
        FieldLenField("lc", None, length_of="data", fmt="!H"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.lc or 0),
        ShortField("le", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class U2FResponseAPDU(Packet):
    """U2F Response APDU.

    Wire format::

        DATA(variable) | SW1(1) | SW2(1)

    ``data`` captures all bytes preceding the mandatory 2-byte status
    word.  A status word of ``(0x90, 0x00)`` indicates success.
    """

    name = "U2F Response APDU"
    fields_desc = [
        _U2FResponseDataField("data", b""),
        ByteEnumField("sw1", 0x90, _u2f_sw1_codes),
        XByteField("sw2", 0x00),
    ]

    def extract_padding(self, s):
        return b"", s


# ============================================================
# U2F application messages
# ============================================================

class U2FRegisterRequest(Packet):
    """U2F Register command request data (INS=0x01).

    Sent by the client inside a U2FCommandAPDU to request the
    authenticator to register a new key pair for the given origin.

    Both parameters are SHA-256 hashes::

        challenge_parameter  – SHA-256 of the client data JSON
        application_parameter – SHA-256 of the application (origin) ID
    """

    name = "U2F Register Request"
    fields_desc = [
        XStrFixedLenField("challenge_parameter", b"\x00" * 32, 32),
        XStrFixedLenField("application_parameter", b"\x00" * 32, 32),
    ]

    def extract_padding(self, s):
        return b"", s


class U2FRegisterResponse(Packet):
    """U2F Register command response data (INS=0x01).

    Returned inside a U2FResponseAPDU on successful registration.

    Wire format::

        0x05(1) | user_public_key(65) | key_handle_length(1)
        | key_handle(key_handle_length) | attestation_cert(DER, var)
        | signature(var)

    The ``reserved`` byte is always ``0x05``.

    ``user_public_key`` is an uncompressed EC point:
    ``0x04 || X[32] || Y[32]``.

    The DER-encoded attestation certificate and ECDSA signature that
    follow the key handle are captured in the Scapy payload (``Raw``).
    """

    name = "U2F Register Response"
    fields_desc = [
        ByteField("reserved", 0x05),
        XStrFixedLenField("user_public_key", b"\x04" + b"\x00" * 64, 65),
        FieldLenField("key_handle_length", None,
                      length_of="key_handle", fmt="B"),
        StrLenField("key_handle", b"",
                    length_from=lambda pkt: pkt.key_handle_length),
    ]


class U2FAuthenticateRequest(Packet):
    """U2F Authenticate command request data (INS=0x02).

    Sent by the client inside a U2FCommandAPDU to authenticate using a
    previously registered key handle.

    ``control`` (placed in the P1 field of the enclosing
    U2FCommandAPDU) governs user-presence checking::

        0x03  check-only
        0x07  enforce-user-presence-and-sign
        0x08  dont-enforce-user-presence-and-sign

    Wire format::

        challenge_parameter(32) | application_parameter(32)
        | key_handle_length(1)  | key_handle(key_handle_length)
    """

    name = "U2F Authenticate Request"
    fields_desc = [
        XStrFixedLenField("challenge_parameter", b"\x00" * 32, 32),
        XStrFixedLenField("application_parameter", b"\x00" * 32, 32),
        FieldLenField("key_handle_length", None,
                      length_of="key_handle", fmt="B"),
        StrLenField("key_handle", b"",
                    length_from=lambda pkt: pkt.key_handle_length),
    ]

    def extract_padding(self, s):
        return b"", s


class U2FAuthenticateResponse(Packet):
    """U2F Authenticate command response data (INS=0x02).

    Returned inside a U2FResponseAPDU on successful authentication.

    Wire format::

        user_presence(1) | counter(4) | signature(var)

    ``user_presence`` is ``0x01`` when the user physically touched the
    device, ``0x00`` otherwise.

    ``counter`` is a monotonically increasing big-endian 32-bit integer
    that the relying party uses to detect cloned authenticators.

    The ECDSA signature over the authenticated data follows as the
    Scapy payload (``Raw``).
    """

    name = "U2F Authenticate Response"
    fields_desc = [
        ByteEnumField("user_presence", 0x01,
                      {0x00: "absent", 0x01: "present"}),
        IntField("counter", 0),
    ]


# ============================================================
# Layer bindings
# ============================================================

# U2F HID MSG command carries a U2F command APDU
bind_layers(U2FHIDInitializationPacket, U2FCommandAPDU, cmd=0x83)
