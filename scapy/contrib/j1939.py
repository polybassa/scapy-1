# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Scapy contributors

# scapy.contrib.description = SAE J1939 Vehicle Network Protocol
# scapy.contrib.status = loads

"""
SAE J1939 - Vehicle network protocol for heavy-duty vehicles.

J1939 uses 29-bit extended CAN identifiers to encode a structured addressing
scheme.  The 29-bit identifier is partitioned as follows::

    Bits 28-26 : Priority        (3 bits, 0 = highest)
    Bit  25    : Reserved        (1 bit)
    Bit  24    : Data Page       (1 bit)
    Bits 23-16 : PDU Format      (8 bits, PF)
    Bits 15-8  : PDU Specific    (8 bits, PS)
                     PF < 240 → Destination Address (PDU1, peer-to-peer)
                     PF ≥ 240 → Group Extension     (PDU2, broadcast)
    Bits  7-0  : Source Address  (8 bits, SA)

PGN (Parameter Group Number):
    PDU1 (PF < 240): PGN = (DP << 16) | (PF << 8)           — PS is DA
    PDU2 (PF ≥ 240): PGN = (DP << 16) | (PF << 8) | GE      — broadcast only

References:
    - SAE J1939 standard
    - Linux kernel J1939 documentation:
      https://www.kernel.org/doc/html/latest/networking/j1939.html
"""

import socket
import struct
import logging
import time

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
)

from scapy.config import conf
from scapy.data import SO_TIMESTAMPNS
from scapy.error import Scapy_Exception, log_runtime, warning
from scapy.fields import (
    BitEnumField,
    BitField,
    BitFieldLenField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FlagsField,
    LEShortField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
    X3BytesField,
    XByteField,
    XShortField,
)
from scapy.layers.can import CAN, CAN_MTU
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.compat import raw

log_j1939 = logging.getLogger("scapy.contrib.j1939")

# ---------------------------------------------------------------------------
# J1939 constants (sourced from Python socket module where available)
# ---------------------------------------------------------------------------

#: 64-bit NAME not used / not relevant
J1939_NO_NAME = socket.J1939_NO_NAME          # 0
#: PGN wildcard – match any PGN when used in bind / filter
J1939_NO_PGN = socket.J1939_NO_PGN            # 0x40000
#: Address wildcard – no specific address
J1939_NO_ADDR = socket.J1939_NO_ADDR          # 0xFF  (global broadcast)
#: Idle/null address (used during address claiming)
J1939_IDLE_ADDR = socket.J1939_IDLE_ADDR      # 0xFE
#: Maximum normal (unicast) address value
J1939_MAX_UNICAST_ADDR = socket.J1939_MAX_UNICAST_ADDR  # 0xFD
#: Global broadcast address
J1939_BROADCAST_ADDR = J1939_NO_ADDR          # 0xFF

# PGN constants
J1939_PGN_REQUEST = socket.J1939_PGN_REQUEST                   # 0xEA00
J1939_PGN_ADDRESS_CLAIMED = socket.J1939_PGN_ADDRESS_CLAIMED   # 0xEE00
J1939_PGN_ADDRESS_COMMANDED = socket.J1939_PGN_ADDRESS_COMMANDED  # 0xFED8
J1939_PGN_MAX = socket.J1939_PGN_MAX                           # 0x3FFFF
J1939_PGN_PDU1_MAX = socket.J1939_PGN_PDU1_MAX                 # 0x3FF00
#: Transport Protocol – Connection Management
J1939_PGN_TP_CM = 0xEC00
#: Transport Protocol – Data Transfer
J1939_PGN_TP_DT = 0xEB00

# TP control byte values (integer constants; the classes share the prefix name)
J1939_TP_CTRL_RTS = 16     # Request To Send
J1939_TP_CTRL_CTS = 17     # Clear To Send
J1939_TP_CTRL_ACK = 19     # End of Message Acknowledge
J1939_TP_CTRL_BAM = 32     # Broadcast Announce Message
J1939_TP_CTRL_ABORT = 255  # Connection Abort

# PDU format threshold: PF < 240 → PDU1 (peer-to-peer), PF ≥ 240 → PDU2 (broadcast)
J1939_PDU1_MAX_PF = 239

# Socket-level constants
SOL_CAN_BASE = 100
SOL_CAN_J1939 = SOL_CAN_BASE + socket.CAN_J1939  # 107

# Default configuration key
conf.contribs['J1939'] = {'channel': 'can0'}


# ---------------------------------------------------------------------------
# Custom field: little-endian 3-byte PGN storage (J1939 wire format)
# ---------------------------------------------------------------------------

class J1939LEPGNField(Field):  # type: ignore[type-arg]
    """Little-endian 3-byte field for J1939 PGN values in TP frames.

    J1939-21 encodes PGN values in TP Connection Management frames as three
    bytes in little-endian order (LSB first).
    """

    def __init__(self, name, default):
        # type: (str, int) -> None
        # Use "<I" as the conceptual format; actual I/O is 3 bytes
        Field.__init__(self, name, default, "<I")

    def addfield(self, pkt, s, val):
        # type: (Any, bytes, int) -> bytes
        val = self.i2m(pkt, val)
        return s + struct.pack("<I", val)[:3]

    def getfield(self, pkt, s):
        # type: (Any, bytes) -> Tuple[bytes, int]
        return s[3:], self.m2i(pkt, struct.unpack("<I", s[:3] + b'\x00')[0])

    def i2repr(self, pkt, val):
        # type: (Any, int) -> str
        return "0x%05X" % (val or 0)

# Common source address names (informational)
J1939_ADDR_NAMES = {
    0x00: "Engine #1",
    0x01: "Engine #2",
    0x02: "Turbocharger",
    0x03: "Transmission #1",
    0x04: "Transmission #2",
    0x0B: "Brakes - System Controller",
    0x0F: "Instrument Cluster #1",
    0x11: "Trip Recorder",
    0x15: "Retarder, Exhaust, Engine #1",
    0x17: "Cruise Control",
    0x21: "Transmission, Automatic #1",
    0x27: "Clutch/Converter Unit",
    0x28: "Auxiliary Valve Control",
    0x29: "Auxiliary Valve Control #2",
    0xEF: "Null/Reserved",
    0xFE: "NULL (no address)",
    0xFF: "Global (broadcast)",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def pgn_is_pdu1(pgn):
    # type: (int) -> bool
    """Return True if *pgn* is a PDU1 (peer-to-peer) Parameter Group Number."""
    return ((pgn >> 8) & 0xFF) < 240


def can_id_to_j1939(can_id):
    # type: (int) -> Dict[str, int]
    """Decode a 29-bit CAN identifier to a dictionary of J1939 fields.

    :param can_id: 29-bit extended CAN identifier
    :returns: dict with keys ``priority``, ``reserved``, ``data_page``,
              ``pdu_format``, ``pdu_specific``, ``src``
    """
    return {
        'priority': (can_id >> 26) & 0x7,
        'reserved': (can_id >> 25) & 0x1,
        'data_page': (can_id >> 24) & 0x1,
        'pdu_format': (can_id >> 16) & 0xFF,
        'pdu_specific': (can_id >> 8) & 0xFF,
        'src': can_id & 0xFF,
    }


def j1939_to_can_id(priority, reserved, data_page, pdu_format, pdu_specific, src):
    # type: (int, int, int, int, int, int) -> int
    """Encode J1939 fields into a 29-bit CAN identifier.

    :returns: 29-bit CAN identifier value
    """
    return (
        (priority & 0x7) << 26 |
        (reserved & 0x1) << 25 |
        (data_page & 0x1) << 24 |
        (pdu_format & 0xFF) << 16 |
        (pdu_specific & 0xFF) << 8 |
        (src & 0xFF)
    )


def pgn_from_fields(data_page, pdu_format, pdu_specific):
    # type: (int, int, int) -> int
    """Compute the PGN from J1939 CAN identifier sub-fields.

    :param data_page: data page bit (0 or 1)
    :param pdu_format: PDU format byte (0-255)
    :param pdu_specific: PDU specific byte (0-255)
    :returns: 18-bit PGN value
    """
    if pdu_format < 240:
        # PDU1: PS is destination address – not included in PGN
        return (data_page << 16) | (pdu_format << 8)
    else:
        # PDU2: PS is group extension – included in PGN
        return (data_page << 16) | (pdu_format << 8) | pdu_specific


def dst_from_fields(pdu_format, pdu_specific):
    # type: (int, int) -> int
    """Return the destination address encoded in J1939 identifier fields.

    :param pdu_format: PDU format byte (0-255)
    :param pdu_specific: PDU specific byte (0-255)
    :returns: destination address (0x00-0xFF), or ``J1939_NO_ADDR`` for PDU2
    """
    if pdu_format < 240:
        return pdu_specific
    return J1939_NO_ADDR


# ---------------------------------------------------------------------------
# J1939 application-layer packet
# ---------------------------------------------------------------------------

class J1939(Packet):
    """SAE J1939 application-layer message.

    This class represents a J1939 message at the application layer.  When used
    with :class:`NativeJ1939Socket`, the Linux kernel J1939 stack handles
    transport-protocol framing (segmentation / reassembly) automatically, so
    ``data`` may be larger than 8 bytes.

    Addressing information – ``priority``, ``pgn``, ``src``, ``dst`` – is
    stored in :attr:`__slots__` rather than as wire fields (the same approach
    used by :class:`~scapy.contrib.isotp.ISOTP`).  These attributes are
    populated by :class:`NativeJ1939Socket` upon reception.

    Example::

        >>> msg = J1939(b'\\x01\\x02\\x03', pgn=0xFECA, src=0x00, dst=0xFF)
        >>> msg.pgn
        65226
        >>> msg.src
        0
    """

    name = 'J1939'
    fields_desc = [
        StrField('data', b'')
    ]
    __slots__ = Packet.__slots__ + ['priority', 'pgn', 'src', 'dst']

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        self.priority = kwargs.pop('priority', 6)    # type: int
        self.pgn = kwargs.pop('pgn', 0)              # type: int
        self.src = kwargs.pop('src', J1939_NO_ADDR)  # type: int
        self.dst = kwargs.pop('dst', J1939_NO_ADDR)  # type: int
        Packet.__init__(self, *args, **kwargs)

    def answers(self, other):
        # type: (Packet) -> int
        if not isinstance(other, J1939):
            return 0
        return self.data == other.data

    def mysummary(self):
        # type: () -> str
        return self.sprintf(
            "J1939 PGN=0x%%J1939.pgn%% SA=%%J1939.src%% DA=%%J1939.dst%% "
            "prio=%%J1939.priority%%"
        )


# ---------------------------------------------------------------------------
# J1939 CAN-frame-level packet
# ---------------------------------------------------------------------------

class J1939_CAN(Packet):
    """J1939 CAN frame – the 29-bit extended CAN identifier decoded as J1939.

    The wire layout is *byte-for-byte identical* to :class:`~scapy.layers.can.CAN`
    (both start with ``flags[3] + identifier[29]``) so a raw CAN frame can be
    reinterpreted as :class:`J1939_CAN` without copying.

    CAN identifier sub-fields::

        priority    (bits 28-26): message priority, 0 = highest, 7 = lowest
        reserved    (bit  25)   : reserved, should be 0
        data_page   (bit  24)   : selects one of two parameter group tables
        pdu_format  (bits 23-16): determines PDU type (< 240 → PDU1)
        pdu_specific(bits 15-8) : DA if PDU1, Group Extension if PDU2
        src         (bits  7-0) : source address

    Convenience properties :attr:`pgn` and :attr:`dst` are derived from the
    sub-fields.

    Example::

        >>> pkt = J1939_CAN(priority=6, pdu_format=0xFE, pdu_specific=0xCA,
        ...                 src=0x00, data=b'\\xff' * 8)
        >>> hex(pkt.pgn)
        '0xfeca'
        >>> hex(pkt.dst)
        '0xff'
    """

    name = 'J1939_CAN'
    fields_desc = [
        # ── first 32 bits: CAN flags(3) + J1939 identifier fields(29) ──────
        FlagsField('flags', 0b100, 3,
                   ['error', 'remote_transmission_request', 'extended']),
        BitField('priority', 6, 3),       # J1939 priority
        BitField('reserved', 0, 1),       # Reserved bit
        BitField('data_page', 0, 1),      # Data Page (DP)
        ByteField('pdu_format', 0xFE),    # PDU Format (PF)
        ByteField('pdu_specific', 0xFF),  # PDU Specific (PS): DA or GE
        ByteField('src', 0xFE),           # Source Address (SA)
        # ── standard CAN data-length + padding ────────────────────────────
        FieldLenField('length', None, length_of='data', fmt='B'),
        ThreeBytesField('reserved2', 0),
        StrLenField('data', b'', length_from=lambda p: int(p.length)),
    ]

    @property
    def pgn(self):
        # type: () -> int
        """PGN (Parameter Group Number) derived from ``data_page``,
        ``pdu_format``, and ``pdu_specific``."""
        return pgn_from_fields(self.data_page, self.pdu_format, self.pdu_specific)

    @property
    def dst(self):
        # type: () -> int
        """Destination address for PDU1 frames; :data:`J1939_NO_ADDR` for PDU2."""
        return dst_from_fields(self.pdu_format, self.pdu_specific)

    def to_can(self):
        # type: () -> CAN
        """Convert this packet to a standard :class:`~scapy.layers.can.CAN` packet."""
        can_id = j1939_to_can_id(
            self.priority, self.reserved, self.data_page,
            self.pdu_format, self.pdu_specific, self.src,
        )
        return CAN(flags=self.flags, identifier=can_id,
                   length=self.length, data=self.data)

    @classmethod
    def from_can(cls, pkt):
        # type: (CAN) -> J1939_CAN
        """Create a :class:`J1939_CAN` from a standard :class:`~scapy.layers.can.CAN` packet."""
        fields = can_id_to_j1939(pkt.identifier)
        return cls(
            flags=pkt.flags,
            priority=fields['priority'],
            reserved=fields['reserved'],
            data_page=fields['data_page'],
            pdu_format=fields['pdu_format'],
            pdu_specific=fields['pdu_specific'],
            src=fields['src'],
            length=pkt.length,
            data=pkt.data,
        )

    def mysummary(self):
        # type: () -> str
        return self.sprintf(
            "J1939_CAN PGN=0x%04x SA=%02x" % (self.pgn, self.src)
        )


# ---------------------------------------------------------------------------
# J1939 Transport Protocol (TP) frames
# ---------------------------------------------------------------------------
# TP allows up to 1785 bytes per multi-packet session using PGN 0xEC00
# (TP.CM – Connection Management) and PGN 0xEB00 (TP.DT – Data Transfer).

_TP_CM_CTRL_NAMES = {
    J1939_TP_CTRL_RTS: 'RTS',
    J1939_TP_CTRL_CTS: 'CTS',
    J1939_TP_CTRL_ACK: 'EOM_ACK',
    J1939_TP_CTRL_BAM: 'BAM',
    J1939_TP_CTRL_ABORT: 'ABORT',
}

_TP_ABORT_REASON = {
    1: 'Already in connection',
    2: 'System resources',
    3: 'Timeout',
    4: 'CTS while DT in progress',
    5: 'Max retransmit exceeded',
    6: 'Unexpected DT packet',
    7: 'Bad sequence number',
    8: 'Duplicate sequence number',
    250: 'Other',
    251: 'Other',
    252: 'Other',
    253: 'Other',
    254: 'Other',
    255: 'Other',
}


class J1939_TP_CM_RTS(Packet):
    """J1939 TP Connection Management – Request To Send (RTS).

    Sent before a peer-to-peer multi-packet message to announce the total
    size and packet count.  Uses PGN 0xEC00.
    """
    name = 'J1939_TP_CM_RTS'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_RTS),         # 16
        LEShortField('total_size', 0),                # total message size (bytes)
        ByteField('num_packets', 0),                  # total number of TP.DT packets
        ByteField('max_packets', 0xFF),               # max packets per CTS (0xFF = no limit)
        J1939LEPGNField('pgn', 0),                    # PGN of the message being transferred
    ]


class J1939_TP_CM_CTS(Packet):
    """J1939 TP Connection Management – Clear To Send (CTS).

    Response to :class:`J1939_TP_CM_RTS`; authorises the sender to transmit
    up to *num_packets* TP.DT packets starting from *next_packet*.
    """
    name = 'J1939_TP_CM_CTS'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_CTS),         # 17
        ByteField('num_packets', 0),                  # number of packets to send now
        ByteField('next_packet', 1),                  # next expected sequence number
        ShortField('reserved', 0xFFFF),
        J1939LEPGNField('pgn', 0),                    # PGN of the message
    ]


class J1939_TP_CM_ACK(Packet):
    """J1939 TP Connection Management – End of Message Acknowledge (EoMAck).

    Sent by the receiver after all TP.DT packets have been received.
    """
    name = 'J1939_TP_CM_ACK'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_ACK),         # 19
        LEShortField('total_size', 0),                # total message size
        ByteField('num_packets', 0),                  # total TP.DT packets received
        ByteField('reserved', 0xFF),
        J1939LEPGNField('pgn', 0),                    # PGN of the message
    ]


class J1939_TP_CM_BAM(Packet):
    """J1939 TP Connection Management – Broadcast Announce Message (BAM).

    Announces a forthcoming multi-packet broadcast; no CTS handshake is used.
    """
    name = 'J1939_TP_CM_BAM'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_BAM),         # 32
        LEShortField('total_size', 0),                # total message size (bytes)
        ByteField('num_packets', 0),                  # total number of TP.DT packets
        ByteField('reserved', 0xFF),
        J1939LEPGNField('pgn', 0),                    # PGN of the message
    ]


class J1939_TP_CM_ABORT(Packet):
    """J1939 TP Connection Management – Connection Abort."""
    name = 'J1939_TP_CM_ABORT'
    fields_desc = [
        ByteField('ctrl', J1939_TP_CTRL_ABORT),       # 255
        ByteField('reason', 0),                       # abort reason
        ShortField('reserved', 0xFFFF),
        ByteField('reserved2', 0xFF),
        J1939LEPGNField('pgn', 0),                    # PGN of the aborted message
    ]


class J1939_TP_CM(Packet):
    """J1939 TP Connection Management frame dispatcher.

    Parses a raw 8-byte TP.CM payload and returns the appropriate sub-class.

    Example::

        >>> J1939_TP_CM(bytes([32, 20, 0, 3, 0xFF, 0xCA, 0xFE, 0x00]))
        <J1939_TP_CM_BAM  ctrl=32 total_size=20 num_packets=3 ... >
    """
    name = 'J1939_TP_CM'

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # type: (Optional[bytes], *Any, **Any) -> Type[Packet]
        if _pkt and len(_pkt) >= 1:
            ctrl = _pkt[0]
            if ctrl == J1939_TP_CTRL_RTS:
                return J1939_TP_CM_RTS
            elif ctrl == J1939_TP_CTRL_CTS:
                return J1939_TP_CM_CTS
            elif ctrl == J1939_TP_CTRL_ACK:
                return J1939_TP_CM_ACK
            elif ctrl == J1939_TP_CTRL_BAM:
                return J1939_TP_CM_BAM
            elif ctrl == J1939_TP_CTRL_ABORT:
                return J1939_TP_CM_ABORT
        return cls

    def do_dissect(self, s):
        # type: (bytes) -> bytes
        return s


class J1939_TP_DT(Packet):
    """J1939 TP Data Transfer frame.

    Each TP.DT packet carries up to 7 bytes of payload; the first byte is the
    sequence number (1–255).  Unused bytes are padded with ``0xFF``.
    """
    name = 'J1939_TP_DT'
    fields_desc = [
        ByteField('seq_num', 1),                      # sequence number 1-255
        StrFixedLenField('data', b'\xff' * 7, 7),     # 7 data bytes (0xFF = unused)
    ]


# ---------------------------------------------------------------------------
# NativeJ1939Socket
# ---------------------------------------------------------------------------

class NativeJ1939Socket(SuperSocket):
    """Linux kernel J1939 socket (``PF_CAN / SOCK_DGRAM / CAN_J1939``).

    The kernel J1939 stack handles transport-protocol framing automatically:
    messages larger than 8 bytes are fragmented / reassembled transparently,
    and the application deals only with complete J1939 messages.

    :param channel:   CAN interface name (default: ``can0``)
    :param src_name:  64-bit J1939 NAME of this node (0 = no name)
    :param src_addr:  Source address to bind to (:data:`J1939_NO_ADDR` for
                      promiscuous reception of all addresses)
    :param pgn:       PGN to bind to (:data:`J1939_NO_PGN` for all PGNs)
    :param promisc:   Enable promiscuous mode – receive all J1939 messages on
                      the interface regardless of destination address
    :param filters:   Optional list of ``j1939_filter`` dicts; each may
                      contain the keys ``name``, ``name_mask``, ``pgn``,
                      ``pgn_mask``, ``addr``, ``addr_mask``
    :param basecls:   Packet class used to wrap received payloads
                      (default: :class:`J1939`)

    Example – sniff all J1939 traffic on *vcan0*::

        >>> sock = NativeJ1939Socket("vcan0", promisc=True)
        >>> pkt = sock.recv()
        >>> print(pkt.pgn, pkt.src, pkt.data)

    Example – send a J1939 message::

        >>> sock = NativeJ1939Socket("vcan0", src_addr=0x00)
        >>> sock.send(J1939(data=b'\\x01\\x02', pgn=0xFECA, dst=0xFF))
    """

    desc = "read/write J1939 messages using Linux kernel PF_CAN/CAN_J1939 sockets"

    # struct j1939_filter layout: name(Q) name_mask(Q) pgn(I) pgn_mask(I) addr(B) addr_mask(B)
    _J1939_FILTER_FMT = "=QQIIBB"
    _J1939_FILTER_PAD = b'\x00' * 4   # 4 bytes of struct padding to reach 28-byte alignment

    def __init__(
            self,
            channel=None,           # type: Optional[str]
            src_name=J1939_NO_NAME,  # type: int
            src_addr=J1939_NO_ADDR,  # type: int
            pgn=J1939_NO_PGN,        # type: int
            promisc=True,            # type: bool
            filters=None,            # type: Optional[List[Dict[str, int]]]
            basecls=J1939,           # type: Type[Packet]
            **kwargs                 # type: Any
    ):
        # type: (...) -> None
        self.channel = channel or conf.contribs['J1939']['channel']
        self.src_name = src_name
        self.src_addr = src_addr
        self.pgn = pgn
        self.basecls = basecls

        self.ins = socket.socket(
            socket.PF_CAN, socket.SOCK_DGRAM, socket.CAN_J1939
        )

        if promisc:
            try:
                self.ins.setsockopt(
                    SOL_CAN_J1939,
                    socket.SO_J1939_PROMISC,
                    struct.pack('i', 1),
                )
            except OSError as exc:
                raise Scapy_Exception(
                    "Could not enable J1939 promiscuous mode: %s" % exc
                )

        # Enable ancillary data so we can read destination address and priority
        try:
            self.ins.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            self.auxdata_available = True
        except OSError:
            self.auxdata_available = False
            log_runtime.info("SO_TIMESTAMPNS not supported on this kernel")

        if filters is not None:
            self._set_filters(filters)

        self.ins.bind((self.channel, src_name, pgn, src_addr))
        self.outs = self.ins

    def _set_filters(self, filters):
        # type: (List[Dict[str, int]]) -> None
        """Apply a list of J1939 filters to the socket.

        Each filter dict may contain any of:
        ``name``, ``name_mask``, ``pgn``, ``pgn_mask``, ``addr``, ``addr_mask``.
        """
        packed = b''
        for f in filters:
            packed += struct.pack(
                self._J1939_FILTER_FMT,
                f.get('name', J1939_NO_NAME),
                f.get('name_mask', J1939_NO_NAME),
                f.get('pgn', J1939_NO_PGN),
                f.get('pgn_mask', J1939_NO_PGN),
                f.get('addr', J1939_NO_ADDR),
                f.get('addr_mask', J1939_NO_ADDR),
            ) + self._J1939_FILTER_PAD
        try:
            self.ins.setsockopt(SOL_CAN_J1939, socket.SO_J1939_FILTER, packed)
        except OSError as exc:
            raise Scapy_Exception(
                "Could not set J1939 filter: %s" % exc
            )

    def recv_raw(self, x=4096):
        # type: (int) -> Tuple[Optional[Type[Packet]], Optional[bytes], Optional[float]]
        """Returns a tuple ``(cls, pkt_data, timestamp)``.

        .. note::
            The returned *pkt_data* is only the raw J1939 payload bytes.
            Addressing metadata (PGN, source/destination address, priority) is
            unavailable through this low-level interface; use :meth:`recv`
            instead to obtain a fully populated :class:`J1939` packet.
        """
        try:
            pkt_data = self.ins.recv(x)
        except BlockingIOError:
            log_j1939.warning('Captured no data, socket in non-blocking mode.')
            return None, None, None
        except socket.timeout:
            log_j1939.warning('Captured no data, socket read timed out.')
            return None, None, None
        except OSError as exc:
            log_j1939.warning('Captured no data: %s', exc)
            return None, None, None

        return self.basecls, pkt_data, None

    def recv(self, x=4096, **kwargs):
        # type: (int, **Any) -> Optional[Packet]
        """Receive one J1939 message, including addressing metadata.

        Returns a :attr:`basecls` instance (default: :class:`J1939`) with
        ``priority``, ``pgn``, ``src``, and ``dst`` populated from the kernel.
        """
        try:
            data, ancdata, _flags, addr = self.ins.recvmsg(x, 256)
        except BlockingIOError:
            log_j1939.warning('Captured no data, socket in non-blocking mode.')
            return None
        except socket.timeout:
            log_j1939.warning('Captured no data, socket read timed out.')
            return None
        except OSError as exc:
            log_j1939.warning('Captured no data: %s', exc)
            return None

        # addr = (iface_name, name, pgn, src_addr)
        _iface, _src_name, src_pgn, src_addr = addr

        dst_addr = J1939_NO_ADDR
        priority = 6
        ts = None

        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_type == socket.SCM_J1939_DEST_ADDR:
                if cmsg_data:
                    dst_addr = struct.unpack('B', cmsg_data[:1])[0]
            elif cmsg_type == socket.SCM_J1939_PRIO:
                if cmsg_data:
                    priority = struct.unpack('B', cmsg_data[:1])[0]

        if ts is None:
            ts = time.time()

        try:
            pkt = self.basecls(
                data,
                priority=priority,
                pgn=src_pgn,
                src=src_addr,
                dst=dst_addr,
            )
        except Exception:
            pkt = self.basecls(data)

        pkt.time = ts
        return pkt

    def send(self, x):
        # type: (Packet) -> int
        """Send a J1939 message.

        If *x* is a :class:`J1939` packet, the ``pgn``, ``dst``, and
        ``priority`` attributes are used.  For other packet types the raw bytes
        are sent to the socket's default destination.
        """
        if x is None:
            return 0

        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        # Extract payload bytes
        if isinstance(x, J1939):
            data = x.data if isinstance(x.data, bytes) else raw(x)
            dst_pgn = x.pgn if x.pgn != 0 else J1939_NO_PGN
            dst_addr = x.dst
            priority = x.priority
        else:
            data = raw(x)
            dst_pgn = J1939_NO_PGN
            dst_addr = J1939_NO_ADDR
            priority = 6

        # Set per-message priority
        try:
            self.outs.setsockopt(
                SOL_CAN_J1939,
                socket.SO_J1939_SEND_PRIO,
                struct.pack('i', priority),
            )
        except OSError:
            pass  # not critical

        dst = (self.channel, J1939_NO_NAME, dst_pgn, dst_addr)
        try:
            return self.outs.sendto(data, dst)
        except OSError as exc:
            log_j1939.error("Failed to send J1939 packet: %s", exc)
            return 0
