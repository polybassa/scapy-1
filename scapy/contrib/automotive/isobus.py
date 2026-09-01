# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = ISOBUS (ISO 11783)
# scapy.contrib.status = loads

"""ISOBUS (ISO 11783) protocol implementation for Scapy.

ISOBUS is the communication standard for agriculture and forestry machinery,
based on SAE J1939 which uses extended CAN frames (29-bit identifiers).

The 29-bit CAN identifier encodes J1939/ISOBUS addressing:

  - Priority (3 bits, bits 28-26): message priority, 0 = highest, 7 = lowest
  - Reserved R (1 bit, bit 25): reserved, should be 0
  - Data Page DP (1 bit, bit 24): selects parameter group number page
  - PDU Format PF (8 bits, bits 23-16): determines PDU type and PGN
  - PDU Specific PS (8 bits, bits 15-8):
      For PDU1 (PF < 0xF0): destination address
      For PDU2 (PF >= 0xF0): group extension (part of PGN)
  - Source Address SA (8 bits, bits 7-0): source address of sending node

References:
  - ISO 11783 (ISOBUS)
  - SAE J1939
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField,
    ByteField,
    ByteEnumField,
    XByteField,
    FlagsField,
    LELongField,
    LEShortField,
    StrFixedLenField,
    ThreeBytesField,
    XLE3BytesField,
    ConditionalField,
)
from scapy.layers.can import CAN

# Typing imports
from typing import Optional, Tuple

# Special ISOBUS/J1939 addresses
ISOBUS_ADDR_GLOBAL = 0xFF   # Global destination address (broadcast)
ISOBUS_ADDR_NULL = 0xFE     # Null/anonymous source address

# ISOBUS Industry Groups (ISO 11783-1)
ISOBUS_INDUSTRY_GROUPS = {
    0: "Global",
    1: "On-Highway",
    2: "Agricultural and Forestry",
    3: "Construction",
    4: "Marine",
    5: "Industrial",
}

# Common ISOBUS/J1939 PGNs (Parameter Group Numbers)
ISOBUS_PGNS = {
    0x00E600: "Working Set Master",
    0x00E700: "Working Set Member",
    0x00E800: "Acknowledgment",
    0x00EA00: "Request for PGN",
    0x00EB00: "Transport Protocol - Data Transfer (TP.DT)",
    0x00EC00: "Transport Protocol - Connection Management (TP.CM)",
    0x00EE00: "Address Claimed / Cannot Claim Address",
    0x00EF00: "Proprietary A",
    0x00FED8: "Commanded Address",
}

# Transport Protocol Connection Management control bytes (TP.CM)
ISOBUS_TP_CM_CONTROL = {
    16: "Request to Send (RTS)",
    17: "Clear to Send (CTS)",
    19: "End of Message Acknowledgment (EOM ACK)",
    32: "Broadcast Announce Message (BAM)",
    255: "Connection Abort",
}

# Acknowledgment control bytes (PGN 0x00E800)
ISOBUS_ACK_CONTROL = {
    0: "Positive Acknowledgment (ACK)",
    1: "Negative Acknowledgment (NACK)",
    2: "Access Denied",
    3: "Cannot Respond",
}

# Connection Abort reason codes
ISOBUS_TP_CM_ABORT_REASONS = {
    1: "Already in one or more connection managed sessions",
    2: "System resources were needed for another task",
    3: "A timeout occurred",
    4: "CTS messages received when data transfer is in progress",
    5: "Maximum retransmit request limit reached",
    6: "Unexpected data transfer packet",
    7: "Bad sequence number (and connection is aborted)",
    8: "Duplicate sequence number (and connection is aborted)",
    250: "Other reasons",
}


def build_isobus_name(identity_number=0, manufacturer_code=0, ecu_instance=0,
                      function_instance=0, function=0, reserved_name=0,
                      device_class=0, device_class_instance=0,
                      industry_group=2, self_configurable_address=1):
    # type: (int, int, int, int, int, int, int, int, int, int) -> int
    """Build a J1939/ISOBUS 64-bit NAME value from its component fields.

    The NAME is an 8-byte little-endian field used in Address Claiming and
    Commanded Address messages to uniquely identify a node on the bus.

    :param identity_number: 21-bit identity number unique to the manufacturer
    :param manufacturer_code: 11-bit manufacturer code (assigned by SAE)
    :param ecu_instance: 3-bit ECU instance (0 if only one ECU per function)
    :param function_instance: 5-bit function instance
    :param function: 8-bit function code (defined per industry group)
    :param reserved_name: 1-bit reserved field (should be 0)
    :param device_class: 7-bit device class
    :param device_class_instance: 4-bit device class instance
    :param industry_group: 3-bit industry group (2 = Agricultural and Forestry)
    :param self_configurable_address: 1-bit flag (1 = can self-configure address)
    :return: 64-bit NAME value (for use with LELongField)

    Example::

        >>> nn = build_isobus_name(
        ...     identity_number=0x001,
        ...     manufacturer_code=0x123,
        ...     industry_group=2,
        ...     device_class=4,
        ... )
        >>> pkt = ISOBUS(priority=6, pdu_format=0xEE, pdu_specific=0xFF,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSAddressClaimed(node_name=nn)
    """
    name = (identity_number & 0x1FFFFF)
    name |= (manufacturer_code & 0x7FF) << 21
    name |= (ecu_instance & 0x7) << 32
    name |= (function_instance & 0x1F) << 35
    name |= (function & 0xFF) << 40
    name |= (reserved_name & 0x1) << 48
    name |= (device_class & 0x7F) << 49
    name |= (device_class_instance & 0xF) << 56
    name |= (industry_group & 0x7) << 60
    name |= (self_configurable_address & 0x1) << 63
    return name


class ISOBUS(CAN):
    """ISOBUS (ISO 11783 / SAE J1939) CAN frame with J1939 addressing.

    Extends the CAN layer by parsing the 29-bit identifier as individual
    J1939 header sub-fields:

    - **priority**: 3-bit message priority (0=highest, 7=lowest, default 6)
    - **reserved**: 1-bit reserved field (should be 0)
    - **data_page**: 1-bit data page selector
    - **pdu_format**: 8-bit PDU format (determines PDU type and PGN)
    - **pdu_specific**: 8-bit destination address (PDU1) or group extension (PDU2)
    - **source_address**: 8-bit source address of the sending node
    - **length**: number of data bytes in this CAN frame (0-8)
    - **reserved2**: 3-byte reserved field (CAN frame structure)

    PDU1 (pdu_format < 0xF0): peer-to-peer message, pdu_specific is the
    destination address. PGN = (reserved << 17) | (data_page << 16) | (pdu_format << 8).

    PDU2 (pdu_format >= 0xF0): broadcast message, pdu_specific is the group
    extension (part of PGN). PGN = (reserved << 17) | (data_page << 16) |
    (pdu_format << 8) | pdu_specific.

    Use the :attr:`pgn` property to compute the PGN from the header fields.

    Example - Build a Request for PGN message::

        >>> pkt = ISOBUS(priority=6, pdu_format=0xEA, pdu_specific=0xFF,
        ...              source_address=0x80, length=3)
        >>> pkt /= ISOBUSRequestForPGN(requested_pgn=0x00EE00)

    Example - Build an Address Claimed message::

        >>> nn = build_isobus_name(identity_number=0x001,
        ...                        manufacturer_code=0x123,
        ...                        industry_group=2, device_class=4)
        >>> pkt = ISOBUS(priority=6, pdu_format=0xEE, pdu_specific=0xFF,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSAddressClaimed(node_name=nn)

    Example - Dissect a raw ISOBUS frame::

        >>> raw_frame = b'\\xc8\\xee\\xff\\x80\\x08\\x00\\x00\\x00' + b'\\x00' * 8
        >>> pkt = ISOBUS(raw_frame)
        >>> pkt.pdu_format  # 0xEE = Address Claimed PGN
        238
        >>> pkt.source_address  # 0x80
        128
    """

    name = "ISOBUS"

    # The 29-bit CAN identifier is split into J1939 sub-fields.
    # Bit layout of the first 4 bytes (32 bits total):
    #   bits 31-29: flags (3 bits)
    #   bits 28-26: priority (3 bits)
    #   bit  25:    reserved (1 bit)
    #   bit  24:    data_page (1 bit)
    #   bits 23-16: pdu_format (8 bits)
    #   bits 15-8:  pdu_specific (8 bits)
    #   bits  7-0:  source_address (8 bits)
    fields_desc = [
        FlagsField('flags', 0, 3, ['error',
                                   'remote_transmission_request',
                                   'extended']),
        BitField('priority', 6, 3),
        BitField('reserved', 0, 1),
        BitField('data_page', 0, 1),
        ByteField('pdu_format', 0),
        XByteField('pdu_specific', 0),
        XByteField('source_address', ISOBUS_ADDR_NULL),
        ByteField('length', 8),
        ThreeBytesField('reserved2', 0),
    ]

    def extract_padding(self, p):
        # type: (bytes) -> Tuple[bytes, Optional[bytes]]
        """Pass CAN data bytes (up to ``length``) to the next protocol layer."""
        return p[:self.length], None

    @property
    def pgn(self):
        # type: () -> int
        """Compute the Parameter Group Number (PGN) from the J1939 header.

        For PDU1 (pdu_format < 0xF0): the destination address is NOT part
        of the PGN. PGN = (reserved << 17) | (data_page << 16) | (pdu_format << 8).

        For PDU2 (pdu_format >= 0xF0): the group extension IS part of the PGN.
        PGN = (reserved << 17) | (data_page << 16) | (pdu_format << 8) | pdu_specific.
        """
        r = self.reserved & 0x1
        dp = self.data_page & 0x1
        pf = self.pdu_format & 0xFF
        if pf < 0xF0:
            return (r << 17) | (dp << 16) | (pf << 8)
        else:
            ps = self.pdu_specific & 0xFF
            return (r << 17) | (dp << 16) | (pf << 8) | ps


class ISOBUSRequestForPGN(Packet):
    """Request for PGN message (PGN 0x00EA00).

    Requests a specific PGN from another node. The 3-byte requested PGN
    is encoded in little-endian byte order. Bytes 4-8 are set to 0xFF.

    Example::

        >>> pkt = ISOBUS(priority=6, pdu_format=0xEA, pdu_specific=0xFF,
        ...              source_address=0x80, length=3)
        >>> pkt /= ISOBUSRequestForPGN(requested_pgn=0x00EE00)
    """

    name = "ISOBUS Request for PGN"
    fields_desc = [
        XLE3BytesField('requested_pgn', 0),
    ]


class ISOBUSAcknowledgment(Packet):
    """Acknowledgment message (PGN 0x00E800).

    Sent in response to PGN requests or commands. Byte 1 indicates the
    acknowledgment type; bytes 2-8 provide additional context.

    Example::

        >>> pkt = ISOBUS(priority=6, pdu_format=0xE8, pdu_specific=0xFF,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSAcknowledgment(control_byte=0,
        ...                             group_function_value=0xFF,
        ...                             pgn=0x00EE00)
    """

    name = "ISOBUS Acknowledgment"
    fields_desc = [
        ByteEnumField('control_byte', 0, ISOBUS_ACK_CONTROL),
        ByteField('group_function_value', 0xFF),
        # Bytes 3-5: reserved (0xFF)
        ByteField('reserved_ack_b3', 0xFF),
        ByteField('reserved_ack_b4', 0xFF),
        ByteField('reserved_ack_b5', 0xFF),
        # Bytes 6-8: PGN being acknowledged (little-endian)
        XLE3BytesField('pgn', 0),
    ]


class ISOBUSAddressClaimed(Packet):
    """Address Claimed / Cannot Claim Address (PGN 0x00EE00).

    Contains the J1939/ISOBUS NAME of the claiming node. The NAME is an
    8-byte little-endian value encoding the node's identity.

    Use :func:`build_isobus_name` to construct the NAME value from individual
    component fields.

    NAME bit layout (64-bit little-endian integer):

    =========================  =====  =========================================
    Field                      Bits   Description
    =========================  =====  =========================================
    identity_number            0-20   21-bit unique identity per manufacturer
    manufacturer_code          21-31  11-bit SAE-assigned manufacturer code
    ecu_instance               32-34  3-bit ECU instance
    function_instance          35-39  5-bit function instance
    function                   40-47  8-bit function code (industry-specific)
    reserved_name              48     1-bit reserved
    device_class               49-55  7-bit device class
    device_class_instance      56-59  4-bit device class instance
    industry_group             60-62  3-bit industry group
    self_configurable_address  63     1-bit self-configurable address flag
    =========================  =====  =========================================

    Subfield access via properties::

        >>> pkt = ISOBUSAddressClaimed(
        ...     node_name=build_isobus_name(identity_number=0x001,
        ...                                 manufacturer_code=0x123,
        ...                                 industry_group=2, device_class=4))
        >>> pkt.identity_number
        1
        >>> pkt.manufacturer_code
        291
        >>> pkt.industry_group
        2
    """

    name = "ISOBUS Address Claimed"
    fields_desc = [
        LELongField('node_name', 0),
    ]

    @property
    def identity_number(self):
        # type: () -> int
        """Extract the 21-bit Identity Number from the NAME."""
        return self.node_name & 0x1FFFFF

    @property
    def manufacturer_code(self):
        # type: () -> int
        """Extract the 11-bit Manufacturer Code from the NAME."""
        return (self.node_name >> 21) & 0x7FF

    @property
    def ecu_instance(self):
        # type: () -> int
        """Extract the 3-bit ECU Instance from the NAME."""
        return (self.node_name >> 32) & 0x7

    @property
    def function_instance(self):
        # type: () -> int
        """Extract the 5-bit Function Instance from the NAME."""
        return (self.node_name >> 35) & 0x1F

    @property
    def function(self):
        # type: () -> int
        """Extract the 8-bit Function from the NAME."""
        return (self.node_name >> 40) & 0xFF

    @property
    def reserved_name(self):
        # type: () -> int
        """Extract the 1-bit Reserved field from the NAME."""
        return (self.node_name >> 48) & 0x1

    @property
    def device_class(self):
        # type: () -> int
        """Extract the 7-bit Device Class from the NAME."""
        return (self.node_name >> 49) & 0x7F

    @property
    def device_class_instance(self):
        # type: () -> int
        """Extract the 4-bit Device Class Instance from the NAME."""
        return (self.node_name >> 56) & 0xF

    @property
    def industry_group(self):
        # type: () -> int
        """Extract the 3-bit Industry Group from the NAME."""
        return (self.node_name >> 60) & 0x7

    @property
    def self_configurable_address(self):
        # type: () -> int
        """Extract the Self-Configurable Address bit from the NAME."""
        return (self.node_name >> 63) & 0x1


class ISOBUSCommandedAddress(Packet):
    """Commanded Address message (PGN 0x00FED8).

    Instructs a specific node (identified by NAME) to use a new address.

    Example::

        >>> nn = build_isobus_name(identity_number=0x001,
        ...                        manufacturer_code=0x123)
        >>> pkt = ISOBUS(priority=6, pdu_format=0xFE, pdu_specific=0xD8,
        ...              source_address=0x26, length=9)
        >>> pkt /= ISOBUSCommandedAddress(node_name=nn, new_source_address=0x42)
    """

    name = "ISOBUS Commanded Address"
    fields_desc = [
        LELongField('node_name', 0),
        XByteField('new_source_address', 0),
    ]


class ISOBUSWorkingSetMaster(Packet):
    """Working Set Master message (PGN 0x00E600).

    Sent periodically by the Working Set Master (WSM) to announce itself
    and the number of members in the Working Set (ISO 11783-7).

    Example::

        >>> pkt = ISOBUS(priority=7, pdu_format=0xE6, pdu_specific=0xFF,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSWorkingSetMaster(number_of_members=3)
    """

    name = "ISOBUS Working Set Master"
    fields_desc = [
        ByteField('number_of_members', 1),
    ]


class ISOBUSWorkingSetMember(Packet):
    """Working Set Member message (PGN 0x00E700).

    Sent by each Working Set Member to announce itself to the Working Set
    Master during Working Set formation (ISO 11783-7).

    Example::

        >>> nn = build_isobus_name(identity_number=0x002,
        ...                        manufacturer_code=0x123)
        >>> pkt = ISOBUS(priority=7, pdu_format=0xE7, pdu_specific=0x80,
        ...              source_address=0x81, length=8)
        >>> pkt /= ISOBUSWorkingSetMember(node_name=nn)
    """

    name = "ISOBUS Working Set Member"
    fields_desc = [
        LELongField('node_name', 0),
    ]


class ISOBUSTransportProtocolCM(Packet):
    """Transport Protocol - Connection Management (TP.CM) (PGN 0x00EC00).

    Manages multi-packet message transfers (9 to 1785 bytes). Supports five
    message types selected by ``control_byte``:

    - **BAM** (32): Broadcast Announce Message, announces a broadcast transfer
    - **RTS** (16): Request to Send, initiates a peer-to-peer transfer
    - **CTS** (17): Clear to Send, authorises the sender to transmit packets
    - **EOM ACK** (19): End of Message Acknowledgment, confirms transfer complete
    - **Abort** (255): Aborts an in-progress connection

    Example - BAM::

        >>> pkt = ISOBUS(priority=7, pdu_format=0xEC, pdu_specific=0xFF,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSTransportProtocolCM(
        ...     control_byte=32,
        ...     total_message_size=20,
        ...     total_number_of_packets=3,
        ...     pgn=0x00FED8)

    Example - RTS::

        >>> pkt = ISOBUS(priority=7, pdu_format=0xEC, pdu_specific=0x42,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSTransportProtocolCM(
        ...     control_byte=16,
        ...     total_message_size=20,
        ...     total_number_of_packets=3,
        ...     max_packets_per_cts=3,
        ...     pgn=0x00FED8)
    """

    name = "ISOBUS TP.CM"

    # Convenience references for control_byte values
    BAM = 32
    RTS = 16
    CTS = 17
    EOM_ACK = 19
    ABORT = 255

    fields_desc = [
        ByteEnumField('control_byte', 32, ISOBUS_TP_CM_CONTROL),

        # BAM / RTS / EOM ACK: total_message_size (bytes 2-3, LE 16-bit)
        ConditionalField(
            LEShortField('total_message_size', 0),
            lambda pkt: pkt.control_byte in (16, 19, 32)
        ),
        # BAM / RTS / EOM ACK: total_number_of_packets (byte 4)
        ConditionalField(
            ByteField('total_number_of_packets', 0),
            lambda pkt: pkt.control_byte in (16, 19, 32)
        ),
        # RTS only: max packets per CTS (byte 5); 0xFF = no limit
        ConditionalField(
            ByteField('max_packets_per_cts', 0xFF),
            lambda pkt: pkt.control_byte == 16
        ),
        # BAM / EOM ACK: reserved byte 5 (0xFF)
        ConditionalField(
            ByteField('reserved_b5', 0xFF),
            lambda pkt: pkt.control_byte in (19, 32)
        ),

        # CTS: number of packets that can be sent (byte 2)
        ConditionalField(
            ByteField('number_of_packets_cts', 0),
            lambda pkt: pkt.control_byte == 17
        ),
        # CTS: next packet number to be sent (byte 3, starts at 1)
        ConditionalField(
            ByteField('next_packet_number', 1),
            lambda pkt: pkt.control_byte == 17
        ),
        # CTS: reserved bytes 4-5 (0xFF 0xFF)
        ConditionalField(
            ByteField('reserved_cts_b4', 0xFF),
            lambda pkt: pkt.control_byte == 17
        ),
        ConditionalField(
            ByteField('reserved_cts_b5', 0xFF),
            lambda pkt: pkt.control_byte == 17
        ),

        # Abort: connection abort reason (byte 2)
        ConditionalField(
            ByteEnumField('abort_reason', 1, ISOBUS_TP_CM_ABORT_REASONS),
            lambda pkt: pkt.control_byte == 255
        ),
        # Abort: reserved bytes 3-5 (0xFF 0xFF 0xFF)
        ConditionalField(
            ByteField('reserved_abort_b3', 0xFF),
            lambda pkt: pkt.control_byte == 255
        ),
        ConditionalField(
            ByteField('reserved_abort_b4', 0xFF),
            lambda pkt: pkt.control_byte == 255
        ),
        ConditionalField(
            ByteField('reserved_abort_b5', 0xFF),
            lambda pkt: pkt.control_byte == 255
        ),

        # Bytes 6-8: PGN of the multi-packet message (little-endian)
        XLE3BytesField('pgn', 0),
    ]


class ISOBUSTransportProtocolDT(Packet):
    """Transport Protocol - Data Transfer (TP.DT) (PGN 0x00EB00).

    Carries individual data packets in a multi-packet message transfer.
    Each packet carries up to 7 bytes of data and a sequence number.

    Sequence numbers start at 1 and increment for each packet. The last
    packet is padded to 7 bytes with 0xFF if the data does not fill it.

    Example::

        >>> pkt = ISOBUS(priority=7, pdu_format=0xEB, pdu_specific=0xFF,
        ...              source_address=0x80, length=8)
        >>> pkt /= ISOBUSTransportProtocolDT(
        ...     sequence_number=1,
        ...     data=b'\\x01\\x02\\x03\\x04\\x05\\x06\\x07')
    """

    name = "ISOBUS TP.DT"
    fields_desc = [
        ByteField('sequence_number', 1),
        # 7 bytes of data payload (padded with 0xFF if the message is shorter)
        StrFixedLenField('data', b'\xff' * 7, length=7),
    ]


# ---------------------------------------------------------------------------
# Layer bindings: dispatch ISOBUS data to PGN-specific handlers
# ---------------------------------------------------------------------------

# PDU1 PGNs (pdu_format < 0xF0): pdu_specific is the destination address
bind_layers(ISOBUS, ISOBUSWorkingSetMaster, pdu_format=0xE6)
bind_layers(ISOBUS, ISOBUSWorkingSetMember, pdu_format=0xE7)
bind_layers(ISOBUS, ISOBUSAcknowledgment, pdu_format=0xE8)
bind_layers(ISOBUS, ISOBUSRequestForPGN, pdu_format=0xEA)
bind_layers(ISOBUS, ISOBUSTransportProtocolDT, pdu_format=0xEB)
bind_layers(ISOBUS, ISOBUSTransportProtocolCM, pdu_format=0xEC)
bind_layers(ISOBUS, ISOBUSAddressClaimed, pdu_format=0xEE)

# PDU2 PGN (pdu_format >= 0xF0): pdu_specific is the group extension
# PGN 0x00FED8: Commanded Address (pdu_format=0xFE, pdu_specific=0xD8)
bind_layers(ISOBUS, ISOBUSCommandedAddress, pdu_format=0xFE, pdu_specific=0xD8)
