# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Scapy contributors

# scapy.contrib.description = SAE J1939 utility functions
# scapy.contrib.status = loads

"""
SAE J1939 utility functions: ECU discovery and fuzzing.

Three main classes are provided:

:class:`J1939ECU`
    Represents a single ECU discovered on the J1939 bus.

:class:`J1939ECUDiscovery`
    Passive and active ECU discovery over a CAN interface.

:class:`J1939Fuzzer`
    Mutation- and generation-based fuzzer for J1939 CAN frames.
"""

import random
import threading
import time

from typing import Dict, List, Optional, Tuple

from scapy.contrib.j1939 import (
    J1939,
    J1939_CAN,
    J1939_NO_ADDR,
    J1939_PDU1_MAX_PF,
    J1939_PGN_ADDRESS_CLAIMED,
    J1939_PGN_REQUEST,
)
from scapy.contrib.j1939_spn_pgn_db import (
    lookup_pgn,
    lookup_spn,
    lookup_src_addr,
    spns_for_pgn,
)
from scapy.packet import Packet

__all__ = [
    "J1939ECU",
    "J1939ECUDiscovery",
    "J1939Fuzzer",
]


# ---------------------------------------------------------------------------
# J1939ECU
# ---------------------------------------------------------------------------

class J1939ECU:
    """Represents an ECU node discovered on a J1939 bus.

    :param address: J1939 source address of this ECU (0-253)
    :param name_bytes: optional 8-byte NAME field from an Address Claimed
        response.  The NAME encodes the ECU's identity (manufacturer, industry
        group, function, etc.).

    Example::

        >>> ecu = J1939ECU(0x00)
        >>> ecu.address
        0
        >>> ecu.preferred_name
        'Engine #1'
    """

    def __init__(self, address, name_bytes=None):
        # type: (int, Optional[bytes]) -> None
        if not (0 <= address <= 255):
            raise ValueError("address must be 0-255, got %d" % address)
        self._address = address
        self._name_bytes = name_bytes      # 8-byte NAME from address claiming
        self._prop_messages = []           # type: List[J1939_CAN]
        self._address_claimed_msg = None   # type: Optional[J1939_CAN]

    @property
    def address(self):
        # type: () -> int
        """J1939 source address (0-255)."""
        return self._address

    @property
    def preferred_name(self):
        # type: () -> str
        """Preferred ECU name from the J1939 preferred source-address table."""
        return lookup_src_addr(self._address)

    @property
    def name_bytes(self):
        # type: () -> Optional[bytes]
        """Raw 8-byte NAME value from the Address Claimed response, or ``None``."""
        return self._name_bytes

    @name_bytes.setter
    def name_bytes(self, value):
        # type: (Optional[bytes]) -> None
        if value is not None and len(value) != 8:
            raise ValueError("J1939 NAME must be exactly 8 bytes")
        self._name_bytes = value

    @property
    def address_claimed_msg(self):
        # type: () -> Optional[J1939_CAN]
        """The raw Address Claimed J1939_CAN frame, if available."""
        return self._address_claimed_msg

    @address_claimed_msg.setter
    def address_claimed_msg(self, msg):
        # type: (J1939_CAN) -> None
        if not isinstance(msg, J1939_CAN):
            raise TypeError("expected J1939_CAN, got %s" % type(msg).__name__)
        if msg.pdu_format != 0xEE:
            raise ValueError(
                "Address Claimed must have pdu_format=0xEE, got 0x%02X" % msg.pdu_format
            )
        self._address_claimed_msg = msg
        if len(msg.data) == 8:
            self._name_bytes = msg.data

    @property
    def prop_messages(self):
        # type: () -> List[J1939_CAN]
        """List of unique proprietary J1939_CAN frames observed from this ECU."""
        return list(self._prop_messages)

    def add_prop_message(self, msg):
        # type: (J1939_CAN) -> None
        """Add a proprietary message to this ECU's list (deduplication by CAN ID + data).

        :param msg: J1939_CAN frame to add
        """
        for existing in self._prop_messages:
            if msg.pdu_format == existing.pdu_format and msg.data == existing.data:
                return
        self._prop_messages.append(msg)

    def decode_name(self):
        # type: () -> Optional[Dict[str, int]]
        """Decode the 64-bit J1939 NAME into its constituent fields.

        Returns a dict with keys ``arbitrary_address_capable``,
        ``industry_group``, ``vehicle_system_instance``, ``vehicle_system``,
        ``reserved``, ``function``, ``function_instance``,
        ``ecu_instance``, ``manufacturer_code``, and ``identity_number``,
        or ``None`` if no NAME is available.

        :returns: dict of decoded NAME fields, or ``None``
        """
        if self._name_bytes is None or len(self._name_bytes) != 8:
            return None
        # J1939 NAME bit layout (LSB first, per little-endian convention):
        # Bits 0-20:  Identity Number        (21 bits)
        # Bits 21-31: Manufacturer Code      (11 bits)
        # Bits 32-34: ECU Instance           (3 bits)
        # Bits 35-39: Function Instance      (5 bits)
        # Bits 40-47: Function               (8 bits)
        # Bit  48:    Reserved               (1 bit)
        # Bits 49-56: Vehicle System         (7 bits) -- note: inclusive 49-55 in spec
        # Bits 56-59: Vehicle System Instance(4 bits)
        # Bits 60-62: Industry Group         (3 bits)
        # Bit  63:    Arbitrary Address Capable (1 bit)
        import struct
        val = struct.unpack_from('<Q', self._name_bytes)[0]
        return {
            "identity_number":          (val >> 0) & 0x1FFFFF,
            "manufacturer_code":        (val >> 21) & 0x7FF,
            "ecu_instance":             (val >> 32) & 0x07,
            "function_instance":        (val >> 35) & 0x1F,
            "function":                 (val >> 40) & 0xFF,
            "reserved":                 (val >> 48) & 0x01,
            "vehicle_system":           (val >> 49) & 0x7F,
            "vehicle_system_instance":  (val >> 56) & 0x0F,
            "industry_group":           (val >> 60) & 0x07,
            "arbitrary_address_capable":(val >> 63) & 0x01,
        }

    def __repr__(self):
        # type: () -> str
        return "J1939ECU(address=0x%02X, name=%r)" % (self._address, self.preferred_name)

    def __str__(self):
        # type: () -> str
        name_hex = ("NAME=0x%016X" % int.from_bytes(self._name_bytes, 'little')
                    if self._name_bytes else "NAME=<unknown>")
        return "SA=0x%02X  %-42s  %s" % (
            self._address, self.preferred_name, name_hex
        )


# ---------------------------------------------------------------------------
# J1939ECUDiscovery
# ---------------------------------------------------------------------------

class J1939ECUDiscovery:
    """Discover ECUs on a J1939 network using passive or active scanning.

    Uses :class:`~scapy.contrib.cansocket_native.NativeCANSocket` with
    ``basecls=J1939_CAN`` for frame capture, so it works at the raw CAN layer
    without requiring the kernel J1939 stack.

    :param channel: CAN interface name (e.g. ``"vcan0"``, ``"can0"``)

    Example (passive 10-second scan)::

        >>> ed = J1939ECUDiscovery("vcan0")
        >>> ecus = ed.passive_scan(duration=10)
        >>> for ecu in ecus:
        ...     print(ecu)
    """

    def __init__(self, channel):
        # type: (str) -> None
        self._channel = channel
        self._known_ecus = {}  # type: Dict[int, J1939ECU]

    @property
    def channel(self):
        # type: () -> str
        return self._channel

    @property
    def known_ecus(self):
        # type: () -> List[J1939ECU]
        """All ECUs accumulated across scans."""
        return list(self._known_ecus.values())

    def get_ecu(self, address):
        # type: (int) -> Optional[J1939ECU]
        """Return the :class:`J1939ECU` for the given address, or ``None``."""
        return self._known_ecus.get(address)

    def _add_ecu(self, address):
        # type: (int) -> J1939ECU
        """Return (or create) the J1939ECU for an address."""
        if address not in self._known_ecus:
            self._known_ecus[address] = J1939ECU(address)
        return self._known_ecus[address]

    def passive_scan(self, duration=10.0):
        # type: (float) -> List[J1939ECU]
        """Listen on the bus for *duration* seconds and record all source addresses.

        :param duration: listening time in seconds (default 10)
        :returns: list of newly discovered :class:`J1939ECU` objects
        """
        from scapy.contrib.cansocket_native import NativeCANSocket

        before = set(self._known_ecus.keys())
        sock = NativeCANSocket(self._channel, basecls=J1939_CAN)
        sock.ins.settimeout(0.2)
        deadline = time.time() + duration
        try:
            while time.time() < deadline:
                try:
                    pkt = sock.recv()
                    if pkt is not None and isinstance(pkt, J1939_CAN):
                        self._add_ecu(pkt.src)
                except Exception:
                    pass
        finally:
            sock.close()

        new_addrs = set(self._known_ecus.keys()) - before
        return [self._known_ecus[a] for a in sorted(new_addrs)]

    def active_scan(self, src_addr=0xF9, timeout=5.0):
        # type: (int, float) -> List[J1939ECU]
        """Broadcast a Request for Address Claimed (PGN 0xEA00, data=0xEE00)
        to every address (0-255) to elicit Address Claimed responses.

        :param src_addr: source address to use for the request frames
        :param timeout: seconds to wait for responses after sending all requests
        :returns: list of newly discovered :class:`J1939ECU` objects
        """
        from scapy.contrib.cansocket_native import NativeCANSocket

        before = set(self._known_ecus.keys())
        sock = NativeCANSocket(self._channel, basecls=J1939_CAN,
                               receive_own_messages=False)
        sock.ins.settimeout(0.1)

        collected = []  # type: List[J1939_CAN]
        done = threading.Event()

        def _recv_loop():
            while not done.is_set():
                try:
                    pkt = sock.recv()
                    if pkt is not None and isinstance(pkt, J1939_CAN):
                        collected.append(pkt)
                except Exception:
                    pass

        t = threading.Thread(target=_recv_loop, daemon=True)
        t.start()

        # Send Request for Address Claimed (PGN 0xEA00, data = LE-encoded 0xEE00)
        # PGN 0xEA00 → PF=0xEA, destination-specific (PDU1)
        # Request data: 3 bytes = target PGN in LE → 0x00, 0xEE, 0x00
        req_data = bytes([0x00, 0xEE, 0x00])
        for dst in range(256):
            frame = J1939_CAN(
                priority=6, reserved=0, data_page=0,
                pdu_format=0xEA, pdu_specific=dst, src=src_addr,
                data=req_data,
            )
            try:
                sock.send(frame)
            except Exception:
                pass

        time.sleep(timeout)
        done.set()
        t.join(timeout=1.0)
        sock.close()

        # Process received Address Claimed frames (PF=0xEE)
        for pkt in collected:
            if pkt.pdu_format == 0xEE:
                ecu = self._add_ecu(pkt.src)
                try:
                    ecu.address_claimed_msg = pkt
                except (ValueError, TypeError):
                    pass

        # Also register any other source addresses seen
        for pkt in collected:
            self._add_ecu(pkt.src)

        new_addrs = set(self._known_ecus.keys()) - before
        return [self._known_ecus[a] for a in sorted(new_addrs)]

    def request_pgn(self, dst_addr, pgn, src_addr=0xF9, timeout=5.0):
        # type: (int, int, int, float) -> Optional[J1939_CAN]
        """Send a PGN request to a specific ECU and wait for its response.

        The request uses PGN 0xEA00 (Request PGN) with the 3-byte
        little-endian PGN value as data.

        :param dst_addr: destination ECU source address
        :param pgn: PGN to request
        :param src_addr: source address for the request frame
        :param timeout: seconds to wait for the response
        :returns: the first matching J1939_CAN response, or ``None``
        """
        from scapy.contrib.cansocket_native import NativeCANSocket

        # Encode PGN as 3-byte little-endian
        pgn_data = bytes([pgn & 0xFF, (pgn >> 8) & 0xFF, (pgn >> 16) & 0xFF])
        req_frame = J1939_CAN(
            priority=6, reserved=0, data_page=0,
            pdu_format=0xEA, pdu_specific=dst_addr, src=src_addr,
            data=pgn_data,
        )
        # Expected PF/PS for the response
        target_pf = (pgn >> 8) & 0xFF
        target_dp = (pgn >> 16) & 0x01

        sock = NativeCANSocket(self._channel, basecls=J1939_CAN,
                               receive_own_messages=False)
        sock.ins.settimeout(0.2)
        result = None  # type: Optional[J1939_CAN]
        try:
            sock.send(req_frame)
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    pkt = sock.recv()
                    if pkt is not None and isinstance(pkt, J1939_CAN):
                        if pkt.src == dst_addr and pkt.pdu_format == target_pf \
                                and pkt.data_page == target_dp:
                            result = pkt
                            break
                except Exception:
                    pass
        finally:
            sock.close()
        return result

    def find_proprietary(self, address, timeout=10.0, src_addr=0xF9):
        # type: (int, float, int) -> List[J1939_CAN]
        """Request all proprietary PGN ranges from an ECU and collect unique responses.

        Sends requests for PGN ranges 0xEF00 and 0xFF00 (PDU2 proprietary
        ranges) to the target address, then listens for replies.

        :param address: target ECU source address
        :param timeout: seconds to listen for responses after sending requests
        :param src_addr: source address for request frames
        :returns: list of unique proprietary J1939_CAN frames from the target
        """
        from scapy.contrib.cansocket_native import NativeCANSocket

        ecu = self._add_ecu(address)
        sock = NativeCANSocket(self._channel, basecls=J1939_CAN,
                               receive_own_messages=False)
        sock.ins.settimeout(0.1)

        collected = []  # type: List[J1939_CAN]
        done = threading.Event()

        def _recv_loop():
            while not done.is_set():
                try:
                    pkt = sock.recv()
                    if pkt is not None and isinstance(pkt, J1939_CAN):
                        if pkt.src == address:
                            collected.append(pkt)
                except Exception:
                    pass

        t = threading.Thread(target=_recv_loop, daemon=True)
        t.start()

        # Build request data for both proprietary PGN ranges
        prop_pgns = []
        for pf in [0xEF, 0xFF]:
            for ge in range(256):
                prop_pgns.append(bytes([ge, pf, 0x00]))  # LE-encoded PGN

        req_base = J1939_CAN(
            priority=6, reserved=0, data_page=0,
            pdu_format=0xEA, pdu_specific=address, src=src_addr,
        )
        for pgn_bytes in prop_pgns:
            frame = req_base.copy()
            frame.data = pgn_bytes
            try:
                sock.send(frame)
            except Exception:
                pass

        time.sleep(timeout)
        done.set()
        t.join(timeout=1.0)
        sock.close()

        for pkt in collected:
            if pkt.pdu_format in (0xEF, 0xFF):
                ecu.add_prop_message(pkt)

        return ecu.prop_messages


# ---------------------------------------------------------------------------
# J1939Fuzzer
# ---------------------------------------------------------------------------

class J1939Fuzzer:
    """Mutation- and generation-based fuzzer for J1939 CAN frames.

    Inspired by TruckDevil's J1939Fuzzer.  All frame manipulation is done at
    the :class:`~scapy.contrib.j1939.J1939_CAN` level so it does not require
    a kernel J1939 socket.

    Three generation modes are supported (``mode`` argument to
    :meth:`generate`):

    * ``0`` – **J1939-aware**: data is generated using SPN bit widths and
      ranges for the requested PGN from the SPN/PGN database.
    * ``1`` – **random, correct length**: data length is taken from the PGN
      database, but bytes are random.
    * ``2`` – **fully random**: random data length (0-8 bytes normal, 9-1785
      bytes for multi-packet, chosen with 10% probability) and random data.

    Example::

        >>> fuzzer = J1939Fuzzer()
        >>> baseline_frame = J1939_CAN(priority=6, pdu_format=0xFE,
        ...                            pdu_specific=0xCA, src=0x00,
        ...                            data=b'\\xff' * 8)
        >>> mutated = fuzzer.mutate(baseline_frame, mutate_data=True)
        >>> generated = fuzzer.generate(pdu_format=0xFE, pdu_specific=0xCA)
    """

    def __init__(self, seed=None):
        # type: (Optional[int]) -> None
        """
        :param seed: optional random seed for reproducibility
        """
        if seed is not None:
            random.seed(seed)

    # ------------------------------------------------------------------
    # mutate
    # ------------------------------------------------------------------

    def mutate(
            self,
            frame,
            mutate_priority=False,
            mutate_reserved=False,
            mutate_data_page=False,
            mutate_pdu_format=False,
            mutate_pdu_specific=False,
            mutate_src=False,
            mutate_data=False,
            mutate_data_length=False,
    ):
        # type: (...) -> J1939_CAN
        """Return a *copy* of *frame* with selected fields randomly mutated.

        :param frame: source :class:`~scapy.contrib.j1939.J1939_CAN` frame
        :param mutate_priority: randomise priority (0-7)
        :param mutate_reserved: randomise reserved bit (0 or 1)
        :param mutate_data_page: randomise data page bit (0 or 1)
        :param mutate_pdu_format: randomise pdu_format – 50 % chance PDU1
            (0-239), 50 % chance PDU2 (240-255)
        :param mutate_pdu_specific: randomise pdu_specific (0-255)
        :param mutate_src: randomise source address (0-255)
        :param mutate_data: flip a random number of random bytes in data
        :param mutate_data_length: randomly shorten or extend data
        :returns: mutated copy of *frame*
        """
        if not isinstance(frame, J1939_CAN):
            raise TypeError("expected J1939_CAN, got %s" % type(frame).__name__)

        result = J1939_CAN(bytes(frame))

        if mutate_priority:
            result.priority = random.randint(0, 7)
        if mutate_reserved:
            result.reserved = random.randint(0, 1)
        if mutate_data_page:
            result.data_page = random.randint(0, 1)
        if mutate_pdu_format:
            if random.randint(0, 1):
                result.pdu_format = random.randint(0, J1939_PDU1_MAX_PF)
            else:
                result.pdu_format = random.randint(J1939_PDU1_MAX_PF + 1, 255)
        if mutate_pdu_specific:
            result.pdu_specific = random.randint(0, 255)
        if mutate_src:
            result.src = random.randint(0, 255)

        data = bytearray(result.data)
        n = len(data)

        if mutate_data and n > 0:
            num_to_flip = random.randint(1, n)
            for _ in range(num_to_flip):
                idx = random.randint(0, n - 1)
                data[idx] = random.randint(0, 255)

        if mutate_data_length and n > 0:
            if random.randint(0, 1):
                # shorten
                new_len = random.randint(0, n - 1)
                data = data[:new_len]
            else:
                # extend (up to 1785 bytes for TP)
                extra = random.randint(1, min(1785 - n, 100))
                data.extend(random.randint(0, 255) for _ in range(extra))

        result.data = bytes(data)
        return result

    # ------------------------------------------------------------------
    # generate
    # ------------------------------------------------------------------

    def generate(
            self,
            mode=None,
            priority=None,
            reserved=None,
            data_page=None,
            pdu_format=None,
            pdu_specific=None,
            src=None,
            data=None,
    ):
        # type: (...) -> J1939_CAN
        """Generate a :class:`~scapy.contrib.j1939.J1939_CAN` frame.

        Any field that is not provided will be randomised.  When *mode* is
        ``0`` or ``1`` and a PGN database entry exists for the inferred PGN,
        the data length is taken from the database; otherwise mode falls back
        to ``2``.

        :param mode: 0 = J1939-aware, 1 = random correct-length, 2 = random
            (default: random choice 0-2)
        :param priority: CAN priority 0-7
        :param reserved: reserved bit 0-1
        :param data_page: data page bit 0-1
        :param pdu_format: PDU Format byte 0-255
        :param pdu_specific: PDU Specific byte 0-255
        :param src: source address 0-255
        :param data: hex string or bytes; if given, *mode* is ignored for data
        :returns: generated :class:`~scapy.contrib.j1939.J1939_CAN` frame
        """
        if mode is None or not (0 <= mode <= 2):
            mode = random.randint(0, 2)

        if priority is None:
            priority = random.randint(0, 7)
        if reserved is None:
            reserved = random.randint(0, 1)
        if data_page is None:
            data_page = random.randint(0, 1)
        if pdu_format is None:
            if random.randint(0, 1):
                pdu_format = random.randint(0, J1939_PDU1_MAX_PF)
            else:
                pdu_format = random.randint(J1939_PDU1_MAX_PF + 1, 255)
        if pdu_specific is None:
            pdu_specific = random.randint(0, 255)
        if src is None:
            src = random.randint(0, 255)

        # Infer PGN from pdu_format / pdu_specific / data_page
        if pdu_format <= J1939_PDU1_MAX_PF:
            pgn = (data_page << 16) | (pdu_format << 8)
        else:
            pgn = (data_page << 16) | (pdu_format << 8) | pdu_specific

        frame_data = b''  # type: bytes

        if data is not None:
            if isinstance(data, str):
                frame_data = bytes.fromhex(data)
            else:
                frame_data = bytes(data)
        else:
            frame_data = self._generate_data(mode, pgn)

        return J1939_CAN(
            priority=priority,
            reserved=reserved,
            data_page=data_page,
            pdu_format=pdu_format,
            pdu_specific=pdu_specific,
            src=src,
            data=frame_data,
        )

    def _generate_data(self, mode, pgn):
        # type: (int, int) -> bytes
        """Internal: generate data bytes for the given PGN and mode."""
        if mode == 0:
            try:
                return self._generate_spn_aware(pgn)
            except (KeyError, TypeError, ValueError):
                mode = 1

        if mode == 1:
            pgn_def = lookup_pgn(pgn)
            if pgn_def is not None and isinstance(pgn_def.data_length, int):
                data_len = pgn_def.data_length
                return bytes(random.randint(0, 255) for _ in range(data_len))
            mode = 2

        # mode == 2: fully random
        if random.randint(0, 9) == 9:
            data_len = random.randint(9, 1785)
        else:
            data_len = random.randint(0, 8)
        return bytes(random.randint(0, 255) for _ in range(data_len))

    def _generate_spn_aware(self, pgn):
        # type: (int) -> bytes
        """Generate data bytes by sampling random values within each SPN's
        bit range as defined in the SPN/PGN database.

        Raises :class:`KeyError` or :class:`ValueError` if the database entry
        is missing or has variable-length SPNs, so the caller can fall back
        to mode 1 or 2.
        """
        pgn_def = lookup_pgn(pgn)
        if pgn_def is None:
            raise KeyError("PGN %d not in database" % pgn)

        data_len = pgn_def.data_length
        if not isinstance(data_len, int):
            raise ValueError("variable-length PGN %d" % pgn)

        spn_list = pgn_def.spn_list
        bin_data = ""
        used_bits = 0

        for spn_num in spn_list:
            if not isinstance(spn_num, int):
                continue
            spn_def = lookup_spn(spn_num)
            if spn_def is None:
                continue
            spn_length = spn_def.spn_length
            if not isinstance(spn_length, int):
                raise ValueError("variable-length SPN %d" % spn_num)

            # Insert padding bits if there is a gap before this SPN starts
            bit_start = spn_def.bit_position_start
            if bit_start > used_bits:
                gap = bit_start - used_bits
                bin_data += "1" * gap
                used_bits += gap

            max_val = (1 << spn_length) - 1
            val = random.randint(0, max_val)
            bin_data += bin(val)[2:].zfill(spn_length)
            used_bits += spn_length

        # Pad remaining bits to full data_len bytes
        total_bits = data_len * 8
        if used_bits < total_bits:
            bin_data += "1" * (total_bits - used_bits)
        elif used_bits > total_bits:
            bin_data = bin_data[:total_bits]

        if not bin_data:
            return bytes(data_len)

        # Convert bit string to bytes
        byte_val = int(bin_data, 2)
        return byte_val.to_bytes(data_len, byteorder='big')

    # ------------------------------------------------------------------
    # fuzz (send a list of frames)
    # ------------------------------------------------------------------

    def fuzz(self, channel, frames, frequency=0.5):
        # type: (str, List[J1939_CAN], float) -> int
        """Send a list of J1939_CAN frames over the given CAN interface.

        :param channel: CAN interface name (e.g. ``"vcan0"``)
        :param frames: list of :class:`~scapy.contrib.j1939.J1939_CAN` frames
        :param frequency: inter-frame delay in seconds (default 0.5)
        :returns: number of frames sent successfully
        """
        from scapy.contrib.cansocket_native import NativeCANSocket

        sock = NativeCANSocket(channel)
        sent = 0
        try:
            for frame in frames:
                try:
                    sock.send(frame)
                    sent += 1
                    if frequency > 0:
                        time.sleep(frequency)
                except Exception:
                    pass
        finally:
            sock.close()
        return sent

    def create_fuzz_list(self, n, baseline_frames=None, mode=None, **fixed_fields):
        # type: (int, Optional[List[J1939_CAN]], Optional[int], ...) -> List[J1939_CAN]
        """Generate a list of *n* fuzz test-case frames.

        If *baseline_frames* is provided, half the test cases (for mode 0 or
        random mode) are generated by mutating a randomly-chosen baseline
        frame; the rest are generated from scratch using :meth:`generate`.

        :param n: number of test cases to generate
        :param baseline_frames: optional list of observed baseline frames to
            mutate from
        :param mode: see :meth:`generate` (``None`` for random per frame)
        :param fixed_fields: any keyword arguments accepted by :meth:`generate`
            that should be kept constant across all test cases
        :returns: list of :class:`~scapy.contrib.j1939.J1939_CAN` frames
        """
        result = []
        for _ in range(n):
            use_mutate = (
                baseline_frames
                and len(baseline_frames) > 0
                and random.randint(0, 1) == 0
            )
            if use_mutate:
                src_frame = baseline_frames[random.randint(0, len(baseline_frames) - 1)]
                tc = self.mutate(
                    src_frame,
                    mutate_data=True,
                    mutate_pdu_specific=True,
                )
            else:
                tc = self.generate(mode=mode, **fixed_fields)
            result.append(tc)
        return result
