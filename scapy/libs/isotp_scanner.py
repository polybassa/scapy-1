# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Alexander Schroeder <alexander1.schroeder@st.othr.de>

"""ISO-TP Scanner Utility Library

This module provides utilities for scanning CAN buses to detect ISO-TP
(ISO 15765-2) communication endpoints. ISO-TP is a transport protocol that
allows sending messages larger than 8 bytes over CAN by fragmenting them
across multiple CAN frames.

The scanner works by:
1. Sending ISO-TP First Frame (FF) packets to potential endpoints
2. Listening for Flow Control (FC) responses that indicate an ISO-TP endpoint
3. Filtering out background noise and periodic packets
4. Optionally verifying results to reduce false positives

The module supports both standard and extended ISO-TP addressing modes.

Example usage:
    >>> from scapy.contrib.cansocket import CANSocket
    >>> from scapy.libs.isotp_scanner import isotp_scan
    >>> sock = CANSocket("can0")
    >>> results = isotp_scan(sock, output_format="text")
    >>> print(results)

Key functions:
    - isotp_scan: Main entry point for scanning
    - scan: Standard addressing scan
    - scan_extended: Extended addressing scan
    - filter_periodic_packets: Remove periodic background traffic
"""

import itertools
import json
import logging
import time

from threading import Event

from scapy.packet import Packet
from scapy.compat import orb
from scapy.layers.can import CAN
from scapy.supersocket import SuperSocket
from scapy.contrib.cansocket import PYTHON_CAN
from scapy.contrib.isotp.isotp_packet import ISOTPHeader, ISOTPHeaderEA, \
    ISOTP_FF, ISOTP

# Typing imports
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
)

log_isotp = logging.getLogger("scapy.contrib.isotp")


def send_multiple_ext(sock, ext_id, packet, number_of_packets):
    # type: (SuperSocket, int, Packet, int) -> None
    """Send multiple packets with extended ISO-TP addresses at once.

    This function is used for scanning with extended addressing mode.
    It sends multiple packets in a batch by iterating the extended ISO-TP
    address field, while keeping the CAN identifier constant. This is more
    efficient than sending packets one-by-one during extended address scanning.

    :param sock: CAN socket interface to send packets through
    :param ext_id: Starting extended ISO-TP address (0-255)
    :param packet: Template packet to use; its extended_address field will be
                   modified for each transmission
    :param number_of_packets: Maximum number of packets to send in one batch
    """
    end_id = min(ext_id + number_of_packets, 255)
    for i in range(ext_id, end_id + 1):
        packet.extended_address = i
        sock.send(packet)


def get_isotp_packet(identifier=0x0, extended=False, extended_can_id=False):
    # type: (int, bool, bool) -> Packet
    """Craft an ISO-TP First Frame packet for scanning purposes.

    Creates a properly formatted ISO-TP First Frame (FF) packet that can be
    used to probe potential ISO-TP endpoints. The packet will trigger a Flow
    Control response if an ISO-TP endpoint is listening on the given identifier.

    :param identifier: CAN identifier (11-bit standard or 29-bit extended)
    :param extended: If True, use ISO-TP extended addressing (EA) mode with
                     extended_address field set to 0
    :param extended_can_id: If True, set CAN frame to use 29-bit extended
                            identifier format
    :return: Crafted ISO-TP First Frame packet ready for transmission
    """
    if extended:
        pkt = ISOTPHeaderEA() / ISOTP_FF()  # type: Packet
        pkt.extended_address = 0
        pkt.data = b'\x00\x00\x00\x00\x00'
    else:
        pkt = ISOTPHeader() / ISOTP_FF()
        pkt.data = b'\x00\x00\x00\x00\x00\x00'
    if extended_can_id:
        pkt.flags = "extended"

    pkt.identifier = identifier
    pkt.message_size = 100
    return pkt


def filter_periodic_packets(packet_dict):
    # type: (Dict[int, Tuple[Packet, int]]) -> None
    """Filter and remove periodic packets from scan results in-place.

    ISO-TP Flow Control responses should be event-driven (triggered by our
    scan packets), not periodic. This filter detects and removes periodic
    background traffic that might cause false positives in scan results.

    A packet stream is considered periodic if:
    - At least 3 packets with the same CAN identifier are received
    - Time gaps between consecutive packets are consistent (within 1ms tolerance)

    The function modifies packet_dict in-place, removing all keys associated
    with periodic packet streams.

    :param packet_dict: Dictionary mapping keys to (packet, identifier) tuples.
                        Keys are typically send-to identifiers or composite keys.
                        Modified in-place to remove periodic packets.
    """
    filter_dict = {}  # type: Dict[int, Tuple[List[int], List[Packet]]]

    # Group packets by identifier
    for key, value in packet_dict.items():
        pkt = value[0]
        idn = value[1]
        if idn not in filter_dict:
            filter_dict[idn] = ([key], [pkt])
        else:
            key_lst, pkt_lst = filter_dict[idn]
            filter_dict[idn] = (key_lst + [key], pkt_lst + [pkt])

    # Check each identifier's packets for periodicity
    for idn in filter_dict:
        key_lst = filter_dict[idn][0]
        pkt_lst = filter_dict[idn][1]
        if len(pkt_lst) < 3:
            # Need at least 3 packets to detect periodicity
            continue

        # Calculate time gaps between consecutive packets
        tg = [float(p1.time) - float(p2.time)
              for p1, p2 in zip(pkt_lst[1:], pkt_lst[:-1])]
        
        # Check if all time gaps are consistent (within 1ms tolerance)
        if all(abs(t1 - t2) < 0.001 for t1, t2 in zip(tg[1:], tg[:-1])):
            log_isotp.info(
                "[i] Identifier 0x%03x seems to be periodic. Filtered.")
            # Remove all packets with this identifier from results
            for k in key_lst:
                del packet_dict[k]


def get_isotp_fc(
        id_value,  # type: int
        id_list,  # type: Union[List[int], Dict[int, Tuple[Packet, int]]]
        noise_ids,  # type: Optional[List[int]]
        extended,  # type: bool
        packet,  # type: Packet
):
    # type: (...) -> None
    """Callback function for sniff() to detect ISO-TP Flow Control frames.

    This callback is invoked for each received CAN frame during scanning.
    It checks if the frame contains an ISO-TP Flow Control (FC) frame, which
    indicates an active ISO-TP endpoint responding to our First Frame probe.

    ISO-TP Flow Control frames have:
    - PCI type = 3 (upper 4 bits of first data byte)
    - Flow Status = 0-2 (lower 4 bits): 0=ContinueToSend, 1=Wait, 2=Overflow

    The function maintains state in two collections:
    - id_list: Accumulates successfully detected ISO-TP endpoints
    - noise_ids: Tracks non-FC frames to filter out in subsequent packets

    :param id_value: The CAN identifier we sent the probe to (for tracking)
    :param id_list: Collection to store detected endpoints. Can be:
                    - List[int]: Appends id_value when FC is detected
                    - Dict: Stores id_value -> (packet, rx_identifier) mapping
    :param noise_ids: Optional list to accumulate identifiers of non-FC frames
                      (background noise) for filtering
    :param extended: True if scanning with extended addressing (affects data
                     byte offset: byte 1 for extended, byte 0 for standard)
    :param packet: Received CAN frame to analyze for ISO-TP FC detection
    """
    # Skip if packet has unexpected flags
    if packet.flags and packet.flags != "extended":
        return

    # Skip if packet identifier is known noise
    if noise_ids is not None and packet.identifier in noise_ids:
        return

    try:
        # Determine data offset based on addressing mode
        # Extended addressing uses byte 0 for address, so PCI is at byte 1
        index = 1 if extended else 0
        
        # Extract ISO-TP Protocol Control Information (PCI) fields
        isotp_pci = orb(packet.data[index]) >> 4  # Upper 4 bits: frame type
        isotp_fc = orb(packet.data[index]) & 0x0f  # Lower 4 bits: flow status
        
        # Check if this is a valid Flow Control frame
        # PCI type 3 = Flow Control, Flow Status 0-2 = valid states
        if isotp_pci == 3 and 0 <= isotp_fc <= 2:
            log_isotp.info("Found flow-control frame from identifier "
                           "0x%03x when testing identifier 0x%03x",
                           packet.identifier, id_value)
            
            # Store result in appropriate format
            if isinstance(id_list, dict):
                id_list[id_value] = (packet, packet.identifier)
            elif isinstance(id_list, list):
                id_list.append(id_value)
            else:
                raise TypeError("Unknown type of id_list")
        else:
            # Not a Flow Control frame - add to noise list
            if noise_ids is not None:
                noise_ids.append(packet.identifier)
    except Exception as e:
        log_isotp.exception(
            "Unknown message Exception: %s on packet: %s",
            e, repr(packet))


def scan(sock,  # type: SuperSocket
         scan_range=range(0x800),  # type: Iterable[int]
         noise_ids=None,  # type: Optional[List[int]]
         sniff_time=0.1,  # type: float
         extended_can_id=False,  # type: bool
         verify_results=True,  # type: bool
         stop_event=None  # type: Optional[Event]
         ):  # type: (...) -> Dict[int, Tuple[Packet, int]]
    """Scan for ISO-TP endpoints using standard addressing mode.

    Performs a systematic scan of CAN identifiers to detect ISO-TP endpoints
    by sending First Frame packets and listening for Flow Control responses.
    This function uses standard ISO-TP addressing (no extended address field).

    The scan process:
    1. For each identifier in scan_range, send an ISO-TP First Frame
    2. Listen for Flow Control responses during sniff_time
    3. Record identifiers that respond with valid Flow Control frames
    4. Optionally verify results by re-scanning detected endpoints with
       longer timeout and testing nearby identifiers (±2) to reduce false
       positives

    :param sock: CAN socket interface for sending/receiving
    :param scan_range: Range of CAN identifiers to scan. Default is 0x0-0x7ff
                       (all standard 11-bit CAN IDs)
    :param noise_ids: Optional list of identifiers to skip during scan
                      (known background traffic)
    :param sniff_time: Duration in seconds to wait for Flow Control responses
                       after sending each First Frame. Default 0.1s
    :param extended_can_id: If True, use 29-bit extended CAN identifiers
    :param verify_results: If True (default), perform verification pass on
                           detected endpoints by rescanning them and nearby
                           IDs (±2) with 10x longer timeout to reduce false
                           positives
    :param stop_event: Optional threading.Event to stop scan asynchronously
    :return: Dictionary mapping send-to identifier -> (response_packet,
             response_identifier) for all detected ISO-TP endpoints
    """
    return_values = dict()  # type: Dict[int, Tuple[Packet, int]]
    
    # Initial scan pass
    for value in scan_range:
        if stop_event is not None and stop_event.is_set():
            break
        if noise_ids and value in noise_ids:
            continue
        sock.send(get_isotp_packet(value, False, extended_can_id))
        sock.sniff(prn=lambda pkt: get_isotp_fc(value, return_values,
                                                noise_ids, False, pkt),
                   timeout=sniff_time, store=False)

    if not verify_results:
        return return_values

    # Verification pass: retest detected endpoints and nearby IDs
    cleaned_ret_val = dict()  # type: Dict[int, Tuple[Packet, int]]
    
    # Generate list of IDs to retest: each detected ID ± 2 positions
    retest_ids = list(set(
        itertools.chain.from_iterable(
            range(max(0, i - 2), i + 2) for i in return_values.keys())))
    
    for value in retest_ids:
        if stop_event is not None and stop_event.is_set():
            break
        sock.send(get_isotp_packet(value, False, extended_can_id))
        sock.sniff(prn=lambda pkt: get_isotp_fc(value, cleaned_ret_val,
                                                noise_ids, False, pkt),
                   timeout=sniff_time * 10, store=False)

    return cleaned_ret_val


def scan_extended(sock,  # type: SuperSocket
                  scan_range=range(0x800),  # type: Iterable[int]
                  scan_block_size=32,  # type: int
                  extended_scan_range=range(0x100),  # type: Iterable[int]
                  noise_ids=None,  # type: Optional[List[int]]
                  sniff_time=0.1,  # type: float
                  extended_can_id=False,  # type: bool
                  stop_event=None  # type: Optional[Event]
                  ):  # type: (...) -> Dict[int, Tuple[Packet, int]]
    """Scan for ISO-TP endpoints using extended addressing mode.

    Similar to scan() but uses ISO-TP extended addressing, where an additional
    address byte precedes the ISO-TP protocol data. This allows multiple
    ISO-TP endpoints to share the same CAN identifier by using different
    extended addresses (0x00-0xFF).

    The scan is performed in two phases:
    1. Fast batch scan: Send blocks of packets with different extended
       addresses for each CAN ID, listening for any responses
    2. Detailed scan: For CAN IDs that responded, carefully scan each
       extended address individually (including ±2 addresses) to pinpoint
       exact endpoints

    :param sock: CAN socket interface for sending/receiving
    :param scan_range: Range of CAN identifiers to scan. Default 0x0-0x7ff
    :param scan_block_size: Number of extended addresses to test in one batch
                            during phase 1. Default 32. Higher values scan
                            faster but may miss responses on busy networks
    :param extended_scan_range: Range of extended addresses to scan for each
                                CAN ID. Default 0x00-0xFF (all values)
    :param noise_ids: Optional list of CAN identifiers to skip (known noise)
    :param sniff_time: Base duration in seconds to wait for responses.
                       Phase 1 uses 3x this value, phase 2 uses 2x
    :param extended_can_id: If True, use 29-bit extended CAN identifiers
    :param stop_event: Optional threading.Event to stop scan asynchronously
    :return: Dictionary mapping composite key (can_id << 8 | ext_addr) ->
             (response_packet, response_identifier) for all detected endpoints
    """
    return_values = dict()  # type: Dict[int, Tuple[Packet, int]]
    scan_block_size = scan_block_size or 1
    r = list(extended_scan_range)

    for value in scan_range:
        if noise_ids and value in noise_ids:
            continue

        pkt = get_isotp_packet(
            value, extended=True, extended_can_id=extended_can_id)
        id_list = []  # type: List[int]
        
        # Phase 1: Fast batch scan of extended addresses
        for ext_isotp_id in range(r[0], r[-1], scan_block_size):
            if stop_event is not None and stop_event.is_set():
                break
            send_multiple_ext(sock, ext_isotp_id, pkt, scan_block_size)
            sock.sniff(prn=lambda p: get_isotp_fc(ext_isotp_id, id_list,
                                                  noise_ids, True, p),
                       timeout=sniff_time * 3, store=False)
            # Sleep to prevent bus flooding
            time.sleep(sniff_time)

        # Phase 2: Detailed scan of responding extended address ranges
        id_list = list(set(id_list))  # Remove duplicates
        for ext_isotp_id in id_list:
            if stop_event is not None and stop_event.is_set():
                break
            # Scan this extended address ±2 positions for precision
            for ext_id in range(max(ext_isotp_id - 2, 0),
                                min(ext_isotp_id + scan_block_size + 2, 256)):
                if stop_event is not None and stop_event.is_set():
                    break
                pkt.extended_address = ext_id
                # Create composite key: CAN ID in upper bits, ext addr in lower
                full_id = (value << 8) + ext_id
                sock.send(pkt)
                sock.sniff(prn=lambda pkt: get_isotp_fc(full_id,
                                                        return_values,
                                                        noise_ids, True,
                                                        pkt),
                           timeout=sniff_time * 2, store=False)

    return return_values


def isotp_scan(sock,  # type: SuperSocket
               scan_range=range(0x7ff + 1),  # type: Iterable[int]
               extended_addressing=False,  # type: bool
               extended_scan_range=range(0x100),  # type: Iterable[int]
               noise_listen_time=2,  # type: int
               sniff_time=0.1,  # type: float
               output_format=None,  # type: Optional[str]
               can_interface=None,  # type: Optional[str]
               extended_can_id=False,  # type: bool
               verify_results=True,  # type: bool
               verbose=False,  # type: bool
               stop_event=None  # type: Optional[Event]
               ):
    # type: (...) -> Union[str, List[SuperSocket]]
    """Scan for ISO-TP endpoints on a CAN bus and return formatted results.

    This is the main entry point for ISO-TP scanning. It orchestrates the
    complete scanning process including noise filtering, endpoint detection,
    periodic packet filtering, and result formatting.

    The scan process:
    1. Listen to background traffic to identify noise (periodic packets)
    2. Scan for ISO-TP endpoints using standard or extended addressing
    3. Filter out periodic responses (false positives)
    4. Format results according to output_format parameter

    :param sock: CANSocket object for communicating with the CAN bus
    :param scan_range: Range of CAN identifiers to scan. Default 0x0-0x7ff
    :param extended_addressing: If True, scan with ISO-TP extended addressing
                                mode (tests extended address 0x00-0xFF for
                                each CAN ID)
    :param extended_scan_range: Range of extended addresses to scan when
                                extended_addressing is True. Default 0x00-0xFF
    :param noise_listen_time: Duration in seconds to listen for background
                              traffic before scanning. Detected traffic is
                              used to identify noise. Default 2 seconds
    :param sniff_time: Duration in seconds to wait for Flow Control responses
                       after sending each probe. Default 0.1s
    :param output_format: Format for results. Options:
                          - "text": Human-readable text description
                          - "code": Python code to create ISOTPSocket objects
                          - "json": JSON array of socket configurations
                          - None (default): Returns list of ISOTPSocket objects
    :param can_interface: CAN interface name (e.g. "can0") used in generated
                          code/json output. If None, uses the provided sock
    :param extended_can_id: If True, use 29-bit extended CAN identifiers
    :param verify_results: If True (default), perform verification pass to
                           reduce false positives. Only applies to standard
                           addressing mode (extended mode always verifies)
    :param verbose: If True, enable debug-level logging during scan
    :param stop_event: Optional threading.Event to stop scan asynchronously
    :return: Scan results in requested format:
             - str: For "text", "code", or "json" output_format
             - List[SuperSocket]: List of ISOTPSocket objects when
               output_format is None
    """
    if verbose:
        log_isotp.setLevel(logging.DEBUG)

    log_isotp.info("Filtering background noise...")

    # Send dummy packet to trigger bus activity for noise detection
    dummy_pkt = CAN(identifier=0x123,
                    data=b'\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb')

    background_pkts = sock.sniff(
        timeout=noise_listen_time,
        started_callback=lambda: sock.send(dummy_pkt))

    noise_ids = list(set(pkt.identifier for pkt in background_pkts))

    # Perform scan with appropriate addressing mode
    if extended_addressing:
        found_packets = scan_extended(sock, scan_range,
                                      extended_scan_range=extended_scan_range,
                                      noise_ids=noise_ids,
                                      sniff_time=sniff_time,
                                      extended_can_id=extended_can_id,
                                      stop_event=stop_event)
    else:
        found_packets = scan(sock, scan_range,
                             noise_ids=noise_ids,
                             sniff_time=sniff_time,
                             extended_can_id=extended_can_id,
                             verify_results=verify_results,
                             stop_event=stop_event)

    filter_periodic_packets(found_packets)

    # Format results according to output_format parameter
    if output_format == "text":
        return generate_text_output(found_packets, extended_addressing)

    if output_format == "code":
        return generate_code_output(found_packets, can_interface,
                                    extended_addressing)

    if output_format == "json":
        return generate_json_output(found_packets, can_interface,
                                    extended_addressing)

    return generate_isotp_list(found_packets, can_interface or sock,
                               extended_addressing)


def generate_text_output(found_packets, extended_addressing=False):
    # type: (Dict[int, Tuple[Packet, int]], bool) -> str
    """Generate a human readable output from the result of the `scan` or the
    `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param extended_addressing: print results from a scan with
                                ISOTP extended addressing
    :return: human readable scan results
    """
    if not found_packets:
        return "No packets found."

    text = "\nFound %s ISOTP-FlowControl Packet(s):" % len(found_packets)
    for pack in found_packets:
        if extended_addressing:
            send_id = pack // 256
            send_ext = pack - (send_id * 256)
            ext_id = hex(orb(found_packets[pack][0].data[0]))
            text += "\nSend to ID:             %s" \
                    "\nSend to extended ID:    %s" \
                    "\nReceived ID:            %s" \
                    "\nReceived extended ID:   %s" \
                    "\nMessage:                %s" % \
                    (hex(send_id), hex(send_ext),
                     hex(found_packets[pack][0].identifier), ext_id,
                     repr(found_packets[pack][0]))
        else:
            text += "\nSend to ID:             %s" \
                    "\nReceived ID:            %s" \
                    "\nMessage:                %s" % \
                    (hex(pack),
                     hex(found_packets[pack][0].identifier),
                     repr(found_packets[pack][0]))

        padding = found_packets[pack][0].length == 8
        if padding:
            text += "\nPadding enabled"
        else:
            text += "\nNo Padding"

        text += "\n"
    return text


def generate_code_output(found_packets, can_interface="iface",
                         extended_addressing=False):
    # type: (Dict[int, Tuple[Packet, int]], Optional[str], bool) -> str
    """Generate a copy&past-able output from the result of the `scan` or
    the `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param can_interface: description string for a CAN interface to be
                          used for the creation of the output.
    :param extended_addressing: print results from a scan with ISOTP
                                extended addressing
    :return: Python-code as string to generate all found sockets
    """
    result = ""
    if not found_packets:
        return result

    header = "\n\nimport can\n" \
             "conf.contribs['CANSocket'] = {'use-python-can': %s}\n" \
             "load_contrib('cansocket')\n" \
             "load_contrib('isotp')\n\n" % PYTHON_CAN

    for pack in found_packets:
        if extended_addressing:
            send_id = pack // 256
            send_ext = pack - (send_id * 256)
            ext_id = orb(found_packets[pack][0].data[0])
            result += "ISOTPSocket(%s, tx_id=0x%x, rx_id=0x%x, padding=%s, " \
                      "ext_address=0x%x, rx_ext_address=0x%x, " \
                      "basecls=ISOTP)\n" % \
                      (can_interface, send_id,
                       int(found_packets[pack][0].identifier),
                       found_packets[pack][0].length == 8,
                       send_ext,
                       ext_id)

        else:
            result += "ISOTPSocket(%s, tx_id=0x%x, rx_id=0x%x, padding=%s, " \
                      "basecls=ISOTP)\n" % \
                      (can_interface, pack,
                       int(found_packets[pack][0].identifier),
                       found_packets[pack][0].length == 8)
    return header + result


def generate_json_output(found_packets,  # type: Dict[int, Tuple[Packet, int]]
                         can_interface="iface",  # type: Optional[str]
                         extended_addressing=False  # type: bool
                         ):
    # type: (...) -> str
    """Generate a list of ISOTPSocket objects from the result of the `scan` or
    the `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param can_interface: description string for a CAN interface to be
                          used for the creation of the output.
    :param extended_addressing: print results from a scan with ISOTP
                                extended addressing
    :return: A list of all found ISOTPSockets
    """
    socket_list = []  # type: List[Dict[str, Any]]
    for pack in found_packets:
        pkt = found_packets[pack][0]

        dest_id = pkt.identifier
        pad = True if pkt.length == 8 else False

        if extended_addressing:
            source_id = pack >> 8
            source_ext = int(pack - (source_id * 256))
            dest_ext = orb(pkt.data[0])
            socket_list.append({"iface": can_interface,
                                "tx_id": source_id,
                                "ext_address": source_ext,
                                "rx_id": dest_id,
                                "rx_ext_address": dest_ext,
                                "padding": pad,
                                "basecls": ISOTP.__name__})
        else:
            source_id = pack
            socket_list.append({"iface": can_interface,
                                "tx_id": source_id,
                                "rx_id": dest_id,
                                "padding": pad,
                                "basecls": ISOTP.__name__})
    return json.dumps(socket_list)


def generate_isotp_list(found_packets,  # type: Dict[int, Tuple[Packet, int]]
                        can_interface,  # type: Union[SuperSocket, str]
                        extended_addressing=False  # type: bool
                        ):
    # type: (...) -> List[SuperSocket]
    """Generate a list of ISOTPSocket objects from the result of the `scan` or
    the `scan_extended` function.

    :param found_packets: result of the `scan` or `scan_extended` function
    :param can_interface: description string for a CAN interface to be
                          used for the creation of the output.
    :param extended_addressing: print results from a scan with ISOTP
                                extended addressing
    :return: A list of all found ISOTPSockets
    """
    from scapy.contrib.isotp import ISOTPSocket

    socket_list = []  # type: List[SuperSocket]
    for pack in found_packets:
        pkt = found_packets[pack][0]

        dest_id = pkt.identifier
        pad = True if pkt.length == 8 else False

        if extended_addressing:
            source_id = pack >> 8
            source_ext = int(pack - (source_id * 256))
            dest_ext = orb(pkt.data[0])
            socket_list.append(ISOTPSocket(can_interface, tx_id=source_id,
                                           ext_address=source_ext,
                                           rx_id=dest_id,
                                           rx_ext_address=dest_ext,
                                           padding=pad,
                                           basecls=ISOTP))
        else:
            source_id = pack
            socket_list.append(ISOTPSocket(can_interface, tx_id=source_id,
                                           rx_id=dest_id, padding=pad,
                                           basecls=ISOTP))
    return socket_list
