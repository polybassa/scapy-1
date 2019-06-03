#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Alexander Schroeder <alexander1.schroeder@st.othr.de>
# This program is published under a GPLv2 license

import argparse

import scapy.modules.six as six
from scapy.config import conf
from scapy.layers.can import CAN

if six.PY2:
    conf.contribs['CANSocket'] = {'use-python-can': True}

from scapy.contrib.cansocket import CANSocket
from scapy.contrib.isotp import ISOTPScan, KeepAwakeThread

if "python_can" in CANSocket.__module__:
    #todo use argparse parameter for iface and add example (socketcan, vector, ...) to help
    import can as python_can
    new_can_socket = lambda iface: \
        CANSocket(iface=python_can.interface.Bus(bustype='socketcan',
                                                 channel=iface))
else:
    new_can_socket = lambda iface: CANSocket(iface)


def main():
    extended = False
    keep_awake = False
    extended_only = False
    piso = False
    awake_interface = ""

#Todo: rename Scan for ISOTP-Sockets
    parser = argparse.ArgumentParser(description="Scan for active "
                                                 "ISOTP-Addresses.",
                                     prog="ISOTP Scanner",
                                     usage="ISOTPScanner.py startID endID "
                                           "interface [-flags]")
    parser.add_argument("startID", type=lambda x: int(x, 16),
                        help="Start scan at this ID (hex)"),
    parser.add_argument("endID", type=lambda x: int(x, 16),
                        help="End scan at this ID (hex)")
    #Todo: interfacestring has to include python_can strings
    #Todo: We need tests for that.
    parser.add_argument("interface", type=str,
                        help="CAN interface for the scan")
    #Todo: Add an optional string parameter for the keep alive interface
    #Todo: If nothing specified, we use the same interface for keepAlive and scan
    parser.add_argument("-e", "--extended", action="store_true",
                        help="Include extended IDs to scan.")
    parser.add_argument("-k", "--keep_alive", type=str,
                        help="'Keep alive' - \
                            Send a periodic dummy-packet to the "
                             "specified interface.")
    parser.add_argument("-eo", "--extended_only", action="store_true",
                        help="Scan only with \
                            extended IDs.")
    parser.add_argument("-p", "--piso", action="store_true",
                        help="Print 'Copy&Paste'-ready ISOTPSockets.")

    args = parser.parse_args()

    scan_interface = args.interface
    if args.extended:
        extended = True
    if args.extended_only:
        extended_only = True
    if args.keep_alive:
        keep_awake = True
        awake_interface = args.keep_alive
    if args.piso:
        piso = True

    # Seconds to listen to noise
    noise_listen_time = 10

    # Interface for communication
    cansocket_communication = new_can_socket(scan_interface)

    # Keep ECU awake
    awake_thread = None
    if keep_awake:
        dummy_pkt = CAN(identifier=0x123,
                        data=b'\xaa\xbb\xcc\xdd\xee\xff\xaa\xbb')
        cansocket_keep_awake = new_can_socket(awake_interface)
        awake_thread = KeepAwakeThread(cansocket_keep_awake,
                                       dummy_pkt)
        awake_thread.start()

    # scan normal IDs
    if not extended_only:
        print("Start scan (" + hex(args.startID) + " - " +
              hex(args.endID) + ")")
        result = ISOTPScan(cansocket_communication,
                           range(args.startID, args.endID + 1),
                           extended_addressing=False,
                           noise_listen_time=noise_listen_time,
                           output_format="code" if piso else "text")
        print("Scan: " + result)

    # scan extended IDs
    if extended or extended_only:
        print("Start scan with extended IDs (" + hex(args.startID) +
              " - " + hex(args.endID) + ")")
        result_extended = ISOTPScan(cansocket_communication,
                                    range(args.startID, args.endID + 1),
                                    extended_addressing=True,
                                    noise_listen_time=noise_listen_time,
                                    output_format="code" if piso else "text")
        print("Extended scan: " + result_extended)

    # Stop "stay awake"-traffic
    if keep_awake:
        awake_thread.stop()


if __name__ == '__main__':
    main()
