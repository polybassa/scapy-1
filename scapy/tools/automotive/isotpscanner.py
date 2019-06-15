#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# Copyright (C) Alexander Schroeder <alexander1.schroeder@st.othr.de>
# This program is published under a GPLv2 license

import argparse
from argparse import RawTextHelpFormatter

import scapy.modules.six as six
from scapy.config import conf
from scapy.consts import LINUX


if six.PY2 or not LINUX:
    conf.contribs['CANSocket'] = {'use-python-can': True}

from scapy.contrib.cansocket import CANSocket, PYTHON_CAN  # noqa: E402
from scapy.contrib.isotp import ISOTPScan  # noqa: E402


def main():
    extended = False
    extended_only = False
    piso = False
    parser = argparse.ArgumentParser(
        description="Scan for open ISOTP-Sockets.",
        formatter_class=RawTextHelpFormatter,
        prog="ISOTPScanner",
        usage="\tISOTPScanner.py interface startID endID [-flags] \n"
              "\tpython -m scapy.tools.automotive.isotpscanner interface "
              "startID endID [-flags]",
        epilog="Example of use:\n\n"
               "Python2 or Windows:\n"
               "python2 -m scapy.tools.automotive.isotpscanner "
               "\"can.interface.Bus(bustype='pcan', channel='PCAN_USBBUS1', "
               "bitrate=250000)\" 0 100 \n"
               "python2 -m scapy.tools.automotive.isotpscanner "
               "\"can.interface.Bus(bustype='socketcan', channel='can0', "
               "bitrate=250000)\" 0 100 \n\n"
               "Python3 on Linux:\n"
               "python3 -m scapy.tools.automotive.isotpscanner can0 0 100")
    parser.add_argument("interface", type=str,
                        help="CAN interface for the scan.\n"
                             "Depends on used interpreter and system,\n"
                             "see examples below. Any python-can interface can"
                             "be provided. Please see: "
                             "https://python-can.readthedocs.io for further "
                             "interface examples.")
    parser.add_argument("startID", type=lambda x: int(x, 16),
                        help="Start scan at this ID (hex)"),
    parser.add_argument("endID", type=lambda x: int(x, 16),
                        help="End scan at this ID (hex)")
    parser.add_argument("-n", "--noise_listen_time", type=int, default=10,
                        help="Set seconds listening for noise before scan.")
    parser.add_argument("-e", "--extended", action="store_true",
                        help="Include extended IDs to scan.")
    parser.add_argument("-eo", "--extended_only", action="store_true",
                        help="Scan only with extended IDs.")
    parser.add_argument("-p", "--piso", action="store_true",
                        help="Print 'Copy&Paste'-ready ISOTPSockets.")

    args = parser.parse_args()

    scan_interface = args.interface
    if "can.interface.Bus" in scan_interface:
        if PYTHON_CAN:
            import can  # noqa: 401
            scan_interface = eval(scan_interface)
        else:
            print("Wrong interface type.")
            exit(-1)
    else:
        if PYTHON_CAN:
            print("Wrong interface type.")
            exit(-1)

    if args.extended:
        extended = True
    if args.extended_only:
        extended_only = True
    if args.piso:
        piso = True

    # Interface for communication
    cansocket_communication = CANSocket(iface=scan_interface)

    # scan normal IDs
    if not extended_only:
        print("Start scan (" + hex(args.startID) + " - " +
              hex(args.endID) + ")")
        result = ISOTPScan(cansocket_communication,
                           range(args.startID, args.endID + 1),
                           extended_addressing=False,
                           noise_listen_time=args.noise_listen_time,
                           output_format="code" if piso else "text")
        print("Scan: " + str(result))

    # scan extended IDs
    if extended or extended_only:
        print("Start scan with extended IDs (" + hex(args.startID) +
              " - " + hex(args.endID) + ")")
        result_extended = ISOTPScan(cansocket_communication,
                                    range(args.startID, args.endID + 1),
                                    extended_addressing=True,
                                    noise_listen_time=args.noise_listen_time,
                                    output_format="code" if piso else "text")
        print("Extended scan: " + str(result_extended))


if __name__ == '__main__':
    main()
