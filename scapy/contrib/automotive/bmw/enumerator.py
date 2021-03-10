# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = BMW specific enumerators
# scapy.contrib.status = loads


from scapy.packet import Packet
from scapy.compat import Any, Iterable, Tuple
from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.scanner.test_case import _AutomotiveTestCaseScanResult
from scapy.contrib.automotive.uds import UDS
from scapy.contrib.automotive.bmw.definitions import DEV_JOB
from scapy.contrib.automotive.uds_scan import UDS_Enumerator


class BMW_DevJobEnumerator(UDS_Enumerator):
    _description = "Available DevelopmentJobs by Identifier " \
                   "and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (UDS() / DEV_JOB(identifier=x) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res)
        return (state,
                "0x%04x: %s" % (req.identifier,
                                req.sprintf("%DEV_JOB.identifier%")),
                label)
