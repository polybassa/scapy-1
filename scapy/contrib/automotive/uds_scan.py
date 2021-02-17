# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = UDS AutomotiveTestCaseExecutor
# scapy.contrib.status = loads

import struct
import random
import time
import itertools
import copy

from collections import defaultdict
from typing import Sequence

from scapy.compat import Dict, Optional, List, Type, Any, Iterable, Tuple, \
    cast, Union, NamedTuple
from scapy.packet import Packet, Raw
from scapy.error import Scapy_Exception, log_interactive
from scapy.contrib.automotive.enumerator import AutomotiveTestCase, \
    AutomotiveTestCaseExecutor, AutomotiveTestCaseABC, StateGenerator, \
    AutomotiveTestCaseExecutorConfiguration, StagedAutomotiveTestCase, \
    _SocketUnion, _TransitionTuple, \
    _AutomotiveTestCaseScanResult, _AutomotiveTestCaseFilteredScanResult
from scapy.contrib.automotive.graph import _Edge
from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.uds import UDS, UDS_NR, UDS_DSC, UDS_TP, \
    UDS_RDBI, UDS_WDBI, UDS_SA, UDS_RC, UDS_IOCBI, UDS_RMBA, UDS_ER, \
    UDS_TesterPresentSender, UDS_CC, UDS_RDBPI, UDS_RD, UDS_TD


# Definition outside the class UDS_RMBASequentialEnumerator
# to allow pickling
_PointOfInterest = NamedTuple("_PointOfInterest", [
    ("memory_address", int),
    ("direction", bool),
    # True = increasing / upward, False = decreasing / downward  # noqa: E501
    ("memorySizeLen", int),
    ("memoryAddressLen", int)])


class UDS_Enumerator(AutomotiveTestCase):
    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        return resp.negativeResponseCode

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        return UDS_NR(negativeResponseCode=nrc).sprintf(
            "%UDS_NR.negativeResponseCode%")

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        label = UDS_Enumerator._get_label(tup[2], "PR: Supported")
        return tup[0], repr(tup[1]), label

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return response.sprintf("NR: %UDS_NR.negativeResponseCode%")


class UDS_DSCEnumerator(UDS_Enumerator, StateGenerator):
    _description = "Available sessions"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        session_range = kwargs.pop("session_range", range(2, 0x100))
        return list(UDS() / UDS_DSC(diagnosticSessionType=session_range))

    def execute(self, socket, state, timeout=3, execution_time=1200, **kwargs):
        # type: (_SocketUnion, EcuState, int, int, Any) -> None  # noqa: E501

        overwrite_timeout = kwargs.pop("overwrite_timeout", True)
        # remove args from kwargs since they will be overwritten
        kwargs.pop("exit_if_service_not_supported", False)
        kwargs.pop("retry_if_busy_returncode", False)

        # Apply a fixed timeout for this execute. Unit-tests want to overwrite
        if overwrite_timeout:
            timeout = 3

        super(UDS_DSCEnumerator, self).execute(
            socket, state, timeout=timeout,
            execution_time=execution_time,
            exit_if_service_not_supported=False,
            retry_if_busy_returncode=False, **kwargs)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%02x: %s" % (req.diagnosticSessionType, req.sprintf(
                    "%UDS_DSC.diagnosticSessionType%")),
                label)

    @staticmethod
    def enter_state(socket, configuration, request):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, Packet) -> bool  # noqa: E501
        ans = socket.sr1(request, timeout=3, verbose=False)
        if ans is not None:
            if configuration.verbose:
                log_interactive.debug(
                    "Try to enter session req: %s, resp: %s" %
                    (repr(request), repr(ans)))
            return cast(int, ans.service) != 0x7f
        else:
            return False

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        edge = super(UDS_DSCEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            # Force TesterPresent if session is changed
            new_state.tp = 1   # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf, req):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, Packet) -> bool  # noqa: E501
        UDS_TPEnumerator.enter(sock, conf)
        # Wait 5 seconds, since some ECUs require time
        # to switch to the bootloader
        delay = conf[UDS_DSCEnumerator.__name__].get("delay_state_change", 5)
        time.sleep(delay)
        state_changed = UDS_DSCEnumerator.enter_state(sock, conf, req)
        if not state_changed:
            UDS_TPEnumerator.cleanup(sock, conf)
        return state_changed

    @staticmethod
    def transition_function(sock, conf, edge):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, _Edge) -> bool  # noqa: E501
        args = UDS_DSCEnumerator._get_args_for_transition_function(
            conf, UDS_DSCEnumerator.__name__, edge)
        if args is None:
            log_interactive.error("Couldn't find args")
            return False
        else:
            return UDS_DSCEnumerator.enter_state_with_tp(sock, conf, *args)

    def get_transition_function(self, socket, config, edge):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, _Edge) -> Optional[_TransitionTuple]  # noqa: E501
        cn = UDS_DSCEnumerator.__name__
        self._set_args_for_transition_function(
            config, cn, edge, (self._results[-1].req, ))
        return UDS_DSCEnumerator.transition_function, UDS_TPEnumerator.cleanup


class UDS_TPEnumerator(UDS_Enumerator, StateGenerator):
    _description = "TesterPresent supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [UDS() / UDS_TP()]

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        label = UDS_Enumerator._get_label(tup[2], "PR: Supported")
        return tup[0], "TesterPresent:", label

    @staticmethod
    def enter(socket, configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        UDS_TPEnumerator.cleanup(socket, configuration)
        configuration["tps"] = UDS_TesterPresentSender(socket)  # noqa: E501
        configuration["tps"].start()
        return True

    @staticmethod
    def transition_function(socket, configuration, _):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, _Edge) -> bool  # noqa: E501
        return UDS_TPEnumerator.enter(socket, configuration)

    @staticmethod
    def cleanup(_, configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        try:
            configuration["tps"].stop()
            configuration["tps"] = None
        except (AttributeError, KeyError):
            pass
        return True

    def get_transition_function(self, socket, config, edge):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, _Edge) -> Optional[_TransitionTuple]  # noqa: E501
        return self.transition_function, self.cleanup


class UDS_EREnumerator(UDS_Enumerator):
    _description = "ECUReset supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        reset_type = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_ER(resetType=reset_type))

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%02x: %s" % (req.resetType, req.sprintf(
                    "%UDS_ER.resetType%")),
                label)


class UDS_CCEnumerator(UDS_Enumerator):
    _description = "CommunicationControl supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        control_type = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_CC(
            controlType=control_type, communicationType0=1,
            communicationType2=15))

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%02x: %s" % (req.controlType, req.sprintf(
                    "%UDS_CC.controlType%")),
                label)


class UDS_RDBPIEnumerator(UDS_Enumerator):
    _description = "ReadDataByPeriodicIdentifier supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        pdid = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_RDBPI(
            transmissionMode=1, periodicDataIdentifier=pdid))

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%02x: %s" % (req.periodicDataIdentifier, req.sprintf(
                    "%UDS_RDBPI.periodicDataIdentifier%")),
                label)


class UDS_ServiceEnumerator(UDS_Enumerator):
    _description = "Available services and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        # Only generate services with unset positive response bit (0x40)
        return (UDS(service=x) for x in range(0x100) if not x & 0x40)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res)
        return (state,
                "0x%02x: %s" % (req.service, req.sprintf("%UDS.service%")),
                label)

    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        pos_reset = [t for t in self.results_with_response
                     if t[2].service == 0x51]
        if len(pos_reset):
            log_interactive.warning(
                "ECUResetPositiveResponse detected! This might have changed "
                "the state of the ECU under test.")

        super(UDS_ServiceEnumerator, self).post_execute(
            socket, state, global_configuration)


class UDS_RDBIEnumerator(UDS_Enumerator):
    _description = "Readable data identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (UDS() / UDS_RDBI(identifiers=[x]) for x in scan_range)

    @staticmethod
    def print_information(resp):
        # type: (Packet) -> str
        load = bytes(resp)[3:] if len(resp) > 3 else "No data available"
        return "PR: %s" % load

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(
            res, UDS_RDBIEnumerator.print_information)
        return (state,
                "0x%04x: %s" % (req.identifiers[0],
                                req.sprintf("%UDS_RDBI.identifiers%")[1:-1]),
                label)


class UDS_RDBISelectiveEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_random_to_sequential(rdbi_random, _):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        rdbi_random = cast(UDS_Enumerator, rdbi_random)
        identifiers_with_positive_response = \
            [p.resp.dataIdentifier
             for p in rdbi_random.results_with_positive_response]

        scan_range = UDS_RDBISelectiveEnumerator. \
            _poi_to_scan_range(identifiers_with_positive_response)
        return {"scan_range": scan_range}

    @staticmethod
    def _poi_to_scan_range(pois):
        # type: (Sequence[int]) -> Iterable[int]

        if len(pois) == 0:
            # quick path for better performance
            return []

        block_size = UDS_RDBIRandomEnumerator.block_size
        generators = []
        for start in range(0, 2 ** 16, block_size):
            end = start + block_size
            pr_in_block = any((start <= identifier < end
                               for identifier in pois))
            if pr_in_block:
                generators.append(range(start, end))
        scan_range = itertools.chain.from_iterable(generators)
        return scan_range

    def __init__(self):
        # type: () -> None
        super(UDS_RDBISelectiveEnumerator, self).__init__(
            [UDS_RDBIRandomEnumerator(), UDS_RDBIEnumerator()],
            [None, self.__connector_random_to_sequential])


class UDS_RDBIRandomEnumerator(UDS_RDBIEnumerator):
    block_size = 2 ** 6

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]

        samples_per_block = {
            4: 29, 5: 22, 6: 19, 8: 11, 9: 11, 10: 13, 11: 14, 12: 31, 13: 4,
            14: 26, 16: 30, 17: 4, 18: 20, 19: 5, 20: 49, 21: 54, 22: 9, 23: 4,
            24: 10, 25: 8, 28: 6, 29: 3, 32: 11, 36: 4, 37: 3, 40: 9, 41: 9,
            42: 3, 44: 2, 47: 3, 48: 4, 49: 3, 52: 8, 64: 35, 66: 2, 68: 24,
            69: 19, 70: 30, 71: 28, 72: 16, 73: 4, 74: 6, 75: 27, 76: 41,
            77: 11, 78: 6, 81: 2, 88: 3, 90: 2, 92: 16, 97: 15, 98: 20, 100: 6,
            101: 5, 102: 5, 103: 10, 106: 10, 108: 4, 124: 3, 128: 7, 136: 15,
            137: 14, 138: 27, 139: 10, 148: 9, 150: 2, 152: 2, 168: 23,
            169: 15, 170: 16, 171: 16, 172: 2, 176: 3, 177: 4, 178: 2, 187: 2,
            232: 3, 235: 2, 240: 8, 252: 25, 256: 7, 257: 2, 287: 6, 290: 2,
            316: 2, 319: 3, 323: 3, 324: 19, 326: 2, 327: 2, 330: 4, 331: 10,
            332: 3, 334: 8, 338: 3, 832: 6, 833: 2, 900: 4, 956: 4, 958: 3,
            964: 12, 965: 13, 966: 34, 967: 3, 972: 10, 1000: 3, 1012: 23,
            1013: 14, 1014: 15
        }
        to_scan = []
        block_size = UDS_RDBIRandomEnumerator.block_size
        for block_index, start in enumerate(range(0, 2 ** 16, block_size)):
            end = start + block_size
            count_samples = samples_per_block.get(block_index, 1)
            to_scan += random.sample(range(start, end), count_samples)

        # Use locality effect
        # If an identifier brought a positive response in any state,
        # it is likely that in another state it is available as well
        positive_identifiers = [t.resp.dataIdentifier for t in
                                self.results_with_positive_response]
        to_scan += positive_identifiers

        # make all identifiers unique with set()
        # Sort for better logs
        to_scan = sorted(list(set(to_scan)))
        return (UDS() / UDS_RDBI(identifiers=[x]) for x in to_scan)


class UDS_WDBIEnumerator(UDS_Enumerator):
    _description = "Writeable data identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        rdbi_enumerator = kwargs.pop("rdbi_enumerator", None)

        if rdbi_enumerator is None:
            log_interactive.debug("[i] Use entire scan range")
            return (UDS() / UDS_WDBI(dataIdentifier=x) for x in scan_range)
        elif isinstance(rdbi_enumerator, UDS_RDBIEnumerator):
            log_interactive.debug("[i] Selective scan based on RDBI results")
            return (UDS() / UDS_WDBI(dataIdentifier=t.resp.dataIdentifier) /
                    Raw(load=bytes(t.resp)[3:])
                    for t in rdbi_enumerator.results_with_positive_response
                    if len(bytes(t.resp)) >= 3)
        else:
            raise Scapy_Exception("rdbi_enumerator has to be an instance "
                                  "of UDS_RDBIEnumerator")

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Writeable")
        return (state,
                "0x%04x: %s" % (req.dataIdentifier,
                                req.sprintf("%UDS_WDBI.dataIdentifier%")),
                label)


class UDS_WDBISelectiveEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rdbi_to_wdbi(rdbi, _):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        return {"rdbi_enumerator": rdbi}

    def __init__(self):
        # type: () -> None
        super(UDS_WDBISelectiveEnumerator, self).__init__(
            [UDS_RDBIEnumerator(), UDS_WDBIEnumerator()],
            [None, self.__connector_rdbi_to_wdbi])


class UDS_SAEnumerator(UDS_Enumerator):
    _description = "Available security seeds with access type and state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(1, 256, 2))
        return (UDS() / UDS_SA(securityAccessType=x) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(
            res, lambda r: "PR: %s" % r.securitySeed)
        return state, req.securityAccessType, label

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        if self._retry_pkt is not None:
            # this is a retry execute. Wait much longer than usual because
            # a required time delay not expired could have been received
            # on the previous attempt
            time.sleep(11)
        else:
            time.sleep(1)

    def _evaluate_response(self, response, **kwargs):
        # type: (Optional[Packet], Any) -> bool
        if super(UDS_SAEnumerator, self)._evaluate_response(
                response, **kwargs):
            return True

        if response is None:
            # Nothing to evaluate, return and continue execute
            return False

        if response.service == 0x7f and \
                response.negativeResponseCode in [0x24, 0x37]:
            # requiredTimeDelayNotExpired or requestSequenceError
            if self._retry_pkt is None:
                # This was no retry since the retry_pkt is None
                self._retry_pkt = self._results[-1].req
                log_interactive.debug(
                    "[-] Exit execute. NR: %s. Retry next time.",
                    response.sprintf("%UDS_NR.negativeResponseCode%"))
                return True
            else:
                # This was an unsuccessful retry, continue execute
                self._retry_pkt = None
                log_interactive.warning(
                    "[-] Unsuccessful retry. NR: %s!",
                    response.sprintf("%UDS_NR.negativeResponseCode%"))
                return False
        else:
            self._retry_pkt = None

        if response.service == 0x67 and response.securityAccessType % 2 == 1:
            log_interactive.debug("[i] Seed received. Leave scan to try a key")
            return True

        return False

    @staticmethod
    def get_seed_pkt(sock, level=1, record=b""):
        # type: (_SocketUnion, int, bytes) -> Optional[Packet]
        req = UDS() / UDS_SA(securityAccessType=level,
                             securityAccessDataRecord=record)
        seed = None
        for t in range(10):
            seed = sock.sr1(req, timeout=5, verbose=False)
            if seed is None or (seed.service == 0x7f and
                                seed.negativeResponseCode != 0x37):
                log_interactive.info("Security access no seed! NR: %s",
                                     repr(seed))
                return None

            if seed.service == 0x7f and seed.negativeResponseCode == 0x37:
                log_interactive.info("Security access retry to get seed")
                time.sleep(10)
                continue

            if t == 9:
                return None
            break
        return seed

    @staticmethod
    def evaluate_security_access_response(res, seed, key):
        # type: (Optional[Packet], Packet, Optional[Packet]) -> bool
        if res is None or res.service == 0x7f:
            log_interactive.info(repr(seed))
            log_interactive.info(repr(key))
            log_interactive.info(repr(res))
            log_interactive.info("Security access error!")
            return False
        else:
            log_interactive.info("Security access granted!")
            return True


class UDS_SA_XOR_Enumerator(UDS_SAEnumerator, StateGenerator):
    _description = "XOR SecurityAccess supported"

    @staticmethod
    def get_key_pkt(seed, level=1):
        # type: (Packet, int) -> Optional[Packet]

        def key_function_int(s):
            # type: (int) -> int
            return 0xffffffff & ~s

        def key_function_short(s):
            # type: (int) -> int
            return 0xffff & ~s

        try:
            s = seed.securitySeed
        except AttributeError:
            return None

        fmt = None
        key_function = None  # Optional[Callable[[int], int]]

        if len(s) == 2:
            fmt = "H"
            key_function = key_function_short

        if len(s) == 4:
            fmt = "I"
            key_function = key_function_int

        if key_function is not None and fmt is not None:
            key = struct.pack(fmt, key_function(struct.unpack(fmt, s)[0]))
            return cast(Packet, UDS() / UDS_SA(securityAccessType=level + 1,
                                               securityKey=key))
        else:
            return None

    @staticmethod
    def get_security_access(sock, level=1, seed_pkt=None):
        # type: (_SocketUnion, int, Optional[Packet]) -> bool
        log_interactive.info(
            "Try bootloader security access for level %d" % level)
        if seed_pkt is None:
            seed_pkt = UDS_SAEnumerator.get_seed_pkt(sock, level)
            if not seed_pkt:
                return False

        key_pkt = UDS_SA_XOR_Enumerator.get_key_pkt(seed_pkt, level)
        if key_pkt is None:
            return False

        res = sock.sr1(key_pkt, timeout=5, verbose=False)
        return UDS_SA_XOR_Enumerator.evaluate_security_access_response(
            res, seed_pkt, key_pkt)

    @staticmethod
    def transition_function(sock, conf, edge):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, _Edge) -> bool  # noqa: E501
        args = UDS_SA_XOR_Enumerator._get_args_for_transition_function(
            conf, UDS_SA_XOR_Enumerator.__name__, edge)
        if args is None:
            log_interactive.error("Couldn't find args")
            return False

        return UDS_SA_XOR_Enumerator.get_security_access(sock, *args)

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        last_resp = self._results[-1].resp
        last_state = self._results[-1].state

        if last_resp is None or last_resp.service == 0x7f:
            return None

        try:
            if last_resp.service != 0x67 or \
                    last_resp.securityAccessType % 2 != 1:
                return None

            seed = last_resp
            sec_lvl = seed.securityAccessType

            if self.get_security_access(socket, sec_lvl, seed):
                log_interactive.debug("Security Access found.")
                # create edge
                new_state = copy.copy(last_state)
                new_state.security_level = seed.securityAccessType + 1  # type: ignore  # noqa: E501
                edge = (last_state, new_state)

                self._set_args_for_transition_function(
                    config, UDS_SA_XOR_Enumerator.__name__, edge, (sec_lvl, ))
                return edge
        except AttributeError:
            pass

        return None

    def get_transition_function(self, socket, config, edge):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration, _Edge) -> Optional[_TransitionTuple]  # noqa: E501
        return self.transition_function, None


class UDS_RCEnumerator(UDS_Enumerator):
    _description = "Available RoutineControls and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        type_list = kwargs.pop("type_list", [1, 2, 3])
        scan_range = kwargs.pop("scan_range", range(0x10000))

        return (
            UDS() / UDS_RC(routineControlType=rc_type,
                           routineIdentifier=data_id)
            for rc_type, data_id in itertools.product(type_list, scan_range)
        )

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res)
        return (state,
                "0x%04x-%d: %s" % (
                    req.routineIdentifier, req.routineControlType,
                    req.sprintf("%UDS_RC.routineIdentifier%")),
                label)


class UDS_RCStartEnumerator(UDS_RCEnumerator):
    _description = "Available RoutineControls and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        if "type_list" in kwargs:
            raise KeyError("'type_list' already set in kwargs.")
        if "scan_range" in kwargs:
            raise KeyError("'scan_range' set in kwargs.")
        kwargs["type_list"] = [1]
        return super(UDS_RCStartEnumerator, self). \
            _get_initial_requests(**kwargs)


class UDS_RCSelectiveEnumerator(StagedAutomotiveTestCase):
    _left_right_width = 132

    @staticmethod
    def points_to_ranges(points_of_interest, range_size=_left_right_width):
        # type: (Iterable[int], int) -> Iterable[int]
        generators = []
        for identifier in points_of_interest:
            start = max(identifier - range_size, 0)
            end = min(identifier + range_size + 1, 0x10000)
            generators.append(range(start, end))
        ranges_with_overlaps = itertools.chain.from_iterable(generators)
        return sorted(set(ranges_with_overlaps))

    @staticmethod
    def __connector_start_to_rest(rc_start, rc_stop):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        rc_start = cast(UDS_Enumerator, rc_start)
        identifiers_with_pr = [resp.routineIdentifier for _, _, resp, _, _
                               in rc_start.results_with_positive_response]
        scan_range = UDS_RCSelectiveEnumerator.points_to_ranges(
            identifiers_with_pr)

        return {"type_list": [2, 3],
                "scan_range": scan_range}

    def __init__(self):
        # type: () -> None
        super(UDS_RCSelectiveEnumerator, self).__init__(
            [UDS_RCStartEnumerator(), UDS_RCEnumerator()],
            [None, self.__connector_start_to_rest])


class UDS_IOCBIEnumerator(UDS_Enumerator):
    _description = "Available Input Output Controls By Identifier " \
                   "and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (UDS() / UDS_IOCBI(dataIdentifier=x) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res)
        return (state,
                "0x%04x: %s" % (req.dataIdentifier,
                                req.sprintf("%UDS_IOCBI.dataIdentifier%")),
                label)


class UDS_RMBAEnumeratorABC(UDS_Enumerator):
    _description = "Readable Memory Addresses " \
                   "and negative response per state"
    _probe_width = 4

    @staticmethod
    def get_addr(pkt):
        # type: (UDS_RMBA) -> int
        """
        Helper function to get the memoryAddress from a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        :return: memory address of the request
        """
        return getattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen)

    @staticmethod
    def set_addr(pkt, addr):
        # type: (UDS_RMBA, int) -> None
        """
        Helper function to set the memoryAddress of a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        :param addr: memory address to be set
        """
        setattr(pkt, "memoryAddress%d" % pkt.memoryAddressLen, addr)

    @staticmethod
    def set_size(pkt, size=_probe_width):
        # type: (UDS_RMBA, int) -> None
        """
        Helper function to set the memorySize of a UDS_RMBA packet
        :param pkt: UDS_RMBA request
        :param size: memory size to be set
        """
        setattr(pkt, "memorySize%d" % pkt.memorySizeLen, size)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(
            res, lambda r: "PR: %s" % r.dataRecord)
        return (state,
                "0x%04x" % UDS_RMBARandomEnumerator.get_addr(req),
                label)


class UDS_RMBARandomEnumerator(UDS_RMBAEnumeratorABC):
    @staticmethod
    def _random_memory_addr_pkt(addr_len=None, size_len=None):
        # type: (Optional[int], Optional[int]) -> Packet
        pkt = UDS() / UDS_RMBA()  # type: Packet
        pkt.memorySizeLen = random.randint(1, 4)
        pkt.memoryAddressLen = addr_len or random.randint(1, 4)
        UDS_RMBARandomEnumerator.set_size(
            pkt, size_len or UDS_RMBAEnumeratorABC._probe_width)
        UDS_RMBARandomEnumerator.set_addr(
            pkt, random.randint(0, 2 ** (8 * pkt.memoryAddressLen) - 1))
        return pkt

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return itertools.chain(
            (self._random_memory_addr_pkt(addr_len=1) for _ in range(100)),
            (self._random_memory_addr_pkt(addr_len=2) for _ in range(500)),
            (self._random_memory_addr_pkt(addr_len=3) for _ in range(1000)),
            (self._random_memory_addr_pkt(addr_len=4) for _ in range(5000)))


class UDS_RMBASequentialEnumerator(UDS_RMBAEnumeratorABC):

    def __init__(self):
        # type: () -> None
        super(UDS_RMBASequentialEnumerator, self).__init__()
        self.__points_of_interest = defaultdict(list)  # type: Dict[EcuState, List[_PointOfInterest]]  # noqa: E501
        self.__initial_points_of_interest = None  # type: Optional[List[_PointOfInterest]]  # noqa: E501

    def _get_memory_addresses_from_results(self, results):
        # type: (Union[List[_AutomotiveTestCaseScanResult], List[_AutomotiveTestCaseFilteredScanResult]]) -> List[int]  # noqa: E501
        mem_areas = [range(self.get_addr(tup.req),
                           self.get_addr(tup.req) + self._probe_width)
                     for tup in results]

        return list(itertools.chain.from_iterable(mem_areas))

    def _pois_to_requests(self, pois):
        # type: (List[_PointOfInterest]) -> Tuple[List[Packet], List[_PointOfInterest]]  # noqa: E501

        tested_addrs = self._get_memory_addresses_from_results(self.results)
        pos_addrs = self._get_memory_addresses_from_results(
            self.results_with_positive_response)

        new_requests = list()
        new_points_of_interest = list()

        for poi_addr, upward, memorySizeLen, memoryAddressLen in pois:
            if poi_addr not in pos_addrs:
                continue
            temp_new_requests = list()
            for i in range(0, 0x400, self._probe_width):
                if upward:
                    addr = min(poi_addr + i, 0xffffffff)
                else:
                    addr = max(poi_addr - i, 0)

                if addr not in tested_addrs:
                    pkt = UDS() / UDS_RMBA(memorySizeLen=memorySizeLen,
                                           memoryAddressLen=memoryAddressLen)
                    self.set_size(pkt)
                    self.set_addr(pkt, addr)
                    temp_new_requests.append(pkt)

            if len(temp_new_requests):
                new_requests += temp_new_requests
                new_points_of_interest.append(
                    _PointOfInterest(self.get_addr(temp_new_requests[-1]),
                                     upward, memorySizeLen, memoryAddressLen))

        return new_requests, new_points_of_interest

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        points_of_interest = kwargs.pop("points_of_interest", list())
        if len(points_of_interest) == 0:
            return []

        reqs, pois = self._pois_to_requests(points_of_interest)
        if not self.__initial_points_of_interest:
            self.__initial_points_of_interest = pois
        return reqs

    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        if not len(self.__points_of_interest[state]):
            if self.__initial_points_of_interest is None:
                # there are no points_of_interest for the current state.
                # Nothing to do.
                return
            else:
                # Transfer initial pois to current state pois
                self.__points_of_interest[state] = \
                    self.__initial_points_of_interest
                self.__initial_points_of_interest = None

        new_requests, new_points_of_interest = self._pois_to_requests(
            self.__points_of_interest[state])

        self.__points_of_interest[state] = list()
        if len(new_requests):
            self._state_completed[state] = False
            self._request_iterators[state] = new_requests
            self.__points_of_interest[state] = new_points_of_interest

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        s = super(UDS_RMBASequentialEnumerator, self).show(
            dump, filtered, verbose) or ""

        try:
            from intelhex import IntelHex

            ih = IntelHex()
            for tup in self.results_with_positive_response:
                for i, b in enumerate(tup.resp.dataRecord):
                    addr = self.get_addr(tup.req)
                    ih[addr + i] = int(b)

            ih.tofile("RMBA_dump.hex", format="hex")
        except ImportError:
            err_msg = "Install 'intelhex' to create a hex file of the memory"
            log_interactive.critical(err_msg)
            with open("RMBA_dump.hex", "w") as file:
                file.write(err_msg)

        if dump:
            return s + "\n"
        else:
            print(s)
            return None


class UDS_RMBAEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rand_to_seq(rand, _):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        points_of_interest = list()  # type: List[_PointOfInterest]
        rand = cast(UDS_RMBARandomEnumerator, rand)
        for tup in rand.results_with_positive_response:
            points_of_interest += \
                [_PointOfInterest(UDS_RMBAEnumeratorABC.get_addr(tup.req),
                                  True, tup.req.memorySizeLen,
                                  tup.req.memoryAddressLen),
                 _PointOfInterest(UDS_RMBAEnumeratorABC.get_addr(tup.req),
                                  False, tup.req.memorySizeLen,
                                  tup.req.memoryAddressLen)]

        return {"points_of_interest": points_of_interest}

    def __init__(self):
        # type: () -> None
        super(UDS_RMBAEnumerator, self).__init__(
            [UDS_RMBARandomEnumerator(), UDS_RMBASequentialEnumerator()],
            [None, self.__connector_rand_to_seq])


class UDS_RDEnumerator(UDS_Enumerator):
    _description = "RequestDownload supported"

    @staticmethod
    def _random_memory_addr_pkt(addr_len=None):  # noqa: E501
        # type: (Optional[int]) -> Packet
        pkt = UDS() / UDS_RD()  # type: Packet
        pkt.dataFormatIdentifiers = random.randint(0, 16)
        pkt.memorySizeLen = random.randint(1, 4)
        pkt.memoryAddressLen = addr_len or random.randint(1, 4)
        UDS_RMBARandomEnumerator.set_size(pkt, 0x10)
        addr = random.randint(0, 2 ** (8 * pkt.memoryAddressLen) - 1) & \
            (0xffffffff << (4 * pkt.memoryAddressLen))
        UDS_RMBARandomEnumerator.set_addr(pkt, addr)
        return pkt

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return itertools.chain(
            (self._random_memory_addr_pkt(addr_len=1) for _ in range(100)),
            (self._random_memory_addr_pkt(addr_len=2) for _ in range(500)),
            (self._random_memory_addr_pkt(addr_len=3) for _ in range(1000)),
            (self._random_memory_addr_pkt(addr_len=4) for _ in range(5000)))

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%04x" % UDS_RMBAEnumeratorABC.get_addr(req),
                label)


class UDS_TDEnumerator(UDS_Enumerator):
    _description = "TransferData supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        cnt = kwargs.pop("scan_range", range(0x100))
        return cast(Iterable[Packet], UDS() / UDS_TD(blockSequenceCounter=cnt))

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = UDS_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%02x: %s" % (req.blockSequenceCounter, req.sprintf(
                    "%UDS_TD.blockSequenceCounter%")),
                label)


class UDS_Scanner(AutomotiveTestCaseExecutor):
    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [UDS_ServiceEnumerator, UDS_DSCEnumerator, UDS_TPEnumerator,
                UDS_SAEnumerator, UDS_RDBIEnumerator,
                UDS_WDBISelectiveEnumerator,
                UDS_RMBAEnumerator, UDS_RCEnumerator, UDS_IOCBIEnumerator]
