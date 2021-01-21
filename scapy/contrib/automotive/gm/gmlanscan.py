#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Markus Schroetter <project.m.schroetter@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = GMLAN AutomotiveTestCaseExecutor Utilities
# scapy.contrib.status = loads

import random

from collections import defaultdict

from scapy.compat import Optional, List, Type, Any, Tuple, Iterable, Dict, cast
from scapy.contrib.automotive.gm.gmlan import GMLAN, GMLAN_SA, GMLAN_RD, \
    GMLAN_TD, GMLAN_RMBA, GMLAN_RDBI, GMLAN_RDBPI, GMLAN_IDO, \
    GMLAN_NR, GMLAN_WDBI, GMLAN_SAPR, GMLAN_DC
from scapy.contrib.automotive.enumerator import AutomotiveTestCase, \
    AutomotiveTestCaseExecutor, StateGenerator, \
    AutomotiveTestCaseExecutorConfiguration, AutomotiveTestCaseABC, \
    StagedAutomotiveTestCase, _TransitionTuple, _SocketUnion, \
    _AutomotiveTestCaseScanResult
from scapy.contrib.automotive.ecu import EcuState
from scapy.packet import Packet
from scapy.contrib.isotp import ISOTPSocket
from scapy.error import Scapy_Exception, log_interactive
from scapy.contrib.automotive.gm.gmlanutils import GMLAN_GetSecurityAccess, \
    GMLAN_InitDiagnostics, GMLAN_TesterPresentSender, GMLAN_RequestDownload

__all__ = ["GMLAN_Scanner", "GMLAN_ServiceEnumerator", "GMLAN_RDBIEnumerator",
           "GMLAN_RDBPIEnumerator", "GMLAN_RMBAEnumerator",
           "GMLAN_TPEnumerator", "GMLAN_IDOEnumerator", "GMLAN_PMEnumerator",
           "GMLAN_RNOEnumerator", "GMLAN_DNCEnumerator", "GMLAN_RDEnumerator",
           "GMLAN_SA1Enumerator", "GMLAN_TDEnumerator", "GMLAN_WDBIEnumerator",
           "GMLAN_SAEnumerator", "GMLAN_WDBISelectiveEnumerator",
           "GMLAN_DCEnumerator"]


class GMLAN_Enumerator(AutomotiveTestCase):

    @staticmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        return resp.returnCode

    @staticmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        return GMLAN_NR(returnCode=nrc).sprintf("%GMLAN_NR.returnCode%")

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        raise NotImplementedError

    @staticmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        return response.sprintf("NR: %GMLAN_NR.returnCode%")


class GMLAN_ServiceEnumerator(GMLAN_Enumerator):
    _description = "Available services and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        services = set(x & ~0x40 for x in range(0x100))
        services.remove(0x10)  # Remove InitiateDiagnosticOperation service
        services.remove(0x20)  # Remove ReturnToNormalOperation
        services.remove(0x28)  # Remove DisableNormalCommunication service
        services.remove(0x3E)  # Remove TesterPresent service
        services.remove(0xa5)  # Remove ProgrammingMode service
        return (GMLAN(service=x) for x in services)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res)
        return (state,
                "0x%02x: %s" % (req.service, req.sprintf("%GMLAN.service%")),
                label)


class GMLAN_TPEnumerator(GMLAN_Enumerator, StateGenerator):
    _description = "TesterPresent supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN(service=0x3E)]

    @staticmethod
    def enter(socket, configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        try:
            if configuration["tps"]:
                configuration["tps"].stop()
                configuration["tps"] = None
        except KeyError:
            pass
        configuration["tps"] = GMLAN_TesterPresentSender(socket)
        configuration["tps"].start()
        return True

    @staticmethod
    def cleanup(_, configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        try:
            if configuration["tps"]:
                configuration["tps"].stop()
                configuration["tps"] = None
        except KeyError:
            pass
        return True

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        return self.enter, self.cleanup

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, _, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "TesterPresent:", label


class GMLAN_IDOEnumerator(GMLAN_Enumerator, StateGenerator):
    _description = "InitiateDiagnosticOperation supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN() / GMLAN_IDO(subfunction=2)]

    @staticmethod
    def enter_diagnostic_session(socket):
        # type: (_SocketUnion) -> bool
        ans = socket.sr1(
            GMLAN() / GMLAN_IDO(subfunction=2), timeout=5, verbose=False)
        if ans is not None and ans.service == 0x7f:
            ans.show()
        return ans is not None and ans.service != 0x7f

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[Tuple[EcuState, EcuState]]  # noqa: E501
        edge = super(GMLAN_IDOEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            if state == new_state:
                return None
            new_state.tp = 1   # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        res = GMLAN_TPEnumerator.enter(sock, conf)
        res2 = GMLAN_IDOEnumerator.enter_diagnostic_session(sock)
        return res and res2

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        return self.enter_state_with_tp, GMLAN_TPEnumerator.cleanup

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, _, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "InitiateDiagnosticOperation:", label


class GMLAN_SAEnumerator(GMLAN_Enumerator):
    _description = "SecurityAccess supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return (GMLAN() / GMLAN_SA(subfunction=x) for x in range(1, 0xff, 2))

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(
            res, lambda r: "PR: %s" % r.securitySeed)
        return state, req.securityAccessType, label


class GMLAN_WDBIEnumerator(GMLAN_Enumerator):
    _description = "Writeable data identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))
        rdbi_enumerator = kwargs.pop("rdbi_enumerator", None)
        if rdbi_enumerator is None:
            return (GMLAN() / GMLAN_WDBI(dataIdentifier=x) for x in scan_range)
        elif isinstance(rdbi_enumerator, GMLAN_RDBIEnumerator):
            return (GMLAN() / GMLAN_WDBI(dataIdentifier=t.resp.dataIdentifier,
                                         dataRecord=bytes(t.resp)[2:])
                    for t in rdbi_enumerator.filtered_results
                    if t.resp.service != 0x7f and len(bytes(t.resp)) >= 2)
        else:
            raise Scapy_Exception("rdbi_enumerator has to be an instance "
                                  "of GMLAN_RDBIEnumerator")

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Writeable")
        return (state,
                "0x%02x: %s" % (req.dataIdentifier,
                                req.sprintf("%GMLAN_WDBI.dataIdentifier%")),
                label)


class GMLAN_WDBISelectiveEnumerator(StagedAutomotiveTestCase):
    @staticmethod
    def __connector_rdbi_to_wdbi(rdbi, _):
        # type: (AutomotiveTestCaseABC, AutomotiveTestCaseABC) -> Dict[str, Any]  # noqa: E501
        return {"rdbi_enumerator": rdbi}

    def __init__(self):
        # type: () -> None
        super(GMLAN_WDBISelectiveEnumerator, self).__init__(
            [GMLAN_RDBIEnumerator(), GMLAN_WDBIEnumerator()],
            [None, self.__connector_rdbi_to_wdbi])


class GMLAN_SA1Enumerator(GMLAN_Enumerator, StateGenerator):
    _description = "SecurityAccess level 1 supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError()

    def execute(self, socket, state, timeout=1, execution_time=1200, **kwargs):
        # type: (_SocketUnion, EcuState, int, int, Any) -> None
        keyfunction = kwargs.pop("keyfunction", None)
        verbose = kwargs.pop("verbose", False)
        retry = kwargs.pop("retry", 3)
        supported = GMLAN_GetSecurityAccess(
            socket, keyfunction, level=1, retry=retry, timeout=timeout,
            verbose=verbose)

        # TODO: Refactor result storage
        if supported:
            self._store_result(state, GMLAN() / GMLAN_SA(subfunction=2),
                               GMLAN() / GMLAN_SAPR(subfunction=2))
        else:
            self._store_result(
                state, GMLAN(service=0x27),
                GMLAN() / GMLAN_NR(returnCode=0x11, requestServiceId=0x27))
        self._state_completed[state] = True

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, _, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "SecurityAccess:", label

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[Tuple[EcuState, EcuState]]  # noqa: E501
        edge = super(GMLAN_SA1Enumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            if state == new_state:
                return None
            new_state.tp = 1   # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        res = GMLAN_TPEnumerator.enter(sock, conf)
        kf = conf[GMLAN_SA1Enumerator.__name__].get("keyfunction")
        vb = conf[GMLAN_SA1Enumerator.__name__].get("verbose", True)
        tm = conf[GMLAN_SA1Enumerator.__name__].get("timeout", 15)
        rt = conf[GMLAN_SA1Enumerator.__name__].get("retry", 5)
        res2 = GMLAN_GetSecurityAccess(
            sock, kf, level=1, timeout=tm, verbose=vb, retry=rt)
        return res and res2

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        return self.enter_state_with_tp, GMLAN_TPEnumerator.cleanup


class GMLAN_RNOEnumerator(GMLAN_Enumerator):
    _description = "ReturnToNormalOperation supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN(service=0x20)]

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, _, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "ReturnToNormalOperation:", label


class GMLAN_DNCEnumerator(GMLAN_Enumerator):
    _description = "DisableNormalCommunication supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN(service=0x28)]

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "DisableNormalCommunication:", label


class GMLAN_RDEnumerator(GMLAN_Enumerator, StateGenerator):
    _description = "RequestDownload supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        return [GMLAN() / GMLAN_RD(memorySize=0x10)]

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[Tuple[EcuState, EcuState]]  # noqa: E501
        edge = super(GMLAN_RDEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            if state == new_state:
                return None
            new_state.tp = 1  # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        res = GMLAN_TPEnumerator.enter(sock, conf)
        res2 = GMLAN_RequestDownload(sock, 0x10, timeout=10, verbose=False)
        return res and res2

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        return self.enter_state_with_tp, GMLAN_TPEnumerator.cleanup

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "RequestDownload:", label


class GMLAN_PMEnumerator(GMLAN_Enumerator, StateGenerator):
    _description = "ProgrammingMode supported"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError()

    def execute(self, socket, state, timeout=1, execution_time=1200, **kwargs):
        # type: (_SocketUnion, EcuState, int, int, Any) -> None
        supported = GMLAN_InitDiagnostics(cast(ISOTPSocket, socket),
                                          timeout=20, verbose=False)
        # TODO: Refactor result storage
        if supported:
            self._store_result(state, GMLAN(service=0xA5), GMLAN(service=0xE5))
        else:
            self._store_result(
                state, GMLAN(service=0xA5),
                GMLAN() / GMLAN_NR(returnCode=0x11, requestServiceId=0xA5))

        self._state_completed[state] = True

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[Tuple[EcuState, EcuState]]  # noqa: E501
        edge = super(GMLAN_PMEnumerator, self).get_new_edge(socket, config)
        if edge:
            state, new_state = edge
            if state == new_state:
                return None
            new_state.tp = 1  # type: ignore
            return state, new_state
        return None

    @staticmethod
    def enter_state_with_tp(sock, conf):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> bool
        res = GMLAN_TPEnumerator.enter(sock, conf)
        res2 = GMLAN_InitDiagnostics(sock, timeout=20, verbose=False)
        return res and res2

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        return self.enter_state_with_tp, GMLAN_TPEnumerator.cleanup

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return state, "ProgrammingMode:", label


class GMLAN_RDBIEnumerator(GMLAN_Enumerator):
    _description = "Readable data identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))
        return (GMLAN() / GMLAN_RDBI(dataIdentifier=x) for x in scan_range)

    @staticmethod
    def print_information(resp):
        # type: (Packet) -> str
        load = bytes(resp)[3:] if len(resp) > 3 else b"No data available"
        return "PR: %r" % ((load[:17] + b"...") if len(load) > 20 else load)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(
            res, GMLAN_RDBIEnumerator.print_information)
        return (state,
                "0x%04x: %s" % (req.dataIdentifier,
                                req.sprintf("%GMLAN_RDBI.dataIdentifier%")),
                label)


class GMLAN_RDBPIEnumerator(GMLAN_Enumerator):
    _description = "Readable parameter identifier per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x10000))
        return (GMLAN() / GMLAN_RDBPI(identifiers=[x]) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(
            res, GMLAN_RDBIEnumerator.print_information)
        return (state,
                "0x%04x: %s" % (req.identifiers[0],
                                req.sprintf(
                                    "%GMLAN_RDBPI.identifiers%")[1:-1]),
                label)


class GMLAN_RMBAEnumerator(GMLAN_Enumerator):
    _description = "Readable Memory Addresses and negative response per state"

    def __init__(self):
        # type: () -> None
        super(GMLAN_RMBAEnumerator, self).__init__()
        self.random_probe_finished = defaultdict(bool)  # type: Dict[EcuState, bool]  # noqa: E501
        self.points_of_interest = defaultdict(list)  # type: Dict[EcuState, List[Tuple[int, bool]]]  # noqa: E501
        self.probe_width = 0x10
        self.random_probes_len = 4000
        self.sequential_probes_len = 0x400

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        self.probe_width = kwargs.pop("probe_width", self.probe_width)
        self.random_probes_len = kwargs.pop("random_probes_len",
                                            self.random_probes_len)
        self.sequential_probes_len = kwargs.pop("sequential_probes_len",
                                                self.sequential_probes_len)
        addresses = random.sample(
            range(self.probe_width, 0xffffffff, self.probe_width),
            self.random_probes_len)
        scan_range = kwargs.pop("scan_range", addresses)
        return (GMLAN() / GMLAN_RMBA(memoryAddress=x,
                                     memorySize=self.probe_width)
                for x in scan_range)

    def post_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
        state = self.results[-1].state

        if not self._state_completed[state]:
            return

        if not self.random_probe_finished[state]:
            log_interactive.info("[i] Random memory probing finished")
            self.random_probe_finished[state] = True
            for tup in [t for t in self.results_with_positive_response
                        if t.state == state]:
                self.points_of_interest[state].append(
                    (tup.req.memoryAddress, True))
                self.points_of_interest[state].append(
                    (tup.req.memoryAddress, False))

        if not len(self.points_of_interest[state]):
            return

        log_interactive.info(
            "[i] Create %d memory points for sequential probing" %
            len(self.points_of_interest[state]))

        tested_addrs = [tup.req.memoryAddress for tup in self.results]
        pos_addrs = [tup.req.memoryAddress for tup in
                     self.results_with_positive_response if tup.state == state]

        new_requests = list()
        new_points_of_interest = list()

        for poi, upward in self.points_of_interest[state]:
            if poi not in pos_addrs:
                continue
            temp_new_requests = list()
            for i in range(0, self.sequential_probes_len, self.probe_width):
                if upward:
                    new_addr = min(poi + i, 0xffffffff)
                else:
                    new_addr = max(poi - i, 0)

                if new_addr not in tested_addrs:
                    pkt = GMLAN() / GMLAN_RMBA(memoryAddress=new_addr,
                                               memorySize=self.probe_width)
                    temp_new_requests.append(pkt)

            if len(temp_new_requests):
                new_points_of_interest.append(
                    (temp_new_requests[-1].memoryAddress, upward))
                new_requests += temp_new_requests

        self.points_of_interest[state] = list()

        if len(new_requests):
            self._state_completed[state] = False
            self._request_iterators[state] = new_requests
            self.points_of_interest[state] = new_points_of_interest
            log_interactive.info(
                "[i] Created %d pkts for sequential probing" %
                len(new_requests))

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        s = super(GMLAN_RMBAEnumerator, self).show(dump, filtered, verbose)
        try:
            from intelhex import IntelHex

            ih = IntelHex()
            for tup in self.filtered_results:
                for i, b in enumerate(tup.resp.dataRecord):
                    ih[tup.req.memoryAddress + i] = int(b)

            ih.tofile("RMBA_dump.hex", format="hex")
        except ImportError:
            err_msg = "Install 'intelhex' to create a hex file of the memory"
            log_interactive.critical(err_msg)
            with open("RMBA_dump.hex", "w") as file:
                file.write(err_msg)

        if dump and s is not None:
            return s + "\n"
        else:
            print(s)
            return None

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(
            res, lambda r: "PR: %s" % r.dataRecord)
        return state, "0x%04x" % req.memoryAddress, label


class GMLAN_TDEnumerator(GMLAN_Enumerator):
    _description = "Transfer Data support and negative response per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x1ff))
        addresses = (random.randint(0, 0xffffffff) // 4 for _ in scan_range)
        return (GMLAN() / GMLAN_TD(subfunction=0, startingAddress=x)
                for x in addresses)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res)
        return state, "0x%04x" % req.startingAddress, label


class GMLAN_DCEnumerator(GMLAN_Enumerator):
    _description = "DeviceControl supported per state"

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        scan_range = kwargs.pop("scan_range", range(0x100))
        return (GMLAN() / GMLAN_DC(CPIDNumber=x) for x in scan_range)

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        state, req, res, _, _ = tup
        label = GMLAN_Enumerator._get_label(res, "PR: Supported")
        return (state,
                "0x%02x: %s" % (req.CPIDNumber,
                                req.sprintf("%GMLAN_DC.CPIDNumber%")),
                label)


# ########################## GMLAN SCANNER ###################################

class GMLAN_Scanner(AutomotiveTestCaseExecutor):
    @property
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        return [GMLAN_ServiceEnumerator, GMLAN_TPEnumerator,
                GMLAN_IDOEnumerator, GMLAN_PMEnumerator, GMLAN_RNOEnumerator,
                GMLAN_DNCEnumerator, GMLAN_RDEnumerator,
                GMLAN_SA1Enumerator, GMLAN_TDEnumerator, GMLAN_RMBAEnumerator,
                GMLAN_WDBISelectiveEnumerator, GMLAN_DCEnumerator]
