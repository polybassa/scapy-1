# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = AutomotiveTestCase definitions
# scapy.contrib.status = library


import time
from collections import defaultdict, OrderedDict

from scapy.compat import Any, Union, List, Optional, Iterable, \
    Dict, Tuple, Set, Callable, cast, NamedTuple, FAKE_TYPING, orb, \
    TYPE_CHECKING
from scapy.error import Scapy_Exception, log_interactive
from scapy.utils import make_lined_table, SingleConversationSocket, EDecimal
import scapy.modules.six as six
from scapy.supersocket import SuperSocket
from scapy.packet import Packet
from scapy.contrib.automotive.scanner.graph import _Edge
from scapy.contrib.automotive.ecu import EcuState, EcuResponse


if TYPE_CHECKING:
    from scapy.contrib.automotive.scanner.configuration import AutomotiveTestCaseExecutorConfiguration  # noqa: E501


if six.PY34:
    from abc import ABC, abstractmethod
else:
    from abc import ABCMeta, abstractmethod
    ABC = ABCMeta('ABC', (), {})  # type: ignore


if not FAKE_TYPING:
    # Definition outside the class AutomotiveTestCase to allow pickling
    _AutomotiveTestCaseScanResult = NamedTuple(
        "_AutomotiveTestCaseScanResult",
        [("state", EcuState),
         ("req", Packet),
         ("resp", Optional[Packet]),
         ("req_ts", Union[EDecimal, float]),
         ("resp_ts", Optional[Union[EDecimal, float]])])

    _AutomotiveTestCaseFilteredScanResult = NamedTuple(
        "_AutomotiveTestCaseFilteredScanResult",
        [("state", EcuState),
         ("req", Packet),
         ("resp", Packet),
         ("req_ts", Union[EDecimal, float]),
         ("resp_ts", Union[EDecimal, float])])

else:
    from collections import namedtuple
    # Definition outside the class AutomotiveTestCase to allow pickling
    _AutomotiveTestCaseScanResult = namedtuple(  # type: ignore
        "_AutomotiveTestCaseScanResult",
        ["state", "req", "resp", "req_ts", "resp_ts"])

    _AutomotiveTestCaseFilteredScanResult = namedtuple(  # type: ignore
        "_AutomotiveTestCaseFilteredScanResult",
        ["state", "req", "resp", "req_ts", "resp_ts"])


# type definitions
_SocketUnion = Union[SuperSocket, SingleConversationSocket]
_TransitionCallable = Callable[[_SocketUnion, "AutomotiveTestCaseExecutorConfiguration", Dict[str, Any]], bool]  # noqa: E501
_CleanupCallable = Callable[[_SocketUnion, "AutomotiveTestCaseExecutorConfiguration"], bool]  # noqa: E501
_TransitionTuple = Tuple[_TransitionCallable, Dict[str, Any], Optional[_CleanupCallable]]  # noqa: E501


class AutomotiveTestCaseABC(ABC):
    """
    Base class for "TestCase" objects. In automotive scanners, these TestCase
    objects are used for individual tasks, for example enumerating over one
    kind of functionality of the protocol. It is also possible, that
    these TestCase objects execute complex tests on an ECU.
    The TestCaseExecuter object has a list of TestCases. The executer
    manipulates a device under test (DUT), to enter a certain state. In this
    state, the TestCase object gets executed.
    """
    @abstractmethod
    def has_completed(self, state):
        # type: (EcuState) -> bool
        """
        Tells if this TestCase was executed for a certain state
        :param state: State of interest
        :return: True, if TestCase was executed in the questioned state
        """
        raise NotImplementedError()

    @abstractmethod
    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        """
        Will be executed previously to ``execute``
        :param socket: Socket object with the connection to a DUT
        :param state: Current state of the DUT
        :param global_configuration: Configuration of the TestCaseExecutor
        """
        raise NotImplementedError()

    @abstractmethod
    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        raise NotImplementedError()

    @abstractmethod
    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        raise NotImplementedError()

    @abstractmethod
    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        raise NotImplementedError()

    @property
    @abstractmethod
    def completed(self):
        # type: () -> bool
        raise NotImplementedError

    @property
    @abstractmethod
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        raise NotImplementedError


class AutomotiveTestCase(AutomotiveTestCaseABC):
    """ Base class for Enumerators"""

    _description = "About my results"

    @staticmethod
    @abstractmethod
    def _get_negative_response_code(resp):
        # type: (Packet) -> int
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def _get_negative_response_desc(nrc):
        # type: (int) -> str
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def _get_negative_response_label(response):
        # type: (Packet) -> str
        raise NotImplementedError()

    @abstractmethod
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        raise NotImplementedError("Overwrite this method")

    def __init__(self):
        # type: () -> None
        self.__result_packets = OrderedDict()  # type: Dict[bytes, Packet]
        self._results = list()  # type: List[_AutomotiveTestCaseScanResult]
        self._state_completed = defaultdict(bool)  # type: Dict[EcuState, bool]
        self._request_iterators = dict()  # type: Dict[EcuState, Iterable[Packet]]  # noqa: E501
        self._retry_pkt = None  # type: Optional[Union[Packet, Iterable[Packet]]]  # noqa: E501
        self._negative_response_blacklist = [0x10, 0x11]  # type: List[int]

    def __reduce__(self):  # type: ignore
        f, t, d = super(AutomotiveTestCase, self).__reduce__()  # type: ignore
        try:
            del d["_request_iterators"]
        except KeyError:
            pass

        try:
            del d["_retry_pkt"]
        except KeyError:
            pass
        return f, t, d

    def has_completed(self, state):
        # type: (EcuState) -> bool
        return self._state_completed[state]

    @property
    def negative_response_blacklist(self):
        # type: () -> List[int]
        return self._negative_response_blacklist

    @property
    def completed(self):
        # type: () -> bool
        if len(self._results):
            return all([self.has_completed(s) for s in self.scanned_states])
        else:
            return all(v for _, v in self._state_completed.items())

    def _store_result(self, state, req, res):
        # type: (EcuState, Packet, Optional[Packet]) -> None
        if bytes(req) not in self.__result_packets:
            self.__result_packets[bytes(req)] = req

        if res and bytes(res) not in self.__result_packets:
            self.__result_packets[bytes(res)] = res

        self._results.append(_AutomotiveTestCaseScanResult(
            state,
            self.__result_packets[bytes(req)],
            self.__result_packets[bytes(res)] if res is not None else None,
            req.sent_time or 0.0,
            res.time if res is not None else None))

    def __get_retry_iterator(self):
        # type: () -> Optional[Iterable[Packet]]
        if self._retry_pkt:
            if isinstance(self._retry_pkt, Packet):
                it = [self._retry_pkt]  # type: Iterable[Packet]
            else:
                # assume self.retry_pkt is a generator or list
                it = self._retry_pkt
            return it
        return None

    def __get_initial_request_iterator(self, state, **kwargs):
        # type: (EcuState, Any) -> Iterable[Packet]
        if state not in self._request_iterators:
            self._request_iterators[state] = iter(
                self._get_initial_requests(**kwargs))

        return self._request_iterators[state]

    def __get_request_iterator(self, state, **kwargs):
        # type: (EcuState, Optional[Dict[str, Any]]) -> Iterable[Packet]
        return self.__get_retry_iterator() or \
            self.__get_initial_request_iterator(state, **kwargs)

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        pass

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        timeout = kwargs.pop('timeout', 1)
        execution_time = kwargs.pop("execution_time", 1200)

        it = self.__get_request_iterator(state, **kwargs)

        # log_interactive.debug("[i] Using iterator %s in state %s", it, state)

        start_time = time.time()
        log_interactive.debug(
            "[i] Start execution of enumerator: %s", time.ctime(start_time))

        for req in it:
            if (start_time + execution_time) < time.time():
                log_interactive.debug(
                    "[i] Finished execution time of enumerator: %s",
                    time.ctime())
                return

            try:
                res = socket.sr1(req, timeout=timeout, verbose=False)
            except (OSError, ValueError, Scapy_Exception, BrokenPipeError) as e:  # noqa: E501
                res = None
                if self._retry_pkt is None:
                    log_interactive.debug(
                        "[-] Exception '%s' in execute. Prepare for retry", e)
                    self._retry_pkt = req
                else:
                    log_interactive.critical(
                        "[-] Exception during retry. This is bad")
                raise e

            self._store_result(state, req, res)

            if self._evaluate_response(state, req, res, **kwargs):
                log_interactive.debug("[i] Stop test_case execution because "
                                      "of response evaluation")
                return

        log_interactive.info("[i] Finished iterator execution")
        self._state_completed[state] = True
        log_interactive.debug("[i] States completed %s",
                              repr(self._state_completed))

    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        pass

    def _evaluate_response(self, state, request, response, **kwargs):
        # type: (EcuState, Packet, Optional[Packet], Optional[Dict[str, Any]]) -> bool  # noqa: E501

        if response is None:
            # Nothing to evaluate, return and continue execute
            return False

        exit_if_service_not_supported = kwargs.pop(
            "exit_if_service_not_supported", False)

        retry_if_busy_returncode = kwargs.pop("retry_if_busy_returncode", True)

        if exit_if_service_not_supported and response.service == 0x7f:
            response_code = self._get_negative_response_code(response)
            if response_code in [0x11, 0x7f]:
                names = {0x11: "serviceNotSupported",
                         0x7f: "serviceNotSupportedInActiveSession"}
                msg = "[-] Exit execute because negative response " \
                      "%s received!" % names[response_code]
                log_interactive.debug(msg)
                # execute of current state is completed,
                # since a serviceNotSupported negative response was received
                self._state_completed[state] = True
                # stop current execute and exit
                return True

        if retry_if_busy_returncode and response.service == 0x7f \
                and self._get_negative_response_code(response) == 0x21:

            if self._retry_pkt is None:
                # This was no retry since the retry_pkt is None
                self._retry_pkt = request
                log_interactive.debug(
                    "[-] Exit execute. Retry packet next time!")
                return True
            else:
                # This was a unsuccessful retry, continue execute
                self._retry_pkt = None
                log_interactive.debug("[-] Unsuccessful retry!")
                return False
        else:
            self._retry_pkt = None

        if EcuState.is_modifier_pkt(response):
            if state != EcuState.get_modified_ecu_state(
                    response, request, state):
                log_interactive.debug(
                    "[-] Exit execute. Ecu state was modified!")
                return True

        return False

    def _compute_statistics(self):
        # type: () -> List[Tuple[str, str, str]]
        data_sets = [("all", self._results)]

        for state in self._state_completed.keys():
            data_sets.append((repr(state),
                              [r for r in self._results if r.state == state]))

        stats = list()  # type: List[Tuple[str, str, str]]

        for desc, data in data_sets:
            answered = [r for r in data if r.resp is not None]
            unanswered = [r for r in data if r.resp is None]
            answertimes = [float(x.resp_ts) - float(x.req_ts) for x in answered if  # noqa: E501
                           x.resp_ts is not None and x.req_ts is not None]
            answertimes_nr = [float(x.resp_ts) - float(x.req_ts) for x in answered if x.resp  # noqa: E501
                              is not None and x.resp_ts is not None and
                              x.req_ts is not None and x.resp.service == 0x7f]
            answertimes_pr = [float(x.resp_ts) - float(x.req_ts) for x in answered if x.resp  # noqa: E501
                              is not None and x.resp_ts is not None and
                              x.req_ts is not None and x.resp.service != 0x7f]

            nrs = [r.resp for r in data if r.resp is not None and
                   r.resp.service == 0x7f]
            stats.append((desc, "num_answered", str(len(answered))))
            stats.append((desc, "num_unanswered", str(len(unanswered))))
            stats.append((desc, "num_negative_resps", str(len(nrs))))

            for postfix, times in zip(
                    ["", "_nr", "_pr"],
                    [answertimes, answertimes_nr, answertimes_pr]):
                try:
                    ma = str(round(max(times), 5))
                except ValueError:
                    ma = "-"

                try:
                    mi = str(round(min(times), 5))
                except ValueError:
                    mi = "-"

                try:
                    avg = str(round(sum(times) / len(times), 5))
                except (ValueError, ZeroDivisionError):
                    avg = "-"

                stats.append((desc, "answertime_min" + postfix, mi))
                stats.append((desc, "answertime_max" + postfix, ma))
                stats.append((desc, "answertime_avg" + postfix, avg))

        return stats

    def _show_statistics(self, dump=False):
        # type: (bool) -> Union[str, None]
        stats = self._compute_statistics()

        s = "Statistics per state\n"
        s += make_lined_table(stats, lambda x: x, dump=True, sortx=str,
                              sorty=str) or ""

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def _prepare_negative_response_blacklist(self):
        # type: () -> None
        nrc_dict = defaultdict(int)  # type: Dict[int, int]
        for nr in self.results_with_negative_response:
            nrc_dict[self._get_negative_response_code(nr.resp)] += 1

        total_nr_count = len(self.results_with_negative_response)
        for nrc, nr_count in nrc_dict.items():
            if nrc not in self.negative_response_blacklist and \
                    nr_count > 30 and (nr_count / total_nr_count) > 0.3:
                log_interactive.info("Added NRC 0x%02x to filter", nrc)
                self.negative_response_blacklist.append(nrc)

            if nrc in self.negative_response_blacklist and nr_count < 10:
                log_interactive.info("Removed NRC 0x%02x to filter", nrc)
                self.negative_response_blacklist.remove(nrc)

    @property
    def results(self):
        # type: () -> List[_AutomotiveTestCaseScanResult]
        return self._results

    @property
    def results_with_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        filtered_results = list()
        for r in self._results:
            if r.resp is None:
                continue
            if r.resp_ts is None:
                continue
            fr = cast(_AutomotiveTestCaseFilteredScanResult, r)
            filtered_results.append(fr)
        return filtered_results

    @property
    def filtered_results(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        filtered_results = list()

        for r in self.results_with_response:
            if r.resp.service != 0x7f:
                filtered_results.append(r)
                continue
            nrc = self._get_negative_response_code(r.resp)
            if nrc not in self.negative_response_blacklist:
                filtered_results.append(r)
        return filtered_results

    @property
    def scanned_states(self):
        # type: () -> Set[EcuState]
        """
        Helper function to get all sacnned states in results
        :return: all scanned states
        """
        return set([tup.state for tup in self._results])

    @property
    def results_with_negative_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        """
        Helper function to get all results with negative response
        :return: all results with negative response
        """
        return [cast(_AutomotiveTestCaseFilteredScanResult, r) for r in self._results  # noqa: E501
                if r.resp and r.resp.service == 0x7f]

    @property
    def results_with_positive_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        """
        Helper function to get all results with positive response
        :return: all results with positive response
        """
        return [cast(_AutomotiveTestCaseFilteredScanResult, r) for r in self._results  # noqa: E501
                if r.resp and r.resp.service != 0x7f]

    @property
    def results_without_response(self):
        # type: () -> List[_AutomotiveTestCaseScanResult]
        """
        Helper function to get all results without response
        :return: all results without response
        """
        return [r for r in self._results if r.resp is None]

    def _show_negative_response_details(self, dump=False):
        # type: (bool) -> Optional[str]
        nrc_dict = defaultdict(int)  # type: Dict[int, int]
        for nr in self.results_with_negative_response:
            nrc_dict[self._get_negative_response_code(nr.resp)] += 1

        s = "These negative response codes were received " + \
            " ".join([hex(c) for c in nrc_dict.keys()]) + "\n"
        for nrc, nr_count in nrc_dict.items():
            s += "\tNRC 0x%02x: %s received %d times" % (
                nrc, self._get_negative_response_desc(nrc), nr_count)
            s += "\n"

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def _show_header(self, dump=False):
        # type: (bool) -> Optional[str]
        s = "\n\n" + "=" * (len(self._description) + 10) + "\n"
        s += " " * 5 + self._description + "\n"
        s += "-" * (len(self._description) + 10) + "\n"

        s += "%d requests were sent, %d answered, %d unanswered" % \
             (len(self._results),
              len(self.results_with_negative_response) +
              len(self.results_with_positive_response),
              len(self.results_without_response)) + "\n"

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def _show_negative_response_information(self, dump, filtered=True):
        # type: (bool, bool) -> Optional[str]
        s = "%d negative responses were received\n" % \
            len(self.results_with_negative_response)

        if not dump:
            print(s)
            s = ""
        else:
            s += "\n"

        s += self._show_negative_response_details(dump) or "" + "\n"
        if filtered and len(self.negative_response_blacklist):
            s += "The following negative response codes are blacklisted: %s\n"\
                 % [self._get_negative_response_desc(nr)
                    for nr in self.negative_response_blacklist]

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def _show_state_information(self, dump):
        # type: (bool) -> Optional[str]
        completed = [(state, self._state_completed[state])
                     for state in self.scanned_states]
        return make_lined_table(
            completed, lambda tup: ("Scan state completed", tup[0], tup[1]),
            dump=dump)

    def _show_results_information(self, dump, filtered):
        # type: (bool, bool) -> Optional[str]
        s = "=== No data to display ===\n"
        data = self._results if not filtered else self.filtered_results  # type: Union[List[_AutomotiveTestCaseScanResult], List[_AutomotiveTestCaseFilteredScanResult]]  # noqa: E501
        if len(data):
            s = make_lined_table(
                data, self._get_table_entry, dump=dump, sortx=str) or ""

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        if filtered:
            self._prepare_negative_response_blacklist()

        s = self._show_header(dump) or ""
        s += self._show_statistics(dump) or ""
        s += self._show_negative_response_information(dump, filtered) or ""
        s += self._show_results_information(dump, filtered) or ""

        if verbose:
            s += self._show_state_information(dump) or ""

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    @classmethod
    def _get_label(cls, response, positive_case="PR: PositiveResponse"):
        # type: (Optional[Packet], Union[Callable[[Packet], str], str]) -> str
        if response is None:
            return "Timeout"
        elif orb(bytes(response)[0]) == 0x7f:
            return cls._get_negative_response_label(response)
        else:
            if isinstance(positive_case, six.string_types):
                return cast(str, positive_case)
            elif callable(positive_case):
                return positive_case(response)
            else:
                raise Scapy_Exception("Unsupported Type for positive_case. "
                                      "Provide a string or a function.")

    @property
    def supported_responses(self):
        # type: () -> List[EcuResponse]

        supported_resps = list()
        all_responses = [p for p in self.__result_packets.values()
                         if orb(bytes(p)[0]) & 0x40]
        for resp in all_responses:
            states = list(set([t.state for t in self.results_with_response
                               if t.resp == resp]))
            supported_resps.append(EcuResponse(state=states, responses=resp))
        return supported_resps


class TestCaseGenerator(ABC):
    @abstractmethod
    def get_generated_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        raise NotImplementedError()


class StateGenerator(ABC):
    _edge_requests = dict()  # type: Dict[_Edge, Packet]

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]  # noqa: E501
        if not isinstance(self, AutomotiveTestCaseABC):
            raise TypeError("Only AutomotiveTestCaseABC instances "
                            "can be a StateGenerator")
        try:
            state, req, resp, _, _ = cast(AutomotiveTestCase, self).results[-1]
        except IndexError:
            return None

        if resp is not None and EcuState.is_modifier_pkt(resp):
            new_state = EcuState.get_modified_ecu_state(resp, req, state)
            if new_state == state:
                return None
            else:
                edge = (state, new_state)
                StateGenerator._edge_requests[edge] = req
                return edge
        else:
            return None

    @abstractmethod
    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        """

        :param socket: Socket to target
        :param edge: Tuple of EcuState objects for the requested
                     transition function
        :return: Returns an optional tuple with two functions. Both functions
                 take a Socket and the TestCaseExecutor configuration as
                 arguments and return True if the execution was successful.
                 The first function is the state enter function, the second
                 function is a cleanup function
        """
        raise NotImplementedError
