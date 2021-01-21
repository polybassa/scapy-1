# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = AutomotiveTestCase and AutomotiveTestCaseExecutor base classes  # noqa: E501
# scapy.contrib.status = loads

import functools
import time

from collections import defaultdict, OrderedDict
from itertools import product

from scapy.compat import Any, Union, List, Optional, Iterable, \
    Dict, Tuple, Set, Callable, Type, cast, FAKE_TYPING
from scapy.error import Scapy_Exception, log_interactive
from scapy.utils import make_lined_table, SingleConversationSocket, EDecimal
import scapy.modules.six as six
from scapy.supersocket import SuperSocket
from scapy.packet import Packet
from scapy.contrib.automotive.ecu import EcuState, EcuStateModifier
from scapy.compat import orb

if six.PY34:
    from abc import ABC, abstractmethod
else:
    from abc import ABCMeta, abstractmethod
    ABC = ABCMeta('ABC', (), {})  # type: ignore


if not FAKE_TYPING:
    from typing import NamedTuple
    # Definition outside the class AutomotiveTestCase to allow pickling
    _AutomotiveTestCaseScanResult = NamedTuple(
        "_AutomotiveTestCaseScanResult",
        [("state", EcuState),
         ("req", Packet),
         ("resp", Optional[Packet]),
         ("req_ts", Union[EDecimal, int, float]),
         ("resp_ts", Optional[Union[EDecimal, int, float]])])

    _AutomotiveTestCaseFilteredScanResult = NamedTuple(
        "_AutomotiveTestCaseFilteredScanResult",
        [("state", EcuState),
         ("req", Packet),
         ("resp", Packet),
         ("req_ts", Union[int, float]),
         ("resp_ts", Union[int, float])])

else:
    from collections import namedtuple
    # Definition outside the class AutomotiveTestCase to allow pickling
    _AutomotiveTestCaseScanResult = namedtuple(  # type: ignore
        "_AutomotiveTestCaseScanResult",
        ["state", "req", "resp", "req_ts", "resp_ts"])

    _AutomotiveTestCaseFilteredScanResult = namedtuple(  # type: ignore
        "_AutomotiveTestCaseFilteredScanResult",
        ["state", "req", "resp", "req_ts", "resp_ts"])


def profile(state, enum=None):
    # type: (Any, Optional[Any]) -> Callable[[Callable[..., Any]], Callable[..., Any]]  # noqa: E501
    def profile_decorator(func):
        # type: (Callable[..., Any]) -> Callable[..., Any]
        @functools.wraps(func)
        def wrapper_profiled(*args, **kwargs):  # type: ignore
            with Profiler(state, enum):
                value = func(*args, **kwargs)
            return value

        return wrapper_profiled
    return profile_decorator


class Profiler:
    # For the profiling we'll use the unix time
    # candump is using the same and thus it would be matchable

    # _candump_fmt_date = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    # _filename_milestone = "milestones-%s.csv" % _candump_fmt_date
    # _filename_profiling = "profiling-%s.csv" % _candump_fmt_date
    _filename_milestone = "milestones.csv"
    _filename_profiling = "profiling.csv"

    _first = True
    enabled = True

    def __init__(self, state, enum=None):
        # type: (Any, Optional[Any]) -> None
        # We use the csv format
        # If len(p) > 1, it would contain a ','
        # For example: "[1, 2, 3]"
        # Thus we replace all ',' with a ';' to avoid this
        self.state = str(state).replace(",", ";")
        self.enum = str(enum or state).replace(",", ";")
        self.start_time = time.time()

        if Profiler._first and Profiler.enabled:
            Profiler._first = False
            with open(Profiler._filename_profiling, mode="a") as f:  # noqa: E501
                # Writing header
                # Not required for milestone file because this is parsed
                # manually instead of using `read_csv` of plotly
                f.write("state,enumerator,start,end\n")

    @classmethod
    def write_milestone(cls, name):
        # type: (str) -> None
        if not cls.enabled:
            return
        with open(cls._filename_milestone, mode="a") as f:
            f.write("%s,%f\n" % (name, time.time()))

    def __enter__(self):
        # type: () -> Profiler
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # type: (Any, Any, Any) -> None
        if not Profiler.enabled:
            return
        with open(Profiler._filename_profiling, mode="a") as f:
            f.write("%s,%s,%f,%f\n" % (
                self.state, self.enum, self.start_time, time.time()))


class AutomotiveTestCaseExecutorConfiguration(object):
    def __setitem__(self, key, value):
        # type: (Any, Any) -> None
        self.__dict__[key] = value

    def __getitem__(self, key):
        # type: (Any) -> Any
        return self.__dict__[key]

    def __init__(self, test_cases, **kwargs):
        # type: (Union[List[Union[AutomotiveTestCaseABC, Type[AutomotiveTestCaseABC]]], List[Type[AutomotiveTestCaseABC]]], Any) -> None  # noqa: E501

        self.verbose = kwargs.get("verbose", False)
        self.delay_state_change = kwargs.pop("delay_state_change", 0.5)

        # test_case can be a mix of classes or instances
        self.test_cases = \
            [e() for e in test_cases if not isinstance(e, AutomotiveTestCaseABC)]  # type: List[AutomotiveTestCaseABC]  # noqa: E501
        self.test_cases += \
            [e for e in test_cases if isinstance(e, AutomotiveTestCaseABC)]

        self.stages = [e for e in self.test_cases
                       if isinstance(e, StagedAutomotiveTestCase)]

        self.staged_test_cases = \
            [i for sublist in [e.test_cases for e in self.stages]
             for i in sublist]

        self.test_case_clss = [
            case.__class__ for case in set(self.staged_test_cases +
                                           self.test_cases)]

        for cls in self.test_case_clss:
            kwargs_name = cls.__name__ + "_kwargs"
            self.__setattr__(cls.__name__, kwargs.pop(kwargs_name, dict()))

        for cls in self.test_case_clss:
            val = self.__getattribute__(cls.__name__)
            for kwargs_key, kwargs_val in kwargs.items():
                if kwargs_key not in val.keys():
                    val[kwargs_key] = kwargs_val
            self.__setattr__(cls.__name__, val)

        log_interactive.debug("The following configuration was created")
        log_interactive.debug(self.__dict__)


# type definitions
_SocketUnion = Union[SuperSocket, SingleConversationSocket]
_TransitionCallable = \
    Callable[[_SocketUnion, AutomotiveTestCaseExecutorConfiguration], bool]
_CleanupCallable = Optional[_TransitionCallable]
_TransitionTuple = Tuple[_TransitionCallable, _CleanupCallable]


class Graph(object):
    def __init__(self):
        # type: () -> None
        """
        self.edges is a dict of all possible next nodes
        e.g. {'X': ['A', 'B', 'C', 'E'], ...}
        self.__transition_functions has all the transition_functions
        between two nodes, with the two nodes as a tuple as the key
        e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
        """
        self.edges = defaultdict(list)  # type: Dict[EcuState, List[EcuState]]
        self.__transition_functions = {}  # type: Dict[Tuple[EcuState, EcuState], Optional[_TransitionTuple]]  # noqa: E501

    def __reduce__(self):  # type: ignore
        f, t, d = super(Graph, self).__reduce__()  # type: ignore
        try:
            del d["_Graph__transition_functions"]
        except KeyError:
            pass
        return f, t, d

    def add_edge(self, from_node, to_node, transition_function=None):
        # type: (EcuState, EcuState, Optional[_TransitionTuple]) -> None  # noqa: E501
        """
        Inserts new edge in directional graph
        :param from_node: start node of edge
        :param to_node: end node of edge
        :param transition_function: tuple with enter and cleanup function
        """
        Profiler.write_milestone(repr(to_node))
        self.edges[from_node].append(to_node)
        self.__transition_functions[(from_node, to_node)] = transition_function

    def get_transition_function(self, from_node, to_node):
        # type: (EcuState, EcuState) -> Optional[_TransitionTuple]  # noqa: E501
        try:
            return self.__transition_functions[(from_node, to_node)]
        except KeyError:
            return None

    @property
    def transition_functions(self):
        # type: () -> Dict[Tuple[EcuState, EcuState], Optional[_TransitionTuple]]  # noqa: E501
        return self.__transition_functions

    @property
    def nodes(self):
        # type: () -> Union[List[EcuState], Set[EcuState]]
        return set([n for _, p in self.edges.items() for n in p])

    @staticmethod
    def dijkstra(graph, initial, end):
        # type: (Graph, EcuState, EcuState) -> List[EcuState]
        """
        Compute shortest paths from initial to end in graph
        From https://benalexkeen.com/implementing-djikstras-shortest-path-algorithm-with-python/  # noqa: E501
        :param graph: Graph where path is computed
        :param initial: Start node
        :param end: End node
        :return: A path as list of nodes
        """
        shortest_paths = {initial: (None, 0)}  # type: Dict[EcuState, Tuple[Optional[EcuState], int]]  # noqa: E501
        current_node = initial
        visited = set()

        while current_node != end:
            visited.add(current_node)
            destinations = graph.edges[current_node]
            weight_to_current_node = shortest_paths[current_node][1]

            for next_node in destinations:
                weight = 1 + weight_to_current_node
                if next_node not in shortest_paths:
                    shortest_paths[next_node] = (current_node, weight)
                else:
                    current_shortest_weight = shortest_paths[next_node][1]
                    if current_shortest_weight > weight:
                        shortest_paths[next_node] = (current_node, weight)

            next_destinations = {node: shortest_paths[node] for node in
                                 shortest_paths if node not in visited}
            if not next_destinations:
                return []
            # next node is the destination with the lowest weight
            current_node = min(next_destinations,
                               key=lambda k: next_destinations[k][1])

        # Work back through destinations in shortest path
        path = []
        while current_node is not None:
            path.append(current_node)
            next_node = cast(EcuState, shortest_paths[current_node][0])
            current_node = next_node
        # Reverse path
        path.reverse()
        return path


class AutomotiveTestCaseABC(ABC):
    @abstractmethod
    def has_completed(self, state):
        # type: (EcuState) -> bool
        raise NotImplementedError()

    @abstractmethod
    def pre_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
        raise NotImplementedError()

    @abstractmethod
    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None  # noqa: E501
        raise NotImplementedError()

    @abstractmethod
    def post_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
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


class TestCaseGenerator(ABC):
    @abstractmethod
    def get_generated_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        raise NotImplementedError()


class StateGenerator(ABC):
    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[Tuple[EcuState, EcuState]]  # noqa: E501
        if not isinstance(self, AutomotiveTestCaseABC):
            raise TypeError("Only AutomotiveTestCaseABC instances "
                            "can be a StateGenerator")
        try:
            state, _, resp, _, _ = cast(AutomotiveTestCase, self).results[-1]
        except IndexError:
            return None

        if resp is not None and EcuStateModifier.modifies_ecu_state(resp):
            new_state = EcuStateModifier.get_modified_ecu_state(resp, state)
            if new_state == state:
                return None
            else:
                return state, new_state
        else:
            return None

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        """

        :param socket: Socket to target
        :param config: Configuration of TestCaseExecutor
        :return: Returns an optional tuple with two functions. Both functions
                 take a Socket and the TestCaseExecutor configuration as
                 arguments and return True if the execution was successful.
                 The first function is the state enter function, the second
                 function is a cleanup function.
        """
        raise NotImplementedError


# type definitions
_TestCaseConnectorCallable = Callable[[AutomotiveTestCaseABC, AutomotiveTestCaseABC], Dict[str, Any]]  # noqa: E501


class StagedAutomotiveTestCase(AutomotiveTestCaseABC, TestCaseGenerator, StateGenerator):  # noqa: E501
    def __init__(self, test_cases, connectors=None):
        # type: (List[AutomotiveTestCaseABC], Optional[List[Optional[_TestCaseConnectorCallable]]]) -> None  # noqa: E501
        super(StagedAutomotiveTestCase, self).__init__()
        self.__test_cases = test_cases
        self.__connectors = connectors
        self.__stage_index = 0
        self.__completion_delay = 0
        self.__current_kwargs = None  # type: Optional[Dict[str, Any]]

    def __getitem__(self, item):
        # type: (int) -> AutomotiveTestCaseABC
        return self.__test_cases[item]

    def __len__(self):
        # type: () -> int
        return len(self.__test_cases)

    def __reduce__(self):  # type: ignore
        f, t, d = super(StagedAutomotiveTestCase, self).__reduce__()  # type: ignore  # noqa: E501
        try:
            del d["_StagedAutomotiveTestCase__connectors"]
        except KeyError:
            pass
        return f, t, d

    @property
    def test_cases(self):
        # type: () -> List[AutomotiveTestCaseABC]
        return self.__test_cases

    @property
    def current_test_case(self):
        # type: () -> AutomotiveTestCaseABC
        return self[self.__stage_index]

    @property
    def current_connector(self):
        # type: () -> Optional[_TestCaseConnectorCallable]
        if not self.__connectors:
            return None
        else:
            return self.__connectors[self.__stage_index]

    @property
    def previous_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        return self.__test_cases[self.__stage_index - 1] if \
            self.__stage_index > 0 else None

    def get_generated_test_case(self):
        # type: () -> Optional[AutomotiveTestCaseABC]
        try:
            test_case = cast(TestCaseGenerator, self.current_test_case)
            return test_case.get_generated_test_case()
        except AttributeError:
            return None

    def get_new_edge(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[Tuple[EcuState, EcuState]]   # noqa: E501
        try:
            test_case = cast(StateGenerator, self.current_test_case)
            return test_case.get_new_edge(socket, config)
        except AttributeError:
            return None

    def get_transition_function(self, socket, config):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_TransitionTuple]  # noqa: E501
        try:
            test_case = cast(StateGenerator, self.current_test_case)
            return test_case.get_transition_function(socket, config)
        except AttributeError:
            return None

    def has_completed(self, state):
        # type: (EcuState) -> bool
        if not (self.current_test_case.has_completed(state) and
                self.current_test_case.completed):
            # current test_case not fully completed, we can skip completed
            # internal states of the current test_case
            self.__completion_delay = 0
            return False

        # current test_case is fully completed
        if self.__stage_index == len(self) - 1:
            # this test_case was the last test_case... nothing to do
            return True

        # current stage is finished. We have to increase the stage
        if self.__completion_delay < 3:
            # First we wait one more iteration of the executor
            # Maybe one more execution reveals new states of other
            # test_cases
            self.__completion_delay += 1
            return False

        else:
            # We waited more iterations and no new state appeared,
            # let's enter the next stage
            log_interactive.info(
                "[+] Staged AutomotiveTestCase %s completed",
                self.current_test_case.__class__.__name__)
            self.__stage_index += 1
            self.__completion_delay = 0
        return False

    def pre_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
        test_case_cls = self.current_test_case.__class__
        try:
            self.__current_kwargs = global_configuration[
                test_case_cls.__name__]
        except KeyError:
            self.__current_kwargs = dict()

        if callable(self.current_connector) and self.__stage_index > 0:
            if self.previous_test_case:
                con = self.current_connector  # type: _TestCaseConnectorCallable  # noqa: E501
                con_kwargs = con(self.previous_test_case,
                                 self.current_test_case)
                if self.__current_kwargs is not None and con_kwargs is not None:  # noqa: E501
                    self.__current_kwargs.update(con_kwargs)

            log_interactive.debug("[i] Stage AutomotiveTestCase %s kwargs: %s",
                                  self.current_test_case.__class__.__name__,
                                  self.__current_kwargs)

        self.current_test_case.pre_execute(socket, global_configuration)

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None  # noqa: E501
        kwargs = self.__current_kwargs or dict()
        self.current_test_case.execute(socket, state, **kwargs)

    def post_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
        self.current_test_case.post_execute(socket, global_configuration)

    @staticmethod
    def _show_headline(headline, sep="=", dump=False):
        # type: (str, str, bool) -> Optional[str]
        s = "\n\n" + sep * (len(headline) + 10) + "\n"
        s += " " * 5 + headline + "\n"
        s += sep * (len(headline) + 10) + "\n"

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    def show(self, dump=False, filtered=True, verbose=False):
        # type: (bool, bool, bool) -> Optional[str]
        s = self._show_headline("AutomotiveTestCase Pipeline", "=", dump) or ""
        for idx, t in enumerate(self.__test_cases):
            s += self._show_headline(
                "AutomotiveTestCase Stage %d" % idx, "-", dump) or ""
            s += t.show(dump, filtered, verbose) or ""

        if dump:
            return s + "\n"
        else:
            print(s)
            return None

    @property
    def completed(self):
        # type: () -> bool
        return all(e.completed for e in self.__test_cases)


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

    def pre_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
        pass

    def execute(self, socket, state, timeout=1, execution_time=1200, **kwargs):
        # type: (_SocketUnion, EcuState, int, int, Any) -> None  # noqa: E501
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

            if self._evaluate_response(res, **kwargs):
                log_interactive.debug("[i] Stop test_case execution because "
                                      "of response evaluation")
                return

        log_interactive.info("[i] Finished iterator execution")
        self._state_completed[state] = True
        log_interactive.debug("[i] States completed %s",
                              repr(self._state_completed))

    def post_execute(self, socket, global_configuration):
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> None
        pass

    def _evaluate_response(self, response, **kwargs):
        # type: (Optional[Packet], Optional[Dict[str, Any]]) -> bool

        if response is None:
            # Nothing to evaluate, return and continue execute
            return False

        exit_if_service_not_supported = kwargs.pop(
            "exit_if_service_not_supported", False)

        retry_if_busy_returncode = kwargs.pop("retry_if_busy_returncode", True)

        if exit_if_service_not_supported and response.service == 0x7f and \
                self._get_negative_response_code(response) == 0x11:
            log_interactive.debug("[-] Exit execute because negative response "
                                  "serviceNotSupported received!")
            # execute of current state is completed,
            # since a serviceNotSupported negative response was received
            self._state_completed[self._results[-1].state] = True
            # stop current execute and exit
            return True

        if retry_if_busy_returncode and response.service == 0x7f \
                and self._get_negative_response_code(response) == 0x21:

            if self._retry_pkt is None:
                # This was no retry since the retry_pkt is None
                self._retry_pkt = self._results[-1].req
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

        if EcuStateModifier.modifies_ecu_state(response):
            state = self._results[-1].state
            if state != EcuStateModifier.get_modified_ecu_state(
                    response, state):
                log_interactive.debug(
                    "[-] Exit execute. Ecu state was modified!")
                return True

        return False

    def dump(self, completed_only=True):
        # type: (bool) -> Dict[str, Any]
        # TODO: Evaluate if dump can be removed since pickle is superior
        if completed_only:
            selected_states = [k for k, v in self._state_completed.items() if v]  # noqa: E501
        else:
            selected_states = list(self._state_completed.keys())

        isotp_params = list()
        for s, req, resp, _, _ in self._results:
            if s in selected_states and resp is not None:
                isotp_tup = (resp.src, resp.dst, resp.exsrc, resp.exdst)
                if isotp_tup not in isotp_params:
                    isotp_params.append(isotp_tup)

        data = [{"state": str(s),
                 "protocol": str(req.__class__.__name__),
                 "req_time": req_ts,
                 "req_idx": list(self.__result_packets.keys()).index(bytes(req)),  # noqa: E501
                 "resp_time": resp_ts if resp is not None else None,
                 "resp_idx": list(self.__result_packets.keys()).index(bytes(resp)) if resp is not None else None,  # noqa: E501
                 "isotp_param_idx": isotp_params.index(
                     (resp.src, resp.dst, resp.exsrc, resp.exdst))
                 if resp is not None else None}
                for s, req, resp, req_ts, resp_ts in self._results
                if s in selected_states]

        return {"format_version": 0.3,
                "name": str(self.__class__.__name__),
                "states_completed": [(str(k), v) for k, v in
                                     self._state_completed.items()],
                "result_packets": [str(k) for k in self.__result_packets.keys()],  # noqa: E501
                "isotp_params": [{"resp_src": t[0], "resp_dst": t[1],
                                  "resp_exsrc": t[2], "resp_exdst": t[3]}
                                 for t in isotp_params],
                "data": data}

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
    def filtered_results(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        filtered_results = list()

        for r in self._results:
            if r.resp is None:
                continue
            if r.resp_ts is None:
                continue
            fr = cast(_AutomotiveTestCaseFilteredScanResult, r)
            if fr.resp.service != 0x7f:
                filtered_results.append(fr)
                continue
            nrc = self._get_negative_response_code(fr.resp)
            if nrc not in self.negative_response_blacklist:
                filtered_results.append(fr)
        return filtered_results

    @property
    def scanned_states(self):
        # type: () -> Set[EcuState]
        return set([tup.state for tup in self._results])

    @property
    def results_with_negative_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        return [cast(_AutomotiveTestCaseFilteredScanResult, r) for r in self._results  # noqa: E501
                if r.resp and r.resp.service == 0x7f]

    @property
    def results_with_positive_response(self):
        # type: () -> List[_AutomotiveTestCaseFilteredScanResult]
        return [cast(_AutomotiveTestCaseFilteredScanResult, r) for r in self._results  # noqa: E501
                if r.resp and r.resp.service != 0x7f]

    @property
    def results_without_response(self):
        # type: () -> List[_AutomotiveTestCaseScanResult]
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

        if filtered:
            self._prepare_negative_response_blacklist()

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
        return make_lined_table(completed,
                                lambda tup: ("Scan state completed",
                                             tup[0], tup[1]),
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

    @staticmethod
    def _get_table_entry(tup):
        # type: (_AutomotiveTestCaseScanResult) -> Tuple[EcuState, str, str]
        label = AutomotiveTestCase._get_label(tup[2], "PR: Supported")
        return tup[0], repr(tup[1]), label

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


class AutomotiveTestCaseExecutor(ABC):

    @property
    def __initial_ecu_state(self):
        # type: () -> EcuState
        return EcuState(session=1)

    def __init__(
            self,
            socket,                     # type: _SocketUnion
            reset_handler=None,         # type: Optional[Callable[[], None]]
            reconnect_handler=None,     # type: Optional[Callable[[], _SocketUnion]]  # noqa: E501
            test_cases=None,            # type: Optional[List[Union[AutomotiveTestCaseABC, Type[AutomotiveTestCaseABC]]]]  # noqa: E501
            **kwargs                    # type: Optional[Dict[str, Any]]
    ):                                  # type: (...) -> None
        # The TesterPresentSender can interfere with a test_case, since a
        # target may only allow one request at a time.
        # The SingleConversationSocket prevents interleaving requests.
        if not isinstance(socket, SingleConversationSocket):
            self.socket = SingleConversationSocket(socket)
        else:
            self.socket = socket

        self.target_state = self.__initial_ecu_state
        self.reset_handler = reset_handler
        self.reconnect_handler = reconnect_handler

        self.state_graph = Graph()
        self.state_graph.add_edge(self.__initial_ecu_state,
                                  self.__initial_ecu_state)

        self.cleanup_functions = list()  # type: List[_TransitionCallable]

        self.configuration = AutomotiveTestCaseExecutorConfiguration(
            test_cases or self.default_test_case_clss, **kwargs)

    def __reduce__(self):  # type: ignore
        f, t, d = super(AutomotiveTestCaseExecutor, self).__reduce__()  # type: ignore  # noqa: E501
        try:
            del d["socket"]
        except KeyError:
            pass
        try:
            del d["reset_handler"]
        except KeyError:
            pass
        try:
            del d["cleanup_functions"]
        except KeyError:
            pass
        try:
            del d["reconnect_handler"]
        except KeyError:
            pass
        return f, t, d

    @property
    @abstractmethod
    def default_test_case_clss(self):
        # type: () -> List[Type[AutomotiveTestCaseABC]]
        raise NotImplementedError()

    def dump(self, completed_only=True):
        # type: (bool) -> Dict[str, Any]
        return {"format_version": 0.1,
                "test_cases": [cast(AutomotiveTestCase, e).dump(completed_only)
                               for e in self.configuration.test_cases],
                "state_graph": [str(p) for p in self.state_paths],
                "verbose": self.configuration.verbose,
                "delay_state_change": self.configuration.delay_state_change}

    @property
    def state_paths(self):
        # type: () -> List[List[EcuState]]
        paths = [Graph.dijkstra(self.state_graph, self.__initial_ecu_state, s)
                 for s in self.state_graph.nodes
                 if s != self.__initial_ecu_state]
        return sorted(
            [p for p in paths if p is not None] + [[self.__initial_ecu_state]],
            key=lambda x: x[-1])

    @property
    def final_states(self):
        # type: () -> List[EcuState]
        return [p[-1] for p in self.state_paths]

    @property
    def scan_completed(self):
        # type: () -> bool
        return all(t.has_completed(s) for t, s in
                   product(self.configuration.test_cases, self.final_states))

    @profile("ECU Reset")
    def reset_target(self):
        # type: () -> None
        log_interactive.info("[i] Target reset")
        if self.reset_handler:
            self.reset_handler()
        self.target_state = self.__initial_ecu_state

    @profile("Reconnect")
    def reconnect(self):
        # type: () -> None
        if self.reconnect_handler:
            try:
                self.socket.close()
            except Exception as e:
                log_interactive.debug(
                    "[i] Exception '%s' during socket.close", e)

            log_interactive.info("[i] Target reconnect")
            socket = self.reconnect_handler()
            if not isinstance(socket, SingleConversationSocket):
                self.socket = SingleConversationSocket(socket)
            else:
                self.socket = socket

    def execute_test_case(self, test_case):
        # type: (AutomotiveTestCaseABC) -> None
        test_case.pre_execute(self.socket, self.configuration)

        try:
            test_case_kwargs = self.configuration[test_case.__class__.__name__]
        except KeyError:
            test_case_kwargs = dict()

        log_interactive.debug("Execute test_case %s with args %s",
                              test_case.__class__.__name__, test_case_kwargs)

        test_case.execute(self.socket, self.target_state, **test_case_kwargs)
        test_case.post_execute(self.socket, self.configuration)

        if isinstance(test_case, StateGenerator):
            edge = test_case.get_new_edge(self.socket, self.configuration)
            if edge:
                log_interactive.debug("Edge found %s %s", edge[0], edge[1])
                transition_function = test_case.get_transition_function(
                    self.socket, self.configuration)
                self.state_graph.add_edge(edge[0], edge[1],
                                          transition_function)

        if isinstance(test_case, TestCaseGenerator):
            new_test_case = cast(TestCaseGenerator, test_case).get_generated_test_case()  # noqa: E501
            if new_test_case:
                self.configuration.test_cases.append(new_test_case)

    def scan(self, timeout=None):
        # type: (Optional[int]) -> None
        kill_time = time.time() + (timeout or 0xffffffff)
        while kill_time > time.time():
            test_case_executed = False
            log_interactive.debug("[i] Scan paths %s", self.state_paths)
            for p in self.state_paths:
                log_interactive.info("[i] Scan path %s", p)
                for test_case in self.configuration.test_cases:
                    final_state = p[-1]
                    if test_case.has_completed(final_state):
                        log_interactive.debug("[+] State %s for %s completed",
                                              repr(final_state), test_case)
                        continue
                    try:
                        if not self.enter_state_path(p):
                            log_interactive.error(
                                "[-] Error entering path %s", p)
                            continue
                        log_interactive.info("[i] EXECUTE SCAN %s for path %s",
                                             test_case.__class__.__name__, p)
                        with Profiler(p, test_case.__class__.__name__):
                            self.execute_test_case(test_case)
                            self.cleanup_state()
                        test_case_executed = True
                    except (OSError, ValueError, Scapy_Exception, BrokenPipeError) as e:  # noqa: E501
                        log_interactive.critical("[-] Exception: %s", e)

            if not test_case_executed:
                log_interactive.info(
                    "[-] Execute failure or completed. Exit scan!")
                break
        self.cleanup_state()
        self.reset_target()

    def enter_state_path(self, path):
        # type: (List[EcuState]) -> bool
        if path[0] != self.__initial_ecu_state:
            raise Scapy_Exception(
                "Initial state of path not equal reset state of the target")

        self.reset_target()
        self.reconnect()
        if len(path) == 1:
            return True

        for next_state in path[1:]:
            if not self.enter_state(self.target_state, next_state):
                return False
        return True

    @profile("State change")
    def enter_state(self, prev_state, next_state):
        # type: (EcuState, EcuState) -> bool
        funcs = self.state_graph.get_transition_function(
            prev_state, next_state)

        if funcs is None:
            log_interactive.error("No transition function for transition from "
                                  "state %s to %s", prev_state, next_state)
            return False

        cleanup_function = funcs[1]
        if cleanup_function is not None:
            self.cleanup_functions.insert(
                len(self.cleanup_functions), cleanup_function)

        if funcs[0](self.socket, self.configuration):
            self.target_state = next_state
            return True

        log_interactive.info(
            "Transition from state %s to %s failed", prev_state, next_state)
        return False

    def cleanup_state(self):
        # type: () -> None
        for f in self.cleanup_functions:
            if f is None:
                continue
            result = f(self.socket, self.configuration)
            if not result:
                log_interactive.info("Cleanup function %s failed", repr(f))

        self.cleanup_functions = list()

    def show_testcases(self):
        # type: () -> None
        for t in self.configuration.test_cases:
            t.show()

    def show_testcases_status(self):
        # type: () -> None
        data = list()
        for t in self.configuration.test_cases:
            for s in self.state_graph.nodes:
                data += [(t.__class__.__name__, repr(s), t.has_completed(s))]
        make_lined_table(data, lambda tup: (tup[1], tup[0], tup[2]))
