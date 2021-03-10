# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Staged AutomotiveTestCase base classes
# scapy.contrib.status = library


from scapy.compat import Any, List, Optional, Dict, Callable, cast, \
    TYPE_CHECKING
from scapy.contrib.automotive.scanner.graph import _Edge
from scapy.error import log_interactive
from scapy.contrib.automotive.ecu import EcuState, EcuResponse
from scapy.contrib.automotive.scanner.test_case import AutomotiveTestCaseABC, \
    TestCaseGenerator, StateGenerator, _SocketUnion


if TYPE_CHECKING:
    from scapy.contrib.automotive.scanner.test_case import _TransitionTuple
    from scapy.contrib.automotive.scanner.configuration import \
        AutomotiveTestCaseExecutorConfiguration


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

    # TODO: Fix unit tests and remove this function
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
        # type: (_SocketUnion, AutomotiveTestCaseExecutorConfiguration) -> Optional[_Edge]   # noqa: E501
        try:
            test_case = cast(StateGenerator, self.current_test_case)
            return test_case.get_new_edge(socket, config)
        except AttributeError:
            return None

    def get_transition_function(self, socket, edge):
        # type: (_SocketUnion, _Edge) -> Optional[_TransitionTuple]
        try:
            test_case = cast(StateGenerator, self.current_test_case)
            return test_case.get_transition_function(socket, edge)
        except AttributeError:
            return None

    def has_completed(self, state):
        # type: (EcuState) -> bool
        if not (self.current_test_case.has_completed(state) and
                self.current_test_case.completed):
            # current test_case not fully completed
            # reset completion delay, since new states could have been appeared
            self.__completion_delay = 0
            return False

        # current test_case is fully completed
        if self.__stage_index == len(self.__test_cases) - 1:
            # this test_case was the last test_case... nothing to do
            return True

        # current stage is finished. We have to increase the stage
        if self.__completion_delay < 5:
            # First we wait five more iteration of the executor
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

    def pre_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
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

        self.current_test_case.pre_execute(socket, state, global_configuration)

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None  # noqa: E501
        kwargs = self.__current_kwargs or dict()
        self.current_test_case.execute(socket, state, **kwargs)

    def post_execute(self, socket, state, global_configuration):
        # type: (_SocketUnion, EcuState, AutomotiveTestCaseExecutorConfiguration) -> None  # noqa: E501
        self.current_test_case.post_execute(socket, state, global_configuration)  # noqa: E501

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

    @property
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        # TODO: Sort results
        supported_responses = list()
        for tc in self.test_cases:
            supported_responses += tc.supported_responses

        return supported_responses