#! /usr/bin/env python

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Helper class for tracking Ecu states (Ecu)
# scapy.contrib.status = loads

import time
import random
import copy

from collections import defaultdict
from typing import Any, Union, Iterable, Callable, List, Optional, Tuple, \
    Type, cast, Dict
from types import GeneratorType

from scapy.packet import Raw, Packet
from scapy.plist import PacketList
from scapy.sessions import DefaultSession
from scapy.ansmachine import AnsweringMachine
from scapy.config import conf
import scapy.modules.six as six
from scapy.supersocket import SuperSocket


if six.PY34:
    from abc import ABC, abstractmethod
else:
    from abc import ABCMeta, abstractmethod  # noqa: F401
    ABC = ABCMeta('ABC', (), {})  # type: ignore

__all__ = ["EcuState", "EcuStateModifier", "Ecu", "EcuResponse",
           "EcuSession", "EcuAnsweringMachine"]


class EcuState(object):
    """
    Stores the state of an Ecu. The state is defined by a protocol, for
    example UDS or GMLAN.
    A EcuState supports comparison and serialization (command()).
    """
    def __init__(self, **kwargs):
        # type: (Any) -> None
        for k, v in kwargs.items():
            if isinstance(v, GeneratorType):
                v = list(v)
            self.__setattr__(k, v)

    def __getitem__(self, item):
        # type: (str) -> Any
        return self.__dict__[item]

    def __setitem__(self, key, value):
        # type: (str, Any) -> None
        self.__dict__[key] = value

    def __repr__(self):
        # type: () -> str
        return "".join([str(k) + str(v) for k, v in
                        sorted(self.__dict__.items(), key=lambda t: t[0])])

    def __eq__(self, other):
        # type: (object) -> bool
        other = cast(EcuState, other)
        if self.__dict__.keys() != other.__dict__.keys():
            return False
        return all(self.__dict__[k] == other.__dict__[k]
                   for k in self.__dict__.keys())

    def __contains__(self, item):
        # type: (EcuState) -> bool
        if not isinstance(item, EcuState):
            return False
        if not self.__dict__.keys() == item.__dict__.keys():
            return False
        return all(ov[1] == sv[1] or
                   (hasattr(sv[1], "__iter__") and ov[1] in sv[1])
                   for sv, ov in
                   zip(self.__dict__.items(), item.__dict__.items()))

    def __ne__(self, other):
        # type: (object) -> bool
        return not other == self

    def __lt__(self, other):
        # type: (EcuState) -> bool
        if self == other:
            return False

        if len(self.__dict__.keys()) < len(other.__dict__.keys()):
            return True

        if len(self.__dict__.keys()) > len(other.__dict__.keys()):
            return False

        common = set(self.__dict__.keys()).intersection(
            set(other.__dict__.keys()))
        if len(common) < len(self.__dict__.keys()):
            raise TypeError("EcuStates with different elements can't be "
                            "compared. Keys1: %s, Keys2: %s" %
                            (self.__dict__.keys(), other.__dict__.keys()))

        for k in sorted(self.__dict__.keys()):
            if not isinstance(other.__dict__[k], type(self.__dict__[k])):
                raise TypeError(
                    "Can't compare %s with %s for the EcuState element %s" %
                    (type(self.__dict__[k]), type(other.__dict__[k]), k))
            if self.__dict__[k] < other.__dict__[k]:
                return True
            if self.__dict__[k] > other.__dict__[k]:
                return False

        raise TypeError("EcuStates should be identical. Something bad happen. "
                        "self: %s other: %s" % (self.__dict__, other.__dict__))

    def __hash__(self):
        # type: () -> int
        return hash(repr(self))

    def reset(self):
        # type: () -> None
        keys = list(self.__dict__.keys())
        for k in keys:
            del self.__dict__[k]

    def command(self):
        # type: () -> str
        return "EcuState(" + ", ".join(
            ["%s=%s" % (k, repr(v)) for k, v in sorted(
                self.__dict__.items(), key=lambda t: t[0])]) + ")"


class EcuStateModifier(object):
    """
    Abstract class to signal that instances of this class can
    change an EcuState.
    """

    def modify_ecu_state(self, state):
        # type: (EcuState) -> None
        raise NotImplementedError

    @staticmethod
    def modifies_ecu_state(pkt):
        # type: (Packet) -> bool
        """
        Helper function to determine if a Packet contains a layer which
        modifies the EcuState.
        :param pkt: Packet to be analyzed
        :return: True if pkt contains layer of instance EcuStateModifier
        """
        return any(issubclass(layer, EcuStateModifier)
                   for layer in pkt.layers())

    @staticmethod
    def get_modified_ecu_state(pkt, state, modify_in_place=False):
        # type: (Packet, EcuState, bool) -> EcuState
        """
        Helper function to get a modified EcuState from a Packet and a
        previous EcuState.
        :param pkt: Packet that supports `modify_ecu_state`
        :param state: A previous EcuState
        :param modify_in_place: If True, the given EcuState will be modified
        :return: The modified EcuState as copy
        """
        if modify_in_place:
            new_state = state
        else:
            new_state = copy.copy(state)

        for layer in pkt.layers():
            if not issubclass(layer, EcuStateModifier):
                continue
            try:
                layer.modify_ecu_state(pkt, new_state)
            except TypeError:
                layer.modify_ecu_state.im_func(pkt, new_state)
        return new_state


class Ecu(object):
    """An Ecu object can be used to
        - track the states of an Ecu.
        - to log all modification to an Ecu.
        - to extract supported responses of a real Ecu.

    Usage:
    >>> print("This ecu logs, tracks and creates supported responses")
    >>> my_virtual_ecu = Ecu()
    >>> my_virtual_ecu.update(PacketList([...]))
    >>> my_virtual_ecu.supported_responses
    >>> print("Another ecu just tracks")
    >>> my_tracking_ecu = Ecu(logging=False, store_supported_responses=False)
    >>> my_tracking_ecu.update(PacketList([...]))
    >>> print("Another ecu just logs all modifications to it")
    >>> my_logging_ecu = Ecu(verbose=False, store_supported_responses=False)
    >>> my_logging_ecu.update(PacketList([...]))
    >>> my_logging_ecu.log
    >>> print("Another ecu just creates supported responses")
    >>> my_response_ecu = Ecu(verbose=False, logging=False)
    >>> my_response_ecu.update(PacketList([...]))
    >>> my_response_ecu.supported_responses
    """
    def __init__(self, logging=True, verbose=True,
                 store_supported_responses=True, lookahead=10):
        # type: (bool, bool, bool, int) -> None
        """
        Initialize an Ecu object

        :param logging: Turn logging on or off. Default is on.
        :param verbose: Turn tracking on or off. Default is on.
        :param store_supported_responses: Create list of supported responses
                                          if True.
        :param lookahead: Configuration for lookahead when computing supported
                          responses
        """
        self.state = EcuState()
        self.verbose = verbose
        self.logging = logging
        self.store_supported_responses = store_supported_responses
        self.lookahead = lookahead
        self.log = defaultdict(list)  # type: Dict[str, List[Any]]
        self.__supported_responses = list()  # type: List[EcuResponse]
        self.__unanswered_packets = PacketList()

    def reset(self):
        # type: () -> None
        self.state = EcuState(session=1)

    def update(self, p):
        # type: (Union[Packet, PacketList]) -> None
        if isinstance(p, PacketList):
            for pkt in p:
                self.update(pkt)
        elif not isinstance(p, Packet):
            raise TypeError("Provide a Packet object for an update")
        else:
            self.__update(p)

    def __update(self, pkt):
        # type: (Packet) -> None
        if self.verbose:
            print(repr(self), repr(pkt))
        if self.store_supported_responses:
            self.__update_supported_responses(pkt)
        if self.logging:
            self.__update_log(pkt)
        self.__update_internal_state(pkt)

    def __update_log(self, pkt):
        # type: (Packet) -> None
        for layer in pkt.layers():
            if hasattr(layer, "get_log"):
                log_key, log_value = layer.get_log(pkt)
                self.log[log_key].append((pkt.time, log_value))

    def __update_internal_state(self, pkt):
        # type: (Packet) -> None
        EcuStateModifier.get_modified_ecu_state(pkt, self.state, True)

    def __update_supported_responses(self, pkt):
        # type: (Packet) -> None
        self.__unanswered_packets.append(pkt)
        reduced_plist = self.__unanswered_packets[-self.lookahead:]
        answered, unanswered = reduced_plist.sr(lookahead=self.lookahead)
        for _, resp in answered:
            added = False
            for sup_resp in self.__supported_responses:
                if resp == sup_resp.key_response:
                    if sup_resp.states is not None and \
                            self.state not in sup_resp.states:
                        sup_resp.states.append(copy.copy(self.state))
                    added = True
                    break

            if added:
                continue

            ecu_resp = EcuResponse(copy.copy(self.state), responses=resp)
            if self.verbose:
                print("[+] ", repr(ecu_resp))
            self.__supported_responses.append(ecu_resp)

        self.__unanswered_packets = unanswered

    @property
    def supported_responses(self):
        # type: () -> List[EcuResponse]
        def sort_key_func(resp):
            # type: (EcuResponse) -> Tuple[bool, int, int, int]
            """
            This sorts responses in the following order:
            1. Positive responses first
            2. Lower ServiceID first
            3. Less states first
            4. Longer (more specific) responses first
            :param resp: EcuResponse to be sorted
            :return: Tuple as sort key
            """
            return (resp.key_response.service == 0x7f,
                    resp.key_response.service,
                    0xffffffff - len(resp.states or []),
                    0xffffffff - len(resp.key_response))

        self.__supported_responses.sort(key=sort_key_func)
        return self.__supported_responses

    @property
    def unanswered_packets(self):
        # type: () -> PacketList
        return self.__unanswered_packets

    def __repr__(self):
        # type: () -> str
        return repr(self.state)


class EcuSession(DefaultSession):
    """Tracks modification to an Ecu 'on-the-flow'.

    Usage:
    >>> sniff(session=EcuSession)
    """
    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        DefaultSession.__init__(self, *args, **kwargs)
        self.ecu = Ecu(logging=kwargs.pop("logging", True),
                       verbose=kwargs.pop("verbose", True),
                       store_supported_responses=kwargs.pop("store_supported_responses", True))  # noqa: E501

    def on_packet_received(self, pkt):
        # type: (Optional[Union[Packet, List[Packet]]]) -> None
        if not pkt:
            return
        if isinstance(pkt, list):
            for p in pkt:
                EcuSession.on_packet_received(self, p)
            return
        self.ecu.update(pkt)
        DefaultSession.on_packet_received(self, pkt)


class EcuResponse:
    """Encapsulates responses and the according EcuStates.
    A list of this objects can be used to configure an Ecu_am.
    This is useful, if you want to clone the behaviour of a real Ecu.

    Usage:
    >>> EcuResponse(EcuState(session=2, security_level=2), responses=UDS()/UDS_RDBIPR(dataIdentifier=2)/Raw(b"deadbeef1"))  # noqa: E501
    >>> EcuResponse([EcuState(session=range(2, 5), security_level=2), EcuState(session=3, security_level=5)], responses=UDS()/UDS_RDBIPR(dataIdentifier=9)/Raw(b"deadbeef4"))  # noqa: E501
    """
    def __init__(self, state=None, responses=Raw(b"\x7f\x10"), answers=None):
        # type: (Optional[Union[EcuState, Iterable[EcuState]]], Union[Iterable[Packet], PacketList, Packet], Optional[Callable[[Packet, Packet], bool]]) -> None  # noqa: E501
        """
        Initialize an EcuResponse capsule

        :param state: EcuState or list of EcuStates in which this response
                      is allowed to be sent. If no state provided, the response
                      packet will always be send.
        :param responses: A Packet or a list of Packet objects. By default the
                          last packet is asked if it answers an incoming
                          packet. This allows to send for example
                          `requestCorrectlyReceived-ResponsePending` packets.
        :param answers: Optional argument to provide a custom answer here:
                        `lambda resp, req: return resp.answers(req)`
                        This allows the modification of a response depending
                        on a request. Custom SecurityAccess mechanisms can
                        be implemented in this way or generic NegativeResponse
                        messages which answers to everything can be realized
                        in this way.
        """
        if state is None:
            self.__states = None  # type: Optional[List[EcuState]]
        else:
            if hasattr(state, "__iter__"):
                state = cast(List[EcuState], state)
                self.__states = state
            else:
                state = cast(EcuState, state)
                self.__states = [state]

        if isinstance(responses, PacketList):
            self.__responses = responses  # type: PacketList
        elif isinstance(responses, Packet):
            self.__responses = PacketList([responses])
        elif hasattr(responses, "__iter__"):
            responses = cast(List[Packet], responses)
            self.__responses = PacketList(responses)
        else:
            raise TypeError(
                "Can't handle type %s as response" % type(responses))

        self.__custom_answers = answers

    @property
    def states(self):
        # type: () -> Optional[List[EcuState]]
        return self.__states

    @property
    def responses(self):
        # type: () -> PacketList
        return self.__responses

    @property
    def key_response(self):
        # type: () -> Packet
        pkt = self.__responses[-1]  # type: Packet
        return pkt

    def supports_state(self, state):
        # type: (EcuState) -> bool
        if self.__states is None or len(self.__states) == 0:
            return True
        else:
            return any(s == state or state in s for s in self.__states)

    def answers(self, other):
        # type: (Packet) -> Union[int, bool]
        if self.__custom_answers is not None:
            return self.__custom_answers(self.key_response, other)
        else:
            return self.key_response.answers(other)

    def __repr__(self):
        # type: () -> str
        return "%s, responses=%s" % \
               (repr(self.__states),
                [resp.summary() for resp in self.__responses])

    def __eq__(self, other):
        # type: (object) -> bool
        other = cast(EcuResponse, other)

        responses_equal = \
            len(self.responses) == len(other.responses) and \
            all(bytes(x) == bytes(y) for x, y in zip(self.responses,
                                                     other.responses))
        if self.__states is None:
            return responses_equal
        else:
            return any(other.supports_state(s) for s in self.__states) and \
                responses_equal

    def __ne__(self, other):
        # type: (object) -> bool
        # Python 2.7 compat
        return not self == other

    def command(self):
        # type: () -> str
        if self.__states is not None:
            return "EcuResponse(%s, responses=%s)" % (
                "[" + ", ".join(s.command() for s in self.__states) + "]",
                "[" + ", ".join(p.command() for p in self.__responses) + "]")
        else:
            return "EcuResponse(responses=%s)" % "[" + ", ".join(
                p.command() for p in self.__responses) + "]"

    __hash__ = None  # type: ignore


conf.contribs['EcuAnsweringMachine'] = {'send_delay': 0}


class EcuAnsweringMachine(AnsweringMachine):
    """AnsweringMachine which emulates the basic behaviour of a real world ECU.
    Provide a list of ``EcuResponse`` objects to configure the behaviour of this
    AnsweringMachine.

    Usage:
    >>> resp = EcuResponse(session=range(0,255), security_level=0, responses=UDS() / UDS_NR(negativeResponseCode=0x7f, requestServiceId=0x10))
    >>> sock = ISOTPSocket(can_iface, sid=0x700, did=0x600, basecls=UDS)
    >>> answering_machine = EcuAnsweringMachine(supported_responses=[resp], main_socket=sock, basecls=UDS)
    >>> sim = threading.Thread(target=answering_machine, kwargs={'count': 4, 'timeout':5})
    >>> sim.start()  # noqa: E501
    """
    function_name = "EcuAnsweringMachine"
    sniff_options_list = ["store", "opened_socket", "count", "filter", "prn",
                          "stop_filter", "timeout"]

    def parse_options(self, supported_responses=None,
                      main_socket=None, broadcast_socket=None, basecls=Raw,
                      timeout=None, initial_ecu_state=None):
        # type: (Optional[List[EcuResponse]], Optional[SuperSocket], Optional[SuperSocket], Type[Packet], Optional[Union[int, float]], Optional[EcuState]) -> None  # noqa: E501
        """
        :param supported_responses: List of ``EcuResponse`` objects to define
                                    the behaviour. The default response is
                                    ``generalReject``.
        :param main_socket: Defines the object of the socket to send
                            and receive packets.
        :param broadcast_socket: Defines the object of the broadcast socket.
                                 Listen-only, responds with the main_socket.
                                 `None` to disable broadcast capabilities.
        :param basecls: Provide a basecls of the used protocol
        :param timeout: Specifies the timeout for sniffing in seconds.
        """
        self.__ecu_state = EcuState(session=1)
        self.__main_socket = main_socket  # type: Optional[SuperSocket]
        self.__sockets = [self.__main_socket]

        if broadcast_socket is not None:
            self.__sockets.append(broadcast_socket)

        if initial_ecu_state:
            self.__ecu_state = initial_ecu_state

        self.__basecls = basecls  # type: Type[Packet]
        self.__supported_responses = supported_responses

        self.sniff_options["timeout"] = timeout
        self.sniff_options["opened_socket"] = self.__sockets

    @property
    def state(self):
        # type: () -> EcuState
        return self.__ecu_state

    def is_request(self, req):
        # type: (Packet) -> bool
        return req.__class__ == self.__basecls

    def print_reply(self, req, reply):
        # type: (Packet, PacketList) -> None
        print("%s ==> %s" % (req.summary(), [res.summary() for res in reply]))

    def make_reply(self, req):
        # type: (Packet) -> PacketList
        if self.__supported_responses is not None:
            for resp in self.__supported_responses:
                if not isinstance(resp, EcuResponse):
                    raise TypeError("Unsupported type for response. "
                                    "Please use `EcuResponse` objects. ")

                if not resp.supports_state(self.__ecu_state):
                    continue

                if not resp.answers(req):
                    continue

                for r in resp.responses:
                    EcuStateModifier.get_modified_ecu_state(
                        r, self.__ecu_state, True)

                return resp.responses

        return PacketList([self.__basecls(
            b"\x7f" + bytes(req)[0:1] + b"\x10")])

    def send_reply(self, reply):
        # type: (PacketList) -> None
        for p in reply:
            time.sleep(conf.contribs['EcuAnsweringMachine']['send_delay'])
            if len(reply) > 1:
                time.sleep(random.uniform(0.01, 0.5))
            if self.__main_socket:
                self.__main_socket.send(p)
