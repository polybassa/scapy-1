# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Classes that implement CBOR (Concise Binary Object Representation) data
structures as packet fields.  Modelled after scapy/asn1fields.py.
"""

import copy

from dataclasses import dataclass
from functools import reduce

from scapy.cbor.cbor import (
    CBOR_Decoding_Error,
    CBOR_Encoding_Error,
    CBOR_MajorTypes,
    CBOR_Object,
    CBOR_UNSIGNED_INTEGER,
    CBOR_NEGATIVE_INTEGER,
    CBOR_BYTE_STRING,
    CBOR_TEXT_STRING,
    CBOR_ARRAY,
    CBOR_SEMANTIC_TAG,
    CBOR_FALSE,
    CBOR_TRUE,
    CBOR_NULL,
    CBOR_UNDEFINED,
    CBOR_UNDEFINED_VALUE,
    CBOR_NO_ITEM,
    CBOR_FLOAT,
    CBOR_MAP,
    CBOR_SIMPLE_VALUE,
    CBORTagValue,
    CBORSimpleValue,
)
from scapy.cbor.cborcodec import (
    CBOR_Codec_Decoding_Error,
    CBOR_INDEFINITE,
    CBOR_decode_head,
    CBOR_encode_head,
    CBOR_encode_indefinite_head,
    CBOR_encode_break,
    cbor_is_break,
    cbor_consume_break,
    CBORcodec_Object,
    CBORcodec_UNSIGNED_INTEGER,
    CBORcodec_NEGATIVE_INTEGER,
    CBORcodec_BYTE_STRING,
    CBORcodec_TEXT_STRING,
    CBORcodec_SIMPLE_AND_FLOAT,
)
from scapy.base_classes import BasePacket
from scapy.error import log_runtime
from scapy.packet import Packet
from scapy.volatile import (
    RandChoice,
    RandFloat,
    RandNum,
    RandString,
    RandField,
)

from scapy import packet, fields, config

from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from scapy.cborpacket import CBOR_Packet  # noqa: F401


class CBORF_badsequence(Exception):
    pass


class CBOR_Type_Mismatch(CBOR_Decoding_Error):
    """Raised when a CBOR field encounters an unexpected major type."""


@dataclass(frozen=True)
class CBORBuildResult(object):
    data: bytes = b""
    items: int = 0


@dataclass(frozen=True)
class CBORDissectResult(object):
    remaining: bytes = b""
    items: int = 0


def cbor_object_to_python(obj):
    # type: (Any) -> Any
    """Convert a :class:`CBOR_Object` tree to native Python values."""
    if not isinstance(obj, CBOR_Object):
        return obj
    if isinstance(obj, CBOR_UNDEFINED):
        return CBOR_UNDEFINED_VALUE
    if isinstance(obj, CBOR_ARRAY):
        return [cbor_object_to_python(item) for item in obj.val]
    if isinstance(obj, CBOR_MAP):
        return {
            cbor_object_to_python(key): cbor_object_to_python(value)
            for key, value in obj.val.items()
        }
    if isinstance(obj, CBOR_SEMANTIC_TAG):
        tag_num, item = obj.val
        return CBORTagValue(tag_num, cbor_object_to_python(item))
    if isinstance(obj, CBOR_SIMPLE_VALUE):
        return CBORSimpleValue(obj.val)
    return obj.val


class CBORF_element(object):
    """Base class for CBOR packet field elements."""

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        data = self.build(pkt)
        return CBORBuildResult(data, self.min_items(pkt))

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        remaining = self.dissect(pkt, s)
        return CBORDissectResult(remaining, self.max_items(pkt))

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        raise NotImplementedError

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        raise NotImplementedError

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


##########################
#    Basic CBOR Field    #
##########################

_I = TypeVar('_I')  # Internal storage


class CBORF_field(CBORF_element, Generic[_I]):
    """Base class for CBOR items in packet fields.

    Packet fields store native Python values (``int``, ``bytes``, ``str``,
    ``bool``, ``float``, ``list``, ``dict``, ``None``).
    """
    holds_packets = 0
    islist = 0
    allows_none = False
    CBOR_tag = None  # type: Optional[Any]

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[_I]
                 ):
        # type: (...) -> None
        self.name = name
        self.default = default
        self.owners = []  # type: List[Type[CBOR_Packet]]

    def register_owner(self, cls):
        # type: (Type[CBOR_Packet]) -> None
        self.owners.append(cls)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, _I) -> str
        return repr(x)

    def i2h(self, pkt, x):
        # type: (CBOR_Packet, _I) -> Any
        return x

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[_I, bytes]
        raise NotImplementedError(
            "Subclasses must implement m2i for %s" % type(self))

    def encode_value(self, x):
        # type: (Any) -> bytes
        """Encode a native Python value to CBOR bytes."""
        raise NotImplementedError(
            "Subclasses must implement encode_value for %s" % type(self))

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Union[bytes, _I]) -> bytes
        if x is None:
            return b""
        if isinstance(x, bytes):
            return x
        return self.encode_value(x)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> _I
        if isinstance(x, CBOR_Object):
            return cast(_I, x.val)
        return cast(_I, x)

    def extract_packet(self,
                       cls,  # type: Type[CBOR_Packet]
                       s,  # type: bytes
                       _underlayer=None,  # type: Optional[CBOR_Packet]
                       ):
        # type: (...) -> Tuple[CBOR_Packet, bytes]
        try:
            c = cls(s, _underlayer=_underlayer)
        except CBORF_badsequence:
            c = packet.Raw(s, _underlayer=_underlayer)  # type: ignore
        craw = c.getlayer(config.conf.raw_layer)
        cpad = c.getlayer(config.conf.padding_layer)
        s = b""
        if craw is not None:
            s = craw.load
            if craw.underlayer:
                del craw.underlayer.payload
        if cpad is not None:
            s = cpad.load
            if cpad.underlayer:
                del cpad.underlayer.payload
        return c, s

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            if self.allows_none:
                return CBORBuildResult(b"", 0)
            raise CBOR_Encoding_Error(
                "Required field %r is None" % self.name)
        return CBORBuildResult(self.encode_value(val), 1)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        val, remain = self.m2i(pkt, s)
        self.set_val(pkt, val)
        return CBORDissectResult(remain, 1)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def do_copy(self, x):
        # type: (Any) -> Any
        if isinstance(x, list):
            x = x[:]
            for i in range(len(x)):
                if isinstance(x[i], BasePacket):
                    x[i] = x[i].copy()
            return x
        if hasattr(x, "copy"):
            return x.copy()
        return x

    def set_val(self, pkt, val):
        # type: (CBOR_Packet, Any) -> None
        pkt.setfieldval(self.name, val)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return pkt.getfieldval(self.name) is None

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [self]

    def __str__(self):
        # type: () -> str
        return repr(self)

    def randval(self):
        # type: () -> RandField[_I]
        return cast(RandField[_I], RandNum(0, 2 ** 32))

    def copy(self):
        # type: () -> CBORF_field[_I]
        return copy.copy(self)


class CBORF_ANY(CBORF_field[Any]):
    """Represent any well-formed CBOR value, including recursion."""

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        return CBORBuildResult(self.encode_value(val), 1)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Any, bytes]
        obj, remain = CBORcodec_Object.decode_cbor_item(s)
        return cbor_object_to_python(obj), remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        if isinstance(x, CBOR_Object):
            x = cbor_object_to_python(x)
        return CBORcodec_Object.encode_cbor_item(x)


#############################
#    Simple CBOR Fields     #
#############################

class CBORF_UNSIGNED_INTEGER(CBORF_field[int]):
    """CBOR unsigned integer field (major type 0)."""
    CBOR_tag = CBOR_MajorTypes.UNSIGNED_INTEGER

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i < 0 or i > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Encoding_Error(
                "Unsigned integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        obj, remain = CBORcodec_UNSIGNED_INTEGER.dec(s)
        if not isinstance(obj, CBOR_UNSIGNED_INTEGER):
            raise CBOR_Type_Mismatch(
                "Expected unsigned integer, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_UNSIGNED_INTEGER.enc(int(x))

    def randval(self):
        # type: () -> RandNum
        return RandNum(0, 2 ** 64 - 1)


class CBORF_NEGATIVE_INTEGER(CBORF_field[int]):
    """CBOR negative integer field (major type 1)."""
    CBOR_tag = CBOR_MajorTypes.NEGATIVE_INTEGER

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i >= 0 or i < -(1 << 64):
            raise CBOR_Encoding_Error(
                "Negative integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        obj, remain = CBORcodec_NEGATIVE_INTEGER.dec(s)
        if not isinstance(obj, CBOR_NEGATIVE_INTEGER):
            raise CBOR_Type_Mismatch(
                "Expected negative integer, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_NEGATIVE_INTEGER.enc(int(x))

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, -1)


class CBORF_INTEGER(CBORF_field[int]):
    """CBOR integer field handling both positive and negative values."""

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> int
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        i = int(x)
        if i < -(1 << 64) or i > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Encoding_Error(
                "Integer out of CBOR range: %r" % (i,))
        return i

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        if not s:
            raise CBOR_Decoding_Error("Empty CBOR data")
        major_type = (s[0] >> 5) & 0x7
        if major_type == 0:
            obj, remain = CBORcodec_UNSIGNED_INTEGER.dec(s)
            return obj.val, remain
        elif major_type == 1:
            obj, remain = CBORcodec_NEGATIVE_INTEGER.dec(s)
            return obj.val, remain
        raise CBOR_Type_Mismatch(
            "Expected integer (major type 0 or 1), got %d" % major_type)

    def encode_value(self, x):
        # type: (Any) -> bytes
        i = int(x)
        if i >= 0:
            return CBORcodec_UNSIGNED_INTEGER.enc(i)
        return CBORcodec_NEGATIVE_INTEGER.enc(i)

    def randval(self):
        # type: () -> RandNum
        return RandNum(-2 ** 64, 2 ** 64 - 1)


class CBORF_BYTE_STRING(CBORF_field[bytes]):
    """CBOR byte string field (major type 2)."""
    CBOR_tag = CBOR_MajorTypes.BYTE_STRING

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        return bytes(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[bytes, bytes]
        obj, remain = CBORcodec_BYTE_STRING.dec(s)
        if not isinstance(obj, CBOR_BYTE_STRING):
            raise CBOR_Type_Mismatch(
                "Expected byte string, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_BYTE_STRING.enc(bytes(x))

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_BYTE_STRING_PACKET(CBORF_field[Packet]):
    """CBOR byte string which wraps another packet field.

    The inner packet may or may not itself be CBOR or CBOR sequence data.
    """
    CBOR_tag = CBOR_MajorTypes.BYTE_STRING
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Packet]
                 pkt_cls=None,  # type: Optional[Type[Packet]]
                 cls_cb=None,  # type: Optional[Callable[[Packet, bytes], Optional[Type[Packet]]]]  # noqa: E501
                 ):
        # type: (...) -> None
        if pkt_cls is None and cls_cb is None:
            raise ValueError('Must give one of pkt_cls or cls_cb')
        super(CBORF_BYTE_STRING_PACKET, self).__init__(name, default)
        self.pkt_cls = pkt_cls
        self.cls_cb = cls_cb

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> Packet
        if isinstance(x, CBOR_BYTE_STRING):
            x = x.val
        if isinstance(x, (bytes, bytearray)):
            pkt_cls = self.pkt_cls or packet.Raw
            try:
                return pkt_cls(bytes(x), _underlayer=pkt)
            except Exception:
                log_runtime.exception(
                    "Failed to decode byte string content to %s", pkt_cls)
                return packet.Raw(bytes(x), _underlayer=pkt)  # type: ignore
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return cast(Packet, x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[Packet, bytes]
        obj, remain = CBORcodec_BYTE_STRING.dec(s)
        if not isinstance(obj, CBOR_BYTE_STRING):
            raise CBOR_Type_Mismatch(
                "Expected byte string, got %r" % obj)

        if self.pkt_cls is not None:
            pkt_cls = self.pkt_cls
        elif self.cls_cb is not None:
            pkt_cls = self.cls_cb(pkt, obj.val)
        else:
            pkt_cls = None
        if pkt_cls is None:
            pkt_cls = packet.Raw

        try:
            sub = pkt_cls(obj.val, _underlayer=pkt)
        except Exception:
            log_runtime.exception(
                "Failed to decode byte string content to %s", pkt_cls)
            sub = packet.Raw(obj.val, _underlayer=pkt)  # type: ignore

        return sub, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_BYTE_STRING.enc(bytes(x))


class CBORF_TEXT_STRING(CBORF_field[str]):
    """CBOR text string field (major type 3)."""
    CBOR_tag = CBOR_MajorTypes.TEXT_STRING

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if isinstance(x, CBOR_Object):
            x = x.val
        if x is None:
            return None  # type: ignore
        return str(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[str, bytes]
        obj, remain = CBORcodec_TEXT_STRING.dec(s)
        if not isinstance(obj, CBOR_TEXT_STRING):
            raise CBOR_Type_Mismatch(
                "Expected text string, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_TEXT_STRING.enc(str(x))

    def randval(self):
        # type: () -> RandString
        return RandString(RandNum(0, 1000))


class CBORF_BOOLEAN(CBORF_field[bool]):
    """CBOR boolean field (major type 7, simple values 20/21)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bool
        if x is None:
            return None  # type: ignore
        if isinstance(x, (CBOR_FALSE, CBOR_TRUE)):
            return x.val
        if isinstance(x, CBOR_Object):
            return bool(x.val)
        return bool(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[bool, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, (CBOR_FALSE, CBOR_TRUE)):
            raise CBOR_Type_Mismatch(
                "Expected boolean (CBOR_FALSE or CBOR_TRUE), got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_SIMPLE_AND_FLOAT.enc(bool(x))

    def randval(self):
        # type: () -> RandChoice
        return RandChoice(True, False)


class CBORF_NULL(CBORF_field[None]):
    """CBOR null field (major type 7, simple value 22)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT
    allows_none = True

    def __init__(self,
                 name,  # type: str
                 default=None,  # type: None
                 ):
        # type: (...) -> None
        super(CBORF_NULL, self).__init__(name, None)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> None
        return None

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[None, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_NULL):
            raise CBOR_Type_Mismatch(
                "Expected null, got %r" % obj)
        return None, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBOR_NULL().enc()

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        return CBORBuildResult(self.encode_value(None), 1)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return False

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_UNDEFINED(CBORF_field[None]):
    """CBOR undefined field (major type 7, simple value 23)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT
    allows_none = True

    def __init__(self,
                 name,  # type: str
                 default=None,  # type: None
                 ):
        # type: (...) -> None
        super(CBORF_UNDEFINED, self).__init__(name, None)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> None
        return None

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[None, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_UNDEFINED):
            raise CBOR_Type_Mismatch(
                "Expected undefined, got %r" % obj)
        return None, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBOR_UNDEFINED().enc()

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        return CBORBuildResult(self.encode_value(None), 1)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return False

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_FLOAT(CBORF_field[float]):
    """CBOR float field (major type 7, double precision)."""
    CBOR_tag = CBOR_MajorTypes.SIMPLE_AND_FLOAT

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> float
        if x is None:
            return None  # type: ignore
        if isinstance(x, CBOR_FLOAT):
            return x.val
        if isinstance(x, CBOR_Object):
            return float(x.val)
        return float(x)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[float, bytes]
        obj, remain = CBORcodec_SIMPLE_AND_FLOAT.dec(s)
        if not isinstance(obj, CBOR_FLOAT):
            raise CBOR_Type_Mismatch(
                "Expected float, got %r" % obj)
        return obj.val, remain

    def encode_value(self, x):
        # type: (Any) -> bytes
        return CBORcodec_SIMPLE_AND_FLOAT.enc(float(x))

    def randval(self):
        # type: () -> RandFloat
        return RandFloat(0, 2 ** 32)


##############################
#    Structured CBOR Fields  #
##############################

class CBORF_UNSIGNED_ENUM(CBORF_UNSIGNED_INTEGER):
    """
    Display like EnumField, codec like CBORF
    """
    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[int]
                 enum,  # type: fields._EnumType[int]
                 ):
        # type: (...) -> None
        CBORF_UNSIGNED_INTEGER.__init__(self, name, default)

        self._enum = fields.EnumField(name, default, enum, "Q")

    def i2repr(self, pkt, x):
        return self._enum.i2repr(pkt, x)

    def any2i(self, pkt, x):
        if isinstance(x, CBOR_Object):
            x = x.val
        x = self._enum.any2i(pkt, x)
        return super().any2i(pkt, x)


class CBORF_UNSIGNED_FLAGS(CBORF_UNSIGNED_INTEGER):
    """
    Display like FlagsField, codec like CBORF
    """
    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[Union[int, fields.FlagValue]]
                 size,  # type: int
                 names,  # type: Union[List[str], str, Dict[int, str]]
                 ):
        # type: (...) -> None
        CBORF_UNSIGNED_INTEGER.__init__(self, name, default)

        self._flags = fields.FlagsField(name, default, size, names)

    def i2repr(self, pkt, x):
        return self._flags.i2repr(pkt, x)

    def any2i(self, pkt, x):
        if isinstance(x, CBOR_Object):
            x = x.val
        x = self._flags.any2i(pkt, x)
        return super().any2i(pkt, x)


class _CBORF_compound(CBORF_element):
    """Shared helpers for sequence-like CBOR field containers."""
    CBOR_tag = None
    holds_packets = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        self.seq = seq
        self.islist = len(seq) > 1

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return reduce(lambda x, y: x + y.get_fields_list(),
                      self.seq, [])

    def _build_children(self, pkt):
        # type: (CBOR_Packet) -> Tuple[bytes, int]
        parts = []  # type: List[bytes]
        total_items = 0
        for field in self.seq:
            result = field.build_result(pkt)
            parts.append(result.data)
            total_items += result.items
        return b"".join(parts), total_items

    def _dissect_children(self, pkt, s, count):
        # type: (CBOR_Packet, bytes, Union[int, CBOR_INDEFINITE]) -> bytes
        remaining = s
        if count is CBOR_INDEFINITE:
            for field in self.seq:
                if cbor_is_break(remaining):
                    if field.min_items(pkt) > 0:
                        raise CBOR_Decoding_Error(
                            "Indefinite array ended before required field %r"
                            % getattr(field, "name", field)
                        )
                    continue
                try:
                    result = field.dissect_result(pkt, remaining)
                except CBORF_badsequence:
                    if field.min_items(pkt) > 0:
                        raise
                    continue
                if result.items == 0 and field.min_items(pkt) > 0:
                    raise CBOR_Decoding_Error(
                        "Required field %r consumed no items"
                        % getattr(field, "name", field)
                    )
                remaining = result.remaining
            return cbor_consume_break(remaining)

        items_left = count
        for field in self.seq:
            needed = field.min_items(pkt)
            if items_left <= 0:
                if needed > 0:
                    raise CBOR_Decoding_Error("CBOR item count mismatch")
                continue
            try:
                result = field.dissect_result(pkt, remaining)
            except CBORF_badsequence:
                if needed > 0:
                    raise CBOR_Decoding_Error("CBOR item count mismatch")
                continue
            if result.items > items_left:
                raise CBOR_Decoding_Error(
                    "CBOR field consumed more items than remaining"
                )
            remaining = result.remaining
            items_left -= result.items
        if items_left != 0:
            raise CBOR_Decoding_Error("CBOR item count mismatch")
        return remaining


class CBORF_SEQUENCE(_CBORF_compound):
    """
    Unframed fixed sequence of named, typed fields.
    Analogous to ASN1F_SEQUENCE: each positional element corresponds to a
    specific CBORF_field.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_SEQUENCE(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        data, total_items = self._build_children(pkt)
        return CBORBuildResult(data, total_items)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        remaining = s
        total_items = 0
        for field in self.seq:
            try:
                result = field.dissect_result(pkt, remaining)
            except CBORF_badsequence:
                break
            remaining = result.remaining
            total_items += result.items
        return CBORDissectResult(remaining, total_items)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return sum(f.min_items(pkt) for f in self.seq)

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return sum(f.max_items(pkt) for f in self.seq)


class CBORF_ARRAY(_CBORF_compound):
    """
    CBOR array with a fixed sequence of named, typed fields (major type 4).
    Analogous to ASN1F_SEQUENCE: each positional element corresponds to a
    specific CBORF_field.  The CBOR array count must match the number of
    declared fields.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_ARRAY(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY

    encode_indefinite = False
    """Set to true to encode using indefinite length."""

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        items_data, total_items = self._build_children(pkt)
        if self.encode_indefinite:
            data = (
                CBOR_encode_indefinite_head(int(CBOR_MajorTypes.ARRAY)) +
                items_data +
                CBOR_encode_break()
            )
        else:
            data = CBOR_encode_head(int(CBOR_MajorTypes.ARRAY), total_items)
            data += items_data
        return CBORBuildResult(data, 1)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        try:
            major_type, count, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 4:
            raise CBOR_Type_Mismatch(
                "Expected major type 4 (array), got %d" % major_type)
        remaining = self._dissect_children(pkt, remaining, count)
        return CBORDissectResult(remaining, 1)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_ARRAY_INDEFINITE(CBORF_ARRAY):
    """A field to act as an array but to always encode to indefinite-length."""

    encode_indefinite = True


_ARRAY_T = Union[
    'CBOR_Packet',
    Type['CBORF_field[Any]'],
    'CBORF_PACKET',
    'CBORF_field[Any]',
]


class CBORF_SEQUENCE_OF(CBORF_field[List[Any]]):
    """
    CBOR sequence of homogeneous elements (no enveloping head).
    Analogous to ASN1F_SEQUENCE_OF: variable-length array where every
    element shares the same type, specified by ``cls``.

    ``cls`` may be a :class:`CBORF_field` class/instance (leaf type) or a
    :class:`CBOR_Packet` subclass (structured type).
    """
    CBOR_tag = None
    islist = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 cls=None,  # type: _ARRAY_T
                 cls_cb=None,  # type: Optional[Callable[[Packet, bytes], Optional[Type[Packet]]]]  # noqa: E501
                 ):
        # type: (...) -> None
        if isinstance(cls, type) and issubclass(cls, CBORF_field) or \
                isinstance(cls, CBORF_field):
            if isinstance(cls, type):
                self.item_field = cls("_item", None)  # type: ignore
            else:
                self.item_field = cls
            self._extract_item = lambda s, pkt: self.item_field.m2i(pkt, s)
            self.holds_packets = 0
        elif hasattr(cls, "CBOR_root") or callable(cls):
            self.cls = cast("Type[CBOR_Packet]", cls)
            self._extract_item = lambda s, pkt: self.extract_packet(
                self.cls, s, _underlayer=pkt)
            self.holds_packets = 1
        elif cls_cb is not None:
            def extract(s, pkt):
                pkt_cls = cls_cb(pkt, s)
                if pkt_cls is CBOR_NO_ITEM or pkt_cls is None:
                    return CBOR_NO_ITEM, s
                return self.extract_packet(pkt_cls, s, _underlayer=pkt)
            self._extract_item = extract
            self.holds_packets = 1
        else:
            raise ValueError("cls must be a CBORF_field or CBOR_Packet")
        super(CBORF_SEQUENCE_OF, self).__init__(name, default)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        lst = []  # type: List[Any]
        while s:
            before_len = len(s)
            c, s = self._extract_item(s, pkt)  # type: ignore
            if c is CBOR_NO_ITEM:
                break
            if len(s) >= before_len:
                raise CBOR_Decoding_Error(
                    "CBOR sequence decode made no progress")
            lst.append(c)
        return lst, s

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required collection field %r is None" % self.name)
        parts = []  # type: List[bytes]
        total_items = 0
        for item in val:
            if self.holds_packets:
                # Wire bytes via Packet.build for protocol hooks (e.g. CRC).
                parts.append(bytes(item))
                if hasattr(item, "cbor_build_result"):
                    total_items += item.cbor_build_result().items
                else:
                    total_items += 1
            else:
                parts.append(self.item_field.encode_value(item))
                total_items += 1
        return CBORBuildResult(b"".join(parts), total_items)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if self.holds_packets:
            return repr(x)
        elif x is None:
            return "()"
        else:
            return "(%s)" % ", ".join(
                self.item_field.i2repr(pkt, item) for item in x
            )

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class CBORF_ARRAY_OF(CBORF_field[List[Any]]):
    """
    CBOR array of homogeneous elements (major type 4).
    Analogous to ASN1F_SEQUENCE_OF: variable-length array where every
    element shares the same type, specified by ``cls``.

    ``cls`` may be a :class:`CBORF_field` class/instance (leaf type) or a
    :class:`CBOR_Packet` subclass (structured type).
    """
    CBOR_tag = CBOR_MajorTypes.ARRAY
    islist = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 cls,  # type: _ARRAY_T
                 ):
        # type: (...) -> None
        if isinstance(cls, type) and issubclass(cls, CBORF_field) or \
                isinstance(cls, CBORF_field):
            if isinstance(cls, type):
                self.item_field = cls("_item", None)  # type: ignore
            else:
                self.item_field = cls
            self._extract_item = lambda s, pkt: self.item_field.m2i(pkt, s)
            self.holds_packets = 0
        elif hasattr(cls, "CBOR_root") or callable(cls):
            self.cls = cast("Type[CBOR_Packet]", cls)
            self._extract_item = lambda s, pkt: self.extract_packet(
                self.cls, s, _underlayer=pkt)
            self.holds_packets = 1
        else:
            raise ValueError("cls must be a CBORF_field or CBOR_Packet")
        super(CBORF_ARRAY_OF, self).__init__(name, default)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[List[Any], bytes]
        try:
            major_type, count, s = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 4:
            raise CBOR_Type_Mismatch(
                "Expected major type 4 (array), got %d" % major_type)
        if count is CBOR_INDEFINITE:
            raise CBOR_Decoding_Error(
                "CBORF_ARRAY_OF does not support indefinite-length arrays")
        lst = []  # type: List[Any]
        for _ in range(count):
            c, s = self._extract_item(s, pkt)  # type: ignore
            if c is CBOR_NO_ITEM:
                raise CBOR_Decoding_Error(
                    "Unexpected end of CBOR array element")
            lst.append(c)
        return lst, s

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        val = pkt.getfieldval(self.name)
        if val is None:
            raise CBOR_Encoding_Error(
                "Required collection field %r is None" % self.name)
        parts = []  # type: List[bytes]
        for item in val:
            if self.holds_packets:
                if hasattr(item, "cbor_build_result"):
                    card = item.cbor_build_result()
                    if card.items != 1:
                        raise CBOR_Encoding_Error(
                            "ARRAY_OF packet elements must emit exactly "
                            "one CBOR item, got %d" % card.items
                        )
                parts.append(bytes(item))
            else:
                parts.append(self.item_field.encode_value(item))
        items = b"".join(parts)
        data = CBOR_encode_head(4, len(val)) + items
        return CBORBuildResult(data, 1)

    def i2repr(self, pkt, x):
        # type: (CBOR_Packet, Any) -> str
        if self.holds_packets:
            return repr(x)
        elif x is None:
            return "[]"
        else:
            return "[%s]" % ", ".join(
                self.item_field.i2repr(pkt, item) for item in x
            )

    def __repr__(self):
        # type: () -> str
        return "<%s %s>" % (self.__class__.__name__, self.name)


class CBORF_MAP(CBORF_element):
    """
    CBOR map with a fixed set of named, typed fields (major type 5).

    Each field in ``seq`` represents one key-value pair.  The key is the
    field's ``name`` encoded as a CBOR text string.  The value is encoded
    and decoded by the corresponding :class:`CBORF_field`.

    Example::

        class MyCBOR(CBOR_Packet):
            CBOR_root = CBORF_MAP(
                CBORF_INTEGER("version", 1),
                CBORF_TEXT_STRING("name", ""),
            )
    """
    CBOR_tag = CBOR_MajorTypes.MAP
    holds_packets = 1
    islist = 1

    def __init__(self, *seq, **kwargs):
        # type: (*Any, **Any) -> None
        self.seq = seq

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.seq)

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return all(f.is_empty(pkt) for f in self.seq)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return reduce(lambda x, y: x + y.get_fields_list(),
                      self.seq, [])

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        parts = []  # type: List[bytes]
        pair_count = 0
        for fld in self.seq:
            value_result = fld.build_result(pkt)
            if value_result.items == 0:
                continue
            if value_result.items != 1:
                raise CBOR_Encoding_Error(
                    "CBOR map value for %r must emit exactly one item"
                    % fld.name
                )
            parts.append(CBORcodec_TEXT_STRING.enc(fld.name))
            parts.append(value_result.data)
            pair_count += 1
        data = CBOR_encode_head(5, pair_count) + b"".join(parts)
        return CBORBuildResult(data, 1)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        try:
            major_type, count, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 5:
            raise CBOR_Type_Mismatch(
                "Expected major type 5 (map), got %d" % major_type)

        field_map = {f.name: f for f in self.seq}
        seen_keys = set()  # type: set[str]

        def _map_text_key(key_obj):
            # type: (Any) -> str
            if not isinstance(key_obj, CBOR_TEXT_STRING):
                raise CBOR_Decoding_Error(
                    "CBOR map field key must be a text string, got %r"
                    % (key_obj,)
                )
            key = key_obj.val
            if key in seen_keys:
                raise CBOR_Decoding_Error(
                    "Duplicate CBOR map field name: %r" % (key,)
                )
            seen_keys.add(key)
            return key

        if count is CBOR_INDEFINITE:
            while True:
                if cbor_is_break(remaining):
                    remaining = cbor_consume_break(remaining)
                    break
                key_obj, remaining = CBORcodec_Object.decode_cbor_item(
                    remaining)
                key = _map_text_key(key_obj)
                fld = field_map.get(key)
                if fld is not None:
                    remaining = fld.dissect(pkt, remaining)
                else:
                    _unknown, remaining = CBORcodec_Object.decode_cbor_item(
                        remaining)
        else:
            for _ in range(count):
                key_obj, remaining = CBORcodec_Object.decode_cbor_item(
                    remaining)
                key = _map_text_key(key_obj)
                fld = field_map.get(key)
                if fld is not None:
                    remaining = fld.dissect(pkt, remaining)
                else:
                    _unknown, remaining = CBORcodec_Object.decode_cbor_item(
                        remaining)
        return CBORDissectResult(remaining, 1)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 1


class CBORF_SEMANTIC_TAG(CBORF_field[int]):
    """
    CBOR semantic tag field (major type 6).

    Wraps an ``inner_field`` with the given numeric ``tag_num``.  The inner
    field handles encoding and decoding of the tagged value.  The outer field
    (named ``name``) stores the tag number, while the inner field stores its
    value under its own name on the packet.

    Example::

        class TimestampPkt(CBOR_Packet):
            CBOR_root = CBORF_SEMANTIC_TAG(
                "tag_info", None, 1, CBORF_INTEGER("ts", 0)
            )
    """
    CBOR_tag = CBOR_MajorTypes.TAG
    holds_packets = 0

    def __init__(self,
                 name,  # type: str
                 default,  # type: Any
                 tag_num,  # type: int
                 inner_field,  # type: CBORF_field[Any]
                 ):
        # type: (...) -> None
        self.tag_num = tag_num
        if tag_num < 0 or tag_num > 0xFFFFFFFFFFFFFFFF:
            raise CBOR_Encoding_Error(
                "Semantic tag number out of uint64 range")
        self.inner_field = inner_field
        super(CBORF_SEMANTIC_TAG, self).__init__(name, tag_num)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[int, bytes]
        try:
            major_type, tag_num, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 6:
            raise CBOR_Type_Mismatch(
                "Expected major type 6 (semantic tag), got %d" % major_type)
        return tag_num, remaining

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        try:
            major_type, tag_num, remaining = CBOR_decode_head(s)
        except CBOR_Codec_Decoding_Error as e:
            raise CBOR_Decoding_Error(str(e))
        if major_type != 6:
            raise CBOR_Type_Mismatch(
                "Expected major type 6 (semantic tag), got %d" % major_type)
        if tag_num != self.tag_num:
            raise CBOR_Type_Mismatch(
                "Expected tag %d, got %d" % (self.tag_num, tag_num))
        inner = self.inner_field.dissect_result(pkt, remaining)
        if inner.items != 1:
            raise CBOR_Decoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        self.set_val(pkt, tag_num)
        return CBORDissectResult(inner.remaining, 1)

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        inner = self.inner_field.build_result(pkt)
        if inner.items != 1:
            raise CBOR_Encoding_Error(
                "Semantic tag content must be exactly one CBOR item")
        data = CBOR_encode_head(6, self.tag_num) + inner.data
        return CBORBuildResult(data, 1)

    def get_fields_list(self):
        # type: () -> List[CBORF_field[Any]]
        return [self] + self.inner_field.get_fields_list()

    def is_empty(self, pkt):
        # type: (CBOR_Packet) -> bool
        return False


##############################
#    Complex CBOR Fields     #
##############################

class CBORF_optional(CBORF_element):
    """
    Wrapper making a :class:`CBORF_field` optional.

    During decoding, if the next CBOR item does not match the expected major
    type, the field value is set to ``None`` and the stream is left unchanged.
    """

    def __init__(self, field):
        # type: (CBORF_field[Any]) -> None
        self._field = field

    def __getattr__(self, attr):
        # type: (str) -> Any
        return getattr(self._field, attr)

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        if self._field.is_empty(pkt):
            return CBORBuildResult(b"", 0)
        return self._field.build_result(pkt)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        try:
            return self._field.dissect_result(pkt, s)
        except CBOR_Type_Mismatch:
            self._field.set_val(pkt, None)
            return CBORDissectResult(s, 0)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return 0

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        return self._field.max_items(pkt)


class CBORF_CONDITIONAL(CBORF_element, fields.ConditionalField):
    """
    Wrapper making a :class:`CBORF_field` conditional on some other packet
    state.
    """

    def __init__(self,
                 fld,  # type: CBORF_field[Any]
                 cond,  # type: Callable[[Packet], bool]
                 ):
        # type: (...) -> None
        fields.ConditionalField.__init__(self, fld, cond)

    def __repr__(self):
        # type: () -> str
        return "<%s%r>" % (self.__class__.__name__, self.fld)

    @property
    def owners(self):
        return self.fld.owners

    def build_result(self, pkt):
        # type: (CBOR_Packet) -> CBORBuildResult
        if self._evalcond(pkt):
            return self.fld.build_result(pkt)
        return CBORBuildResult(b"", 0)

    def dissect_result(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> CBORDissectResult
        if self._evalcond(pkt):
            return self.fld.dissect_result(pkt, s)
        return CBORDissectResult(s, 0)

    def build(self, pkt):
        # type: (CBOR_Packet) -> bytes
        return self.build_result(pkt).data

    def dissect(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> bytes
        return self.dissect_result(pkt, s).remaining

    def min_items(self, pkt):
        # type: (CBOR_Packet) -> int
        if self._evalcond(pkt):
            return self.fld.min_items(pkt)
        return 0

    def max_items(self, pkt):
        # type: (CBOR_Packet) -> int
        if self._evalcond(pkt):
            return self.fld.max_items(pkt)
        return 0


class CBORF_PACKET(CBORF_field['CBOR_Packet']):
    """
    CBOR field that encapsulates a nested :class:`CBOR_Packet`.

    The nested packet is encoded as-is (its ``CBOR_root.build()`` output)
    and decoded by instantiating ``cls`` from the current byte stream.
    """
    holds_packets = 1

    def __init__(self,
                 name,  # type: str
                 default,  # type: Optional[CBOR_Packet]
                 cls,  # type: Type[CBOR_Packet]
                 ):
        # type: (...) -> None
        self.cls = cls
        super(CBORF_PACKET, self).__init__(name, default)

    def m2i(self, pkt, s):
        # type: (CBOR_Packet, bytes) -> Tuple[CBOR_Packet, bytes]
        return self.extract_packet(self.cls, s, _underlayer=pkt)

    def i2m(self, pkt, x):
        # type: (CBOR_Packet, Any) -> bytes
        if x is None:
            return b""
        if isinstance(x, bytes):
            return x
        return bytes(x)

    def any2i(self, pkt, x):
        # type: (CBOR_Packet, Any) -> CBOR_Packet
        if hasattr(x, "add_underlayer"):
            x.add_underlayer(pkt)
        return cast('CBOR_Packet', x)

    def encode_value(self, x):
        # type: (Any) -> bytes
        return bytes(x)

    def randval(self):  # type: ignore
        # type: () -> CBOR_Packet
        return packet.fuzz(self.cls())
