# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Brian Sipos <brian.sipos@gmail.com>

# scapy.contrib.description = Bundle Protocol Version 7 (BPv7)
# scapy.contrib.status = loads

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import datetime
import enum
import struct
from typing import Any, Callable, ClassVar, Iterator, Optional, Union, cast

from scapy import volatile
from scapy.cbor.cborcodec import CBOR_decode_head, CBOR_MajorTypes, cbor_is_break
from scapy.cbor import (
    CBORF_field,
    CBORF_UNSIGNED_INTEGER,
    CBORF_ARRAY,
    CBORF_ARRAY_INDEFINITE,
    CBORF_BYTE_STRING,
    CBORF_CONDITIONAL,
    CBORF_SEQUENCE_OF,
    CBORF_PACKET,
    CBORF_BYTE_STRING_PACKET,
    CBORF_UNSIGNED_ENUM,
    CBORF_UNSIGNED_FLAGS,
    CBORcodec_ARRAY,
    CBOR_UNSIGNED_INTEGER,
    CBOR_TEXT_STRING,
    CBOR_ARRAY,
    CBOR_Object,
)
from scapy.cborpacket import CBOR_Packet
from scapy.error import log_runtime
from scapy.libs.crc import CRC, CRC_16_X25, CRC_32C
from scapy.packet import Packet

_MISSING = object()


@contextmanager
def _temporary_internal_field(pkt: Packet, name: str, value: Any) -> Iterator[None]:
    """Temporarily set a field value via the internal fields dict."""
    fields = pkt.fields
    had = name in fields
    old = fields.get(name, _MISSING)
    fields[name] = value
    try:
        yield
    finally:
        if had:
            fields[name] = old
        else:
            fields.pop(name, None)


def _native_int(val: Any) -> int:
    if isinstance(val, CBOR_Object):
        return int(val.val)
    return int(val)


def _crc_bytes(val: Any) -> bytes:
    if val is None or val is _MISSING:
        return b""
    if isinstance(val, CBOR_Object):
        return cast(bytes, val.val)
    return cast(bytes, val)


class DtnTimeField(CBORF_UNSIGNED_INTEGER):
    """A DTN time value representing number of milliseconds from the
    DTN epoch 2000-01-01T00:00:00Z.

    This value is automatically converted from a
    :py:cls:`datetime.datetime` object and human friendly text in ISO8601
    format.
    The special human value "zero" represents the zero value time.
    """

    DTN_EPOCH = datetime.datetime(2000, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)

    @staticmethod
    def datetime_to_dtntime(val: Optional[datetime.datetime]) -> int:
        if val is None:
            return 0
        delta = val - DtnTimeField.DTN_EPOCH
        return int(delta / datetime.timedelta(milliseconds=1))

    @staticmethod
    def dtntime_to_datetime(val: Any) -> Optional[datetime.datetime]:
        if val is None:
            return None
        ival = _native_int(val)
        if ival == 0:
            return None
        delta = datetime.timedelta(milliseconds=ival)
        return delta + DtnTimeField.DTN_EPOCH

    def i2h(self, pkt, x):
        if x is None:
            return None
        if _native_int(x) == 0:
            return "zero"
        dtval = DtnTimeField.dtntime_to_datetime(x)
        return dtval.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def h2i(self, pkt, x):
        return self.any2i(pkt, x)

    @staticmethod
    def _parse_text(val: Union[str, bytes]) -> int:
        if val in ("zero", b"zero"):
            return 0
        text = val.decode("ascii") if isinstance(val, bytes) else val
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(text)
        if dt.tzinfo is None:
            raise ValueError("DTN time requires a timezone-aware datetime")
        dt = dt.astimezone(datetime.timezone.utc)
        ms = DtnTimeField.datetime_to_dtntime(dt)
        if ms < 0:
            raise ValueError("DTN time before epoch is not allowed")
        return ms

    def any2i(self, pkt, x):
        if x is None:
            return 0
        if isinstance(x, (str, bytes)):
            return self._parse_text(x)
        if isinstance(x, datetime.datetime):
            if x.tzinfo is None:
                raise ValueError("DTN time requires a timezone-aware datetime")
            x = x.astimezone(datetime.timezone.utc)
            ms = DtnTimeField.datetime_to_dtntime(x)
            if ms < 0:
                raise ValueError("DTN time before epoch is not allowed")
            return ms
        val = _native_int(x)
        if val < 0:
            raise ValueError("DTN time must be unsigned")
        if val > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("DTN time exceeds uint64")
        return val

    def randval(self):
        return volatile.RandNum(0, int(2**16))


class BundleTimestamp(CBOR_Packet):
    """A structured representation of an DTN Timestamp.
    The timestamp is a two-tuple of (time, sequence number)
    The creation time portion is automatically converted from a
    :py:cls:`datetime.datetime` object and text.
    """

    CBOR_root = CBORF_ARRAY(
        DtnTimeField("dtntime", default=0),
        CBORF_UNSIGNED_INTEGER("seqno", default=0),
    )


@enum.unique
class EidScheme(enum.IntEnum):
    """Handled EID scheme names and values."""

    dtn = 1
    ipn = 2


_DTN_WELL_KNOWN_SSP = {
    0: "none",
}
"""Compressed SSP encoding."""


@dataclass(frozen=True)
class IpnSsp:
    """Normalized IPN scheme-specific part."""

    allocator: int
    node: int
    service: int

    def __post_init__(self) -> None:
        for name, value in (
            ("allocator", self.allocator),
            ("node", self.node),
            ("service", self.service),
        ):
            if value < 0:
                raise ValueError("%s cannot be negative" % name)
        if self.allocator > 0xFFFFFFFF:
            raise ValueError("allocator exceeds uint32")
        if self.node > 0xFFFFFFFF:
            raise ValueError("node exceeds uint32")

    @classmethod
    def from_wire(cls, parts: list[int]) -> IpnSsp:
        if len(parts) == 2:
            fqnn, service = parts
            return cls(fqnn >> 32, fqnn & 0xFFFFFFFF, service)
        if len(parts) == 3:
            return cls(parts[0], parts[1], parts[2])
        raise ValueError("IPN SSP must be 2 or 3 elements")

    def to_wire(self) -> list[int]:
        if self.allocator == 0:
            return [self.node, self.service]
        return [self.allocator, self.node, self.service]

    def to_wire_packed(self) -> list[int]:
        if self.allocator == 0:
            return [self.node, self.service]
        fqnn = (self.allocator << 32) | self.node
        return [fqnn, self.service]

    def to_text(self) -> str:
        if self.allocator == 0:
            return "ipn:{:d}.{:d}".format(self.node, self.service)
        return "ipn:{:d}.{:d}.{:d}".format(
            self.allocator, self.node, self.service
        )


@dataclass(frozen=True)
class EidStruct:
    """
    Internal state for the :class:`BundleEidField` class.
    """

    scheme: EidScheme
    ssp: Union[int, str, IpnSsp]

    @staticmethod
    def from_text(text: str) -> EidStruct:
        scheme_name, ssp_text = text.split(":", 1)

        try:
            scheme = EidScheme[scheme_name.lower()]
        except KeyError:
            raise ValueError(f"BP EID scheme {scheme_name} not understood")
        ssp = None
        if scheme == EidScheme.dtn:
            for key, val in _DTN_WELL_KNOWN_SSP.items():
                if ssp_text == val:
                    ssp = key
                    break
            if ssp is None:
                ssp = ssp_text

        elif scheme == EidScheme.ipn:
            parts = [int(part, 10) for part in ssp_text.split(".")]
            if len(parts) == 2:
                ssp = IpnSsp(0, parts[0], parts[1])
            elif len(parts) == 3:
                ssp = IpnSsp(parts[0], parts[1], parts[2])
            else:
                raise ValueError("IPN SSP must be 2 or 3 elements")

        else:
            raise ValueError("Invalid scheme state")

        return EidStruct(scheme=scheme, ssp=ssp)

    def to_text(self) -> str:
        if self.scheme == EidScheme.dtn:
            if isinstance(self.ssp, int):
                ssp = _DTN_WELL_KNOWN_SSP[self.ssp]
            else:
                ssp = str(self.ssp)
            return "dtn:" + ssp
        if self.scheme == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                return self.ssp.to_text()
            return IpnSsp.from_wire(list(self.ssp)).to_text()
        raise ValueError("Invalid scheme state")

    @staticmethod
    def _wire_parts(ssp_item: Any) -> list[int]:
        if isinstance(ssp_item, CBOR_ARRAY):
            return [_native_int(item) for item in ssp_item.val]
        return [_native_int(item) for item in ssp_item]

    @staticmethod
    def from_cbor(item: Union[CBOR_ARRAY, list[Any]]) -> EidStruct:
        if isinstance(item, CBOR_ARRAY):
            scheme_id, ssp_item = item.val
        elif isinstance(item, (list, tuple)):
            scheme_id, ssp_item = item
        else:
            raise TypeError(f"Need an array, have {item}")
        try:
            scheme = EidScheme(_native_int(scheme_id))
        except ValueError:
            raise ValueError(f"BP EID scheme {scheme_id} not understood")

        if scheme == EidScheme.dtn:
            if isinstance(ssp_item, CBOR_UNSIGNED_INTEGER):
                ssp = _native_int(ssp_item)
            elif isinstance(ssp_item, CBOR_TEXT_STRING):
                ssp = str(ssp_item.val)
            else:
                ssp = ssp_item
        elif scheme == EidScheme.ipn:
            ssp = IpnSsp.from_wire(EidStruct._wire_parts(ssp_item))
        else:
            raise ValueError("Invalid scheme state")

        return EidStruct(scheme=scheme, ssp=ssp)

    def to_cbor(self) -> list[Any]:
        if self.scheme == EidScheme.dtn:
            ssp_item = self.ssp
        elif self.scheme == EidScheme.ipn:
            if isinstance(self.ssp, IpnSsp):
                ssp_item = self.ssp.to_wire()
            else:
                ssp_item = IpnSsp.from_wire(list(self.ssp)).to_wire()
        else:
            raise ValueError("Invalid scheme state")

        return [int(self.scheme), ssp_item]


class BundleEidField(CBORF_field[EidStruct]):
    """Provide a human-friendly representation of a BP Endpoint ID (EID) as
    a single field.
    The EID is a two-item array of (scheme ID, scheme-specific part).
    """

    def i2h(self, _pkt, x):
        if x is None:
            return None
        if not isinstance(x, EidStruct):
            raise ValueError("EID must be decoded into an EidStruct")
        return x.to_text()

    def h2i(self, _pkt, x):
        if x is None:
            return None
        if isinstance(x, EidStruct):
            return x
        return EidStruct.from_text(x)

    def any2i(self, pkt, x):
        if x is None:
            return None
        if isinstance(x, str):
            return self.h2i(pkt, x)
        if isinstance(x, EidStruct):
            return x
        return x

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def encode_value(self, x):
        if isinstance(x, str):
            x = EidStruct.from_text(x)
        if isinstance(x, EidStruct):
            return CBORcodec_ARRAY.enc(x.to_cbor())
        if isinstance(x, CBOR_Object):
            return x.enc()
        raise TypeError("Cannot encode EID value %r" % (x,))

    def m2i(self, pkt, s):
        item, remain = CBORcodec_ARRAY.dec(s)
        return EidStruct.from_cbor(item), remain


@enum.unique
class CrcType(enum.IntEnum):
    """
    CRC type values defined in RFC 9171.
    """

    NONE = 0
    CRC16 = 1
    CRC32 = 2


@dataclass
class CrcInfo:
    """
    Processing for a specific :class:`CrcType`
    """

    cls: type[CRC]
    encode: Callable[[int], bytes]


_CRC_DEFN: dict[CrcType, CrcInfo] = {
    CrcType.CRC16: CrcInfo(
        cls=CRC_16_X25,
        encode=lambda val: struct.pack(">H", val),
    ),
    CrcType.CRC32: CrcInfo(
        cls=CRC_32C,
        encode=lambda val: struct.pack(">L", val),
    ),
}


def _enum_dict(cls: type[enum.IntEnum]) -> dict[int, str]:
    return {item.value: item.name for item in cls}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    message: str
    severity: str = "error"


class AbstractBlock:
    """Represent an abstract block internal interface mixin."""

    _crc_type_name = "crc_type"
    _crc_value_name = "crc_value"

    def has_crc(self) -> bool:
        crc_type = self.getfieldval(self._crc_type_name)
        return _native_int(crc_type) != int(CrcType.NONE)

    def _build_root_with_crc_value(self, crc_value: bytes) -> bytes:
        with _temporary_internal_field(self, self._crc_value_name, crc_value):
            return self.CBOR_root.build(self)

    def calculate_crc(self) -> Optional[bytes]:
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            return None
        defn = _CRC_DEFN[CrcType(crc_type)]
        pre_crc = self._build_root_with_crc_value(defn.encode(0))
        crc_int = defn.cls(pre_crc)
        return defn.encode(crc_int)

    def _self_build_with_crc(self) -> bytes:
        if self.raw_packet_cache is not None:
            return self.raw_packet_cache
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            return self.CBOR_root.build(self)
        crc_value = self.getfieldval(self._crc_value_name)
        if crc_value is not None and crc_value is not _MISSING:
            return self._build_root_with_crc_value(_crc_bytes(crc_value))
        computed = self.calculate_crc()
        return self._build_root_with_crc_value(computed)

    def freeze_crc(self) -> None:
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            self.setfieldval(self._crc_value_name, None)
        else:
            self.setfieldval(self._crc_value_name, self.calculate_crc())

    def check_crc(self) -> bool:
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        actual = _crc_bytes(self.getfieldval(self._crc_value_name))
        if crc_type == int(CrcType.NONE):
            expect = b""
            valid = actual == b""
        else:
            expect = self.calculate_crc() or b""
            valid = actual == expect

        if not valid:
            log_runtime.warning(
                "CRC check failed for %s: expected %s, got %s",
                self.__class__.__name__,
                expect.hex(),
                actual.hex(),
            )

        return valid

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = []
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        crc_value = self.getfieldval(self._crc_value_name)
        if crc_type == int(CrcType.NONE) and _crc_bytes(crc_value):
            issues.append(
                ValidationIssue(
                    "unexpected-crc",
                    path,
                    "CRC value present when CRC type is NONE",
                )
            )
        elif crc_type != int(CrcType.NONE):
            if crc_value is None:
                issues.append(
                    ValidationIssue(
                        "missing-crc",
                        path,
                        "CRC value missing for enabled CRC type",
                        severity="warning",
                    )
                )
            elif not self.check_crc():
                issues.append(
                    ValidationIssue("crc-mismatch", path, "CRC check failed")
                )
        return issues


class PrimaryBlock(CBOR_Packet, AbstractBlock):
    """The primary block definition"""

    @enum.unique
    class Flag(enum.IntFlag):
        """Bundle processing control flags."""

        REQ_DELETION_REPORT = 0x040000
        REQ_DELIVERY_REPORT = 0x020000
        REQ_FORWARDING_REPORT = 0x010000
        REQ_RECEPTION_REPORT = 0x004000
        REQ_STATUS_TIME = 0x000040
        USER_APP_ACK = 0x000020
        NO_FRAGMENT = 0x000004
        PAYLOAD_ADMIN = 0x000002
        IS_FRAGMENT = 0x000001

    def is_fragment(self) -> bool:
        flags = _native_int(self.getfieldval("bundle_flags"))
        return bool(flags & PrimaryBlock.Flag.IS_FRAGMENT)

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("version", default=7),
        CBORF_UNSIGNED_FLAGS(
            "bundle_flags", default=0, size=64, names=_enum_dict(Flag)
        ),
        CBORF_UNSIGNED_ENUM("crc_type", default=CrcType.NONE, enum=CrcType),
        BundleEidField("destination", default="dtn:none"),
        BundleEidField("source", default="dtn:none"),
        BundleEidField("report_to", default="dtn:none"),
        CBORF_PACKET("create_ts", default=BundleTimestamp(), cls=BundleTimestamp),
        CBORF_UNSIGNED_INTEGER("lifetime", default=0),
        CBORF_CONDITIONAL(
            CBORF_UNSIGNED_INTEGER("fragment_offset", default=0), cond=is_fragment
        ),
        CBORF_CONDITIONAL(
            CBORF_UNSIGNED_INTEGER("total_app_data_len", default=0), cond=is_fragment
        ),
        CBORF_CONDITIONAL(
            CBORF_BYTE_STRING("crc_value", default=None), cond=AbstractBlock.has_crc
        ),
    )

    def self_build(self):
        return self._self_build_with_crc()

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = super().validate(path)
        if _native_int(self.getfieldval("version")) != 7:
            issues.append(
                ValidationIssue(
                    "bad-version",
                    path,
                    "Primary block version must be 7",
                )
            )
        if self.is_fragment():
            if self.getfieldval("fragment_offset") is None:
                issues.append(
                    ValidationIssue(
                        "missing-fragment-offset",
                        path,
                        "Fragment offset required for fragments",
                    )
                )
            if self.getfieldval("total_app_data_len") is None:
                issues.append(
                    ValidationIssue(
                        "missing-total-app-data-len",
                        path,
                        "Total application data length required for fragments",
                    )
                )
        return issues


class CanonicalBlock(CBOR_Packet, AbstractBlock):
    """The canonical block definition with a block-type-specific data (BTSD)
    field containing a dissected Packet.
    """

    @enum.unique
    class Flag(enum.IntFlag):
        """Block processing control flags"""

        REMOVE_IF_NO_PROCESS = 0x10
        DELETE_IF_NO_PROCESS = 0x04
        STATUS_IF_NO_PROCESS = 0x02
        REPLICATE_IN_FRAGMENT = 0x01

    _reg_types: ClassVar[dict[int, type[Packet]]] = {}
    _reg_codes: ClassVar[dict[type[Packet], int]] = {}

    @classmethod
    def register_type(cls, type_code: int) -> Callable[[type[Packet]], type[Packet]]:
        def reg(pkt_cls: type[Packet]) -> type[Packet]:
            if type_code in cls._reg_types and cls._reg_types[type_code] is not pkt_cls:
                raise ValueError(
                    "Block type code %d already registered to %s"
                    % (type_code, cls._reg_types[type_code].__name__)
                )
            if pkt_cls in cls._reg_codes and cls._reg_codes[pkt_cls] != type_code:
                raise ValueError(
                    "Block class %s already registered as type %d"
                    % (pkt_cls.__name__, cls._reg_codes[pkt_cls])
                )
            cls._reg_types[type_code] = pkt_cls
            cls._reg_codes[pkt_cls] = type_code
            pkt_cls.BPV7_BLOCK_TYPE = type_code
            return pkt_cls

        return reg

    def inferred_type_code(self) -> Optional[int]:
        btsd = self.getfieldval("btsd")
        if btsd is None:
            return None
        for cls in type(btsd).mro():
            if cls in self._reg_codes:
                return self._reg_codes[cls]
        return None

    def _effective_type_code(self) -> Optional[int]:
        type_code = self.getfieldval("type_code")
        if type_code is not None:
            return _native_int(type_code)
        return self.inferred_type_code()

    def btsd_class(self, data: bytes):
        type_code = self._effective_type_code()
        if type_code is not None:
            try:
                return self._reg_types[type_code]
            except KeyError:
                pass
        return None

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("type_code", default=None),
        CBORF_UNSIGNED_INTEGER("block_num", default=None),
        CBORF_UNSIGNED_FLAGS("block_flags", default=0, size=64, names=_enum_dict(Flag)),
        CBORF_UNSIGNED_ENUM("crc_type", default=CrcType.NONE, enum=CrcType),
        CBORF_BYTE_STRING_PACKET("btsd", default=None, cls_cb=btsd_class),
        CBORF_CONDITIONAL(
            CBORF_BYTE_STRING("crc_value", default=None), cond=AbstractBlock.has_crc
        ),
    )

    def extract_padding(self, s):
        return None, s

    def self_build(self):
        type_code = self.getfieldval("type_code")
        if type_code is None:
            effective = self.inferred_type_code()
            if effective is not None:
                with _temporary_internal_field(self, "type_code", effective):
                    return self._self_build_with_crc()
        return self._self_build_with_crc()

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = super().validate(path)
        effective = self._effective_type_code()
        if effective is None:
            issues.append(
                ValidationIssue("missing-type-code", path, "Block type code is missing")
            )
        else:
            btsd = self.getfieldval("btsd")
            if btsd is not None:
                inferred = self.inferred_type_code()
                if inferred is not None and inferred != effective:
                    issues.append(
                        ValidationIssue(
                            "type-code-mismatch",
                            path,
                            "Block type code %d does not match BTSD type %d"
                            % (effective, inferred),
                        )
                    )
        if self.getfieldval("block_num") is None:
            issues.append(
                ValidationIssue("missing-block-num", path, "Block number is missing")
            )
        if self.getfieldval("btsd") is None:
            issues.append(ValidationIssue("missing-btsd", path, "BTSD is missing"))
        return issues


@CanonicalBlock.register_type(6)
class PreviousNodeBlock(CBOR_Packet):
    """Block data content from Section 4.4.1 of RFC 9171."""

    CBOR_root = BundleEidField("node", default=None)


@CanonicalBlock.register_type(7)
class BundleAgeBlock(CBOR_Packet):
    """Block data content from Section 4.4.2 of RFC 9171."""

    CBOR_root = CBORF_UNSIGNED_INTEGER("age", default=None)


@CanonicalBlock.register_type(10)
class HopCountBlock(CBOR_Packet):
    """Block data content from Section 4.4.3 of RFC 9171."""

    CBOR_root = CBORF_ARRAY(
        CBORF_UNSIGNED_INTEGER("limit", default=None),
        CBORF_UNSIGNED_INTEGER("count", default=0),
    )


class BundleV7(CBOR_Packet):
    """An entire decoded bundle contents.

    Bundles with administrative records are handled specially in that the
    AdminRecord object will be made a (scapy) payload of the "payload block"
    which is block type code 1.
    """

    BLOCK_TYPE_PAYLOAD = 1
    BLOCK_NUM_PAYLOAD = 1

    def _block_until_break(self, data: bytes):
        if cbor_is_break(data):
            return None
        return CanonicalBlock

    CBOR_root = CBORF_ARRAY_INDEFINITE(
        CBORF_PACKET("primary", default=PrimaryBlock(), cls=PrimaryBlock),
        CBORF_SEQUENCE_OF("blocks", default=[], cls_cb=_block_until_break),
    )

    def check_crc(self) -> bool:
        return self.primary.check_crc() and all(blk.check_crc() for blk in self.blocks)

    def validate(self) -> list[ValidationIssue]:
        issues = []
        if self.primary is not None:
            issues.extend(self.primary.validate("primary"))
        else:
            issues.append(
                ValidationIssue(
                    "missing-primary",
                    "primary",
                    "Primary block is missing",
                )
            )

        payload_blocks = []
        seen_nums: dict[int, int] = {}
        for index, blk in enumerate(self.blocks):
            path = "blocks[%d]" % index
            issues.extend(blk.validate(path))
            type_code = None
            if isinstance(blk, CanonicalBlock):
                type_code = blk._effective_type_code()
            block_num = blk.getfieldval("block_num")
            if block_num is not None:
                bnum = _native_int(block_num)
                if bnum in seen_nums:
                    issues.append(
                        ValidationIssue(
                            "duplicate-block-num",
                            path,
                            "Block number %d already used at blocks[%d]"
                            % (bnum, seen_nums[bnum]),
                        )
                    )
                else:
                    seen_nums[bnum] = index
                if type_code != self.BLOCK_TYPE_PAYLOAD and bnum == self.BLOCK_NUM_PAYLOAD:
                    issues.append(
                        ValidationIssue(
                            "reserved-payload-block-num",
                            path,
                            "Non-payload block must not use block number 1",
                        )
                    )
            if type_code == self.BLOCK_TYPE_PAYLOAD:
                payload_blocks.append((index, block_num))

        if not self.blocks:
            issues.append(
                ValidationIssue(
                    "missing-canonical-blocks",
                    "blocks",
                    "Bundle has no canonical blocks",
                )
            )
        if len(payload_blocks) != 1:
            issues.append(
                ValidationIssue(
                    "missing-payload",
                    "blocks",
                    "Bundle must contain exactly one payload block",
                )
            )
        elif payload_blocks[0][0] != len(self.blocks) - 1:
            issues.append(
                ValidationIssue(
                    "payload-not-last",
                    "blocks[%d]" % payload_blocks[0][0],
                    "Payload block must be the last block",
                )
            )
        elif (
            payload_blocks[0][1] is None
            or _native_int(payload_blocks[0][1]) != self.BLOCK_NUM_PAYLOAD
        ):
            issues.append(
                ValidationIssue(
                    "bad-payload-block-num",
                    "blocks[%d]" % payload_blocks[0][0],
                    "Payload block number must be 1",
                )
            )
        return issues

    def assert_valid(self) -> None:
        issues = self.validate()
        errors = [issue for issue in issues if issue.severity == "error"]
        if errors:
            raise ValueError(
                "\n".join(
                    "%s at %s: %s" % (issue.code, issue.path, issue.message)
                    for issue in errors
                )
            )
