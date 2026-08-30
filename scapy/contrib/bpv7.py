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
from typing import Any, Callable, ClassVar, Iterator, Optional, Union, cast

from scapy import volatile
from scapy.cbor.cborcodec import (
    cbor_is_break,
    cbor_find_non_deterministic,
    CBOR_decode_head,
    CBOR_INDEFINITE,
)
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
    CBOR_NO_ITEM,
    CBOR_Encoding_Error,
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
        if val.tzinfo is None:
            raise ValueError("DTN time requires a timezone-aware datetime")
        val = val.astimezone(datetime.timezone.utc)
        if val < DtnTimeField.DTN_EPOCH:
            raise ValueError("DTN time before epoch is not allowed")
        delta = val - DtnTimeField.DTN_EPOCH
        return (
            delta.days * 86400000
            + delta.seconds * 1000
            + delta.microseconds // 1000
        )

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
        return DtnTimeField.datetime_to_dtntime(dt)

    def any2i(self, pkt, x):
        if x is None:
            return 0
        if isinstance(x, (str, bytes)):
            return self._parse_text(x)
        if isinstance(x, datetime.datetime):
            return DtnTimeField.datetime_to_dtntime(x)
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
    """Normalized IPN scheme-specific part.

    Stores the RFC 9758 logical triple ``(allocator, node, service)`` and the
    CBOR array arity used on the wire. The 2- vs 3-element choice is part of
    the value: after an EID is first encoded, later decode/re-encode cycles
    must preserve that element count.
    """

    allocator: int
    node: int
    service: int
    # 2 = packed [fqnn, service]; 3 = explicit [allocator, node, service]
    wire_elements: int = 3

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
        if self.service > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("service exceeds uint64")
        if self.wire_elements not in (2, 3):
            raise ValueError("IPN wire element count must be 2 or 3")

    @classmethod
    def from_wire(cls, parts: list[int]) -> IpnSsp:
        if len(parts) == 2:
            fqnn, service = parts
            return cls(
                fqnn >> 32,
                fqnn & 0xFFFFFFFF,
                service,
                wire_elements=2,
            )
        if len(parts) == 3:
            return cls(
                parts[0],
                parts[1],
                parts[2],
                wire_elements=3,
            )
        raise ValueError("IPN SSP must be 2 or 3 elements")

    def to_wire(self) -> list[int]:
        if self.wire_elements == 2:
            fqnn = (self.allocator << 32) | self.node
            return [fqnn, self.service]
        return [self.allocator, self.node, self.service]

    def same_endpoint(self, other: object) -> bool:
        """Return True when *other* names the same logical IPN endpoint."""
        if not isinstance(other, IpnSsp):
            return False
        return (
            self.allocator == other.allocator
            and self.node == other.node
            and self.service == other.service
        )

    def to_text(self) -> str:
        if self.allocator == 0 and self.wire_elements == 2:
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
                ssp = IpnSsp(0, parts[0], parts[1], wire_elements=2)
            elif len(parts) == 3:
                ssp = IpnSsp(
                    parts[0], parts[1], parts[2], wire_elements=3
                )
            else:
                raise ValueError("IPN SSP must be 2 or 3 elements")

        else:
            raise ValueError("Invalid scheme state")

        return EidStruct(scheme=scheme, ssp=ssp)

    def to_text(self) -> str:
        if self.scheme == EidScheme.dtn:
            if isinstance(self.ssp, int):
                try:
                    ssp = _DTN_WELL_KNOWN_SSP[self.ssp]
                except KeyError:
                    ssp = "!unknown-ssp-%d" % self.ssp
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
                if ssp not in _DTN_WELL_KNOWN_SSP:
                    raise ValueError(
                        "Unknown compressed DTN SSP value: %r" % (ssp,)
                    )
            elif isinstance(ssp_item, CBOR_TEXT_STRING):
                ssp = str(ssp_item.val)
            elif isinstance(ssp_item, int):
                ssp = int(ssp_item)
                if ssp not in _DTN_WELL_KNOWN_SSP:
                    raise ValueError(
                        "Unknown compressed DTN SSP value: %r" % (ssp,)
                    )
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


@dataclass(frozen=True)
class CrcInfo:
    """
    Processing for a specific :class:`CrcType`
    """

    cls: type[CRC]
    width: int

    def encode(self, value: int) -> bytes:
        return value.to_bytes(self.width, "big")


_CRC_DEFN: dict[CrcType, CrcInfo] = {
    CrcType.CRC16: CrcInfo(cls=CRC_16_X25, width=2),
    CrcType.CRC32: CrcInfo(cls=CRC_32C, width=4),
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

    @contextmanager
    def _effective_build_context(self) -> Iterator[None]:
        """Hook for derived values needed during CRC-aware builds."""
        yield

    def _crc_definition(self) -> Optional[CrcInfo]:
        value = _native_int(self.getfieldval(self._crc_type_name))
        try:
            return _CRC_DEFN[CrcType(value)]
        except (ValueError, KeyError):
            return None

    def _build_root_with_crc_value(self, crc_value: bytes) -> bytes:
        with self._effective_build_context():
            with _temporary_internal_field(self, self._crc_value_name, crc_value):
                return self.CBOR_root.build(self)

    def cbor_build_result(self):
        """Return final wire bytes and cardinality in one schema traversal."""
        from scapy.cbor.cborfields import CBORBuildResult
        return CBORBuildResult(self.self_build(), 1)

    def calculate_crc(self) -> Optional[bytes]:
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            return None
        defn = self._crc_definition()
        if defn is None:
            raise CBOR_Encoding_Error(
                "Unsupported CRC type %d" % crc_type
            )
        # Build once with zero placeholder; derive CRC from that buffer.
        pre_crc = self._build_root_with_crc_value(defn.encode(0))
        return defn.encode(defn.cls(pre_crc))

    def _self_build_with_crc(self) -> bytes:
        if self._raw_packet_cache_is_valid():  # type: ignore[attr-defined]
            return self.raw_packet_cache  # type: ignore[return-value]
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            with self._effective_build_context():
                return self.CBOR_root.build(self)
        crc_value = self.getfieldval(self._crc_value_name)
        if crc_value is not None and crc_value is not _MISSING:
            actual = _crc_bytes(crc_value)
            defn = self._crc_definition()
            if defn is None:
                raise CBOR_Encoding_Error(
                    "Unsupported CRC type %d" % crc_type
                )
            if len(actual) != defn.width:
                raise CBOR_Encoding_Error(
                    "CRC value length %d does not match type %s"
                    % (len(actual), CrcType(crc_type).name)
                )
            return self._build_root_with_crc_value(actual)
        # Single schema traversal: build once with a zero CRC, then patch.
        defn = self._crc_definition()
        if defn is None:
            raise CBOR_Encoding_Error(
                "Unsupported CRC type %d" % crc_type
            )
        zero = defn.encode(0)
        pre_crc = self._build_root_with_crc_value(zero)
        crc_bytes = defn.encode(defn.cls(pre_crc))
        if len(crc_bytes) != len(zero):
            raise CBOR_Encoding_Error("CRC width mismatch during patch")
        idx = pre_crc.rfind(zero)
        if idx < 0:
            # Fall back to a second build if the placeholder was not unique.
            return self._build_root_with_crc_value(crc_bytes)
        patched = bytearray(pre_crc)
        patched[idx:idx + len(zero)] = crc_bytes
        return bytes(patched)

    def freeze_crc(self) -> None:
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        if crc_type == int(CrcType.NONE):
            self.setfieldval(self._crc_value_name, None)
        else:
            self.setfieldval(self._crc_value_name, self.calculate_crc())

    def _crc_over_received_or_built(self, defn: CrcInfo, actual: bytes) -> bytes:
        """CRC over exact received bytes when available; else rebuilt form."""
        # Nested mutations must invalidate a dissected raw cache first.
        if hasattr(self, "_raw_packet_cache_is_valid"):
            self._raw_packet_cache_is_valid()
        raw = self.raw_packet_cache
        if raw is not None and actual:
            from scapy.cbor.cborcodec import CBOR_encode_head
            head = CBOR_encode_head(2, len(actual))
            needle = head + actual
            idx = raw.rfind(needle)
            if idx >= 0:
                zeroed = bytearray(raw)
                content_off = idx + len(head)
                for i in range(len(actual)):
                    zeroed[content_off + i] = 0
                return defn.encode(defn.cls(bytes(zeroed)))
        return self.calculate_crc() or b""

    def check_crc(self) -> bool:
        crc_type = _native_int(self.getfieldval(self._crc_type_name))
        actual = _crc_bytes(self.getfieldval(self._crc_value_name))
        if crc_type == int(CrcType.NONE):
            expect = b""
            valid = actual == b""
        else:
            defn = self._crc_definition()
            if defn is None:
                return False
            expect = self._crc_over_received_or_built(defn, actual)
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
        actual = _crc_bytes(crc_value)
        if crc_type == int(CrcType.NONE) and actual:
            issues.append(
                ValidationIssue(
                    "unexpected-crc",
                    path,
                    "CRC value present when CRC type is NONE",
                )
            )
        elif crc_type != int(CrcType.NONE):
            defn = self._crc_definition()
            if defn is None:
                issues.append(
                    ValidationIssue(
                        "unsupported-crc-type",
                        path,
                        "Unsupported CRC type %d" % crc_type,
                    )
                )
            else:
                expect_len = defn.width
                if crc_value is None:
                    issues.append(
                        ValidationIssue(
                            "missing-crc",
                            path,
                            "CRC value missing for enabled CRC type",
                            severity="warning",
                        )
                    )
                elif len(actual) != expect_len:
                    issues.append(
                        ValidationIssue(
                            "bad-crc-length",
                            path,
                            "CRC value length %d does not match type %s"
                            % (len(actual), CrcType(crc_type).name),
                        )
                    )
                elif not self.check_crc():
                    issues.append(
                        ValidationIssue("crc-mismatch", path, "CRC check failed")
                    )
        return issues


def _append_non_deterministic_issues(
    issues: list[ValidationIssue],
    raw: Optional[bytes],
    path: str,
) -> None:
    if not raw:
        return
    for offset, message in cbor_find_non_deterministic(
        raw, allow_indefinite=True
    ):
        issues.append(
            ValidationIssue(
                "non-deterministic-cbor",
                path,
                "%s at offset %d" % (message, offset),
            )
        )


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
            CBORF_BYTE_STRING("crc_value", default=None, definite_only=True),
            cond=AbstractBlock.has_crc
        ),
    )

    def self_build(self):
        return self._self_build_with_crc()

    def cbor_build_result(self):
        return AbstractBlock.cbor_build_result(self)

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = super().validate(path)
        _append_non_deterministic_issues(
            issues, self.raw_packet_cache, path
        )
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
        return getattr(type(btsd), "BPV7_BLOCK_TYPE", None)

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
        CBORF_BYTE_STRING_PACKET(
            "btsd", default=None, cls_cb=btsd_class, definite_only=True
        ),
        CBORF_CONDITIONAL(
            CBORF_BYTE_STRING("crc_value", default=None, definite_only=True),
            cond=AbstractBlock.has_crc
        ),
    )

    def extract_padding(self, s):
        return None, s

    @contextmanager
    def _effective_build_context(self) -> Iterator[None]:
        type_code = self.getfieldval("type_code")
        if type_code is None:
            effective = self.inferred_type_code()
            if effective is not None:
                with _temporary_internal_field(self, "type_code", effective):
                    yield
                return
        yield

    def self_build(self):
        return self._self_build_with_crc()

    def cbor_build_result(self):
        return AbstractBlock.cbor_build_result(self)

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
                if hasattr(btsd, "validate"):
                    issues.extend(btsd.validate(path + ".btsd"))
        if self.getfieldval("block_num") is None:
            issues.append(
                ValidationIssue("missing-block-num", path, "Block number is missing")
            )
        if self.getfieldval("btsd") is None:
            issues.append(ValidationIssue("missing-btsd", path, "BTSD is missing"))
        _append_non_deterministic_issues(
            issues, self.raw_packet_cache, path
        )
        btsd = self.getfieldval("btsd")
        if btsd is not None:
            btsd_raw = getattr(btsd, "raw_packet_cache", None)
            if not btsd_raw and hasattr(btsd, "original"):
                btsd_raw = btsd.original
            _append_non_deterministic_issues(
                issues, btsd_raw, path + ".btsd"
            )
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

    def validate(self, path: str = "") -> list[ValidationIssue]:
        issues = []  # type: list[ValidationIssue]
        limit = self.getfieldval("limit")
        count = self.getfieldval("count")
        if limit is None or _native_int(limit) < 1 or _native_int(limit) > 255:
            issues.append(
                ValidationIssue(
                    "bad-hop-limit",
                    path,
                    "Hop Count limit must be in 1..255",
                )
            )
        elif count is not None and _native_int(count) > _native_int(limit):
            issues.append(
                ValidationIssue(
                    "hop-count-exceeds-limit",
                    path,
                    "Hop Count count must not exceed limit",
                )
            )
        return issues


class BundleV7(CBOR_Packet):
    """An entire decoded BPv7 bundle (primary block plus canonical blocks)."""

    BLOCK_TYPE_PAYLOAD = 1
    BLOCK_NUM_PAYLOAD = 1
    BLOCK_TYPE_PREVIOUS_NODE = 6
    BLOCK_TYPE_BUNDLE_AGE = 7
    BLOCK_TYPE_HOP_COUNT = 10
    STATUS_REPORT_FLAGS = (
        int(PrimaryBlock.Flag.REQ_DELETION_REPORT)
        | int(PrimaryBlock.Flag.REQ_DELIVERY_REPORT)
        | int(PrimaryBlock.Flag.REQ_FORWARDING_REPORT)
        | int(PrimaryBlock.Flag.REQ_RECEPTION_REPORT)
    )

    def _block_until_break(self, data: bytes):
        if cbor_is_break(data):
            return CBOR_NO_ITEM
        return CanonicalBlock

    CBOR_root = CBORF_ARRAY_INDEFINITE(
        CBORF_PACKET("primary", default=PrimaryBlock(), cls=PrimaryBlock),
        CBORF_SEQUENCE_OF("blocks", default=[], cls_cb=_block_until_break),
    )

    def check_crc(self) -> bool:
        return self.primary.check_crc() and all(blk.check_crc() for blk in self.blocks)

    def validate(
        self,
        primary_integrity_protected: bool = False,
    ) -> list[ValidationIssue]:
        issues = []
        raw = self.raw_packet_cache
        if raw:
            try:
                major_type, count, _ = CBOR_decode_head(raw)
                if major_type == 4 and count is not CBOR_INDEFINITE:
                    issues.append(
                        ValidationIssue(
                            "bundle-array-must-be-indefinite",
                            "",
                            "BPv7 bundle array must use indefinite length",
                        )
                    )
            except Exception:
                pass
            _append_non_deterministic_issues(issues, raw, "")
        primary = self.primary
        if primary is not None:
            issues.extend(primary.validate("primary"))
        else:
            issues.append(
                ValidationIssue(
                    "missing-primary",
                    "primary",
                    "Primary block is missing",
                )
            )

        flags = 0
        source_text = ""
        create_dtntime = 0
        is_admin = False
        is_anonymous = False
        if primary is not None:
            flags = int(primary.getfieldval("bundle_flags") or 0)
            crc_type = _native_int(primary.getfieldval("crc_type"))
            if crc_type == int(CrcType.NONE) and not primary_integrity_protected:
                issues.append(
                    ValidationIssue(
                        "primary-crc-required",
                        "primary",
                        "Primary block requires a nonzero CRC type unless a "
                        "Block Integrity Block protects the primary block",
                    )
                )
            source = primary.getfieldval("source")
            if hasattr(source, "to_text"):
                source_text = source.to_text()
            else:
                source_text = str(source)
            is_anonymous = source_text == "dtn:none"
            is_admin = bool(flags & int(PrimaryBlock.Flag.PAYLOAD_ADMIN))
            if is_anonymous and not (flags & int(PrimaryBlock.Flag.NO_FRAGMENT)):
                issues.append(
                    ValidationIssue(
                        "anonymous-source-must-not-fragment",
                        "primary",
                        "Anonymous source must set must-not-fragment",
                    )
                )
            if is_anonymous and (flags & self.STATUS_REPORT_FLAGS):
                issues.append(
                    ValidationIssue(
                        "anonymous-source-status-flags",
                        "primary",
                        "Anonymous source must not request status reports",
                    )
                )
            if is_admin and (flags & self.STATUS_REPORT_FLAGS):
                issues.append(
                    ValidationIssue(
                        "admin-record-status-flags",
                        "primary",
                        "Administrative records must not request status reports",
                    )
                )
            create_ts = primary.getfieldval("create_ts")
            if create_ts is not None:
                create_dtntime = _native_int(create_ts.getfieldval("dtntime") or 0)

        payload_blocks = []
        seen_nums: dict[int, int] = {}
        type_counts: dict[int, int] = {}
        for index, blk in enumerate(self.blocks):
            path = "blocks[%d]" % index
            if isinstance(blk, CanonicalBlock):
                issues.extend(blk.validate(path))
            type_code = None
            if isinstance(blk, CanonicalBlock):
                type_code = blk._effective_type_code()
            if type_code is not None:
                type_counts[type_code] = type_counts.get(type_code, 0) + 1
            block_num = blk.getfieldval("block_num")
            if block_num is not None:
                bnum = _native_int(block_num)
                if bnum == 0:
                    issues.append(
                        ValidationIssue(
                            "canonical-block-uses-primary-number",
                            path,
                            "Canonical block number 0 is reserved",
                        )
                    )
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
                if (
                    type_code != self.BLOCK_TYPE_PAYLOAD
                    and bnum == self.BLOCK_NUM_PAYLOAD
                ):
                    issues.append(
                        ValidationIssue(
                            "reserved-payload-block-num",
                            path,
                            "Non-payload block must not use block number 1",
                        )
                    )
            if type_code == self.BLOCK_TYPE_PAYLOAD:
                payload_blocks.append((index, block_num))
            if isinstance(blk, CanonicalBlock):
                block_flags = int(blk.getfieldval("block_flags") or 0)
                if block_flags & int(CanonicalBlock.Flag.STATUS_IF_NO_PROCESS):
                    if is_anonymous or is_admin:
                        issues.append(
                            ValidationIssue(
                                "forbidden-block-status-report",
                                path,
                                "Block status-report flag forbidden for "
                                "anonymous or administrative bundles",
                            )
                        )

        if type_counts.get(self.BLOCK_TYPE_PREVIOUS_NODE, 0) > 1:
            issues.append(
                ValidationIssue(
                    "duplicate-previous-node",
                    "blocks",
                    "At most one Previous Node block is allowed",
                )
            )
        age_count = type_counts.get(self.BLOCK_TYPE_BUNDLE_AGE, 0)
        if create_dtntime == 0 and age_count != 1:
            issues.append(
                ValidationIssue(
                    "bundle-age-required",
                    "blocks",
                    "Zero creation time requires exactly one Bundle Age block",
                )
            )
        if age_count > 1:
            issues.append(
                ValidationIssue(
                    "duplicate-bundle-age",
                    "blocks",
                    "At most one Bundle Age block is allowed",
                )
            )
        if type_counts.get(self.BLOCK_TYPE_HOP_COUNT, 0) > 1:
            issues.append(
                ValidationIssue(
                    "duplicate-hop-count",
                    "blocks",
                    "At most one Hop Count block is allowed",
                )
            )

        if not self.blocks:
            issues.append(
                ValidationIssue(
                    "missing-canonical-blocks",
                    "blocks",
                    "Bundle has no canonical blocks",
                )
            )
        if len(payload_blocks) == 0:
            issues.append(
                ValidationIssue(
                    "missing-payload",
                    "blocks",
                    "Bundle must contain exactly one payload block",
                )
            )
        elif len(payload_blocks) > 1:
            issues.append(
                ValidationIssue(
                    "bad-payload-count",
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
