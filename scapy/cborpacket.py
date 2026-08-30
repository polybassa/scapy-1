# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Packet

Packet holding data encoded in Concise Binary Object Representation (CBOR).
Modelled after scapy/asn1packet.py.
"""

from scapy.base_classes import Packet_metaclass
from scapy.packet import Packet

from typing import (
    Any,
    Dict,
    Tuple,
    Type,
    Optional,
    cast,
)


class CBORPacket_metaclass(Packet_metaclass):
    def __new__(cls,
                name,  # type: str
                bases,  # type: Tuple[type, ...]
                dct  # type: Dict[str, Any]
                ):
        # type: (...) -> Type[CBOR_Packet]
        if dct.get("CBOR_root") is not None:
            dct["fields_desc"] = dct["CBOR_root"].get_fields_list()
        return cast(
            'Type[CBOR_Packet]',
            super(CBORPacket_metaclass, cls).__new__(cls, name, bases, dct),
        )


class CBOR_Packet(Packet, metaclass=CBORPacket_metaclass):
    CBOR_root = None  # type: Optional[Any]

    def cbor_build_result(self):
        # type: () -> Any
        """Return the CBOR build result for this packet's root schema.

        Prefer a still-valid raw packet cache so nested rebuilds preserve the
        exact received representation of untouched children.
        """
        from scapy.cbor.cborfields import CBORBuildResult
        if self._raw_packet_cache_is_valid():
            # Cardinality matches a single top-level item for framed roots;
            # unframed SEQUENCE roots report via a fresh build_result.
            root = self.CBOR_root
            if getattr(root, "CBOR_tag", None) is None and hasattr(root, "seq"):
                return root.build_result(self)
            return CBORBuildResult(self.raw_packet_cache, 1)
        return self.CBOR_root.build_result(self)

    def _snapshot_raw_packet_cache_fields(self):
        # type: () -> None
        """Record mutable/nested field values used to invalidate the raw cache."""
        from scapy.cbor.cborfields import CBOR_ABSENT
        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if f.name not in self.fields:
                continue
            fval = self.fields[f.name]
            if fval is CBOR_ABSENT:
                self.raw_packet_cache_fields[f.name] = CBOR_ABSENT
                continue
            if getattr(f, "isconditional", False) and fval is None:
                continue
            if (
                f.islist
                or f.holds_packets
                or getattr(f, "ismutable", False)
            ) and fval is not None:
                self.raw_packet_cache_fields[f.name] = \
                    self._raw_packet_cache_field_value(f, fval, copy=True)

    def do_init_cached_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        super(CBOR_Packet, self).do_init_cached_fields(
            for_dissect_only=for_dissect_only
        )
        if for_dissect_only:
            return
        # Packet uses shallow .copy() for list defaults; deepen ismutable ones.
        for f in self.fields_desc:
            if getattr(f, "ismutable", False) and f.name in self.fields:
                self.fields[f.name] = f.do_copy(self.fields[f.name])

    def getfield_and_val(self, attr):
        # type: (str) -> Tuple[Any, Any]
        # __getattr__ uses this path; isolate mutable defaults per instance.
        if attr not in self.fields and attr in self.default_fields:
            fld = self.get_field(attr)
            if fld is not None and getattr(fld, "ismutable", False):
                self.fields[attr] = fld.do_copy(self.default_fields[attr])
                return fld, self.fields[attr]
        return super(CBOR_Packet, self).getfield_and_val(attr)

    def getfieldval(self, attr):
        # type: (str) -> Any
        if attr not in self.fields and attr in self.default_fields:
            fld = self.get_field(attr)
            if fld is not None and getattr(fld, "ismutable", False):
                self.fields[attr] = fld.do_copy(self.default_fields[attr])
                return self.fields[attr]
        return super(CBOR_Packet, self).getfieldval(attr)

    def _raw_packet_cache_is_valid(self):
        # type: () -> bool
        """Return True if ``raw_packet_cache`` still matches nested field state."""
        if self.raw_packet_cache is None or self.raw_packet_cache_fields is None:
            return False
        for fname, fval in self.raw_packet_cache_fields.items():
            fld, val = self.getfield_and_val(fname)
            if self._raw_packet_cache_field_value(fld, val) != fval:
                self.raw_packet_cache = None
                self.raw_packet_cache_fields = None
                self.wirelen = None
                return False
        return True

    def self_build(self):
        # type: () -> bytes
        """Build this CBOR packet to wire bytes using CBOR_root.

        Returns the raw packet cache when still valid for the current field
        state, otherwise delegates to CBOR_root.build().
        """
        if self._raw_packet_cache_is_valid():
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        """Dissect CBOR-encoded bytes into packet fields.

        Delegates to CBOR_root.dissect() which reads CBOR items from *x*,
        populates each field on the packet, and returns any unconsumed bytes.
        Retains ``raw_packet_cache`` over the consumed item span so nested
        packets and CRC verification can use the exact received bytes.
        """
        _raw = x
        remain = self.CBOR_root.dissect(self, x)
        self.raw_packet_cache = _raw[:-len(remain)] if remain else _raw
        self._snapshot_raw_packet_cache_fields()
        self.explicit = 1
        return remain
