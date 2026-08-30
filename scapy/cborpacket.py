# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
CBOR Packet

Packet holding data encoded in Concise Binary Object Representation (CBOR).
Modelled after scapy/asn1packet.py: a thin root-schema wrapper around Packet.
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


def _finalize_cbor_raw_cache(pkt, raw, remain):
    # type: (Packet, bytes, bytes) -> None
    """Record raw cache + mutable-field snapshot after CBOR_root.dissect.

    Mirrors ``Packet.do_dissect`` cache bookkeeping so ``CBOR_Packet`` itself
    stays ASN.1-thin. Handles ``CBOR_ABSENT`` which ordinary Packet fields
    do not use.
    """
    from scapy.cbor.cborfields import CBOR_ABSENT
    pkt.raw_packet_cache = raw[:-len(remain)] if remain else raw
    pkt.raw_packet_cache_fields = {}
    for f in pkt.fields_desc:
        if f.name not in pkt.fields:
            continue
        fval = pkt.fields[f.name]
        if fval is CBOR_ABSENT:
            pkt.raw_packet_cache_fields[f.name] = CBOR_ABSENT
            continue
        if getattr(f, "isconditional", False) and fval is None:
            continue
        if (f.islist or f.holds_packets or getattr(f, "ismutable", False)) \
                and fval is not None:
            pkt.raw_packet_cache_fields[f.name] = \
                pkt._raw_packet_cache_field_value(f, fval, copy=True)
    pkt.explicit = 1


def _cbor_raw_cache_is_valid(pkt):
    # type: (Packet) -> bool
    """Return True if ``raw_packet_cache`` still matches nested field state."""
    if pkt.raw_packet_cache is None or pkt.raw_packet_cache_fields is None:
        return False
    for fname, fval in pkt.raw_packet_cache_fields.items():
        fld, val = pkt.getfield_and_val(fname)
        if pkt._raw_packet_cache_field_value(fld, val) != fval:
            pkt.raw_packet_cache = None
            pkt.raw_packet_cache_fields = None
            pkt.wirelen = None
            return False
    return True


class CBOR_Packet(Packet, metaclass=CBORPacket_metaclass):
    """ASN.1-shaped CBOR packet: metaclass + root build/dissect only.

    Mutable-field defaults and cache snapshots are handled via field flags
    (``islist`` / ``ismutable`` / ``holds_packets``) and module helpers so this
    class does not re-implement Scapy's Packet cache policy.
    """

    CBOR_root = None  # type: Optional[Any]

    def cbor_build_result(self):
        # type: () -> Any
        """Return ``CBORResult`` for this packet's root schema."""
        from scapy.cbor.cborfields import CBORResult
        if _cbor_raw_cache_is_valid(self):
            root = self.CBOR_root
            # Unframed SEQUENCE roots need a real item count, not "1".
            if getattr(root, "CBOR_tag", None) is None and hasattr(root, "seq"):
                return root.build_result(self)
            return CBORResult(data=self.raw_packet_cache, items=1)
        return self.CBOR_root.build_result(self)

    def do_init_cached_fields(self, for_dissect_only=False):
        # type: (bool) -> None
        super(CBOR_Packet, self).do_init_cached_fields(
            for_dissect_only=for_dissect_only
        )
        if for_dissect_only:
            return
        # Packet only deep-copies list/dict/set defaults; deepen ismutable.
        for f in self.fields_desc:
            if getattr(f, "ismutable", False) and f.name in self.fields:
                self.fields[f.name] = f.do_copy(self.fields[f.name])

    def getfield_and_val(self, attr):
        # type: (str) -> Tuple[Any, Any]
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

    def self_build(self):
        # type: () -> bytes
        if _cbor_raw_cache_is_valid(self):
            return self.raw_packet_cache
        return self.CBOR_root.build(self)

    def do_dissect(self, x):
        # type: (bytes) -> bytes
        remain = self.CBOR_root.dissect(self, x)
        _finalize_cbor_raw_cache(self, x, remain)
        return remain
