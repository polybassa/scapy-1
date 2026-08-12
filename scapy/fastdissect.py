# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Proof of concept: compile the loaded packet classes into a dissection tree.

Dissection walks a layer field by field, asking each one to cut its own bytes
off the front of the packet, walks the bindings of the layer to find what
comes next, and builds it. All three are decided again for every packet,
although all three follow from the class alone: the fields it declares, the
layers bound to it, and the state its packets start their life with.

This compiles that knowledge once, per class, into three generated functions:

- ``do_dissect``, where every run of fixed size fields is read by a single
  ``struct.unpack_from``. Bit fields that fill whole bytes are read as one
  integer of the same run and shifted apart, so the fourteen bytes of an
  Ethernet header, or the twelve first of an IP one, each take one unpack.
  A field that reads a length of its own, a conditional field or one whose
  type depends on the packet ends the run and is dissected as it always was.
- ``guess_payload_class``, where the bindings become a dict keyed by the
  fields they compare, so picking the next class is a lookup rather than a
  walk of every binding of every alias of the layer.
- ``build``, which lays out a packet of the class attribute by attribute,
  holding the ones that are the same for all of them, and runs the dissection
  of the layer and of what follows it. It stands in for the constructor,
  which spends more on a layer than reading its header does, and is only used
  once what it leaves behind has been compared against what the constructor
  does. Layers are built through it by ``Packet.do_dissect_payload``, the one
  method this hands to ``Packet`` itself.

Nothing else changes: the same field objects, the same values in
``pkt.fields``, the same layers, built in the same order. Use it as::

    conf.compile_dissectors = True   # and False to give it all back

which compiles a class the first time a packet of it turns up, half a
millisecond each, rather than the second it takes to compile the two thousand
classes a session loads to dissect the dozen a capture holds. Compiling them
all up front, and reading what came of one, is::

    from scapy.fastdissect import enable, explain, stats
    enable()
    print(explain(IP))       # the plan of a class, as generated source
    print(stats())           # what was compiled, and what was left alone

A plan is only as good as what it was compiled from, and both may move:
``bind_layers`` gives a class new bindings, and importing a layer brings in
classes that inherit from compiled ones. A compiled class therefore starts by
comparing the identity of the field list and of the bindings it was compiled
from against the ones the packet at hand has, and hands the packet back to the
stock dissection, or compiles itself again, when they differ.

A class this cannot follow keeps what it had, layer by layer and step by step:
one that dissects itself is still given a payload dispatch, one that builds its
packets itself is still dissected field by field, and a class with no plan at
all is built and dissected the way it always was, from a layer that has one.
``stats()`` counts what was compiled, and ``explain(cls)`` tells of a class
that was not why it was left alone.
"""

import struct

from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import Field, _BitField, _FieldContainer
from scapy.packet import NoPayload, Packet
from scapy.utils import issubtype

# Typing imports
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
)

__all__ = ["enable", "disable", "explain", "compile_class", "stats"]

_BYTE_ORDER = "!<>=@"

# Classes this compiled, and the methods it generated for them
_installed = {}  # type: Dict[Type[Packet], List[str]]
# Classes handed back a method of their own, to keep a compiled parent from
# answering for them
_shields = {}  # type: Dict[Type[Packet], List[str]]
# Why a class was left alone, for explain()
_skipped = {}  # type: Dict[Type[Packet], str]


_METHODS = ("do_dissect", "guess_payload_class")


def _own(cls, name):
    # type: (Type[Packet], str) -> Any
    """The method a class ran before any of this, from its own or a parent.

    A compiled method sits in the dictionary of its class like any other, so
    the ones this installed are stepped over to find what a class really does.
    """
    for base in cls.__mro__:
        if name in base.__dict__:
            if name in _installed.get(base, ()) or \
                    name in _shields.get(base, ()):
                continue
            return base.__dict__[name]
    return None


def _packet_classes():
    # type: () -> List[Type[Packet]]
    """Every packet class that is loaded, parents before children."""
    found = []  # type: List[Type[Packet]]
    seen = set()  # type: Any

    def walk(cls):
        # type: (Type[Packet]) -> None
        for sub in cls.__subclasses__():
            if sub not in seen:
                seen.add(sub)
                found.append(sub)
                walk(sub)

    walk(Packet)
    return found


class _Miss(object):
    """A field the packet does not carry, which no binding matches."""

    def __repr__(self):
        # type: () -> str
        return "<missing>"


_MISS = _Miss()


def _val(pkt, name):
    # type: (Packet, str) -> Any
    """The value of a field the packet holds somewhere other than in fields."""
    try:
        return pkt.getfieldval(name)
    except AttributeError:
        return _MISS


def _stock_dissect(pkt, raw, s, index):
    # type: (Packet, bytes, bytes, int) -> bytes
    """Dissect the fields left the way the class always did.

    A plan gives up on what it cannot read ahead of time, and on a packet too
    short for a run, so that a truncated header fails on the very field it
    failed on before, with the fields before it already set.
    """
    if not index:
        # A whole layer, which a class that inherited a plan of another hands
        # back here, and which Packet.do_dissect starts by clearing
        pkt.raw_packet_cache_fields = {}
    for fld in pkt.fields_desc[index:]:
        s, fval = fld.getfield(pkt, s)
        if fld.isconditional and fval is None:
            continue
        if (fld.islist or fld.holds_packets or fld.ismutable) and \
                fval is not None:
            held = pkt._raw_packet_cache_field_value(fld, fval, copy=True)
            pkt.raw_packet_cache_fields[fld.name] = held  # type: ignore
        pkt.fields[fld.name] = fval
        if not s and (fld.ismayend or
                      (fval is not None and fld.isconditional and
                       fld.fld.ismayend)):  # type: ignore
            break
    pkt.raw_packet_cache = raw[:-len(s)] if s else raw
    pkt.explicit = 1
    return s


# Reading the fields


def _reads_with(fld, method):
    # type: (Any, Any) -> bool
    """Whether a field takes its bytes off the packet the given way.

    Asking the bound method rather than the class sees through the wrappers
    (Emph, MayEnd) a class may put around a field.
    """
    return getattr(fld.getfield, "__func__", None) is method


def _one_value_format(fld):
    # type: (Field[Any, Any]) -> Optional[Tuple[str, str]]
    """The byte order and format of a field read as one struct item."""
    if not _reads_with(fld, Field.getfield):
        # The field cuts its bytes off in its own way
        return None
    fmt = fld.fmt
    order, code = (fmt[0], fmt[1:]) if fmt[0] in _BYTE_ORDER else ("!", fmt)
    try:
        parsed = struct.Struct(order + code)
    except struct.error:
        return None
    if parsed.size != fld.sz or len(parsed.unpack(b"\x00" * fld.sz)) != 1:
        return None
    return order, code


def _plain_field(fld):
    # type: (Any) -> Optional[Tuple[str, str]]
    """The struct item a fixed size field reads, if a run may hold it."""
    if fld.isconditional or fld.ismayend:
        # Whether it is there at all, or whether anything follows it, is only
        # known once the fields before it have been read
        return None
    return _one_value_format(fld)


def _bit_group(fields, index):
    # type: (List[Any], int) -> Tuple[List[Any], int]
    """The bit fields from index on that together fill whole bytes."""
    group = []  # type: List[Any]
    bits = 0
    while index < len(fields):
        fld = fields[index]
        if not _reads_with(fld, _BitField.getfield):
            break
        if fld.rev or fld.isconditional or fld.ismayend:
            break
        group.append(fld)
        bits += fld.size
        index += 1
        if bits % 8 == 0:
            return group, bits // 8
    return [], 0


def _unwrap(fld):
    # type: (Any) -> Any
    """The field a wrapper holds, as long as it always holds the same one.

    Emph and MayEnd forward everything to one field, while a
    MultipleTypeField picks the field it forwards to per packet and is
    therefore left alone.
    """
    while isinstance(fld, _FieldContainer):
        if isinstance(getattr(type(fld), "fld", None), property):
            break
        fld = fld.fld
    return fld


_KINDS = ("islist", "holds_packets", "ismutable")


def _remembers(fld):
    # type: (Any) -> Optional[bool]
    """Whether the value of a field is one to remember for the raw cache.

    :return: None when only the packet at hand can tell
    """
    inner = _unwrap(fld)
    flags = [getattr(type(inner), kind, None) for kind in _KINDS]
    if any(not isinstance(flag, int) for flag in flags):
        return None
    return any(flags)


_INT_CODE = {1: "B", 2: "H", 4: "I", 8: "Q"}


def _plan(cls):
    # type: (Type[Packet]) -> List[Any]
    """The steps that read a class: runs of struct items, and lone fields.

    A step is ``("run", order, [items], size, index)`` where an item is either
    ``("field", fld, code)`` or ``("bits", [flds], code, nbytes)``, or
    ``("field", fld, index)`` for a field left to itself.
    """
    fields = list(cls.fields_desc)  # type: List[Any]
    steps = []  # type: List[Any]
    items = []  # type: List[Any]
    order = ""
    size = 0
    start = 0
    index = 0

    def flush():
        # type: () -> None
        if items:
            steps.append(("run", order, list(items), size, start))
        del items[:]

    while index < len(fields):
        fld = fields[index]
        group, nbytes = _bit_group(fields, index)
        if group:
            code = _INT_CODE.get(nbytes) or "%ds" % nbytes
            if items and order != "!":
                flush()
                size = 0
            if not items:
                order, start, size = "!", index, 0
            items.append(("bits", group, code, nbytes))
            size += nbytes
            index += len(group)
            continue
        plain = _plain_field(fld)
        if plain:
            forder, code = plain
            if items and forder != order:
                flush()
                size = 0
            if not items:
                order, start, size = forder, index, 0
            items.append(("field", fld, code))
            size += fld.sz
            index += 1
            continue
        flush()
        size = 0
        steps.append(("field", fld, index))
        index += 1
    flush()
    return steps


def _remember(fld, held, indent, hold):
    # type: (Any, Optional[str], str, Any) -> List[str]
    """The source that keeps a value the packet may change under our feet.

    Building a packet again compares such a value against what was dissected,
    to know whether the bytes it was read from still describe it.
    """
    remembers = _remembers(fld)
    if remembers is False:
        return []
    if held is None:
        held = hold(fld, "_fld")
    condition = "v is not None"
    if remembers is None:
        # A field that only the packet at hand knows the kind of
        condition = "(%s.islist or %s.holds_packets or %s.ismutable) " \
            "and v is not None" % (held, held, held)
    return [
        "%sif %s:" % (indent, condition),
        "%s    self.raw_packet_cache_fields[%r] = "
        "self._raw_packet_cache_field_value(%s, v, copy=True)" % (
            indent, fld.name, held
        ),
    ]


def _assign(fld, value, namespace, hold):
    # type: (Field[Any, Any], str, Dict[str, Any], Any) -> List[str]
    """The source that puts a value in the packet, converted if it must be."""
    if getattr(fld.m2i, "__func__", None) is not Field.m2i:
        value = "%s(self, %s)" % (hold(fld.m2i, "_m2i"), value)
    remembered = _remember(fld, None, "    ", hold) if _remembers(fld) \
        else []
    if not remembered:
        return ["    f[%r] = %s" % (fld.name, value)]
    return ["    v = %s" % value, "    f[%r] = v" % fld.name] + remembered


def _dissect_source(cls, steps, namespace):
    # type: (Type[Packet], List[Any], Dict[str, Any]) -> str
    """Generate the dissection of a class from its plan."""
    namespace["_fields_desc"] = cls.fields_desc
    lines = [
        "def do_dissect(self, s):",
        # A class that came along later and inherited this reads other fields
        "    if self.fields_desc is not _fields_desc:",
        "        return _stock_dissect(self, s, s, 0)",
        "    _raw = s",
        "    self.raw_packet_cache_fields = {}",
        "    f = self.fields",
    ]
    tail = [
        "    self.raw_packet_cache = _raw[:-len(s)] if s else _raw",
        "    self.explicit = 1",
        "    return s",
    ]

    def constant(value, prefix):
        # type: (Any, str) -> str
        name = "%s%d" % (prefix, len(namespace))
        namespace[name] = value
        return name

    # Only a field that reads a size of its own may leave something other
    # than the bytes left behind, such as the half read byte of a bit field
    plain_bytes = True

    for step in steps:
        if step[0] == "field":
            fld, index = step[1], step[2]
            held = constant(fld, "_fld")
            lines.append("    s, v = %s.getfield(self, s)" % held)
            plain_bytes = False
            indent = "    "
            if fld.isconditional:
                lines.append("    if v is not None:")
                indent = "        "
            lines.extend(_remember(fld, held, indent, constant))
            lines.append("%sf[%r] = v" % (indent, fld.name))
            mayend = fld.ismayend or (
                fld.isconditional and getattr(fld.fld, "ismayend", False)
            )
            if mayend:
                lines.append("    if not s:")
                lines.extend("    " + line for line in tail)
            continue

        _, order, items, size, index = step
        fmt = order + "".join(
            item[2] for item in items
        )
        held = constant(struct.Struct(fmt), "_st")
        lines.append("    if %slen(s) < %d:" % (
            "" if plain_bytes else "type(s) is not bytes or ", size
        ))
        lines.append(
            "        return _stock_dissect(self, _raw, s, %d)" % index
        )
        values = ["_v%d" % i for i in range(len(items))]
        lines.append(
            "    %s%s = %s.unpack_from(s)" % (
                ", ".join(values), "," if len(values) == 1 else "", held
            )
        )
        for value, item in zip(values, items):
            if item[0] == "field":
                lines.extend(_assign(item[1], value, namespace, constant))
                continue
            group, code, nbytes = item[1], item[2], item[3]
            if code.endswith("s"):
                lines.append(
                    "    %s = int.from_bytes(%s, 'big')" % (value, value)
                )
            left = nbytes * 8
            for fld in group:
                left -= fld.size
                mask = (1 << fld.size) - 1
                read = value if not left else "(%s >> %d)" % (value, left)
                lines.extend(_assign(
                    fld, "%s & %d" % (read, mask), namespace, constant
                ))
        lines.append("    s = s[%d:]" % size)

    lines.extend(tail)
    return "\n".join(lines)


# Picking the next layer


def _bindings(cls):
    # type: (Type[Packet]) -> List[Tuple[Dict[str, Any], Type[Packet]]]
    """Every binding the class looks at, in the order it looks at them."""
    found = []  # type: List[Tuple[Dict[str, Any], Type[Packet]]]
    for alias in cls.aliastypes:
        for fval, upper in alias.payload_guess:
            found.append((fval, upper))
    return found


def _guess_source(cls, namespace):
    # type: (Type[Packet], Dict[str, Any]) -> Optional[str]
    """Generate the payload dispatch of a class from its bindings."""
    groups = {}  # type: Dict[Tuple[str, ...], Dict[Any, Any]]
    always = None  # type: Optional[Type[Packet]]
    for order, (fval, upper) in enumerate(_bindings(cls)):
        keys = tuple(fval)
        if not keys:
            # A binding on no field at all, which every packet matches
            always = upper
            break
        try:
            values = tuple(fval[k] for k in keys)  # type: Any
            hash(values)
        except TypeError:
            # A binding that compares something a dict cannot hold
            return None
        if len(keys) == 1:
            values = values[0]
        # setdefault, because the first binding that matches wins
        groups.setdefault(keys, {}).setdefault(values, (order, upper))

    namespace["_aliastypes"] = cls.aliastypes
    namespace["_stale"] = _stale(cls)
    # A binding added since, or a class that came along later and inherited
    # this, are both something this was not compiled for. Binding a layer
    # gives the lower class a new list, so its identity dates the tables.
    fresh = ["self.aliastypes is not _aliastypes"]
    for number, alias in enumerate(cls.aliastypes):
        namespace["_alias%d" % number] = alias
        namespace["_guess%d" % number] = alias.payload_guess
        fresh.append(
            "_alias%d.payload_guess is not _guess%d" % (number, number)
        )
    lines = [
        "def guess_payload_class(self, payload):",
        "    if %s:" % " or ".join(fresh),
        "        return _stale(self, payload)",
    ]
    if groups:
        # The bindings of a layer rarely compare the same fields one after
        # the other, so they are gathered by the fields they compare and the
        # rank of each is kept, the first binding that matches being the one
        # that answers however they were declared
        ranked = len(groups) > 1
        lines.append("    f = self.fields")
        if ranked:
            lines.append("    _b = None")
        lines.append("    try:")
        for keys, table in groups.items():
            held = "_tbl%d" % len(namespace)
            namespace[held] = table if ranked else {
                value: upper for value, (_, upper) in table.items()
            }
            reads = [
                'f[%r] if %r in f else _val(self, %r)' % (k, k, k)
                for k in keys
            ]
            read = reads[0] if len(keys) == 1 else "(%s)" % ", ".join(reads)
            lines.append("        _c = %s.get(%s)" % (held, read))
            if ranked:
                lines.append("        if _c is not None and "
                             "(_b is None or _c[0] < _b[0]):")
                lines.append("            _b = _c")
            else:
                lines.append("        if _c is not None:")
                lines.append("            return _c")
        lines.append("    except TypeError:")
        lines.append(
            "        return Packet.guess_payload_class(self, payload)"
        )
        if ranked:
            lines.append("    if _b is not None:")
            lines.append("        return _b[1]")
    if always is not None:
        held = "_cls%d" % len(namespace)
        namespace[held] = always
        lines.append("    return %s" % held)
    else:
        lines.append("    return self.default_payload_class(payload)")
    return "\n".join(lines)


def _stale(cls):
    # type: (Type[Packet]) -> Any
    """What a class runs once what it was compiled from has moved on."""
    aliastypes = cls.aliastypes

    def outdated(pkt, payload):
        # type: (Packet, bytes) -> Any
        if pkt.aliastypes is not aliastypes:
            # Another class reached this, through super() or by inheriting
            # it, and its own bindings are the ones that answer for it
            return Packet.guess_payload_class(pkt, payload)
        # The bindings of the class itself changed, so compile it again
        refresh(cls)
        return pkt.guess_payload_class(payload)
    return outdated


# Building the next layer


_set = object.__setattr__
_NOPAYLOAD = NoPayload()
# The one method of Packet this stands in for, kept to be given back
_stock_payload = Packet.__dict__["do_dissect_payload"]

# What builds and dissects a layer, per class
_builders = {}  # type: Dict[Type[Packet], Any]
# The classes whose dissection a builder runs itself, step by step
_inlined = set()  # type: Any

# What a class must leave to Packet for its dissection to be run step by step
_PLAIN = ("dissect", "pre_dissect", "post_dissect", "extract_padding",
          "do_dissect_payload")
# What a built packet may hold that a constructed one does not: the time it
# was dissected at, the bytes it was read from and what came of them
_FREE = ("time", "original", "fields", "payload", "underlayer",
         "stop_dissection_after")


def _prime(cls):
    # type: (Type[Packet]) -> bool
    """Fill the field caches of a class the way its first packet would.

    A packet takes the defaults, the types and the packet fields of its class
    from caches that the first packet of the class fills. They are filled here
    instead, on a packet that is handed to no one and whose constructor is
    never run, because a class is free to do more in its own than fill caches.

    :return: whether the class keeps the fields of its packets in those caches
    """
    if not cls.fields_desc:
        # Nothing to cache, and every packet gets empty ones of its own
        return True
    if Packet.class_default_fields.get(cls) is None:
        probe = Packet.__new__(cls)
        for slot, empty in (("fields", {}), ("fieldtype", {}),
                            ("packetfields", []), ("default_fields", {})):
            _set(probe, slot, empty)
        probe.prepare_cached_fields(cls.fields_desc)
    return Packet.class_default_fields.get(cls) is not None and \
        not Packet.class_dont_cache.get(cls, False)


def _builder_source(cls, namespace):
    # type: (Type[Packet], Dict[str, Any]) -> Optional[str]
    """Generate the construction of a layer, and the dissection it starts.

    Building a layer is the same two dozen attributes every time, all but
    three of them the same for every packet of a class, and the constructor
    that sets them costs more than reading the header it is built around.
    Baking them into a function of the class turns it into as many stores.
    """
    if _own(cls, "__init__") is not Packet.__init__:
        _skipped[cls] = "builds its packets itself"
        return None
    if getattr(cls, "__new__", None) is not object.__new__ or \
            "dispatch_hook" in cls.__dict__:
        _skipped[cls] = "picks the class of its packets itself"
        return None
    if not _prime(cls):
        _skipped[cls] = "gives every packet defaults of its own"
        return None

    def constant(value, prefix):
        # type: (Any, str) -> str
        name = "%s%d" % (prefix, len(namespace))
        namespace[name] = value
        return name

    namespace["_cls"] = cls
    namespace["_new"] = object.__new__
    namespace["_set"] = _set
    namespace["_fields_desc"] = cls.fields_desc
    if cls.fields_desc:
        held = (
            constant(Packet.class_default_fields[cls], "_def"),
            constant(Packet.class_fieldtype[cls], "_typ"),
            constant(Packet.class_packetfields[cls], "_pfl"),
        )
    else:
        # Nothing shared to hold, so every packet is given its own
        held = ("{}", "{}", "[]")
    slots = [
        ("time", "0.0"),
        ("sent_time", "None"),
        ("name", constant(
            cls.__name__ if getattr(cls, "_name", None) is None
            else cls._name, "_nam"
        )),
        ("default_fields", held[0]),
        ("overload_fields", constant(cls._overload_fields, "_ovl")),
        ("overloaded_fields", "{}"),
        ("fields", "{}"),
        ("fieldtype", held[1]),
        ("packetfields", held[2]),
        ("payload", "_nopayload"),
        ("underlayer", "under"),
        ("parent", "None"),
        ("original", "s"),
        ("explicit", "0"),
        ("raw_packet_cache", "None"),
        ("raw_packet_cache_fields", "None"),
        ("wirelen", "None"),
        ("direction", "None"),
        ("sniffed_on", "None"),
        ("comments", "None"),
        ("process_information", "None"),
        ("stop_dissection_after", "stop_after"),
        ("post_transforms", "[]"),
    ]
    namespace["_nopayload"] = _NOPAYLOAD
    body = ["    p = _new(_cls)"] + [
        "    _set(p, %r, %s)" % (slot, value) for slot, value in slots
    ]

    if all(_own(cls, name) is getattr(Packet, name) for name in _PLAIN):
        # Nothing of the class steps in around its fields, so the walk of the
        # layer and of what follows it is what Packet.dissect would do
        _inlined.add(cls)
        namespace["_conf"] = conf
        after = [
            "    _left = _dissect(p, s)",
            # A field is free to hand the packet a method of its own while it
            # is read, the way a checksum read from the end of a layer undoes
            # the cache of the bytes it was read from
            "    if p.__dict__:",
            "        _left = p.post_dissect(_left)",
            "        _left, _pad = p.extract_padding(_left)",
            "        p.do_dissect_payload(_left)",
            "        if _pad and _conf.padding:",
            "            p.add_payload(_conf.padding_layer(_pad))",
            "    elif _left:",
            "        p.do_dissect_payload(_left)",
        ]
    else:
        after = ["    p.dissect(s)"]

    return "\n".join(
        ["def construct(s, under, stop_after):"] + body + ["    return p"] +
        ["", "", "def build(s, under, stop_after):",
         # A class whose fields moved is one this was not compiled for
         "    if _cls.fields_desc is not _fields_desc:",
         "        return None"] + body + after + ["    return p"]
    )


def _matches_init(cls, construct):
    # type: (Type[Packet], Any) -> Optional[str]
    """The first slot a built packet and a constructed one part ways on.

    The constructor of a class is only worth skipping once what it leaves
    behind is known, so what it leaves behind is compared, slot by slot,
    against what the generated one does.
    """
    try:
        stock = Packet.__new__(cls)
        Packet.__init__(stock)
        mine = construct(b"", None, None)
        for slot in sorted(cls.__all_slots__):
            held = [
                getattr(packet, slot, _MISS) for packet in (stock, mine)
            ]
            if (held[0] is _MISS) != (held[1] is _MISS):
                return slot
            if slot in _FREE or held[0] is held[1]:
                continue
            if held[0] != held[1]:
                return slot
    except Exception:
        # A class this cannot even compare is one to leave its packets to
        return "state"
    return None


def _dissect_payload(self, s):
    # type: (Packet, bytes) -> None
    """Dissect what follows a layer, building it from the plan of its class.

    This is Packet.do_dissect_payload, up to the constructor of the next
    layer: a class that was compiled is built and dissected by what was
    generated for it, and any other one is built the way it always was.
    """
    if not s:
        return
    if _lazy and type(self) not in _learned:
        # The layer at hand, compiled for the packets after this one
        _learn(type(self))
    if self.stop_dissection_after and \
            isinstance(self, self.stop_dissection_after):
        self.add_payload(conf.raw_layer(s, _internal=1, _underlayer=self))
        return
    cls = self.guess_payload_class(s)
    build = _builders.get(cls)
    if build is None and _lazy and cls not in _learned:
        _learn(cls)
        build = _builders.get(cls)
    try:
        p = None
        if build is not None and type(s) is bytes:
            p = build(s, self, self.stop_dissection_after)
        if p is None:
            # A class with no plan, or one it has moved on from
            p = cls(
                s,
                stop_dissection_after=self.stop_dissection_after,
                _internal=1,
                _underlayer=self,
            )
    except KeyboardInterrupt:
        raise
    except Exception:
        if conf.debug_dissector:
            if issubtype(cls, Packet):
                log_runtime.error("%s dissector failed", cls.__name__)
            else:
                log_runtime.error("%s.guess_payload_class() returned "
                                  "[%s]",
                                  self.__class__.__name__, repr(cls))
            if cls is not None:
                raise
        p = conf.raw_layer(s, _internal=1, _underlayer=self)
    self.add_payload(p)


# Compiling


_PARTS = ("dissect", "guess", "build")
# What the classes were last compiled with, for the ones compiled again since
_parts = _PARTS  # type: Tuple[str, ...]
# Whether a class is compiled the first time a packet of it is dissected
_lazy = False
# The classes that first packet has come for
_learned = set()  # type: Any


def _learn(cls):
    # type: (Type[Packet]) -> None
    """Compile a class the first time the dissection reaches it.

    Compiling every class that is loaded costs about a second, most of it for
    classes a capture never holds, while compiling one costs half a
    millisecond. A class is therefore left alone until a packet of it turns
    up, which is also what lets a layer imported later be compiled at all.
    """
    _learned.add(cls)
    try:
        compile_class(cls, _parts)
    except Exception as ex:  # a plan is never worth a dissection
        _skipped[cls] = "could not be compiled: %s" % ex
        return
    _shield(_descendants(cls))


def _descendants(cls):
    # type: (Type[Packet]) -> List[Type[Packet]]
    """The classes that inherit from one, parents before children."""
    found = []  # type: List[Type[Packet]]
    for sub in cls.__subclasses__():
        found.append(sub)
        found.extend(_descendants(sub))
    return found


def compile_class(cls, parts=_PARTS):
    # type: (Type[Packet], Tuple[str, ...]) -> List[str]
    """Give a class the dissection its fields, bindings and layer describe.

    :param parts: what to compile, of the fields, the bindings and the layer
    :return: the names of what was generated for it
    """
    if cls in _installed:
        return _installed[cls]
    namespace = {
        "_stock_dissect": _stock_dissect,
        "_val": _val,
        "Packet": Packet,
    }  # type: Dict[str, Any]
    sources = {}  # type: Dict[str, str]

    if "dissect" in parts:
        if _own(cls, "do_dissect") is not Packet.__dict__["do_dissect"]:
            _skipped[cls] = "dissects itself"
        elif not cls.fields_desc:
            _skipped[cls] = "has no field"
        else:
            steps = _plan(cls)
            if any(step[0] == "run" for step in steps):
                sources["do_dissect"] = _dissect_source(cls, steps, namespace)
            else:
                _skipped[cls] = "no field of a size known ahead of time"

    if "guess" in parts and _own(cls, "guess_payload_class") is \
            Packet.__dict__["guess_payload_class"]:
        guess = _guess_source(cls, namespace)
        if guess is not None:
            sources["guess_payload_class"] = guess

    if "build" in parts:
        build = _builder_source(cls, namespace)
        if build is not None:
            sources["build"] = build

    # Compile and weigh everything before handing the class anything, so
    # that a class this cannot read entirely keeps the dissection it had
    for name, source in sources.items():
        exec(compile(source, "<%s %s>" % (name, cls.__name__), "exec"),
             namespace)
        namespace["_source_" + name] = source

    if "build" in sources:
        parted = _matches_init(cls, namespace["construct"])
        if parted is not None:
            # Something of the class ends up elsewhere than where the
            # generated constructor puts it, so its own is left to do it
            del sources["build"]
            _inlined.discard(cls)
            _skipped[cls] = "leaves its packets a %s of its own" % parted

    for name in sources:
        if name in _METHODS:
            setattr(cls, name, namespace[name])
            shielded = _shields.get(cls)
            if shielded and name in shielded:
                # What the class was handed back is what this now compiled
                shielded.remove(name)

    if "build" in sources:
        # The dissection of the class, as it stands now that it is installed
        namespace["_dissect"] = cls.__dict__.get("do_dissect") or \
            _own(cls, "do_dissect")
        _builders[cls] = namespace["build"]

    if sources:
        cls._fastdissect = namespace  # type: ignore
        _installed[cls] = list(sources)
    return list(sources)


def enable(classes=None, parts=_PARTS, lazy=False, shield=True):
    # type: (Optional[List[Type[Packet]]], Tuple[str, ...], bool, bool) -> int
    """Compile the packet classes that are loaded.

    :param classes: the classes to compile, all of the loaded ones by default
    :param parts: what to compile, of the fields, the bindings and the layer
    :param lazy: compile a class when a packet of it first turns up instead
    :param shield: hand a class that inherits a plan of another its own
        method back. Compiling without it leaves every such class to the
        guards the generated code opens with, which is what they are for and
        what a class loaded after the one it inherits from meets anyway.
    :return: how many of them were given a dissection of their own
    """
    global _parts, _lazy
    disable()
    _parts = parts
    _lazy = lazy
    if lazy or "build" in parts:
        # The one place a layer is built from another, and the only method
        # this hands to Packet itself, where it answers for every class
        Packet.do_dissect_payload = _dissect_payload  # type: ignore
    if lazy:
        return 0
    for cls in (classes if classes is not None else _packet_classes()):
        try:
            compile_class(cls, parts)
        except Exception as ex:  # a plan is never worth an import error
            _skipped[cls] = "could not be compiled: %s" % ex
    if shield:
        _shield()
    return len(_installed)


def refresh(cls):
    # type: (Type[Packet]) -> List[str]
    """Compile a class again, after what it was compiled from changed."""
    for name in _installed.pop(cls, []) + _shields.pop(cls, []):
        if name in _METHODS and name in cls.__dict__:
            delattr(cls, name)
    if "_fastdissect" in cls.__dict__:
        delattr(cls, "_fastdissect")
    _builders.pop(cls, None)
    _inlined.discard(cls)
    _skipped.pop(cls, None)
    given = compile_class(cls, _parts)
    _shield(_descendants(cls) if _lazy else None)
    return given


def _shield(classes=None):
    # type: (Optional[List[Type[Packet]]]) -> None
    """Keep a compiled class from reading the fields of its children.

    A class that inherits its dissection would find the one compiled for its
    parent, which reads other fields. Such a class is handed back what it ran
    before, on itself, where it comes first.
    """
    for cls in (classes if classes is not None else _packet_classes()):
        for name in _METHODS:
            if name in cls.__dict__:
                continue
            wanted = _own(cls, name)
            if getattr(cls, name, None) is not wanted:
                setattr(cls, name, wanted)
                _shields.setdefault(cls, []).append(name)


def disable():
    # type: () -> None
    """Give the classes their stock dissection back."""
    global _lazy
    _lazy = False
    _learned.clear()
    if Packet.__dict__["do_dissect_payload"] is _dissect_payload:
        Packet.do_dissect_payload = _stock_payload  # type: ignore
    for held in (_installed, _shields):
        for cls, given in held.items():
            for name in given:
                if name in _METHODS and name in cls.__dict__:
                    delattr(cls, name)
            if "_fastdissect" in cls.__dict__:
                delattr(cls, "_fastdissect")
        held.clear()
    _builders.clear()
    _inlined.clear()
    _skipped.clear()


def explain(cls):
    # type: (Type[Packet]) -> str
    """The dissection a class was given, as the source it was generated from."""
    namespace = getattr(cls, "_fastdissect", None)
    if namespace is None or cls not in _installed:
        return "%s: %s" % (
            cls.__name__, _skipped.get(cls, "not compiled")
        )
    parts = [
        namespace[key]
        for key in ("_source_build", "_source_do_dissect",
                    "_source_guess_payload_class")
        if key in namespace
    ]
    return "\n\n".join(parts)


def stats():
    # type: () -> Dict[str, Any]
    """What the compilation covered."""
    given = list(_installed.values())
    return {
        "classes": len(_packet_classes()),
        "lazy": _lazy,
        "seen": len(_learned),
        "compiled": len(_installed),
        "do_dissect": sum(1 for names in given if "do_dissect" in names),
        "guess_payload_class": sum(
            1 for names in given if "guess_payload_class" in names
        ),
        "build": len(_builders),
        "inlined": len(_inlined),
        "shielded": len(_shields),
        "skipped": len(_skipped),
    }
