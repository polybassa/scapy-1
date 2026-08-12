#!/usr/bin/env python3
"""Check and benchmark the compiled dissection of scapy.fastdissect.

    python3 test/bench_fastdissect.py check   # same result as the stock one
    python3 test/bench_fastdissect.py bench   # how much faster
    python3 test/bench_fastdissect.py         # both
"""

import os
import sys
import timeit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import (  # noqa: E402
    ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Dot1Q, Ether, GRE, ICMP, IP, IPv6,
    Raw, TCP, UDP, conf,
)
from scapy.layers.inet6 import ICMPv6EchoRequest  # noqa: E402
from scapy.layers.l2 import LLC, SNAP  # noqa: E402
from scapy.layers.sctp import SCTP, SCTPChunkData  # noqa: E402
from scapy.packet import Packet  # noqa: E402
from scapy import fastdissect  # noqa: E402

conf.verb = 0


def corpus():
    """The packets test/bench_dissect.py measures, as raw bytes."""
    return [
        ("Ether/ARP", bytes(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP())),
        ("Ether/Dot1Q/IP", bytes(Ether() / Dot1Q(vlan=42) / IP() / Raw(b"x" * 64))),  # noqa: E501
        ("Ether/IP/Raw(64)", bytes(Ether() / IP() / Raw(b"x" * 64))),
        ("Ether/IP/TCP/Raw(20)", bytes(Ether() / IP() / TCP() / Raw(b"x" * 20))),  # noqa: E501
        ("Ether/IP/TCP/Raw(1400)", bytes(Ether() / IP() / TCP() / Raw(b"x" * 1400))),  # noqa: E501
        ("Ether/IP/UDP/Raw(512)", bytes(Ether() / IP() / UDP() / Raw(b"x" * 512))),  # noqa: E501
        ("Ether/IP/ICMP", bytes(Ether() / IP() / ICMP() / Raw(b"x" * 32))),
        ("Ether/IPv6/ICMPv6", bytes(Ether() / IPv6() / ICMPv6EchoRequest() / Raw(b"x" * 32))),  # noqa: E501
        ("Ether/IP/UDP/DNS(q)", bytes(Ether() / IP() / UDP() / DNS(rd=1, qd=DNSQR(qname="www.example.com")))),  # noqa: E501
        ("Ether/IP/UDP/DNS(resp)", bytes(Ether() / IP() / UDP(sport=53) / DNS(
            id=0x1234, qr=1, ra=1,
            qd=DNSQR(qname="www.example.com"),
            an=DNSRR(rrname="www.example.com", rdata="93.184.216.34"),
        ))),
        ("Ether/IP/UDP/DHCP", bytes(Ether() / IP() / UDP(sport=68, dport=67) / BOOTP() / DHCP())),  # noqa: E501
        ("Ether/LLC/SNAP/IP/TCP", bytes(Ether() / LLC() / SNAP() / IP() / TCP() / Raw(b"x" * 100))),  # noqa: E501
        ("Ether/IP/GRE/IP/TCP", bytes(Ether() / IP() / GRE() / IP() / TCP() / Raw(b"x" * 100))),  # noqa: E501
        ("Ether/IP/SCTP", bytes(Ether() / IP(proto=132) / SCTP() / SCTPChunkData(data=b"hello"))),  # noqa: E501
        ("Ether/Dot1Q/QinQ/IP/TCP/1k", bytes(Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP() / TCP() / Raw(b"y" * 1024))),  # noqa: E501
    ]


def check():
    """Dissect everything both ways and compare what comes out."""
    cases = [(name, Ether, raw) for name, raw in corpus()]

    # Every class that builds a default packet, dissected as itself and
    # truncated, which is where a plan hands back to the stock dissection.
    for cls in list(conf.layers):
        if not issubclass(cls, Packet) or not cls.fields_desc:
            continue
        try:
            data = bytes(cls())
        except Exception:
            continue
        if not data:
            continue
        cases.append((cls.__name__, cls, data))
        cases.append((cls.__name__ + "[:-1]", cls, data[:-1]))
        cases.append((cls.__name__ + "[:2]", cls, data[:2]))
        cases.append((cls.__name__ + "+pad", cls, data + b"\x00" * 8))

    def dissect(cls, data):
        """Everything the dissection of some bytes is expected to produce."""
        try:
            pkt = cls(data)
            out = [pkt.show(dump=True), repr(bytes(pkt))]
            layer = pkt
            while layer:
                # The mutable fields, which building the packet again looks at
                out.append("%s %s %r" % (
                    layer.__class__.__name__,
                    sorted(layer.raw_packet_cache_fields or ()),
                    layer.raw_packet_cache,
                ))
                layer = layer.payload
            return "\n".join(out)
        except Exception as ex:
            return "%s: %s" % (type(ex).__name__, ex)

    fastdissect.disable()
    stock = [dissect(cls, data) for _, cls, data in cases]

    bad = []
    for label, shield in (("compiled", True), ("inherited", False)):
        # Without shielding, a class that inherits the plan of another runs
        # it and has to be handed back by the guards it opens with, the way
        # a class loaded after the one it inherits from is
        compiled = fastdissect.enable(shield=shield)
        fast = [dissect(cls, data) for _, cls, data in cases]
        fastdissect.disable()
        differ = [
            ("%s %s" % (label, name), a, b)
            for (name, _, _), a, b in zip(cases, stock, fast) if a != b
        ]
        print("%s: %d classes, %d dissections, %d differ%s" % (
            label, compiled, len(cases), len(differ),
            "" if not differ else
            ": " + ", ".join(name for name, _, _ in differ[:8])))
        bad.extend(differ)

    if os.environ.get("SHOW"):
        for name, a, b in bad[:int(os.environ["SHOW"])]:
            print("\n=== %s differs ===\n--- stock\n%s\n--- compiled\n%s" %
                  (name, a, b))
    return not bad


def _pps(cls, data, budget=0.2):
    """Packets a second, over runs of about `budget` seconds each."""
    def run():
        cls(data)
    for _ in range(100):
        run()
    once = timeit.timeit(run, number=20) / 20
    number = max(20, int(budget / once))
    return number / min(timeit.timeit(run, number=number) for _ in range(5))


_RUNS = (
    ("stock", None),
    ("fields", ("dissect",)),
    ("bindings", ("guess",)),
    ("layers", ("build",)),
    ("all", ("dissect", "guess", "build")),
)


def bench():
    packets = corpus()
    runs = []
    for label, parts in _RUNS:
        fastdissect.disable()
        if parts:
            fastdissect.enable(parts=parts)
        rows = {name: _pps(Ether, data) for name, data in packets}
        runs.append((label, rows))
    fastdissect.disable()

    labels = [label for label, _ in _RUNS]
    header = "%-28s %5s" % ("packet", "B") + \
        "".join("%10s" % label for label in labels) + "%8s" % "delta"
    print()
    print(header)
    print("-" * len(header))
    means = {label: [] for label in labels}
    for name, data in packets:
        cells = [rows[name] for _, rows in runs]
        for label, cell in zip(labels, cells):
            means[label].append(cell)
        print("%-28s %5d%s%+7.1f%%" % (
            name, len(data), "".join("%10.0f" % cell for cell in cells),
            (cells[-1] / cells[0] - 1) * 100))
    print("-" * len(header))
    avg = {
        label: sum(values) / len(values) for label, values in means.items()
    }
    print("%-28s %5s%s%+7.1f%%" % (
        "mean pkt/s", "", "".join("%10.0f" % avg[la] for la in labels),
        (avg["all"] / avg["stock"] - 1) * 100))
    print("%-28s %5s%s" % (
        "mean us/pkt", "",
        "".join("%10.1f" % (1e6 / avg[la]) for la in labels)))


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    ok = True
    if what in ("check", "all"):
        ok = check()
    if what in ("bench", "all"):
        bench()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
