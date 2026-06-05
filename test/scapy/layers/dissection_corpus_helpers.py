import os
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import Union

from scapy.config import conf
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.packet import Packet
from scapy.tools.UTscapy import scapy_path
from scapy.utils import rdpcap
from scapy.utils import tcpdump

ScapyFieldValue = Optional[Tuple[Any, str]]
CompareFunction = Callable[[str, ScapyFieldValue], bool]
CompareEntry = Union[CompareFunction, Sequence[CompareFunction]]
DissectionMapEntry = Dict[str, Any]
DissectionMapping = Mapping[str, DissectionMapEntry]

LAYER_BY_NAME = {
    "IP": IP,
    "TCP": TCP,
    "UDP": UDP,
}


def _get_scapy_raw_value(scapy_value: ScapyFieldValue) -> Any:
    if isinstance(scapy_value, tuple):
        return scapy_value[0]
    return scapy_value


def _get_scapy_display_value(scapy_value: ScapyFieldValue) -> Any:
    if isinstance(scapy_value, tuple):
        return scapy_value[1]
    return scapy_value


def _normalize_scapy_value(value: ScapyFieldValue) -> str:
    value = _get_scapy_raw_value(value)
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _parse_int_value(value: ScapyFieldValue) -> Optional[int]:
    value = _get_scapy_raw_value(value)
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
        try:
            if value.lower().startswith(("0x", "+0x", "-0x")):
                return int(value, 16)
            return int(value)
        except ValueError:
            return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _compare_int_field(tshark_value: str, scapy_value: ScapyFieldValue) -> bool:
    if tshark_value == "":
        return scapy_value is None
    if scapy_value is None:
        return False
    tshark_int = _parse_int_value(tshark_value)
    scapy_int = _parse_int_value(scapy_value)
    if tshark_int is None or scapy_int is None:
        return False
    return tshark_int == scapy_int


def _compare_tcp_flags(tshark_value: str, scapy_value: ScapyFieldValue) -> bool:
    return _compare_int_field(tshark_value, scapy_value)


def _default_compare(tshark_value: str, scapy_value: ScapyFieldValue) -> bool:
    return tshark_value == _normalize_scapy_value(scapy_value)


def _normalize_alnum_lower(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def _compare_enum_field(tshark_value: str, scapy_value: ScapyFieldValue) -> bool:
    scapy_value = _get_scapy_display_value(scapy_value)
    tshark_enum = _normalize_alnum_lower(tshark_value)
    scapy_enum = _normalize_alnum_lower(scapy_value)
    if not tshark_enum or not scapy_enum:
        return False
    return tshark_enum == scapy_enum


def _get_compare_functions(
    tshark_field: str, entry: DissectionMapEntry
) -> List[CompareFunction]:
    compare = entry.get("compare")
    compare_functions: Sequence[CompareFunction]
    if compare is None:
        compare_functions = [_default_compare]
    elif isinstance(compare, (list, tuple)):
        assert compare, (
            f"At least one compare function must be provided for "
            f"{tshark_field!r} ({entry.get('scapy', 'unknown')!r})"
        )
        compare_functions = compare
    else:
        compare_functions = [compare]
    for compare_func in compare_functions:
        assert callable(compare_func), (
            f"Invalid compare function in mapping for "
            f"{tshark_field!r} ({entry.get('scapy', 'unknown')!r}): "
            f"{compare_func!r}"
        )
    return list(compare_functions)


def _get_scapy_field(packet: Packet, scapy_field: str) -> ScapyFieldValue:
    assert scapy_field.count(".") == 1, (
        f"Invalid scapy_field format: {scapy_field!r}. "
        "Expected format: LayerName.field_name (exactly one dot)"
    )
    layer_name, field_name = scapy_field.split(".", 1)
    assert layer_name and field_name, (
        f"Invalid scapy field mapping: {scapy_field!r}. "
        "Layer and field names must be non-empty"
    )
    assert layer_name in LAYER_BY_NAME, (
        f"Unsupported layer in mapping: {layer_name!r}. "
        f"Supported layers: {list(LAYER_BY_NAME.keys())!r}"
    )
    layer = LAYER_BY_NAME[layer_name]
    if layer not in packet:
        return None
    assert hasattr(packet[layer], field_name), (
        f"Field {field_name!r} does not exist on layer {layer_name!r}"
    )
    return (
        getattr(packet[layer], field_name),
        packet.sprintf(f"%{layer_name}.{field_name}%"),
    )


def _extract_tshark_rows(
    pcap_path: str, mapping: DissectionMapping
) -> List[List[str]]:
    args = ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for tshark_field in mapping:
        args.extend(["-e", tshark_field])
    output = tcpdump(
        pcap_path,
        prog=conf.prog.tshark,
        getfd=True,
        args=args,
        dump=True,
        wait=True,
    )
    lines = output.decode("utf-8").splitlines()
    rows = [line.split("\t") for line in lines]
    return rows


def _compare_pcap_dissection(
    pcap_file: str, mapping: DissectionMapping
) -> None:
    pcap_path = scapy_path("/" + pcap_file)
    assert os.path.exists(pcap_path)

    packets = rdpcap(pcap_path)
    tshark_rows = _extract_tshark_rows(pcap_path, mapping)

    assert len(packets) == len(tshark_rows), (
        f"Packet count mismatch for {pcap_file}: "
        f"scapy={len(packets)} tshark={len(tshark_rows)}"
    )

    tshark_fields = list(mapping)
    for packet_number, (packet, tshark_row) in enumerate(
        zip(packets, tshark_rows), 1
    ):
        assert len(tshark_row) == len(tshark_fields), (
            f"Field count mismatch for {pcap_file} packet #{packet_number}"
        )
        for field_idx, tshark_field in enumerate(tshark_fields):
            entry = mapping[tshark_field]
            compare_functions = _get_compare_functions(tshark_field, entry)
            scapy_value = _get_scapy_field(packet, entry["scapy"])
            tshark_value = tshark_row[field_idx]
            assert any(
                compare_func(tshark_value, scapy_value)
                for compare_func in compare_functions
            ), (
                f"Mismatch in {pcap_file} packet #{packet_number} for "
                f"{tshark_field}/{entry['scapy']}: "
                f"tshark={tshark_value!r} scapy={scapy_value!r}"
            )
