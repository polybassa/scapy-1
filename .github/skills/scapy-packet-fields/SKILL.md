---
name: Scapy packet, field, and layer patterns
description: Use this when adding or modifying Scapy protocol layers, fields, payload binding logic, or UTScapy tests.
---

# Scapy packet, field, and layer patterns

Use this skill when working on protocol implementation in Scapy core/layers, especially around `Packet`, `Field`, `fields_desc`, layer binding, and regression tests via UTScapy.

## Core model

- A layer is a `Packet` subclass with a `fields_desc` list.
- Field values flow through human/internal/machine conversions (`h2i`, `i2h`, `i2m`, `m2i`, `any2i`).
- Building and dissecting are centralized in `Packet` (`do_build`, `post_build`, `do_dissect`, `guess_payload_class`, `extract_padding`).

## Packet and field usage patterns

### 1) Define layers as `Packet` subclasses with `fields_desc`

- Prefer explicit defaults in `fields_desc`.
- Use field types that encode semantics (e.g. `EnumField`, `FlagsField`, `PacketListField`) instead of generic numeric/string fields when possible.
- For optional/variant fields, use `ConditionalField` and `MultipleTypeField`.

Examples:
- `scapy/layers/inet.py` (`IP`, `TCP`, `UDP`, `ICMP`)
- `scapy/layers/l2.py` (`Ether`, `ARP`, `GRE`, `Dot1Q`)

### 2) Compute deferred values in `post_build`

- Keep `None` defaults for values that must be computed from final bytes (checksums, lengths, header offsets).
- Implement updates in `post_build(self, p, pay)` after payload is available.

Common examples:
- `IP.post_build`: IHL/len/checksum
- `TCP.post_build`: data offset + checksum
- `UDP.post_build`: len + checksum
- `GRE.post_build`: conditional checksum

### 3) Split payload/padding with `extract_padding` when length is explicit

- If a layer encodes payload length, override `extract_padding`.
- Return `(payload, padding)` correctly to keep dissection aligned.

Examples:
- `IP.extract_padding`
- `UDP.extract_padding`
- `Dot3.extract_padding`

### 4) Bind layers with `bind_layers` first; use `guess_payload_class` only when needed

- Prefer declarative `bind_layers(Upper, Lower, field=value)` for stable protocol dispatch.
- Override `guess_payload_class` only for dynamic/non-equality logic.
- Keep fallback behavior aligned with `Packet.default_payload_class` (`conf.raw_layer`) when no match applies.

Examples:
- Extensive bindings in `scapy/layers/l2.py` and `scapy/layers/inet.py`
- Custom dispatch in `ICMP.guess_payload_class`

### 5) Request/response matching and stream reassembly hooks

- Implement `hashret()` when a protocol needs stable request/response correlation keys.
  - Base `Packet.hashret()` delegates to payload; many layers override it (e.g. IP/TCP/UDP) to include flow context.
- Implement `answers(other)` to express protocol-level "is response to" logic.
  - Base behavior matches same class then delegates to payload.
  - Typical checks include type/code pairs, id/seq tuples, and src/dst or sport/dport relationships.
- For stream-aware sniffing:
  - `IPSession` performs on-the-fly IPv4 defragmentation.
  - `TCPSession` reconstructs TCP byte streams and can call layer `tcp_reassemble(data, metadata, session)` when implemented.
  - `tcp_reassemble` should return a packet when enough bytes are present, else `None` and keep state in `metadata` / `session`.

References:
- `scapy/packet.py` (`hashret`, `answers`)
- `scapy/layers/inet.py` (`IP/TCP/UDP/ICMP` overrides)
- `scapy/sessions.py` (`IPSession`, `TCPSession`, `streamcls`)

### 6) Use specialized field helpers for protocol correctness

- **Length-coupled fields**
  - `FieldLenField` + `StrLenField` / `PacketListField` / `StrFixedLenField`
  - Pattern: one field stores encoded length/count, another consumes it via `length_from` / `count_from`.
- **Bit-packed structures**
  - `BitField`, `FlagsField`, and enum variants for compact headers and flag masks.
- **Conditional and variant typing**
  - `ConditionalField` for optional layout branches.
  - `MultipleTypeField` to switch field type from surrounding context (e.g. ARP IPv4 vs IPv6 address fields).
- **Container/composition helpers**
  - `PacketField` / `PacketListField` for nested packets.
  - `MayEnd` where short/error forms can legally stop dissection early.
- **Value representation helpers**
  - Enum helpers (`ByteEnumField`, `ShortEnumField`, `MultiEnumField`) for readable symbolic values.
  - Display wrappers like `Emph(...)` when emphasizing fields in output.
- **Intentional raw injection**
  - `RawVal` bypasses field conversion for explicit low-level byte control.

Examples:
- `scapy/layers/inet.py`: `IP.options` (`PacketListField`), `ICMP` conditionals/multi-types
- `scapy/layers/l2.py`: `ARP` multi-type address fields, GRE conditionals

## UTScapy integration patterns

Use UTScapy for regression coverage of layer behavior.

### Campaign structure

- Campaign syntax in test files:
  - `%` campaign
  - `+` test set
  - `=` unit test
  - `~` keywords
  - `*` comments
- The last Python expression in a unit test determines pass/fail truthiness.

References:
- `doc/scapy/development.rst` (Testing with UTScapy)
- `scapy/tools/UTscapy.py` (`parse_campaign_file`, campaign execution/filtering)

### Useful UTScapy CLI patterns

- Run one or more campaigns: `-t`
- Include/exclude keyword groups: `-k` / `-K`
- Select tests by number: `-n`
- Load `.utsc` JSON config: `-c`
- Output formats: `-f text|ansi|HTML|LaTeX|xUnit|live`
- Generate docs from campaign comments/tests: `-R`
- Non-root mode keyword filtering: `-N`

Reference:
- `scapy/tools/UTscapy.py` (`usage()`, `main()`)

### Typical test workflow

1. Add/modify protocol layer fields and binding logic.
2. Add/adjust UTScapy tests in `test/` configs/campaign files with meaningful keywords.
3. Run through existing wrappers (`./test/run_tests` or tox environments using `scapy.tools.UTscapy`).
4. Keep tests focused on:
   - build/dissect roundtrips
   - computed fields (len/checksum/options)
   - payload dispatch and edge-case fallback

## Quick references

- Core packet behavior: `scapy/packet.py`
- Field internals: `scapy/fields.py`
- Common layer patterns: `scapy/layers/inet.py`, `scapy/layers/l2.py`
- Test runner internals: `scapy/tools/UTscapy.py`
- Design guidance: `doc/scapy/build_dissect.rst`
