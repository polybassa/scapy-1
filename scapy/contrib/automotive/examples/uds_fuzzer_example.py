#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
UDS Fuzzer Enumerator Example
==============================

This example demonstrates how to use the UDS_FuzzerEnumerator for intelligent
fuzzing of UDS-based automotive ECUs.

The UDS_FuzzerEnumerator implements a score-based fuzzing approach that:
1. Generates mutations of UDS packets
2. Analyzes ECU responses and assigns scores
3. Prioritizes high-scoring mutations for further fuzzing
4. Supports health checks to prevent ECU crashes
"""

from scapy.contrib.automotive.uds import UDS, UDS_DSC, UDS_TP, UDS_RDBI
from scapy.contrib.automotive.uds_scan import UDS_FuzzerEnumerator
from scapy.contrib.automotive.ecu import EcuState

# Example 1: Basic Fuzzing
print("Example 1: Basic Fuzzing")
print("-" * 50)

fuzzer = UDS_FuzzerEnumerator()
print("Fuzzer initialized with default settings")
print(f"  Mutation count: {fuzzer._mutation_count}")
print(f"  Seen response codes: {len(fuzzer._seen_response_codes)}")
print()

# Example 2: Custom Seeds
print("Example 2: Custom Seeds and Strategy")
print("-" * 50)

custom_seeds = [
    UDS() / UDS_DSC(diagnosticSessionType=2),
    UDS() / UDS_DSC(diagnosticSessionType=3),
    UDS() / UDS_TP(),
]

# Note: Mutation generates raw bytes which may not be valid UDS packets
# This is expected behavior for fuzzing
mutations = list(fuzzer._get_initial_requests(
    initial_seeds=custom_seeds,
    max_mutations=20,  # Reduced for example
    mutation_strategy='random',  # Use random for simpler example
    mutation_rate=0.1,
    max_payload_size=128
))

print(f"Generated {len(mutations)} mutations from {len(custom_seeds)} custom seeds")
print("First few mutations (as hex):")
for i, mut in enumerate(mutations[:3]):
    print(f"  Mutation {i+1}: {bytes(mut).hex()[:40]}...")
print()

# Example 3: Response Scoring
print("Example 3: Response Scoring")
print("-" * 50)

fuzzer = UDS_FuzzerEnumerator()
test_cases = [
    (UDS() / UDS_DSC(diagnosticSessionType=2),
     UDS(b'\x50\x02'), "Positive response"),
    (UDS() / UDS_DSC(diagnosticSessionType=2),
     None, "Timeout"),
    (UDS() / UDS_DSC(diagnosticSessionType=2),
     UDS(b'\x7f\x10\x31'), "New negative response"),
    (UDS() / UDS_DSC(diagnosticSessionType=2),
     UDS(b'\x7f\x10\x11'), "Common rejection"),
]

for req, resp, description in test_cases:
    score = fuzzer._score_response(req, resp)
    print(f"{description:30s}: Score = {score}")

print()
print("=" * 50)
print("For more information, see the UDS_FuzzerEnumerator docstring:")
print("  help(UDS_FuzzerEnumerator)")
print("=" * 50)
