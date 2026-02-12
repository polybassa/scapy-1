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

print()
print("=" * 50)
print("Example 4: Authentication Service Fuzzing")
print("=" * 50)
print()

# Example 4: Authentication Service (0x29) Fuzzing
# =================================================

print()
print("=" * 50)
print("Example 4: Authentication Service Fuzzing")
print("=" * 50)
print()

# Example 4: Authentication Service (0x29) Fuzzing
print("UDS Authentication Service (0x29) is critical for security.")
print("The UDS_AuthenticationFuzzerEnumerator provides specialized fuzzing")
print("for all 8 authentication subfunctions.")
print()

from scapy.contrib.automotive.uds import UDS_AUTH
from scapy.contrib.automotive.uds_scan import UDS_AuthenticationFuzzerEnumerator

auth_fuzzer = UDS_AuthenticationFuzzerEnumerator()

print("Authentication fuzzer initialized:")
print(f"  Description: {auth_fuzzer._description}")
print()

# Show authentication subfunctions being tested
print("Authentication subfunctions tested:")
auth_subfuncs = {
    0x00: 'deAuthenticate',
    0x01: 'verifyCertificateUnidirectional',
    0x02: 'verifyCertificateBidirectional',
    0x03: 'proofOfOwnership',
    0x04: 'transmitCertificate',
    0x05: 'requestChallengeForAuthentication',
    0x06: 'verifyProofOfOwnershipUnidirectional',
    0x07: 'verifyProofOfOwnershipBidirectional',
    0x08: 'authenticationConfiguration'
}

for code, name in auth_subfuncs.items():
    print(f"  0x{code:02x}: {name}")

print()
print("Authentication-specific response scoring:")
print("  - Successful authentication: 150 points (CRITICAL)")
print("  - Certificate/key errors (0x35, 0x36, 0x50-0x5d): 70 points (HIGH)")
print("  - Other responses: standard scoring")
print()

print("Example usage with health check:")
print("""
# For actual ECU fuzzing:
def health_check(socket):
    resp = socket.sr1(UDS()/UDS_TP(), timeout=1, verbose=False)
    return resp is not None and resp.service != 0x7f

fuzzer = UDS_AuthenticationFuzzerEnumerator()
fuzzer.execute(
    socket,
    EcuState(session=1),
    health_check_callback=health_check,
    health_check_interval=25,
    mutation_strategy='smart',
    max_mutations=500
)
""")

print("=" * 50)
print("Authentication service fuzzing example complete!")
print("=" * 50)

print()
print("=" * 70)
print("Example 5: Tier 2 Service Fuzzers (Write/Control Operations)")
print("=" * 70)
print()

print("Tier 2 services represent write/control operations with medium-to-high")
print("security implications. These fuzzers target services that can modify")
print("ECU configuration, control hardware, or manipulate firmware.")
print()

# Import Tier 2 fuzzers
from scapy.contrib.automotive.uds_scan import (
    UDS_WriteDataByIdentifierFuzzerEnumerator,
    UDS_InputOutputControlByIdentifierFuzzerEnumerator,
    UDS_RoutineControlFuzzerEnumerator,
    UDS_WriteMemoryByAddressFuzzerEnumerator,
    UDS_DataTransferFuzzerEnumerator
)

print("Available Tier 2 Fuzzers:")
print("-" * 70)

tier2_fuzzers = [
    ("WriteDataByIdentifier (0x2E)", UDS_WriteDataByIdentifierFuzzerEnumerator(),
     "Modifies ECU data identifiers (VIN, calibration, config)"),
    ("InputOutputControlByIdentifier (0x2F)", UDS_InputOutputControlByIdentifierFuzzerEnumerator(),
     "Controls hardware actuators and sensors"),
    ("RoutineControl (0x31)", UDS_RoutineControlFuzzerEnumerator(),
     "Executes diagnostic procedures and calibration routines"),
    ("WriteMemoryByAddress (0x3D)", UDS_WriteMemoryByAddressFuzzerEnumerator(),
     "Direct memory write operations (HIGHEST RISK)"),
    ("DataTransfer (0x34/35/36/37)", UDS_DataTransferFuzzerEnumerator(),
     "Firmware download/upload and transfer operations")
]

for name, fuzzer, description in tier2_fuzzers:
    print(f"\n{name}")
    print(f"  {description}")
    print(f"  Scoring: ", end="")
    
    # Show scoring emphasis
    if "WriteMemoryByAddress" in name:
        print("200 pts for successful write (CRITICAL)")
    elif "DataTransfer" in name:
        print("160 pts for successful transfer (HIGH)")
    elif "WriteDataByIdentifier" in name or "InputOutputControl" in name:
        print("150 pts for successful write/control (HIGH)")
    else:
        print("140 pts for successful execution (MEDIUM-HIGH)")

print()
print("-" * 70)
print()

print("Security Risk Hierarchy (by scoring):")
print("  1. WriteMemoryByAddress:        200 pts (direct memory access)")
print("  2. DataTransfer:                160 pts (firmware manipulation)")
print("  3. WriteDataByIdentifier:       150 pts (config modification)")
print("  4. InputOutputControlByIdentifier: 150 pts (hardware control)")
print("  5. RoutineControl:              140 pts (procedure execution)")
print()

print("Example usage - WriteDataByIdentifier fuzzer:")
print("-" * 70)
print("""
# Fuzz write operations to data identifiers
from scapy.contrib.automotive.uds_scan import UDS_WriteDataByIdentifierFuzzerEnumerator

def health_check(socket):
    resp = socket.sr1(UDS()/UDS_TP(), timeout=1, verbose=False)
    return resp is not None and resp.service != 0x7f

fuzzer = UDS_WriteDataByIdentifierFuzzerEnumerator()
fuzzer.execute(
    socket,
    EcuState(session=1),
    health_check_callback=health_check,
    health_check_interval=50,
    mutation_strategy='smart',  # Prioritize high-scoring mutations
    max_mutations=300
)

# Review results
print(fuzzer.show_statistics())
""")

print()
print("Example usage - WriteMemoryByAddress fuzzer (HIGHEST RISK):")
print("-" * 70)
print("""
# CAUTION: This fuzzer targets direct memory writes
# Only use in controlled testing environments!

from scapy.contrib.automotive.uds_scan import UDS_WriteMemoryByAddressFuzzerEnumerator

fuzzer = UDS_WriteMemoryByAddressFuzzerEnumerator()
fuzzer.execute(
    socket,
    EcuState(session=1),
    health_check_callback=health_check,
    health_check_interval=20,  # More frequent health checks
    mutation_strategy='guided',  # Focus on high-scoring seeds
    max_mutations=200  # Fewer mutations due to risk
)
""")

print()
print("Example usage - DataTransfer fuzzer (Firmware operations):")
print("-" * 70)
print("""
# Fuzz firmware download/upload/transfer sequences
from scapy.contrib.automotive.uds_scan import UDS_DataTransferFuzzerEnumerator

fuzzer = UDS_DataTransferFuzzerEnumerator()
fuzzer.execute(
    socket,
    EcuState(session=1),
    health_check_callback=health_check,
    health_check_interval=30,
    mutation_strategy='smart',
    max_mutations=400  # More mutations to cover all transfer stages
)

# Check discovered transfer vulnerabilities
stats = fuzzer.show_statistics()
print(stats)
if len(fuzzer._high_score_seeds) > 0:
    print("\\nHigh-scoring transfer sequences discovered!")
""")

print()
print("=" * 70)
print("Tier 2 fuzzer examples complete!")
print("=" * 70)
