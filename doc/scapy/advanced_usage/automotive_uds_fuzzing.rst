.. UDS Fuzzing documentation

###################
UDS Fuzzing
###################

.. sectionauthor:: Nils Weiss <nils@we155.de>

********
Overview
********

This document describes the UDS (Unified Diagnostic Services) fuzzer enumerators available in Scapy.
These fuzzers implement intelligent mutation strategies to test ECU implementations for security
vulnerabilities and robustness issues.

The fuzzing framework uses a score-based approach where responses from the ECU are analyzed and
assigned scores based on their significance. Mutations that trigger interesting responses are more
likely to be used as seeds for further mutations.

.. note::
    The UDS fuzzers are located in ``scapy.contrib.automotive.uds_fuzzer`` but are also available
    through ``scapy.contrib.automotive.uds_scan`` for backward compatibility.

******************
Fuzzer Architecture
******************

Score-Based Fuzzing
===================

The fuzzing engine assigns scores to ECU responses:

- **High score (100+ points)**: Unexpected positive responses, successful write/control operations
- **Medium score (50 points)**: New negative response codes not seen before
- **Low score (10 points)**: Known negative responses
- **Very low score (5 points)**: Common rejections (serviceNotSupported, etc.)
- **Zero score (1 point)**: No response (timeout)

Mutation Strategies
===================

Three mutation strategies are available:

1. **random**: Pure random mutations - each seed has equal probability
2. **smart**: Score-weighted selection - higher scoring seeds are more likely to be selected (default)
3. **guided**: Exclusively uses high-scoring seeds for maximum efficiency

Mutation Types
==============

The fuzzer implements six mutation types:

1. **Bit flips**: Single bit inversions for subtle changes
2. **Byte replacements**: Random byte substitutions
3. **Byte insertions**: Add random bytes to test length handling
4. **Byte deletions**: Remove bytes to test incomplete packets
5. **Interesting values**: Inject boundary values (0x00, 0xFF, 0x7F, 0x80, 0x01)
6. **Multiple mutations**: Combine several mutations for complex test cases

Health Check Mechanism
======================

The fuzzer supports health check callbacks to monitor ECU responsiveness during fuzzing:

.. code-block:: python

    def health_check(socket):
        """Check if ECU is still responding"""
        resp = socket.sr1(UDS()/UDS_TP(), timeout=1, verbose=False)
        return resp is not None and resp.service != 0x7f

The fuzzer will call this function at regular intervals (configurable via ``health_check_interval``).
If the health check fails, fuzzing is automatically terminated to prevent ECU damage.

**********************
Available Fuzzer Classes
**********************

Base Fuzzer
===========

``UDS_FuzzerEnumerator``
------------------------

The base fuzzer class that implements the core fuzzing engine with intelligent mutation.

**Example:**

.. code-block:: python

    from scapy.contrib.automotive.uds_scan import UDS_FuzzerEnumerator
    from scapy.contrib.automotive.ecu import EcuState
    
    fuzzer = UDS_FuzzerEnumerator()
    fuzzer.execute(
        socket,
        EcuState(session=1),
        mutation_strategy='smart',
        max_mutations=1000,
        mutation_rate=0.1
    )

**Parameters:**

- ``health_check_callback``: Optional callable to verify ECU health (signature: socket -> bool)
- ``health_check_interval``: Number of requests between health checks (default: 50)
- ``mutation_strategy``: 'random', 'smart', or 'guided' (default: 'smart')
- ``initial_seeds``: List of UDS packets to use as mutation seeds
- ``max_mutations``: Maximum number of mutations to generate (default: 1000)
- ``mutation_rate``: Probability of mutating each byte (default: 0.1)
- ``max_payload_size``: Maximum size of mutated payload (default: 256 bytes)

Specialized Fuzzers
===================

``UDS_AuthenticationFuzzerEnumerator`` - Service 0x29
------------------------------------------------------

Targets the Authentication service which handles certificate verification, proof of ownership,
and challenge-response authentication mechanisms.

**Security scoring:**
- Successful authentication: 150 points (CRITICAL)
- Certificate/key errors (0x35, 0x36, 0x50-0x5d): 70 points (HIGH)

**Subfunctions tested:**
- 0x00: deAuthenticate
- 0x01: verifyCertificateUnidirectional
- 0x02: verifyCertificateBidirectional
- 0x03: proofOfOwnership
- 0x04: transmitCertificate
- 0x05: requestChallengeForAuthentication
- 0x06: verifyProofOfOwnershipUnidirectional
- 0x07: verifyProofOfOwnershipBidirectional
- 0x08: authenticationConfiguration

**Example:**

.. code-block:: python

    from scapy.contrib.automotive.uds_scan import UDS_AuthenticationFuzzerEnumerator
    
    fuzzer = UDS_AuthenticationFuzzerEnumerator()
    fuzzer.execute(
        socket,
        EcuState(session=1),
        health_check_callback=health_check,
        health_check_interval=25,
        mutation_strategy='smart',
        max_mutations=500
    )

``UDS_WriteDataByIdentifierFuzzerEnumerator`` - Service 0x2E
-------------------------------------------------------------

Fuzzes write operations to ECU data identifiers. Successful unauthorized writes represent
significant security risks as they can modify critical configuration parameters.

**Security scoring:**
- Successful write: 150 points (CRITICAL)
- Write-specific errors (0x31, 0x33, 0x72): 65 points

**Example DIDs tested:**
- 0xF190: VIN (Vehicle Identification Number)
- 0xF186: Active Diagnostic Session
- 0xF18A: ECU Software Number
- 0xF100-0xF150: Various manufacturer-specific identifiers

**Example:**

.. code-block:: python

    from scapy.contrib.automotive.uds_scan import UDS_WriteDataByIdentifierFuzzerEnumerator
    
    fuzzer = UDS_WriteDataByIdentifierFuzzerEnumerator()
    fuzzer.execute(
        socket,
        EcuState(session=1),
        mutation_strategy='smart',
        max_mutations=300
    )

``UDS_InputOutputControlByIdentifierFuzzerEnumerator`` - Service 0x2F
----------------------------------------------------------------------

Targets IO control operations which can directly manipulate hardware actuators and sensors.
Unauthorized control represents serious safety and security risks.

**Security scoring:**
- Successful IO control: 150 points (CRITICAL)

**Control parameters tested:**
- 0x00: returnControlToECU
- 0x01: resetToDefault
- 0x02: freezeCurrentState
- 0x03: shortTermAdjustment

**Example:**

.. code-block:: python

    from scapy.contrib.automotive.uds_scan import UDS_InputOutputControlByIdentifierFuzzerEnumerator
    
    fuzzer = UDS_InputOutputControlByIdentifierFuzzerEnumerator()
    fuzzer.execute(
        socket,
        EcuState(session=1),
        health_check_interval=30,
        mutation_strategy='smart',
        max_mutations=300
    )

``UDS_RoutineControlFuzzerEnumerator`` - Service 0x31
------------------------------------------------------

Fuzzes routine execution which can trigger diagnostic procedures, calibration routines,
and system resets.

**Security scoring:**
- Successful routine execution: 140 points (HIGH)

**Control types tested:**
- 0x01: startRoutine
- 0x02: stopRoutine
- 0x03: requestRoutineResults

**Example:**

.. code-block:: python

    from scapy.contrib.automotive.uds_scan import UDS_RoutineControlFuzzerEnumerator
    
    fuzzer = UDS_RoutineControlFuzzerEnumerator()
    fuzzer.execute(
        socket,
        EcuState(session=1),
        mutation_strategy='guided',
        max_mutations=300
    )

``UDS_WriteMemoryByAddressFuzzerEnumerator`` - Service 0x3D
------------------------------------------------------------

Targets direct memory write operations - the highest security risk as they allow arbitrary
memory modification. Successful writes can completely compromise ECU security.

**Security scoring:**
- Successful memory write: 200 points (EXTREMELY CRITICAL)

**Address configurations tested:**
- Various address lengths (1-4 bytes)
- Various memory sizes (1-4 bytes)
- Boundary addresses (0x0000, 0x1000, 0x8000, 0xF000)

**Example:**

.. code-block:: python

    from scapy.contrib.automotive.uds_scan import UDS_WriteMemoryByAddressFuzzerEnumerator
    
    # CAUTION: Only use in controlled testing environments!
    fuzzer = UDS_WriteMemoryByAddressFuzzerEnumerator()
    fuzzer.execute(
        socket,
        EcuState(session=1),
        health_check_callback=health_check,
        health_check_interval=20,  # More frequent health checks
        mutation_strategy='guided',
        max_mutations=200  # Fewer mutations due to risk
    )

``UDS_DataTransferFuzzerEnumerator`` - Services 0x34/35/36/37
--------------------------------------------------------------

Unified fuzzer for the complete download/upload/transfer sequence used for firmware updates
and memory programming. Compromising these services could allow firmware modification or
extraction of sensitive data.

**Services covered:**
- 0x34: RequestDownload
- 0x35: RequestUpload
- 0x36: TransferData
- 0x37: RequestTransferExit

**Security scoring:**
- Successful transfer operation: 160 points (HIGH)

**Example:**

.. code-block:: python

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

*************************
Security Risk Hierarchy
*************************

The fuzzers are designed with security-focused scoring:

.. list-table::
   :header-rows: 1
   :widths: 10 50 15 25

   * - Rank
     - Service
     - Score
     - Risk Level
   * - 1
     - WriteMemoryByAddress (0x3D)
     - 200 pts
     - CRITICAL - Direct memory access
   * - 2
     - DataTransfer (0x34-37)
     - 160 pts
     - HIGH - Firmware manipulation
   * - 3
     - Authentication (0x29)
     - 150 pts
     - HIGH - Security mechanism bypass
   * - 4
     - WriteDataByIdentifier (0x2E)
     - 150 pts
     - HIGH - Configuration modification
   * - 5
     - InputOutputControl (0x2F)
     - 150 pts
     - HIGH - Hardware control
   * - 6
     - RoutineControl (0x31)
     - 140 pts
     - MEDIUM-HIGH - Procedure execution

********************
Usage Best Practices
********************

1. **Start with Safe Services**

   Begin fuzzing with read-only services before attempting write/control operations:

   .. code-block:: python

       # Start with base fuzzer on read services
       fuzzer = UDS_FuzzerEnumerator()
       fuzzer.execute(socket, state, max_mutations=100)

2. **Always Use Health Checks**

   Implement robust health checks to prevent ECU damage:

   .. code-block:: python

       def health_check(socket):
           """Verify ECU responsiveness"""
           try:
               resp = socket.sr1(UDS()/UDS_TP(), timeout=1, verbose=False)
               if resp and resp.service == 0x7e:
                   return True
               return False
           except:
               return False

3. **Use Guided Strategy for High-Risk Services**

   For dangerous services like WriteMemoryByAddress, use the 'guided' strategy
   to focus only on high-scoring seeds:

   .. code-block:: python

       fuzzer = UDS_WriteMemoryByAddressFuzzerEnumerator()
       fuzzer.execute(
           socket, state,
           mutation_strategy='guided',  # Only high-scoring seeds
           health_check_interval=10,     # Frequent checks
           max_mutations=100             # Limited attempts
       )

4. **Monitor Results Continuously**

   Review statistics during and after fuzzing:

   .. code-block:: python

       # After fuzzing
       stats = fuzzer.show_statistics()
       print(stats)
       
       # Check for critical findings
       if any(r[2].service in [0x6E, 0x6F, 0x7D] for r in fuzzer.results_with_positive_response):
           print("⚠️ CRITICAL: Successful write/control operation detected!")

5. **Use Appropriate Mutation Rates**

   - High-risk services: Use lower mutation rates (0.05-0.1) for subtle changes
   - Exploration: Use higher mutation rates (0.2-0.3) for aggressive fuzzing

6. **Custom Seed Selection**

   Provide custom seeds based on ECU documentation:

   .. code-block:: python

       from scapy.contrib.automotive.uds import UDS, UDS_WDBI
       
       custom_seeds = [
           UDS() / UDS_WDBI(dataIdentifier=0xF190),  # VIN
           UDS() / UDS_WDBI(dataIdentifier=0xF100),  # Manufacturer ID
       ]
       
       fuzzer = UDS_WriteDataByIdentifierFuzzerEnumerator()
       fuzzer.execute(
           socket, state,
           initial_seeds=custom_seeds,
           max_mutations=200
       )

***************
Troubleshooting
***************

ECU Becomes Unresponsive
=========================

If the ECU stops responding during fuzzing:

1. Verify health check callback is properly implemented
2. Reduce ``health_check_interval`` for more frequent checks
3. Use 'guided' strategy to avoid low-quality mutations
4. Reduce ``mutation_rate`` for less aggressive fuzzing

No Interesting Results
======================

If fuzzing doesn't discover vulnerabilities:

1. Increase ``max_mutations`` to generate more test cases
2. Try different mutation strategies ('random' vs 'smart' vs 'guided')
3. Provide custom seeds based on ECU documentation
4. Check if ECU requires security access (use UDS_SAEnumerator first)

High Memory Usage
=================

If fuzzer consumes excessive memory:

1. Reduce ``max_mutations``
2. Reduce ``max_payload_size``
3. Clear results periodically in long-running fuzzing sessions

**********
References
**********

- ISO 14229-1: Road vehicles — Unified diagnostic services (UDS)
- Scapy Automotive documentation: :doc:`../layers/automotive`
- UDS Scanner documentation: See ``scapy.contrib.automotive.uds_scan``
