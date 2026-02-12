# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

"""
UDS Fuzzer Enumerators

This module contains specialized fuzzer enumerators for the UDS (Unified Diagnostic Services)
protocol. These fuzzers implement intelligent mutation strategies to test ECU implementations
for security vulnerabilities and robustness issues.

The fuzzers use a score-based approach to prioritize interesting mutations that trigger
unexpected or security-relevant responses from the ECU.
"""

import copy
import random
from collections import defaultdict
from typing import Optional, Any, Iterable, Set

from scapy.packet import Packet, Raw
from scapy.contrib.automotive import log_automotive
from scapy.contrib.automotive.scanner.enumerator import (
    ServiceEnumerator,
    _AutomotiveTestCaseScanResult
)
from scapy.contrib.automotive.uds import (
    UDS, UDS_TP, UDS_DSC, UDS_ER, UDS_SA, UDS_RDBI, UDS_CC,
    UDS_AUTH, UDS_WDBI, UDS_IOCBI, UDS_RC, UDS_WMBA,
    UDS_RD, UDS_RU, UDS_TD, UDS_RTE
)

# Import base class - this works because uds_scan is imported first
# in the normal flow, defining all classes before fuzzer is loaded
import scapy.contrib.automotive.uds_scan as uds_scan_module
UDS_Enumerator = uds_scan_module.UDS_Enumerator

class UDS_FuzzerEnumerator(UDS_Enumerator):
    """
    Fuzzer enumerator for UDS protocol that intelligently mutates requests
    based on ECU responses. This enumerator implements a score-based fuzzing
    approach where successful mutations (those that trigger interesting
    responses) are more likely to be used as seeds for further mutations.
    
    The enumerator analyzes responses and assigns scores:
    - High score: Unexpected positive responses, crashes, or unusual behavior
    - Medium score: New negative response codes not seen before
    - Low score: Common negative responses (serviceNotSupported, etc.)
    - Zero score: No response (timeout)
    
    Example:
        >>> def health_check(socket):
        >>>     resp = socket.sr1(UDS()/UDS_TP(), timeout=1, verbose=False)
        >>>     return resp is not None and resp.service != 0x7f
        >>>
        >>> enumerator = UDS_FuzzerEnumerator()
        >>> enumerator.execute(
        >>>     socket,
        >>>     EcuState(session=1),
        >>>     health_check_callback=health_check,
        >>>     health_check_interval=50,
        >>>     mutation_strategy='smart',
        >>>     initial_seeds=[UDS()/UDS_DSC(diagnosticSessionType=2)],
        >>>     max_mutations=1000
        >>> )
    """
    _description = "Fuzzing with intelligent mutation"
    _supported_kwargs = copy.copy(ServiceEnumerator._supported_kwargs)
    _supported_kwargs.update({
        'health_check_callback': (type(lambda: None), None),
        'health_check_interval': (int, lambda x: x > 0),
        'mutation_strategy': (str, lambda x: x in ['random', 'smart', 'guided']),
        'initial_seeds': ((list, tuple), None),
        'max_mutations': (int, lambda x: x > 0),
        'mutation_rate': (float, lambda x: 0.0 < x <= 1.0),
        'max_payload_size': (int, lambda x: x > 0),
    })
    _supported_kwargs_doc = ServiceEnumerator._supported_kwargs_doc + """
        :param health_check_callback: Callable function to check if the ECU
                                      is still healthy/responsive. Should return
                                      True if healthy, False otherwise.
                                      Signature: (socket) -> bool
        :type health_check_callback: Callable
        :param int health_check_interval: Number of requests between health
                                          checks. Default is 50.
        :param str mutation_strategy: Strategy for mutation generation.
                                      'random': Pure random mutations
                                      'smart': Based on response scoring
                                      'guided': Prioritize high-scoring seeds
                                      Default is 'smart'.
        :param initial_seeds: List of initial UDS packets to use as mutation
                             seeds. If not provided, uses common UDS services.
        :type initial_seeds: list or tuple
        :param int max_mutations: Maximum number of mutations to generate.
                                 Default is 1000.
        :param float mutation_rate: Probability of mutating each byte.
                                   Default is 0.1 (10% chance per byte).
        :param int max_payload_size: Maximum size of mutated payload.
                                    Default is 256 bytes."""

    # Response score weights
    SCORE_POSITIVE_RESPONSE = 100
    SCORE_NEW_NEGATIVE_RESPONSE = 50
    SCORE_KNOWN_NEGATIVE_RESPONSE = 10
    SCORE_NO_RESPONSE = 1
    SCORE_COMMON_REJECTION = 5  # serviceNotSupported, generalReject, etc.
    
    # Fuzzing parameters
    SEED_ADDITION_PROBABILITY = 0.1  # Probability of adding mutation to seed pool
    MAX_SEED_POOL_SIZE = 100  # Maximum number of seeds in the pool
    MAX_HIGH_SCORE_SEEDS = 50  # Maximum number of high-score seeds to keep

    def __init__(self):
        # type: () -> None
        super(UDS_FuzzerEnumerator, self).__init__()
        self._seed_scores = defaultdict(int)  # type: Dict[bytes, int]
        self._seen_response_codes = set()  # type: Set[int]
        self._mutation_count = 0
        self._health_check_failures = 0
        self._high_score_seeds = []  # type: List[Packet]

    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """
        Score the response to determine how interesting it is.
        Higher scores indicate more interesting responses that should
        be used as seeds for future mutations.
        """
        if resp is None:
            return self.SCORE_NO_RESPONSE

        # Positive response - very interesting!
        if resp.service != 0x7f:
            return self.SCORE_POSITIVE_RESPONSE

        # Negative response - score based on the response code
        try:
            nrc = self._get_negative_response_code(resp)
        except (AttributeError, IndexError):
            # Malformed response - interesting!
            return self.SCORE_POSITIVE_RESPONSE

        # Common rejection codes are less interesting
        if nrc in [0x10, 0x11, 0x12, 0x7e, 0x7f]:
            # generalReject(0x10), serviceNotSupported(0x11),
            # subFunctionNotSupported(0x12),
            # subFunctionNotSupportedInActiveSession(0x7e),
            # serviceNotSupportedInActiveSession(0x7f)
            if nrc not in self._seen_response_codes:
                self._seen_response_codes.add(nrc)
                return self.SCORE_NEW_NEGATIVE_RESPONSE
            return self.SCORE_COMMON_REJECTION

        # New negative response code - interesting!
        if nrc not in self._seen_response_codes:
            self._seen_response_codes.add(nrc)
            return self.SCORE_NEW_NEGATIVE_RESPONSE

        return self.SCORE_KNOWN_NEGATIVE_RESPONSE

    def _mutate_packet(self, seed, mutation_rate=0.1, max_size=256):
        # type: (Packet, float, int) -> Packet
        """
        Mutate a packet by randomly modifying bytes in its payload.
        Uses various mutation strategies including bit flips, byte
        replacements, insertions, and deletions.
        """
        # Get packet bytes
        pkt_bytes = bytearray(bytes(seed))
        
        # Ensure we have at least the UDS service byte
        if len(pkt_bytes) == 0:
            pkt_bytes = bytearray([random.randint(0, 0xff)])

        # Apply various mutations
        mutation_type = random.randint(0, 5)
        
        if mutation_type == 0:  # Bit flip
            if len(pkt_bytes) > 1:
                idx = random.randint(1, len(pkt_bytes) - 1)
                bit_pos = random.randint(0, 7)
                pkt_bytes[idx] ^= (1 << bit_pos)
        
        elif mutation_type == 1:  # Byte replacement
            if len(pkt_bytes) > 1:
                idx = random.randint(1, len(pkt_bytes) - 1)
                pkt_bytes[idx] = random.randint(0, 0xff)
        
        elif mutation_type == 2:  # Insert random byte
            if len(pkt_bytes) < max_size:
                idx = random.randint(1, len(pkt_bytes))
                pkt_bytes.insert(idx, random.randint(0, 0xff))
        
        elif mutation_type == 3:  # Delete byte
            if len(pkt_bytes) > 2:
                idx = random.randint(1, len(pkt_bytes) - 1)
                del pkt_bytes[idx]
        
        elif mutation_type == 4:  # Replace with interesting value
            if len(pkt_bytes) > 1:
                idx = random.randint(1, len(pkt_bytes) - 1)
                interesting_values = [0x00, 0xff, 0x7f, 0x80, 0x01]
                pkt_bytes[idx] = random.choice(interesting_values)
        
        else:  # Multiple random byte mutations
            num_mutations = random.randint(1, min(3, len(pkt_bytes)))
            for _ in range(num_mutations):
                if len(pkt_bytes) > 1:
                    idx = random.randint(1, len(pkt_bytes) - 1)
                    if random.random() < mutation_rate:
                        pkt_bytes[idx] = random.randint(0, 0xff)

        # Ensure the packet doesn't exceed max size
        if len(pkt_bytes) > max_size:
            pkt_bytes = pkt_bytes[:max_size]

        # Return mutated packet
        return UDS(bytes(pkt_bytes))

    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """
        Generate initial requests using mutation-based fuzzing.
        """
        # Get parameters
        max_mutations = kwargs.get('max_mutations', 1000)
        mutation_rate = kwargs.get('mutation_rate', 0.1)
        max_payload_size = kwargs.get('max_payload_size', 256)
        mutation_strategy = kwargs.get('mutation_strategy', 'smart')
        initial_seeds = kwargs.get('initial_seeds', None)

        # Default seed packets covering common UDS services
        if initial_seeds is None:
            initial_seeds = [
                UDS() / UDS_DSC(diagnosticSessionType=1),
                UDS() / UDS_DSC(diagnosticSessionType=2),
                UDS() / UDS_DSC(diagnosticSessionType=3),
                UDS() / UDS_TP(),
                UDS() / UDS_ER(resetType=1),
                UDS() / UDS_RDBI(identifiers=[0x0100]),
                UDS() / UDS_RDBI(identifiers=[0xf190]),
                UDS() / UDS_WDBI(dataIdentifier=0x0100) / Raw(b'\x00'),
                UDS() / UDS_SA(securityAccessType=1),
                UDS() / UDS_RC(routineControlType=1, routineIdentifier=0x0100),
                UDS() / UDS_CC(controlType=0),
                UDS() / Raw(b'\x27\x01'),  # Raw security access
                UDS() / Raw(b'\x31\x01'),  # Raw routine control
            ]

        # Store seeds for mutation
        seed_pool = list(initial_seeds)
        
        # Generate mutations
        for i in range(max_mutations):
            # Select seed based on strategy
            if mutation_strategy == 'guided' and self._high_score_seeds:
                # Prefer high-scoring seeds
                seed = random.choice(self._high_score_seeds)
            elif mutation_strategy == 'smart' and self._seed_scores:
                # Weighted random selection based on scores
                seeds_with_scores = [
                    (s, self._seed_scores.get(bytes(s), 1))
                    for s in seed_pool
                ]
                total_score = sum(score for _, score in seeds_with_scores)
                if total_score > 0:
                    r = random.uniform(0, total_score)
                    cumsum = 0
                    for pkt, score in seeds_with_scores:
                        cumsum += score
                        if cumsum >= r:
                            seed = pkt
                            break
                    else:
                        seed = random.choice(seed_pool)
                else:
                    seed = random.choice(seed_pool)
            else:
                # Random selection
                seed = random.choice(seed_pool)

            # Mutate and yield
            mutated = self._mutate_packet(seed, mutation_rate, max_payload_size)
            self._mutation_count += 1
            yield mutated

            # Occasionally add the mutated packet to seed pool for further mutation
            if (random.random() < self.SEED_ADDITION_PROBABILITY and
                    len(seed_pool) < self.MAX_SEED_POOL_SIZE):
                seed_pool.append(mutated)

    def _store_result(self, state, request, response):
        # type: (EcuState, Packet, Optional[Packet]) -> None
        """
        Store result and update scoring for the seed.
        """
        super(UDS_FuzzerEnumerator, self)._store_result(
            state, request, response
        )
        
        # Score the response
        score = self._score_response(request, response)
        
        # Update seed scores
        req_bytes = bytes(request)
        self._seed_scores[req_bytes] = max(
            self._seed_scores[req_bytes], score
        )
        
        # Add high-scoring requests to the high-score seed pool
        if score >= self.SCORE_NEW_NEGATIVE_RESPONSE:
            if request not in self._high_score_seeds:
                self._high_score_seeds.append(copy.copy(request))
                # Limit the size of high-score seeds
                if len(self._high_score_seeds) > self.MAX_HIGH_SCORE_SEEDS:
                    self._high_score_seeds.pop(0)

    def execute(self, socket, state, **kwargs):
        # type: (_SocketUnion, EcuState, Any) -> None
        """
        Execute fuzzing with health checks.
        """
        # Get health check parameters
        health_check_callback = kwargs.get('health_check_callback', None)
        health_check_interval = kwargs.get('health_check_interval', 50)
        
        # If health check is provided, wrap the execution
        if health_check_callback is not None:
            # Execute in chunks with health checks
            chunk_size = health_check_interval
            total_requests = kwargs.get('max_mutations', 1000)
            
            for chunk_start in range(0, total_requests, chunk_size):
                # Update count for this chunk
                kwargs['count'] = min(chunk_size, total_requests - chunk_start)
                
                # Execute chunk
                super(UDS_FuzzerEnumerator, self).execute(socket, state, **kwargs)
                
                # Perform health check
                if chunk_start + chunk_size < total_requests:
                    log_automotive.debug(
                        "Performing health check after %d requests" % 
                        (chunk_start + chunk_size)
                    )
                    try:
                        is_healthy = health_check_callback(socket)
                        if not is_healthy:
                            self._health_check_failures += 1
                            log_automotive.warning(
                                "Health check failed after %d requests. "
                                "Stopping fuzzing." % (chunk_start + chunk_size)
                            )
                            break
                        else:
                            log_automotive.debug("Health check passed")
                    except Exception as e:
                        log_automotive.error(
                            "Health check raised exception: %s" % str(e)
                        )
                        self._health_check_failures += 1
                        break
                
                # Check if we should continue
                if self.completed:
                    break
        else:
            # No health check, execute normally
            super(UDS_FuzzerEnumerator, self).execute(socket, state, **kwargs)

    execute.__doc__ = _supported_kwargs_doc

    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        """Format table entry for display."""
        req = tup[1]
        score = self._seed_scores.get(bytes(req), 0)
        return "Mutation (score: %d): %s" % (score, repr(req)[:50])

    def show_statistics(self):
        # type: () -> str
        """
        Show fuzzing statistics including mutation count, response
        distribution, and health check status.
        """
        # Build statistics from parent's show() method
        base_stats = self.show(dump=True, filtered=True, verbose=False)
        
        additional_stats = "\n" + "=" * 50 + "\n"
        additional_stats += "Fuzzer-Specific Statistics:\n"
        additional_stats += "=" * 50 + "\n"
        additional_stats += "Total mutations generated: %d\n" % self._mutation_count
        additional_stats += "Unique response codes seen: %d\n" % len(self._seen_response_codes)
        additional_stats += "High-score seeds collected: %d\n" % len(self._high_score_seeds)
        additional_stats += "Health check failures: %d\n" % self._health_check_failures
        
        if self._seed_scores:
            top_seeds = sorted(
                self._seed_scores.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            additional_stats += "\nTop 10 seeds by score:\n"
            for seed_bytes, score in top_seeds:
                try:
                    pkt = UDS(seed_bytes)
                    additional_stats += "  Score %3d: %s\n" % (score, repr(pkt)[:60])
                except Exception:
                    additional_stats += "  Score %3d: <unparseable>\n" % score
        
        return base_stats + additional_stats


class UDS_AuthenticationFuzzerEnumerator(UDS_FuzzerEnumerator):
    """
    Specialized fuzzer for UDS Authentication service (0x29).
    
    This fuzzer targets the Authentication service which is critical for
    security as it handles certificate verification, proof of ownership,
    and challenge-response authentication mechanisms.
    
    The Authentication service has 8 subfunctions:
    - 0x00: deAuthenticate
    - 0x01: verifyCertificateUnidirectional
    - 0x02: verifyCertificateBidirectional
    - 0x03: proofOfOwnership
    - 0x04: transmitCertificate
    - 0x05: requestChallengeForAuthentication
    - 0x06: verifyProofOfOwnershipUnidirectional
    - 0x07: verifyProofOfOwnershipBidirectional
    - 0x08: authenticationConfiguration
    
    Example:
        >>> from scapy.contrib.automotive.uds import UDS, UDS_AUTH
        >>> from scapy.contrib.automotive.uds_scan import UDS_AuthenticationFuzzerEnumerator
        >>> from scapy.contrib.automotive.ecu import EcuState
        >>> 
        >>> def health_check(socket):
        >>>     resp = socket.sr1(UDS()/UDS_TP(), timeout=1, verbose=False)
        >>>     return resp is not None and resp.service != 0x7f
        >>> 
        >>> fuzzer = UDS_AuthenticationFuzzerEnumerator()
        >>> fuzzer.execute(
        >>>     socket,
        >>>     EcuState(session=1),
        >>>     health_check_callback=health_check,
        >>>     health_check_interval=25,
        >>>     mutation_strategy='smart',
        >>>     max_mutations=500
        >>> )
    """
    _description = "Authentication service (0x29) fuzzing with intelligent mutation"
    
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """
        Generate initial seed packets for Authentication service fuzzing.
        
        Creates seed packets for all 8 Authentication subfunctions with
        various data patterns to trigger different authentication paths.
        """
        # Get user-provided seeds or use Authentication-specific defaults
        initial_seeds = kwargs.get('initial_seeds', None)
        
        if initial_seeds is None:
            # Create comprehensive Authentication service seeds
            initial_seeds = []
            
            # 0x00: deAuthenticate - simple request, no parameters
            initial_seeds.append(UDS() / UDS_AUTH(subFunction=0x00))
            
            # 0x01: verifyCertificateUnidirectional
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x01,
                communicationConfiguration=0x00,
                certificateClient=b'\x00' * 32,
                challengeClient=b'\x00' * 16
            ))
            
            # 0x02: verifyCertificateBidirectional
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x02,
                communicationConfiguration=0x00,
                certificateClient=b'\x00' * 32,
                challengeClient=b'\x00' * 16
            ))
            
            # 0x03: proofOfOwnership
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x03,
                proofOfOwnershipClient=b'\x00' * 32,
                ephemeralPublicKeyClient=b'\x00' * 64
            ))
            
            # 0x04: transmitCertificate
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x04,
                certificateEvaluationId=0x0001,
                certificateData=b'\x30\x82' + b'\x00' * 100  # ASN.1 structure
            ))
            
            # 0x05: requestChallengeForAuthentication
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x05,
                communicationConfiguration=0x00,
                algorithmIndicator=b'\x00' * 16
            ))
            
            # 0x06: verifyProofOfOwnershipUnidirectional
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x06,
                algorithmIndicator=b'\x00' * 16,
                proofOfOwnershipClient=b'\x00' * 32,
                challengeClient=b'\x00' * 16,
                additionalParameter=b'\x00' * 8
            ))
            
            # 0x07: verifyProofOfOwnershipBidirectional
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x07,
                algorithmIndicator=b'\x00' * 16,
                proofOfOwnershipClient=b'\x00' * 32,
                challengeClient=b'\x00' * 16,
                additionalParameter=b'\x00' * 8
            ))
            
            # 0x08: authenticationConfiguration
            initial_seeds.append(UDS() / UDS_AUTH(subFunction=0x08))
            
            # Add some edge case seeds
            # Invalid subfunction
            initial_seeds.append(UDS() / UDS_AUTH(subFunction=0x09))
            initial_seeds.append(UDS() / UDS_AUTH(subFunction=0xFF))
            
            # Minimal/empty data for functions that expect data
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x01,
                communicationConfiguration=0x00,
                certificateClient=b'',
                challengeClient=b''
            ))
            
            # Oversized data
            initial_seeds.append(UDS() / UDS_AUTH(
                subFunction=0x04,
                certificateEvaluationId=0xFFFF,
                certificateData=b'\xFF' * 255
            ))
        
        # Use parent class logic with Authentication-specific seeds
        kwargs['initial_seeds'] = initial_seeds
        return super(UDS_AuthenticationFuzzerEnumerator, self)._get_initial_requests(**kwargs)
    
    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """
        Score responses with Authentication-specific logic.
        
        Authentication responses are particularly interesting because:
        - Successful authentication attempts indicate security vulnerabilities
        - Certificate validation errors reveal crypto implementation details
        - Timing differences may indicate authentication state changes
        """
        # Check for Authentication-specific scoring BEFORE calling parent
        if resp is not None and resp.service == 0x69:  # Positive response
            # Authentication success is VERY interesting
            return self.SCORE_POSITIVE_RESPONSE + 50
        
        if resp is not None and resp.service == 0x7f:
            try:
                nrc = self._get_negative_response_code(resp)
                # Authentication-specific interesting error codes
                if nrc in [0x35, 0x36, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
                          0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d]:
                    # These are authentication/certificate-specific errors:
                    # 0x35: invalidKey
                    # 0x36: exceededNumberOfAttempts
                    # 0x50-0x5d: Certificate/authentication verification errors
                    if nrc not in self._seen_response_codes:
                        self._seen_response_codes.add(nrc)
                        return self.SCORE_NEW_NEGATIVE_RESPONSE + 20
                    return self.SCORE_KNOWN_NEGATIVE_RESPONSE + 10
            except (AttributeError, IndexError):
                pass
        
        # Use parent scoring for everything else
        return super(UDS_AuthenticationFuzzerEnumerator, self)._score_response(req, resp)
    
    def _get_table_entry_y(self, tup):
        # type: (_AutomotiveTestCaseScanResult) -> str
        """Format table entry for Authentication service."""
        req = tup[1]
        try:
            if hasattr(req, 'subFunction'):
                return "Auth subFunc 0x%02x" % req.subFunction
        except Exception:
            pass
        return super(UDS_AuthenticationFuzzerEnumerator, self)._get_table_entry_y(tup)


class UDS_WriteDataByIdentifierFuzzerEnumerator(UDS_FuzzerEnumerator):
    """
    Specialized fuzzer for UDS WriteDataByIdentifier service (0x2E).
    
    This fuzzer targets write operations to ECU data identifiers, which can
    modify critical configuration parameters, calibration values, and system
    settings. Successful unauthorized writes represent significant security risks.
    
    Example:
        >>> fuzzer = UDS_WriteDataByIdentifierFuzzerEnumerator()
        >>> fuzzer.execute(socket, EcuState(session=1),
        >>>                mutation_strategy='smart', max_mutations=300)
    """
    _description = "WriteDataByIdentifier service (0x2E) fuzzing with intelligent mutation"
    
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """Generate initial seed packets for WriteDataByIdentifier fuzzing."""
        initial_seeds = kwargs.get('initial_seeds', None)
        
        if initial_seeds is None:
            initial_seeds = []
            
            # Common data identifiers often used in automotive ECUs
            common_dids = [
                0xF190,  # VIN
                0xF186,  # Active Diagnostic Session
                0xF187,  # Vehicle Manufacturer Spare Part Number
                0xF18A,  # ECU Software Number
                0xF100,  # System Supplier Identifier
                0xF150,  # Vehicle Manufacturer ECU Software Number
                0x0100,  # Generic identifier
                0x0200,  # Generic identifier
                0x1000,  # Generic identifier
                0xF000,  # High range identifier
            ]
            
            # Create seeds with various data patterns
            for did in common_dids:
                # Empty data
                initial_seeds.append(UDS() / UDS_WDBI(dataIdentifier=did))
                # Small data
                initial_seeds.append(UDS() / UDS_WDBI(dataIdentifier=did) / Raw(b'\x00'))
                # Medium data
                initial_seeds.append(UDS() / UDS_WDBI(dataIdentifier=did) / Raw(b'\x00' * 16))
            
            # Edge cases
            initial_seeds.append(UDS() / UDS_WDBI(dataIdentifier=0x0000))  # Min
            initial_seeds.append(UDS() / UDS_WDBI(dataIdentifier=0xFFFF))  # Max
            initial_seeds.append(UDS() / UDS_WDBI(dataIdentifier=0x1234) / Raw(b'\xFF' * 100))  # Large
        
        kwargs['initial_seeds'] = initial_seeds
        return super(UDS_WriteDataByIdentifierFuzzerEnumerator, self)._get_initial_requests(**kwargs)
    
    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """Score with emphasis on successful write operations (security concern)."""
        if resp is not None and resp.service == 0x6E:  # Positive response
            # Successful write is CRITICAL - major security concern
            return self.SCORE_POSITIVE_RESPONSE + 50
        
        if resp is not None and resp.service == 0x7f:
            try:
                nrc = self._get_negative_response_code(resp)
                # Write-specific errors
                if nrc in [0x31, 0x33, 0x72]:  # requestOutOfRange, securityAccessDenied, generalProgrammingFailure
                    if nrc not in self._seen_response_codes:
                        self._seen_response_codes.add(nrc)
                        return self.SCORE_NEW_NEGATIVE_RESPONSE + 15
                    return self.SCORE_KNOWN_NEGATIVE_RESPONSE + 5
            except (AttributeError, IndexError):
                pass
        
        return super(UDS_WriteDataByIdentifierFuzzerEnumerator, self)._score_response(req, resp)


class UDS_InputOutputControlByIdentifierFuzzerEnumerator(UDS_FuzzerEnumerator):
    """
    Specialized fuzzer for UDS InputOutputControlByIdentifier service (0x2F).
    
    This fuzzer targets IO control operations which can directly manipulate
    hardware actuators, sensors, and control systems. Unauthorized control
    represents serious safety and security risks.
    
    Example:
        >>> fuzzer = UDS_InputOutputControlByIdentifierFuzzerEnumerator()
        >>> fuzzer.execute(socket, EcuState(session=1),
        >>>                mutation_strategy='smart', max_mutations=300)
    """
    _description = "InputOutputControlByIdentifier service (0x2F) fuzzing with intelligent mutation"
    
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """Generate initial seed packets for IOCBI fuzzing."""
        initial_seeds = kwargs.get('initial_seeds', None)
        
        if initial_seeds is None:
            initial_seeds = []
            
            # Common IO control identifiers
            common_io_ids = [
                0x0100, 0x0101, 0x0102,  # Generic IO controls
                0x0200, 0x0201, 0x0202,
                0x1000, 0x1001, 0x1002,
                0xF000, 0xF001, 0xF002,
            ]
            
            # Control parameter types (typically first byte after identifier)
            control_params = [
                b'\x00',  # returnControlToECU
                b'\x01',  # resetToDefault
                b'\x02',  # freezeCurrentState
                b'\x03',  # shortTermAdjustment
            ]
            
            for io_id in common_io_ids:
                for param in control_params:
                    initial_seeds.append(UDS() / UDS_IOCBI(dataIdentifier=io_id) / Raw(param))
                    # With additional control data
                    initial_seeds.append(UDS() / UDS_IOCBI(dataIdentifier=io_id) / Raw(param + b'\x00' * 4))
            
            # Edge cases
            initial_seeds.append(UDS() / UDS_IOCBI(dataIdentifier=0x0000))
            initial_seeds.append(UDS() / UDS_IOCBI(dataIdentifier=0xFFFF))
        
        kwargs['initial_seeds'] = initial_seeds
        return super(UDS_InputOutputControlByIdentifierFuzzerEnumerator, self)._get_initial_requests(**kwargs)
    
    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """Score with emphasis on successful IO control (safety/security concern)."""
        if resp is not None and resp.service == 0x6F:  # Positive response
            # Successful IO control is CRITICAL
            return self.SCORE_POSITIVE_RESPONSE + 50
        
        if resp is not None and resp.service == 0x7f:
            try:
                nrc = self._get_negative_response_code(resp)
                if nrc in [0x31, 0x33]:  # requestOutOfRange, securityAccessDenied
                    if nrc not in self._seen_response_codes:
                        self._seen_response_codes.add(nrc)
                        return self.SCORE_NEW_NEGATIVE_RESPONSE + 15
                    return self.SCORE_KNOWN_NEGATIVE_RESPONSE + 5
            except (AttributeError, IndexError):
                pass
        
        return super(UDS_InputOutputControlByIdentifierFuzzerEnumerator, self)._score_response(req, resp)


class UDS_RoutineControlFuzzerEnumerator(UDS_FuzzerEnumerator):
    """
    Specialized fuzzer for UDS RoutineControl service (0x31).
    
    This fuzzer targets routine execution which can trigger diagnostic procedures,
    calibration routines, and system resets. Unauthorized routine execution can
    compromise system integrity and safety.
    
    Example:
        >>> fuzzer = UDS_RoutineControlFuzzerEnumerator()
        >>> fuzzer.execute(socket, EcuState(session=1),
        >>>                mutation_strategy='smart', max_mutations=300)
    """
    _description = "RoutineControl service (0x31) fuzzing with intelligent mutation"
    
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """Generate initial seed packets for RoutineControl fuzzing."""
        initial_seeds = kwargs.get('initial_seeds', None)
        
        if initial_seeds is None:
            initial_seeds = []
            
            # Routine control types
            control_types = [1, 2, 3]  # start, stop, requestResults
            
            # Common routine identifiers
            common_routines = [
                0x0100, 0x0101, 0x0102,  # Generic routines
                0x0200, 0x0201, 0x0202,
                0xFF00, 0xFF01, 0xFF02,  # Manufacturer specific
                0x1000, 0x2000, 0x3000,
            ]
            
            for routine_id in common_routines:
                for ctrl_type in control_types:
                    # Basic routine control
                    initial_seeds.append(UDS() / UDS_RC(
                        routineControlType=ctrl_type,
                        routineIdentifier=routine_id
                    ))
                    # With routine control option record
                    initial_seeds.append(UDS() / UDS_RC(
                        routineControlType=ctrl_type,
                        routineIdentifier=routine_id
                    ) / Raw(b'\x00' * 4))
            
            # Edge cases
            initial_seeds.append(UDS() / UDS_RC(routineControlType=1, routineIdentifier=0x0000))
            initial_seeds.append(UDS() / UDS_RC(routineControlType=1, routineIdentifier=0xFFFF))
            initial_seeds.append(UDS() / UDS_RC(routineControlType=0xFF, routineIdentifier=0x1234))
        
        kwargs['initial_seeds'] = initial_seeds
        return super(UDS_RoutineControlFuzzerEnumerator, self)._get_initial_requests(**kwargs)
    
    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """Score with emphasis on successful routine execution."""
        if resp is not None and resp.service == 0x71:  # Positive response
            # Successful routine execution is HIGH priority
            return self.SCORE_POSITIVE_RESPONSE + 40
        
        if resp is not None and resp.service == 0x7f:
            try:
                nrc = self._get_negative_response_code(resp)
                if nrc in [0x24, 0x31, 0x33, 0x72]:  # Various routine errors
                    if nrc not in self._seen_response_codes:
                        self._seen_response_codes.add(nrc)
                        return self.SCORE_NEW_NEGATIVE_RESPONSE + 15
                    return self.SCORE_KNOWN_NEGATIVE_RESPONSE + 5
            except (AttributeError, IndexError):
                pass
        
        return super(UDS_RoutineControlFuzzerEnumerator, self)._score_response(req, resp)


class UDS_WriteMemoryByAddressFuzzerEnumerator(UDS_FuzzerEnumerator):
    """
    Specialized fuzzer for UDS WriteMemoryByAddress service (0x3D).
    
    This fuzzer targets direct memory write operations, which represent the
    highest security risk as they allow arbitrary memory modification. Successful
    writes can completely compromise ECU security and functionality.
    
    Example:
        >>> fuzzer = UDS_WriteMemoryByAddressFuzzerEnumerator()
        >>> fuzzer.execute(socket, EcuState(session=1),
        >>>                mutation_strategy='smart', max_mutations=200)
    """
    _description = "WriteMemoryByAddress service (0x3D) fuzzing with intelligent mutation"
    
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """Generate initial seed packets for WriteMemoryByAddress fuzzing."""
        initial_seeds = kwargs.get('initial_seeds', None)
        
        if initial_seeds is None:
            initial_seeds = []
            
            # Various address and size length combinations
            for addr_len in [1, 2, 3, 4]:
                for size_len in [1, 2, 3, 4]:
                    # Test different address values
                    addresses = [0x0000, 0x1000, 0x8000, 0xF000] if addr_len <= 2 else [0x00000000, 0x10000000, 0x80000000]
                    
                    for addr in addresses[:2]:  # Limit to 2 addresses per combination
                        pkt = UDS() / UDS_WMBA(
                            memoryAddressLen=addr_len,
                            memorySizeLen=size_len
                        )
                        
                        # Set appropriate address field
                        if addr_len == 1:
                            pkt.memoryAddress1 = addr & 0xFF
                        elif addr_len == 2:
                            pkt.memoryAddress2 = addr & 0xFFFF
                        elif addr_len == 3:
                            pkt.memoryAddress3 = addr & 0xFFFFFF
                        else:
                            pkt.memoryAddress4 = addr
                        
                        # Set size
                        if size_len == 1:
                            pkt.memorySize1 = 0x10
                        elif size_len == 2:
                            pkt.memorySize2 = 0x0100
                        elif size_len == 3:
                            pkt.memorySize3 = 0x001000
                        else:
                            pkt.memorySize4 = 0x00010000
                        
                        # Add with data
                        initial_seeds.append(pkt / Raw(b'\x00' * 16))
                        initial_seeds.append(pkt / Raw(b'\xFF' * 16))
            
            # Edge cases - zero address/size
            pkt = UDS() / UDS_WMBA(memoryAddressLen=2, memorySizeLen=2)
            pkt.memoryAddress2 = 0x0000
            pkt.memorySize2 = 0x0000
            initial_seeds.append(pkt)
        
        kwargs['initial_seeds'] = initial_seeds
        return super(UDS_WriteMemoryByAddressFuzzerEnumerator, self)._get_initial_requests(**kwargs)
    
    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """Score with MAXIMUM emphasis on successful memory writes (CRITICAL security)."""
        if resp is not None and resp.service == 0x7D:  # Positive response
            # Successful memory write is EXTREMELY CRITICAL
            return self.SCORE_POSITIVE_RESPONSE + 100
        
        if resp is not None and resp.service == 0x7f:
            try:
                nrc = self._get_negative_response_code(resp)
                if nrc in [0x31, 0x33, 0x72, 0x73]:  # Memory write errors
                    if nrc not in self._seen_response_codes:
                        self._seen_response_codes.add(nrc)
                        return self.SCORE_NEW_NEGATIVE_RESPONSE + 20
                    return self.SCORE_KNOWN_NEGATIVE_RESPONSE + 10
            except (AttributeError, IndexError):
                pass
        
        return super(UDS_WriteMemoryByAddressFuzzerEnumerator, self)._score_response(req, resp)


class UDS_DataTransferFuzzerEnumerator(UDS_FuzzerEnumerator):
    """
    Specialized fuzzer for UDS Data Transfer services (0x34/0x35/0x36/0x37).
    
    This fuzzer targets the download/upload/transfer sequence which is used for
    firmware updates and memory programming. Compromising these services could
    allow firmware modification, code injection, or extraction of sensitive data.
    
    Services covered:
    - 0x34: RequestDownload
    - 0x35: RequestUpload  
    - 0x36: TransferData
    - 0x37: RequestTransferExit
    
    Example:
        >>> fuzzer = UDS_DataTransferFuzzerEnumerator()
        >>> fuzzer.execute(socket, EcuState(session=1),
        >>>                mutation_strategy='smart', max_mutations=400)
    """
    _description = "Data Transfer services (0x34/35/36/37) fuzzing with intelligent mutation"
    
    def _get_initial_requests(self, **kwargs):
        # type: (Any) -> Iterable[Packet]
        """Generate initial seed packets for data transfer fuzzing."""
        initial_seeds = kwargs.get('initial_seeds', None)
        
        if initial_seeds is None:
            initial_seeds = []
            
            # RequestDownload (0x34) seeds
            for addr_len in [2, 3, 4]:
                for size_len in [2, 3, 4]:
                    pkt = UDS() / UDS_RD(
                        dataFormatIdentifier=0x00,
                        memoryAddressLen=addr_len,
                        memorySizeLen=size_len
                    )
                    
                    # Set address
                    if addr_len == 2:
                        pkt.memoryAddress2 = 0x1000
                    elif addr_len == 3:
                        pkt.memoryAddress3 = 0x100000
                    else:
                        pkt.memoryAddress4 = 0x10000000
                    
                    # Set size
                    if size_len == 2:
                        pkt.memorySize2 = 0x1000
                    elif size_len == 3:
                        pkt.memorySize3 = 0x100000
                    else:
                        pkt.memorySize4 = 0x01000000
                    
                    initial_seeds.append(pkt)
            
            # RequestUpload (0x35) seeds
            for addr_len in [2, 3]:
                pkt = UDS() / UDS_RU(
                    dataFormatIdentifier=0x00,
                    memoryAddressLen=addr_len,
                    memorySizeLen=addr_len
                )
                
                if addr_len == 2:
                    pkt.memoryAddress2 = 0x2000
                    pkt.memorySize2 = 0x0100
                else:
                    pkt.memoryAddress3 = 0x200000
                    pkt.memorySize3 = 0x010000
                
                initial_seeds.append(pkt)
            
            # TransferData (0x36) seeds
            for block_seq in [0x00, 0x01, 0x02, 0xFF]:
                # Small transfer
                initial_seeds.append(UDS() / UDS_TD(
                    blockSequenceCounter=block_seq,
                    transferRequestParameterRecord=b'\x00' * 16
                ))
                # Large transfer
                initial_seeds.append(UDS() / UDS_TD(
                    blockSequenceCounter=block_seq,
                    transferRequestParameterRecord=b'\xFF' * 128
                ))
            
            # RequestTransferExit (0x37) seeds
            initial_seeds.append(UDS() / UDS_RTE())
            initial_seeds.append(UDS() / UDS_RTE() / Raw(b'\x00' * 4))
            
            # Edge cases
            pkt = UDS() / UDS_RD(dataFormatIdentifier=0xFF, memoryAddressLen=4, memorySizeLen=4)
            pkt.memoryAddress4 = 0xFFFFFFFF
            pkt.memorySize4 = 0xFFFFFFFF
            initial_seeds.append(pkt)
        
        kwargs['initial_seeds'] = initial_seeds
        return super(UDS_DataTransferFuzzerEnumerator, self)._get_initial_requests(**kwargs)
    
    def _score_response(self, req, resp):
        # type: (Packet, Optional[Packet]) -> int
        """Score with high emphasis on successful transfer operations."""
        if resp is not None:
            # Positive responses for transfer services
            if resp.service in [0x74, 0x75, 0x76, 0x77]:
                # Successful download/upload/transfer is HIGH priority
                return self.SCORE_POSITIVE_RESPONSE + 60
        
        if resp is not None and resp.service == 0x7f:
            try:
                nrc = self._get_negative_response_code(resp)
                # Transfer-specific errors
                if nrc in [0x31, 0x33, 0x70, 0x71, 0x72, 0x73, 0x92, 0x93]:
                    if nrc not in self._seen_response_codes:
                        self._seen_response_codes.add(nrc)
                        return self.SCORE_NEW_NEGATIVE_RESPONSE + 20
                    return self.SCORE_KNOWN_NEGATIVE_RESPONSE + 10
            except (AttributeError, IndexError):
                pass
        
        return super(UDS_DataTransferFuzzerEnumerator, self)._score_response(req, resp)
