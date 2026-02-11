# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""CRC (Cyclic Redundancy Check) Library

This module provides a flexible and extensible framework for computing CRC
(Cyclic Redundancy Check) checksums. It supports various CRC algorithms with
different parameters and provides utilities for:

- Computing CRCs with standard and custom parameters
- Searching for CRC patterns in binary data
- Testing CRC implementations against known test vectors
- Creating custom CRC variants dynamically

Key Features:
    - Pre-defined CRC algorithms (CRC-16, CRC-32, CRC-16-CCITT, CRC-32-AUTOSAR)
    - Table-driven computation for performance
    - Support for reflected/non-reflected input and output
    - Custom header/trailer support
    - CRC search and detection in binary streams
    - Test vector validation

CRC Parameters:
    The CRC algorithms are defined by the following parameters:
    
    - poly: The generator polynomial (without the implicit highest bit)
    - size: Size of the CRC in bits (e.g., 16, 32)
    - init_crc: Initial value for the CRC register
    - xor: Final XOR value applied to the result
    - reflect_input: Whether to reflect (reverse bits of) input bytes
    - reflect_output: Whether to reflect the final CRC value
    - header: Optional bytes prepended before computing CRC
    - trailer: Optional bytes appended before finalizing CRC

Example Usage:
    # Using pre-defined CRC algorithms
    >>> from scapy.libs.crc import CRC_32
    >>> crc = CRC_32()
    >>> checksum = crc(b"123456789")
    >>> print(f"{checksum:#010x}")
    0xcbf43926

    # Using context API for incremental computation
    >>> crc = CRC_32()
    >>> crc.init()
    >>> crc.update(b"1234")
    >>> crc.update(b"56789")
    >>> checksum = crc.finish()
    >>> print(f"{checksum:#010x}")
    0xcbf43926

    # Creating custom CRC variant
    >>> CustomCRC = CRC.from_parameters(
    ...     name="Custom-CRC16",
    ...     poly=0x1021,
    ...     size=16,
    ...     init_crc=0xFFFF,
    ...     xor=0,
    ...     reflect_input=False,
    ...     reflect_output=False
    ... )
    >>> crc = CustomCRC()
    >>> checksum = crc(b"Hello")

    # Searching for CRCs in binary data
    >>> results = CRC.search(binary_data, min_substring_len=4)
    >>> for (start, end), crc_value, crc_class in results:
    ...     print(f"Found {crc_class.name} at bytes {start}-{end}: {crc_value:#x}")

Well-Known Polynomials:
    The module includes well-known CRC polynomials from Wikipedia:
    - 16-bit: CRC-16-CCITT (0x1021), CRC-16-IBM (0x8005), and others
    - 32-bit: CRC-32 (0x04c11db7), CRC-32C (0x1edc6f41), and others

References:
    - https://en.wikipedia.org/wiki/Cyclic_redundancy_check
    - https://reveng.sourceforge.io/crc-catalogue/
"""

from functools import lru_cache
from collections import defaultdict
import itertools
from typing import Set, List, Tuple, Any, Dict, Optional


# Taken from https://en.wikipedia.org/wiki/Cyclic_redundancy_check
# Only direct representation. Reversed, reciprocal,
# reversed reciprocal polynoms can be deduced.
WELL_KNOWN_POLY = {
    16: [0x1021, 0x8005, 0xa02b, 0x2f15, 0xc867, 0x0589, 0x8bb7, 0x3d65,
         0x5935, 0x755b, 0x1dcf],
    32: [0x04c11db7, 0x1edc6f41, 0x741b8cd7, 0x32583499, 0x814141ab, 0xf4acfb13]
}


class CRCParam:
    """Container for CRC algorithm parameters.
    
    This class encapsulates all parameters needed to define a CRC algorithm,
    including the polynomial, size, initialization value, XOR output,
    reflection settings, and optional header/trailer bytes.
    
    Attributes:
        poly (int): Generator polynomial (without implicit highest bit)
        size (int): CRC size in bits (e.g., 16, 32)
        init_crc (int): Initial value for the CRC register
        xor (int): Final XOR value applied to the result
        reflect_input (bool): Whether to reflect input bytes
        reflect_output (bool): Whether to reflect final CRC value
        header (bytes): Optional bytes prepended before CRC computation
        trailer (bytes): Optional bytes appended before finalization
        name (str): Descriptive name for this CRC variant
        test_vectors (list): List of (input, expected_output) tuples for validation
    
    Example:
        >>> param = CRCParam(
        ...     name="CRC-16",
        ...     poly=0x8005,
        ...     size=16,
        ...     init_crc=0,
        ...     xor=0,
        ...     reflect_input=True,
        ...     reflect_output=True
        ... )
        >>> print(param)
        <Param for CRC-16 poly=0x8005, size=16, ...>
    """
    
    MISC = ["name", "test_vectors"]
    PARAMETERS = ["poly", "size", "init_crc", "xor",
                  "reflect_input", "reflect_output"]
    OPTIONS = ["header", "trailer"]
    FMT = {"size": "", "reflect_input": "", "reflect_output": ""}

    def __init__(self, **args):
        # type: (Any) -> None
        """Initialize CRC parameters.
        
        Args:
            **args: Keyword arguments for CRC parameters. Required parameters
                   are: poly, size, init_crc, xor, reflect_input, reflect_output.
                   Optional: header, trailer, name, test_vectors.
        
        Raises:
            Exception: If any mandatory parameter is missing.
        """
        self.remain = set(args) - set(self.PARAMETERS + self.OPTIONS + self.MISC)

        self.param = dict(header=b"", trailer=b"", test_vectors=[],
                          reflect_input=False, reflect_output=False)
        try:
            self.param.update({n: args[n] for n in self.PARAMETERS})
        except KeyError as e:
            raise Exception(f"CRC parameter {e} is mandatory")

        self.param.update({n: args[n] for n in self.OPTIONS + self.MISC if n in args})
        self.__dict__.update(self.param)
        if "name" not in self.param or self.param["name"] is None:
            self.name = self.param["name"] = f"CRCsig_{self.signature()}"

    def copy(self):
        # type: () -> CRCParam
        """Create a deep copy of this CRCParam object.
        
        Returns:
            CRCParam: A new CRCParam instance with the same parameters.
        """
        return self.__class__(**self.param)

    def param_repr(self):
        # type: () -> str
        """Generate a string representation of the parameters.
        
        Returns:
            str: Formatted string showing key CRC parameters.
        """
        s = [f"{k}={getattr(self, k): {self.FMT.get(k, '#x')}}"
             for k in self.PARAMETERS]
        s += [f"+{k}" for k in self.OPTIONS if getattr(self, k)]
        return ", ".join(s)

    def __repr__(self):
        # type: () -> str
        name = self.name if hasattr(self, "name") else "CRC param"
        s = self.param_repr()
        return f"<Param for {name} {s}>"

    def __eq__(self, other):
        # type: (object) -> bool
        """Check equality based on all parameters and options.
        
        Args:
            other: Object to compare with.
        
        Returns:
            bool: True if all parameters match, False otherwise.
        """
        return all(getattr(self, k) == getattr(other, k)
                   for k in self.PARAMETERS + self.OPTIONS)

    def __hash__(self):
        # type: () -> int
        """Compute hash based on parameters and options.
        
        Returns:
            int: Hash value for this parameter set.
        """
        return hash(tuple(getattr(self, k) for k in self.PARAMETERS + self.OPTIONS))

    def __iter__(self):
        """Iterate over all parameter names and their values.
        
        Yields:
            tuple: (parameter_name, parameter_value) pairs.
        """
        for k in self.PARAMETERS + self.MISC + self.OPTIONS:
            yield (k, getattr(self, k))

    def signature(self):
        # type: () -> str
        """Generate a unique signature string for this parameter set.
        
        The signature encodes all CRC parameters in a compact hexadecimal
        string format that uniquely identifies this CRC variant.
        
        Returns:
            str: Hexadecimal signature string.
        """
        sig_end = ((self.reflect_input << 3) | (self.reflect_output << 2)
                   | (bool(self.header) << 1) | bool(self.trailer))
        return f"{self.poly:0{self.size // 4}x}_{self.init_crc:x}_{self.xor:x}_{sig_end:x}"  # noqa: E231,E501


class _CRC_metaclass(type):
    """Metaclass for CRC implementations.
    
    This metaclass automatically:
    - Creates CRCParam from class attributes
    - Pre-computes CRC lookup tables for performance
    - Registers CRC classes in a global registry
    - Provides factory methods for creating CRC variants
    
    The metaclass enables declarative CRC class definitions where you simply
    specify the parameters as class attributes, and the metaclass handles
    initialization and optimization automatically.
    """
    
    REGISTRY = set()  # type: Set[CRC]

    def __new__(cls, name, bases, dct):
        """Create a new CRC class with automatic initialization.
        
        Args:
            name (str): Name of the class being created.
            bases (tuple): Base classes.
            dct (dict): Class dictionary with attributes.
        
        Returns:
            type: The new CRC class with initialized tables and parameters.
        """
        newcls = super(_CRC_metaclass, cls).__new__(cls, name, bases, dct)
        if not hasattr(newcls, "name"):
            newcls.name = newcls.__name__
        if bases:  # exclude parent class because it is virtual
            newcls.param = CRCParam(**dct)
            newcls.precal_table = (
                cls._precalc_table_reflect
                if newcls.reflect_input
                else cls._precalc_table
            )
            newcls.table = newcls.precal_table(newcls.poly, newcls.size)
            if not getattr(newcls, "do_not_register", False):
                newcls.REGISTRY.add(newcls)
            newcls.mask = (1 << newcls.size) - 1
        else:
            newcls.param = None
        return newcls

    @staticmethod
    @lru_cache(maxsize=128)
    def _precalc_table_reflect(crcpoly, sz):
        # type: (int, int) -> List[int]
        """Pre-compute CRC lookup table for reflected (LSB-first) algorithms.
        
        For reflected CRCs, input bytes are processed LSB-first and the
        polynomial operates on the lower bits of the CRC register.
        
        Args:
            crcpoly (int): CRC polynomial.
            sz (int): CRC size in bits.
        
        Returns:
            List[int]: 256-entry lookup table for fast CRC computation.
        """
        revpoly = CRC._reverse_bits(crcpoly, sz)
        t = []
        for i in range(256):
            crc = i
            for j in range(8):
                b0 = crc & 1
                crc >>= 1
                if b0:
                    crc ^= revpoly
            t.append(crc)
        return t

    @staticmethod
    @lru_cache(maxsize=128)
    def _precalc_table(crcpoly, sz):
        # type: (int, int) -> List[int]
        """Pre-compute CRC lookup table for non-reflected (MSB-first) algorithms.
        
        For non-reflected CRCs, input bytes are processed MSB-first and the
        polynomial operates on the upper bits of the CRC register.
        
        Args:
            crcpoly (int): CRC polynomial.
            sz (int): CRC size in bits.
        
        Returns:
            List[int]: 256-entry lookup table for fast CRC computation.
        """
        t = []
        hbmsk = (1 << (sz - 1))
        msk = (1 << sz) - 1
        for i in range(256):
            crc = i << (sz - 8)
            for j in range(8):
                bsz = crc & hbmsk
                crc <<= 1
                if bsz:
                    crc ^= crcpoly
            t.append(crc & msk)
        return t

    @staticmethod
    def _reverse_bits(x, sz):
        # type: (int, int) -> int
        """Reverse the bit order of an integer.
        
        Args:
            x (int): Integer value to reverse.
            sz (int): Number of significant bits to consider.
        
        Returns:
            int: Integer with reversed bit order.
        
        Example:
            >>> _reverse_bits(0b10110, 5)  # Returns 0b01101
            13
        """
        y = 0
        for i in range(sz):
            y <<= 1
            y |= x & 1
            x >>= 1
        return y

    def from_parameters(self, crc_param=None, name=None,
                        do_not_register=False, **kargs):
        # type: (Optional[CRCParam], Optional[str], bool, Any) -> type
        """Create a new CRC class from parameters.
        
        This factory method creates a new CRC class dynamically with the
        specified parameters, inheriting from the current CRC class.
        
        Args:
            crc_param (CRCParam, optional): Pre-built CRC parameters object.
            name (str, optional): Name for the new CRC class.
            do_not_register (bool): If True, don't add to global registry.
            **kargs: CRC parameters (poly, size, init_crc, xor, etc.).
        
        Returns:
            type: A new CRC class with the specified parameters.
        
        Example:
            >>> CustomCRC = CRC.from_parameters(
            ...     name="Custom16",
            ...     poly=0x1021,
            ...     size=16,
            ...     init_crc=0xFFFF,
            ...     xor=0,
            ...     reflect_input=False,
            ...     reflect_output=False
            ... )
            >>> crc = CustomCRC()
            >>> checksum = crc(b"test")
        """
        if crc_param is None:
            crc_param = CRCParam(name=name, **kargs)
        p = dict(crc_param)
        if name is not None:
            p["name"] = name
        p["do_not_register"] = do_not_register
        cls = type(self).__new__(type(self), p["name"], (self,), p)
        return cls

    def create_context(self):
        # type: () -> CRC
        """Create a new CRC computation context.
        
        This creates an instance of the CRC class without initializing it,
        allowing manual control over the init/update/finish cycle.
        
        Returns:
            CRC: A new CRC instance ready for init().
        """
        i = self.__new__(self)
        i.__init__()
        return i

    def _init(self):
        # type: () -> int
        """Initialize CRC computation with header bytes.
        
        Returns:
            int: Initial CRC register value after processing header.
        """
        return self._update(self.param.init_crc, self.param.header)

    def _update(self, crc, msg):
        # type: (int, bytes) -> int
        """Update CRC with message bytes.
        
        This is the core CRC computation using the pre-computed lookup table.
        The algorithm varies based on whether input reflection is enabled.
        
        Args:
            crc (int): Current CRC register value.
            msg (bytes): Message bytes to process.
        
        Returns:
            int: Updated CRC register value.
        """
        if self.param.reflect_input:
            # Reflected: process from LSB, shift right
            for c in msg:
                idx = (crc & 0xff) ^ c
                crc >>= 8
                crc ^= self.table[idx]
        else:
            # Non-reflected: process from MSB, shift left
            for c in msg:
                idx = (crc >> (self.param.size - 8)) ^ c
                crc <<= 8
                crc &= self.mask
                crc ^= self.table[idx]
        return crc

    def _finish(self, crc):
        # type: (int) -> int
        """Finalize CRC computation with trailer and XOR.
        
        Args:
            crc (int): Current CRC register value.
        
        Returns:
            int: Final CRC value after trailer, XOR, and output reflection.
        """
        crc = self._update(crc, self.param.trailer)
        crc = (crc ^ self.param.xor) & self.mask
        if self.param.reflect_input ^ self.param.reflect_output:
            crc = self._reverse_bits(crc, self.param.size)
        return crc

    def __call__(self, msg):
        # type: (bytes) -> int
        """Compute CRC of a message in one call.
        
        Args:
            msg (bytes): Message to compute CRC for.
        
        Returns:
            int: Computed CRC value.
        
        Raises:
            AssertionError: If msg is not bytes type.
        """
        assert type(msg) is bytes, "type of input is bytes"
        crc = self._init()
        crc = self._update(crc, msg)
        return self._finish(crc)

    def test(self):
        # type: () -> bool
        """Test CRC implementation against test vectors.
        
        Runs all test vectors defined in the CRC parameters and prints
        results, showing whether each test passed or failed.
        
        Returns:
            bool: True if all tests passed, False otherwise.
        """
        ok = True
        for (tvin, tvout) in self.param.test_vectors:
            out = self(tvin)
            ok &= (out == tvout)
            print(f"{self.name}\t({tvin.hex()})\t = {out:#0{self.size // 4}x}\t{'ok' if out == tvout else f'FAILED. Expected {tvout:#0{self.size // 4}x}'}".expandtabs(32))  # noqa: E501,E231
        return ok

    def __eq__(self, other):
        # type: (object) -> bool
        return hasattr(other, "param") and (self.param == other.param)

    def __hash__(self):
        # type: () -> int
        return hash(self.param)  # if hasattr(self, "param") else 0)

    def __repr__(self):
        # type: () -> str
        repr = self.param.param_repr() if self.param else "-"
        return f"<{self.name} {repr}>"

    def autotest(self):
        # type: () -> bool
        """Run tests on all registered CRC classes.
        
        Tests every CRC class in the global registry against their test
        vectors and prints a summary.
        
        Returns:
            bool: True if all tests passed, False otherwise.
        """
        ok = 0
        n = len(self.REGISTRY)
        ok = sum(c.test() for c in self.REGISTRY)
        print(f"TOTAL: {ok}/{n} CRC test passed")
        return ok == n

    def lookup(self, crc):
        # type: (Any) -> Optional[type]
        """Look up a CRC class in the registry by parameters.
        
        Args:
            crc: Either a CRC instance or CRCParam to search for.
        
        Returns:
            type or None: The matching CRC class if found, None otherwise.
        """
        param = crc.param if isinstance(crc, self.__class__) else crc
        for c in self.REGISTRY:
            if c.param == param:
                return c
        return None

    def find_substring_from_crc(self, s, *target_crc):
        # type: (bytes, int) -> List[Tuple[Tuple[int,int],int]]
        """Find substrings in a byte sequence that produce specific CRC values.
        
        Searches for all substrings of the input that produce any of the
        target CRC values when processed with this CRC algorithm.
        
        Args:
            s (bytes): Byte sequence to search within.
            *target_crc: One or more target CRC values to search for.
        
        Returns:
            List[Tuple[Tuple[int,int],int]]: List of ((start, end), crc_value)
                tuples for each matching substring.
        
        Example:
            >>> crc = CRC_32()
            >>> results = crc.find_substring_from_crc(data, 0x12345678)
            >>> for (start, end), crc_val in results:
            ...     print(f"Substring at {start}:{end} has CRC {crc_val:#x}")
        """
        l = len(s)  # noqa: E741
        i = 0
        res = []
        while i < l:
            j = i
            c = self.create_context()
            c.init()
            while j < l:
                c.update(s[j:j + 1])
                crc = c.finish()
                if crc in target_crc:
                    res.append(((i, j), crc))
                j += 1
            i += 1
        return res

    def find_crc_from_string(self, s, *target_crc):
        # type: (bytes, int) -> List[Tuple[int, type]]
        """Find which registered CRC algorithms produce specific values for input.
        
        Tests all registered CRC algorithms on the input string and returns
        those that produce any of the target CRC values.
        
        Args:
            s (bytes): Input bytes to compute CRC for.
            *target_crc: One or more target CRC values to match.
        
        Returns:
            List[Tuple[int, type]]: List of (crc_value, CRC_class) tuples
                for each matching algorithm.
        
        Example:
            >>> results = CRC.find_crc_from_string(b"test", 0xabcd1234)
            >>> for crc_val, crc_class in results:
            ...     print(f"{crc_class.name} produced {crc_val:#x}")
        """
        res = []
        for crc in self.REGISTRY:
            c = crc(s)
            if c in target_crc:
                res.append((c, crc))
        return res

    def search(self, s, min_substring_len=4, only_registry=False):
        # type: (bytes, int, bool) -> List[Tuple[Tuple[int,int],int,type]]
        """Search for CRC values embedded in a byte sequence.
        
        This powerful search function looks for CRC checksums within binary
        data by:
        1. Extracting all possible CRC-sized values from the data
        2. Computing CRCs of all substrings with various algorithms
        3. Matching computed CRCs against extracted values
        
        This can help identify where CRCs are used in unknown protocols or
        file formats.
        
        Args:
            s (bytes): Binary data to search within.
            min_substring_len (int): Minimum substring length to consider.
                Default is 4 bytes.
            only_registry (bool): If True, only test registered CRC algorithms.
                If False (default), also test combinations of well-known
                polynomials with different parameter variations.
        
        Returns:
            List[Tuple[Tuple[int,int],int,type]]: List of
                ((start, end), crc_value, CRC_class) tuples for each potential
                CRC found in the data.
        
        Example:
            >>> # Search for potential CRCs in a binary file
            >>> with open("data.bin", "rb") as f:
            ...     data = f.read()
            >>> results = CRC.search(data, min_substring_len=8)
            >>> for (start, end), crc_val, crc_class in results:
            ...     print(f"Potential {crc_class.name} at offset {start}: "
            ...           f"data[{start}:{end}] -> CRC {crc_val:#x}")
        """
        if only_registry:
            crc_list = self.REGISTRY
        else:
            # Generate comprehensive set of CRC variants from well-known polynomials
            crc_list = set()
            for sz, poly_lst in WELL_KNOWN_POLY.items():
                msk = (1 << sz) - 1
                # Include both direct and bit-reversed polynomials
                poly_lst_and_rev = (
                    poly_lst +
                    [self._reverse_bits(p, sz) for p in poly_lst]
                )
                # Test all combinations of parameters
                crc_list |= {
                    self.from_parameters(
                        do_not_register=True,
                        poly=poly, size=sz, init_crc=init & msk, xor=xor & msk,
                        reflect_input=r_in, reflect_output=r_out)
                    for poly, init, xor, r_in, r_out
                    in itertools.product(poly_lst_and_rev, [0, -1], [0, -1],
                                         [False, True], [False, True])
                }

        l = len(s)  # noqa: E741
        sizes = set(c.size // 8 for c in crc_list)
        
        # Extract all potential CRC values from the data (both endiannesses)
        targets = defaultdict(set)  # type: Dict[int, Set[int]]
        for sz in sizes:
            i = 0
            while i <= l - sz:
                ss = s[i:i + sz]
                targets[sz].add(int.from_bytes(ss, "little"))
                targets[sz].add(int.from_bytes(ss, "big"))
                i += 1

        # Group CRCs by size for efficient processing
        crcs = defaultdict(list)  # type: Dict[int, List[type]]
        for c in crc_list:
            crcs[c.size].append(c)

        res = []

        # Create CRC contexts for each algorithm
        ctx = {k // 8: [c.create_context() for c in v] for k, v in crcs.items()}
        
        # Search for matching CRCs
        i = 0
        while i < l:
            # Initialize all contexts
            for clst in ctx.values():
                for c in clst:
                    c.init()
            j = i
            while j < l:
                # Update all contexts with next byte
                for sz in sizes:
                    for c in ctx[sz]:
                        c.update(s[j:j + 1])
                        if j - i + 1 >= min_substring_len:
                            crc = c.finish()
                            # Check if this CRC matches any extracted value
                            if crc in targets[sz]:
                                res.append(((i, j + 1), crc, c.__class__))
                j += 1
            i += 1
        return res


class CRC(metaclass=_CRC_metaclass):
    """Base class for CRC implementations.
    
    This is the base class for all CRC algorithms. Subclasses define specific
    CRC variants by setting class attributes (poly, size, init_crc, etc.).
    
    The class provides two interfaces:
    1. Single-shot: crc_value = CRC_class()(message)
    2. Incremental (context API): init(), update(), finish()
    
    Example:
        # Define a custom CRC-16 variant
        >>> class MyCRC16(CRC):
        ...     name = "My-CRC16"
        ...     size = 16
        ...     poly = 0x1021
        ...     init_crc = 0xFFFF
        ...     xor = 0
        ...     reflect_input = False
        ...     reflect_output = False
        ...     test_vectors = [(b"123456789", 0x29b1)]
        
        # Use it
        >>> crc = MyCRC16()
        >>> checksum = crc(b"test data")
    """
    
    def __init__(self):
        """Initialize a CRC computation context.
        
        This prepares the CRC for incremental computation using the
        init/update/finish pattern.
        """
        self.init()

    # Context API: init()/update()/finish()
    # finish() does not change state, so update()/finish() can be called again

    def init(self):
        # type: () -> None
        """Initialize CRC computation state.
        
        Resets the CRC register to the initial value (including header
        processing). Call this before the first update() or to restart
        computation.
        """
        self.crc = self.__class__._init()

    def update(self, msg):
        # type: (bytes) -> None
        """Update CRC with additional message bytes.
        
        Incrementally processes message bytes, updating the internal CRC
        state. Can be called multiple times to process a message in chunks.
        
        Args:
            msg (bytes): Message bytes to process.
        
        Example:
            >>> crc = CRC_32()
            >>> crc.init()
            >>> crc.update(b"Hello ")
            >>> crc.update(b"World")
            >>> checksum = crc.finish()
        """
        self.crc = self.__class__._update(self.crc, msg)

    def finish(self):
        # type: () -> int
        """Finalize and return the CRC value.
        
        Completes CRC computation by processing trailer, applying final XOR,
        and optionally reflecting the output. Does not modify the internal
        state, so update() can be called again followed by another finish().
        
        Returns:
            int: The computed CRC value.
        """
        return self.__class__._finish(self.crc)

    def __repr__(self):
        # type: () -> str
        return f"<{self.name} CTX>"


# Pre-defined CRC algorithms with test vectors

class CRC_16(CRC):
    """CRC-16 (also known as CRC-16-ANSI or CRC-16-IBM).
    
    This is one of the most common 16-bit CRC algorithms, used in many
    protocols including Modbus, USB, and XMODEM.
    
    Parameters:
        - Polynomial: 0x8005 (x^16 + x^15 + x^2 + 1)
        - Initial value: 0x0000
        - Final XOR: 0x0000
        - Reflect input: Yes
        - Reflect output: Yes
    
    Test vector: CRC("123456789") = 0xbb3d
    """
    name = "CRC-16"
    size = 16
    poly = 0x8005
    init_crc = 0
    xor = 0
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"123456789", 0xbb3d)]


class CRC_32(CRC):
    """CRC-32 (also known as CRC-32-IEEE 802.3).
    
    This is the standard 32-bit CRC used in Ethernet, ZIP, PNG, and many
    other applications. It provides strong error detection for typical
    data transmission scenarios.
    
    Parameters:
        - Polynomial: 0x04c11db7 (x^32 + x^26 + x^23 + ... + x^2 + x + 1)
        - Initial value: 0xffffffff
        - Final XOR: 0xffffffff
        - Reflect input: Yes
        - Reflect output: Yes
    
    Test vector: CRC("123456789") = 0xcbf43926
    """
    name = "CRC-32"
    size = 32
    poly = 0x4c11db7
    init_crc = 0xffffffff
    xor = 0xffffffff
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"123456789", 0xcbf43926)]


class CRC_16_CCITT(CRC):
    """CRC-16-CCITT (also known as KERMIT CRC or CRC-16-CCITT-TRUE).
    
    Used in XMODEM, Bluetooth, and many telecommunications protocols.
    Note: There are several variants called "CRC-16-CCITT" with different
    parameters; this is the "true" CCITT version with init=0.
    
    Parameters:
        - Polynomial: 0x1021 (x^16 + x^12 + x^5 + 1)
        - Initial value: 0x0000
        - Final XOR: 0x0000
        - Reflect input: Yes
        - Reflect output: Yes
    
    Test vector: CRC(0xcb37) = 0x6b3e
    """
    name = "CRC16 CCITT"
    size = 16
    poly = 0x1021
    init_crc = 0
    xor = 0
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"\xcb\x37", 0x6b3e)]


class CRC_32_AUTOSAR(CRC):
    """CRC-32 used in AUTOSAR automotive standard.
    
    This CRC is specified in the AUTOSAR (Automotive Open System Architecture)
    standard for automotive electronic control units (ECUs). It uses a
    different polynomial than the standard CRC-32.
    
    Parameters:
        - Polynomial: 0xf4acfb13
        - Initial value: 0xffffffff
        - Final XOR: 0xffffffff
        - Reflect input: Yes
        - Reflect output: Yes
    
    Test vectors:
        - CRC(0x00000000) = 0x6fb32240
        - CRC(0x332255aabbccddee) = 0xa65a343d
    """
    name = "CRC32 AUTOSAR"
    size = 32
    poly = 0xf4acfb13
    init_crc = 0xffffffff
    xor = 0xffffffff
    reflect_input = True
    reflect_output = True
    test_vectors = [(b"\0\0\0\0", 0x6fb32240),
                    (b"\x33\x22\x55\xAA\xBB\xCC\xDD\xEE\xFF", 0xa65a343d)]
