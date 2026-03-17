# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Generic codec base classes combining identical parts from the ASN.1 and
CBOR codec implementations.

Both the ASN.1 BER codec (BERcodec_Object) and the CBOR codec
(CBORcodec_Object) share:

- A metaclass that registers each codec class with its associated tag upon
  class creation (``GenericCodec_metaclass``).
- A base codec class providing ``check_string``, ``dec``, ``safedec``, and
  ``enc`` template methods (``GenericCodecObject``).
"""

from typing import Any, Generic, Optional, Tuple, Type, TypeVar, cast

_K = TypeVar('_K')


class GenericCodec_metaclass(type):
    """Metaclass for codec objects shared by BER and CBOR implementations.

    Upon class creation, registers each codec class with its associated tag
    by calling ``c.tag.register(c.codec, c)``.  Subclass metaclasses can
    customise the behaviour on registration failure by overriding
    ``_handle_registration_error``.
    """

    def __new__(cls,
                name,   # type: str
                bases,  # type: Tuple[type, ...]
                dct     # type: Any
                ):
        # type: (...) -> Type[GenericCodecObject[Any]]
        c = cast(
            'Type[GenericCodecObject[Any]]',
            super(GenericCodec_metaclass, cls).__new__(cls, name, bases, dct)
        )
        try:
            c.tag.register(c.codec, c)
        except Exception as exc:
            cls._handle_registration_error(c, exc)
        return c

    @classmethod
    def _handle_registration_error(cls, c, exc):
        # type: (Type[Any], Exception) -> None
        """Called when tag registration fails.  Override to add logging."""
        pass


class GenericCodecObject(Generic[_K], metaclass=GenericCodec_metaclass):
    """Generic base class for codec objects.

    Combines the identical functionality shared between ASN.1's
    ``BERcodec_Object`` and CBOR's ``CBORcodec_Object``:

    * ``check_string`` — raises a decoding error when the input is empty.
    * ``dec`` — decodes bytes with optional *safe* mode that wraps errors in
      an error object instead of raising an exception.
    * ``safedec`` — convenience wrapper that calls ``dec`` in safe mode.
    * ``enc`` — encode stub (must be implemented by concrete subclasses).

    Concrete subclasses must define the following **class-level** attributes
    so that the shared methods work correctly:

    ``tag``
        The codec tag (e.g. an ``ASN1Tag`` or ``CBORTag`` instance).
    ``codec``
        The codec identifier (e.g. ``ASN1_Codecs.BER`` or
        ``CBOR_Codecs.CBOR``).
    ``_decoding_error_class``
        Exception class instantiated by ``check_string`` when the input is
        empty (e.g. ``BER_Decoding_Error`` or ``CBOR_Codec_Decoding_Error``).
    ``_generic_error_classes``
        Tuple of exception classes caught by ``dec`` when operating in safe
        mode (e.g. ``(BER_Decoding_Error, ASN1_Error)``).
    ``_decoding_error_object_class``
        Object class used to wrap decoding errors in safe mode (e.g.
        ``ASN1_DECODING_ERROR`` or ``CBOR_DECODING_ERROR``).

    Concrete subclasses must also implement:

    ``do_dec(cls, s, context, safe)``
        The actual decoding logic.
    ``enc(cls, s)``
        The encoding logic.
    """

    @classmethod
    def check_string(cls, s):
        # type: (bytes) -> None
        """Raise a decoding error if the input bytes *s* are empty."""
        if not s:
            raise cls._decoding_error_class(  # type: ignore
                "%s: Got empty object while expecting tag %r" %
                (cls.__name__, cls.tag),
                remaining=s
            )

    @classmethod
    def do_dec(cls,
               s,           # type: bytes
               context=None,  # type: Optional[Any]
               safe=False   # type: bool
               ):
        # type: (...) -> Tuple[Any, bytes]
        """Decode bytes.

        Raises :exc:`NotImplementedError` by default; concrete subclasses must
        override this method with format-specific decode logic.
        """
        raise NotImplementedError("Subclasses must implement do_dec")

    @classmethod
    def dec(cls,
            s,           # type: bytes
            context=None,  # type: Optional[Any]
            safe=False   # type: bool
            ):
        # type: (...) -> Tuple[Any, bytes]
        """Decode bytes with optional *safe* mode.

        When *safe* is ``False`` (the default), any decoding exception
        propagates to the caller unchanged.

        When *safe* is ``True``, exceptions listed in
        ``_generic_error_classes`` are caught and returned as an instance of
        ``_decoding_error_object_class`` paired with an empty remainder
        (``b""``), so callers never receive an exception in safe mode.
        """
        if not safe:
            return cls.do_dec(s, context, safe)
        try:
            return cls.do_dec(s, context, safe)
        except cls._generic_error_classes as e:  # type: ignore
            return cls._decoding_error_object_class(s, exc=e), b""  # type: ignore

    @classmethod
    def safedec(cls,
                s,           # type: bytes
                context=None  # type: Optional[Any]
                ):
        # type: (...) -> Tuple[Any, bytes]
        """Decode bytes in safe mode (decoding errors are wrapped, not raised).

        This is a convenience wrapper around ``dec(s, context, safe=True)``.
        """
        return cls.dec(s, context, safe=True)

    @classmethod
    def enc(cls, s):
        # type: (Any) -> bytes
        """Encode *s* to bytes.  Must be implemented by concrete subclasses."""
        raise NotImplementedError("Subclasses must implement enc")
