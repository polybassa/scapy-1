# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.status = skip

"""
Generic utilities for automotive protocol single layer mode support.

These helpers allow automotive protocol base classes (UDS, KWP, OBD, GMLAN …)
to offer a *single layer mode* where every service packet (e.g. ``UDS_DSC``) is
returned directly by the base-class dispatcher instead of being nested inside
the parent layer.

To add single layer support to a protocol:

1. Add a ``_service_cls = {}`` class attribute and a ``dispatch_hook``
   classmethod to the base class (see :func:`_make_dispatch_hook`)::

       class KWP(ISOTP):
           _service_cls = {}
           ...
           @classmethod
           def dispatch_hook(cls, _pkt=b"", *args, **kwargs):
               return _make_dispatch_hook('KWP', 'single_layer_KWP')(
                   cls, _pkt, *args, **kwargs)

2. Create the per-protocol decorator and mode-toggle with the factories::

       _kwp_service = _make_service_decorator(KWP, 'KWP', 'single_layer_KWP')
       kwp_single_layer_mode = _make_single_layer_mode(KWP, 'KWP', 'single_layer_KWP')

3. Decorate every service subpacket instead of calling ``bind_layers``::

       @_kwp_service(0x10)
       class KWP_SDS(Packet):
           ...

   For classes defined in a separate module (e.g. OBD), apply the decorator
   post-definition using the functional form::

       _obd_service(0x01)(OBD_S01)
"""

import struct

from typing import Any

from scapy.compat import orb
from scapy.config import conf
from scapy.fields import ConditionalField, XByteEnumField
from scapy.packet import Packet, bind_layers, split_layers


def _make_service_decorator(base_cls, conf_contrib_key, single_layer_flag):
    # type: (type, str, str) -> Any
    """Return a class-decorator factory for an automotive protocol service.

    The returned decorator factory accepts a *service_id* integer and returns
    a class decorator that:

    1. Prepends a conditional ``service`` field (visible only in single layer
       mode) to the subpacket's ``fields_desc``.
    2. Registers the class in ``base_cls._service_cls`` so the
       ``dispatch_hook`` can route raw bytes to the correct type.
    3. Calls :func:`~scapy.packet.bind_layers` to link the subpacket to
       *base_cls* (multi-layer mode).  When the module is loaded with
       single layer mode already enabled the binding is skipped because
       ``dispatch_hook`` handles dissection.
    4. Injects a ``hashret`` method that returns the correct value for
       request/response matching in single layer mode (unless the class
       already defines its own ``hashret``).

    Args:
        base_cls: The base protocol class (e.g. ``UDS``, ``KWP``).
        conf_contrib_key: Key used in :attr:`~scapy.config.conf.contribs`
                          (e.g. ``'UDS'``, ``'KWP'``).
        single_layer_flag: Flag name inside
                           ``conf.contribs[conf_contrib_key]``
                           (e.g. ``'single_layer_UDS'``).

    Returns:
        A ``service_decorator(service_id)`` factory function.

    Example::

        _kwp_service = _make_service_decorator(KWP, 'KWP', 'single_layer_KWP')

        @_kwp_service(0x10)
        class KWP_SDS(Packet):
            ...
    """
    _base = base_cls
    _key = conf_contrib_key
    _flag = single_layer_flag

    def service_decorator(service_id):
        # type: (int) -> Any
        def decorator(cls):
            # type: (type) -> type
            # Prepend a conditional service field so that in single layer mode
            # the service byte is part of the subpacket itself.
            svc_field = ConditionalField(
                XByteEnumField('service', service_id, _base.services),
                lambda pkt: conf.contribs[_key].get(_flag, False)
            )
            cls.fields_desc = [svc_field] + list(cls.fields_desc)
            # Register in base class dispatch table for single layer mode.
            _base._service_cls[service_id] = cls
            # In multi-layer mode bind to base class for backward compatibility.
            if not conf.contribs[_key].get(_flag, False):
                bind_layers(_base, cls, service=service_id)
            # Capture service_id by value to avoid late-binding closure issues.
            _sid = service_id

            def _hashret(self):
                # type: () -> bytes
                if conf.contribs[_key].get(_flag, False):
                    return struct.pack('B', _sid & ~0x40)
                return Packet.hashret(self)

            if 'hashret' not in cls.__dict__:
                cls.hashret = _hashret
            return cls
        return decorator
    return service_decorator


def _make_single_layer_mode(base_cls, conf_contrib_key, single_layer_flag):
    # type: (type, str, str) -> Any
    """Return a function that enables or disables single layer mode.

    The returned function, when called with ``enable=True`` (default), removes
    the :func:`~scapy.packet.bind_layers` associations between *base_cls* and
    its service subclasses so that ``dispatch_hook`` takes over dissection.
    When called with ``enable=False``, the traditional multi-layer bindings
    are restored.

    The function is idempotent: calling it multiple times with the same
    argument is safe (no duplicate bindings are created).

    Args:
        base_cls: The base protocol class (e.g. ``UDS``, ``KWP``).
        conf_contrib_key: Key used in :attr:`~scapy.config.conf.contribs`.
        single_layer_flag: Flag name inside
                           ``conf.contribs[conf_contrib_key]``.

    Returns:
        A ``single_layer_mode(enable=True)`` toggle function.

    Example::

        kwp_single_layer_mode = _make_single_layer_mode(
            KWP, 'KWP', 'single_layer_KWP')

        >>> kwp_single_layer_mode(True)
        >>> KWP(b'\\x10\\x01')
        <KWP_SDS  service=StartDiagnosticSession ...>
        >>> kwp_single_layer_mode(False)   # revert to multi-layer mode
    """
    _base = base_cls
    _key = conf_contrib_key
    _flag = single_layer_flag

    def single_layer_mode(enable=True):
        # type: (bool) -> None
        conf.contribs[_key][_flag] = enable
        for service_id, cls in _base._service_cls.items():
            # Always split first to ensure idempotency (no duplicate bindings).
            split_layers(_base, cls, service=service_id)
            if not enable:
                bind_layers(_base, cls, service=service_id)

    return single_layer_mode
