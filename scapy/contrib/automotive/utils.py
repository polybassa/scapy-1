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
   classmethod to the base class::

       class KWP(ISOTP):
           _service_cls = {}
           ...
           @classmethod
           def dispatch_hook(cls, _pkt=b"", *args, **kwargs):
               if conf.contribs['KWP'].get('single_layer_mode', False) and \
                       len(_pkt) >= 1:
                   service = orb(_pkt[0])
                   return cls._service_cls.get(service, cls)
               return cls

2. Create the per-protocol service decorator::

       _kwp_service = _make_service_decorator(KWP, 'KWP')

3. Decorate every service subpacket instead of calling ``bind_layers``::

       @_kwp_service(0x10)
       class KWP_SDS(Packet):
           ...

   For classes defined in a separate module (e.g. OBD), apply the decorator
   post-definition using the functional form::

       _obd_service(0x01)(OBD_S01)

4. To enable or disable single layer mode at runtime, set the config flag
   directly::

       conf.contribs['KWP']['single_layer_mode'] = True   # enable
       conf.contribs['KWP']['single_layer_mode'] = False  # disable
"""

import struct
from typing import Any, Callable

from scapy.config import conf
from scapy.fields import ConditionalField, XByteEnumField
from scapy.packet import Packet, bind_layers


def _make_service_decorator(base_cls, conf_contrib_key):
    # type: (Any, str) -> Callable[[int], Any]
    """Return a class-decorator factory for an automotive protocol service.

    The returned decorator factory accepts a *service_id* integer and returns
    a class decorator that:

    1. Prepends a conditional ``service`` field (visible only in single layer
       mode) to the subpacket's ``fields_desc``.
    2. Registers the class in ``base_cls._service_cls`` so the
       ``dispatch_hook`` can route raw bytes to the correct type.
    3. Calls :func:`~scapy.packet.bind_layers` to link the subpacket to
       *base_cls* (multi-layer mode).
    4. Injects a ``hashret`` method that returns the correct value for
       request/response matching in single layer mode (unless the class
       already defines its own ``hashret``).

    The single layer mode is controlled at runtime via
    ``conf.contribs[conf_contrib_key]['single_layer_mode']``.

    Args:
        base_cls: The base protocol class (e.g. ``UDS``, ``KWP``).
        conf_contrib_key: Key used in :attr:`~scapy.config.conf.contribs`
                          (e.g. ``'UDS'``, ``'KWP'``).

    Returns:
        A ``service_decorator(service_id)`` factory function.

    Example::

        _kwp_service = _make_service_decorator(KWP, 'KWP')

        @_kwp_service(0x10)
        class KWP_SDS(Packet):
            ...
    """
    _base = base_cls
    _key = conf_contrib_key
    _flag = 'single_layer_mode'

    def service_decorator(service_id: int) -> Callable[[Any], Any]:
        def decorator(cls: Any) -> Any:
            # Prepend a conditional service field so that in single layer mode
            # the service byte is part of the subpacket itself.
            svc_field = ConditionalField(
                XByteEnumField('service', service_id, _base.services),
                lambda pkt: conf.contribs[_key].get(_flag, False)
            )
            cls.fields_desc = [svc_field] + list(cls.fields_desc)
            # Register in base class dispatch table for single layer mode.
            _base._service_cls[service_id] = cls
            # Bind to base class for multi-layer mode payload routing.
            bind_layers(_base, cls, service=service_id)
            # Capture service_id by value to avoid late-binding closure issues.
            _sid = service_id

            def _hashret(self: Any) -> bytes:
                if conf.contribs[_key].get(_flag, False):
                    return struct.pack('B', _sid & ~0x40)
                return Packet.hashret(self)

            if 'hashret' not in cls.__dict__:
                cls.hashret = _hashret
            return cls
        return decorator
    return service_decorator
