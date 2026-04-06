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

Single layer mode is controlled via the ``single_layer_mode`` flag in the
protocol's :attr:`~scapy.config.conf.contribs` entry::

    conf.contribs['UDS']['single_layer_mode'] = True   # enable
    conf.contribs['UDS']['single_layer_mode'] = False  # disable (default)

The same key is used for all supported protocols (``'UDS'``, ``'KWP'``,
``'OBD'``, ``'GMLAN'``).

Each service packet class carries a conditional ``service`` field as its first
field.  The field is visible (included in build / dissection) only when single
layer mode is active::

    ConditionalField(
        XByteEnumField('service', 0x10, UDS.services),
        lambda pkt: conf.contribs['UDS'].get('single_layer_mode', False))

In single layer mode the base class ``dispatch_hook`` reads the first byte of
raw data and routes it directly to the appropriate service class via the
``_service_cls`` dispatch table that is populated at module load time.
"""
