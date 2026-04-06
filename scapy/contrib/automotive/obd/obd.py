# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = On Board Diagnostic Protocol (OBD-II)
# scapy.contrib.status = loads

import struct

from scapy.contrib.automotive.obd.iid.iids import *
from scapy.contrib.automotive.obd.mid.mids import *
from scapy.contrib.automotive.obd.pid.pids import *
from scapy.contrib.automotive.obd.tid.tids import *
from scapy.contrib.automotive.obd.services import *
from scapy.packet import NoPayload, bind_layers
from scapy.config import conf
from scapy.fields import ConditionalField, XByteEnumField
from scapy.contrib.isotp import ISOTP
from scapy.compat import orb

try:
    if conf.contribs['OBD']['treat-response-pending-as-answer']:
        pass
except KeyError:
    # log_automotive.info("Specify \"conf.contribs['OBD'] = "
    #                     "{'treat-response-pending-as-answer': True}\" to treat "
    #                     "a negative response 'requestCorrectlyReceived-"
    #                     "ResponsePending' as answer of a request. \n"
    #                     "The default value is False.")
    conf.contribs['OBD'] = {'treat-response-pending-as-answer': False,
                            'single_layer_mode': False}


class OBD(ISOTP):
    services = {
        0x01: 'CurrentPowertrainDiagnosticDataRequest',
        0x02: 'PowertrainFreezeFrameDataRequest',
        0x03: 'EmissionRelatedDiagnosticTroubleCodesRequest',
        0x04: 'ClearResetDiagnosticTroubleCodesRequest',
        0x05: 'OxygenSensorMonitoringTestResultsRequest',
        0x06: 'OnBoardMonitoringTestResultsRequest',
        0x07: 'PendingEmissionRelatedDiagnosticTroubleCodesRequest',
        0x08: 'ControlOperationRequest',
        0x09: 'VehicleInformationRequest',
        0x0A: 'PermanentDiagnosticTroubleCodesRequest',
        0x41: 'CurrentPowertrainDiagnosticDataResponse',
        0x42: 'PowertrainFreezeFrameDataResponse',
        0x43: 'EmissionRelatedDiagnosticTroubleCodesResponse',
        0x44: 'ClearResetDiagnosticTroubleCodesResponse',
        0x45: 'OxygenSensorMonitoringTestResultsResponse',
        0x46: 'OnBoardMonitoringTestResultsResponse',
        0x47: 'PendingEmissionRelatedDiagnosticTroubleCodesResponse',
        0x48: 'ControlOperationResponse',
        0x49: 'VehicleInformationResponse',
        0x4A: 'PermanentDiagnosticTroubleCodesResponse',
        0x7f: 'NegativeResponse'}

    name = "On-board diagnostics"

    fields_desc = [
        XByteEnumField('service', 0, services)
    ]

    def hashret(self):
        if self.service == 0x7f:
            return struct.pack('B', self.request_service_id & ~0x40)
        return struct.pack('B', self.service & ~0x40)

    def answers(self, other):
        if other.__class__ != self.__class__:
            return False
        if self.service == 0x7f:
            return self.payload.answers(other)
        if self.service == (other.service + 0x40):
            if isinstance(self.payload, NoPayload) or \
                    isinstance(other.payload, NoPayload):
                return True
            else:
                return self.payload.answers(other.payload)
        return False

    _service_cls = {}  # type: ignore

    @classmethod
    def dispatch_hook(cls, _pkt=b"", *args, **kwargs):
        # type: (...) -> type
        """Dispatch to the correct OBD service class in single layer mode."""
        if conf.contribs['OBD'].get('single_layer_mode', False) and len(_pkt) >= 1:
            service = orb(_pkt[0])
            return cls._service_cls.get(service, cls)
        return cls


_OBD_SERVICES = [
    (0x01, OBD_S01),
    (0x02, OBD_S02),
    (0x03, OBD_S03),
    (0x04, OBD_S04),
    (0x06, OBD_S06),
    (0x07, OBD_S07),
    (0x08, OBD_S08),
    (0x09, OBD_S09),
    (0x0A, OBD_S0A),
    (0x41, OBD_S01_PR),
    (0x42, OBD_S02_PR),
    (0x43, OBD_S03_PR),
    (0x44, OBD_S04_PR),
    (0x46, OBD_S06_PR),
    (0x47, OBD_S07_PR),
    (0x48, OBD_S08_PR),
    (0x49, OBD_S09_PR),
    (0x4A, OBD_S0A_PR),
    (0x7F, OBD_NR),
]

for _sid, _cls in _OBD_SERVICES:
    _cls.fields_desc = [
        ConditionalField(
            XByteEnumField('service', _sid, OBD.services),
            lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
    ] + list(_cls.fields_desc)
    bind_layers(OBD, _cls, service=_sid)
    OBD._service_cls[_sid] = _cls

del _sid, _cls
