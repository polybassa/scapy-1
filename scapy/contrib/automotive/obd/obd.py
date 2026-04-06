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


OBD_S01.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x01, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S01.fields_desc)
bind_layers(OBD, OBD_S01, service=0x01)
OBD._service_cls[0x01] = OBD_S01

OBD_S02.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x02, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S02.fields_desc)
bind_layers(OBD, OBD_S02, service=0x02)
OBD._service_cls[0x02] = OBD_S02

OBD_S03.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x03, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S03.fields_desc)
bind_layers(OBD, OBD_S03, service=0x03)
OBD._service_cls[0x03] = OBD_S03

OBD_S04.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x04, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S04.fields_desc)
bind_layers(OBD, OBD_S04, service=0x04)
OBD._service_cls[0x04] = OBD_S04

OBD_S06.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x06, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S06.fields_desc)
bind_layers(OBD, OBD_S06, service=0x06)
OBD._service_cls[0x06] = OBD_S06

OBD_S07.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x07, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S07.fields_desc)
bind_layers(OBD, OBD_S07, service=0x07)
OBD._service_cls[0x07] = OBD_S07

OBD_S08.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x08, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S08.fields_desc)
bind_layers(OBD, OBD_S08, service=0x08)
OBD._service_cls[0x08] = OBD_S08

OBD_S09.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x09, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S09.fields_desc)
bind_layers(OBD, OBD_S09, service=0x09)
OBD._service_cls[0x09] = OBD_S09

OBD_S0A.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x0A, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S0A.fields_desc)
bind_layers(OBD, OBD_S0A, service=0x0A)
OBD._service_cls[0x0A] = OBD_S0A

OBD_S01_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x41, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S01_PR.fields_desc)
bind_layers(OBD, OBD_S01_PR, service=0x41)
OBD._service_cls[0x41] = OBD_S01_PR

OBD_S02_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x42, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S02_PR.fields_desc)
bind_layers(OBD, OBD_S02_PR, service=0x42)
OBD._service_cls[0x42] = OBD_S02_PR

OBD_S03_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x43, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S03_PR.fields_desc)
bind_layers(OBD, OBD_S03_PR, service=0x43)
OBD._service_cls[0x43] = OBD_S03_PR

OBD_S04_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x44, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S04_PR.fields_desc)
bind_layers(OBD, OBD_S04_PR, service=0x44)
OBD._service_cls[0x44] = OBD_S04_PR

OBD_S06_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x46, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S06_PR.fields_desc)
bind_layers(OBD, OBD_S06_PR, service=0x46)
OBD._service_cls[0x46] = OBD_S06_PR

OBD_S07_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x47, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S07_PR.fields_desc)
bind_layers(OBD, OBD_S07_PR, service=0x47)
OBD._service_cls[0x47] = OBD_S07_PR

OBD_S08_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x48, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S08_PR.fields_desc)
bind_layers(OBD, OBD_S08_PR, service=0x48)
OBD._service_cls[0x48] = OBD_S08_PR

OBD_S09_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x49, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S09_PR.fields_desc)
bind_layers(OBD, OBD_S09_PR, service=0x49)
OBD._service_cls[0x49] = OBD_S09_PR

OBD_S0A_PR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x4A, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_S0A_PR.fields_desc)
bind_layers(OBD, OBD_S0A_PR, service=0x4A)
OBD._service_cls[0x4A] = OBD_S0A_PR

OBD_NR.fields_desc = [
    ConditionalField(
        XByteEnumField('service', 0x7F, OBD.services),
        lambda pkt: conf.contribs['OBD'].get('single_layer_mode', False))
] + list(OBD_NR.fields_desc)
bind_layers(OBD, OBD_NR, service=0x7F)
OBD._service_cls[0x7F] = OBD_NR
