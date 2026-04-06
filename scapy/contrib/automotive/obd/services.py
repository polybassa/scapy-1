# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Andreas Korb <andreas.d.korb@gmail.com>
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

from scapy.fields import ByteField, XByteField, BitEnumField, \
    PacketListField, XBitField, XByteEnumField, FieldListField, \
    FieldLenField, ConditionalField
from scapy.packet import Packet
from scapy.contrib.automotive.obd.packet import OBD_Packet
from scapy.config import conf

_OBD_SERVICES = {
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
    0x7f: 'NegativeResponse',
}


def _obd_slm(pkt):
    return conf.contribs['OBD'].get('single_layer_mode', False)


class OBD_DTC(OBD_Packet):
    name = "DiagnosticTroubleCode"

    locations = {
        0b00: 'Powertrain',
        0b01: 'Chassis',
        0b10: 'Body',
        0b11: 'Network',
    }

    fields_desc = [
        BitEnumField('location', 0, 2, locations),
        XBitField('code1', 0, 2),
        XBitField('code2', 0, 4),
        XBitField('code3', 0, 4),
        XBitField('code4', 0, 4),
    ]


class OBD_NR(Packet):
    name = "NegativeResponse"

    responses = {
        0x10: 'generalReject',
        0x11: 'serviceNotSupported',
        0x12: 'subFunctionNotSupported-InvalidFormat',
        0x21: 'busy-RepeatRequest',
        0x22: 'conditionsNotCorrectOrRequestSequenceError',
        0x78: 'requestCorrectlyReceived-ResponsePending'
    }

    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x7F, _OBD_SERVICES), _obd_slm),
        XByteField('request_service_id', 0),
        XByteEnumField('response_code', 0, responses)
    ]

    def answers(self, other):
        return self.request_service_id == other.service and \
            (self.response_code != 0x78 or
             conf.contribs['OBD']['treat-response-pending-as-answer'])


class OBD_S01(Packet):
    name = "S1_CurrentData"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x01, _OBD_SERVICES), _obd_slm),
        FieldListField("pid", [], XByteField('', 0))
    ]


class OBD_S02_Record(OBD_Packet):
    fields_desc = [
        XByteField('pid', 0),
        ByteField('frame_no', 0)
    ]


class OBD_S02(Packet):
    name = "S2_FreezeFrameData"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x02, _OBD_SERVICES), _obd_slm),
        PacketListField("requests", [], OBD_S02_Record)
    ]


class OBD_S03(Packet):
    name = "S3_RequestDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x03, _OBD_SERVICES), _obd_slm),
    ]


class OBD_S03_PR(Packet):
    name = "S3_ResponseDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x43, _OBD_SERVICES), _obd_slm),
        FieldLenField('count', None, count_of='dtcs', fmt='B'),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S03)


class OBD_S04(Packet):
    name = "S4_ClearDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x04, _OBD_SERVICES), _obd_slm),
    ]


class OBD_S04_PR(Packet):
    name = "S4_ClearDTCsPositiveResponse"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x44, _OBD_SERVICES), _obd_slm),
    ]

    def answers(self, other):
        return isinstance(other, OBD_S04)


class OBD_S06(Packet):
    name = "S6_OnBoardDiagnosticMonitoring"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x06, _OBD_SERVICES), _obd_slm),
        FieldListField("mid", [], XByteField('', 0))
    ]


class OBD_S07(Packet):
    name = "S7_RequestPendingDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x07, _OBD_SERVICES), _obd_slm),
    ]


class OBD_S07_PR(Packet):
    name = "S7_ResponsePendingDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x47, _OBD_SERVICES), _obd_slm),
        FieldLenField('count', None, count_of='dtcs', fmt='B'),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S07)


class OBD_S08(Packet):
    name = "S8_RequestControlOfSystem"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x08, _OBD_SERVICES), _obd_slm),
        FieldListField("tid", [], XByteField('', 0))
    ]


class OBD_S09(Packet):
    name = "S9_VehicleInformation"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x09, _OBD_SERVICES), _obd_slm),
        FieldListField("iid", [], XByteField('', 0))
    ]


class OBD_S0A(Packet):
    name = "S0A_RequestPermanentDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x0A, _OBD_SERVICES), _obd_slm),
    ]


class OBD_S0A_PR(Packet):
    name = "S0A_ResponsePermanentDTCs"
    fields_desc = [
        ConditionalField(XByteEnumField('service', 0x4A, _OBD_SERVICES), _obd_slm),
        FieldLenField('count', None, count_of='dtcs', fmt='B'),
        PacketListField('dtcs', [], OBD_DTC, count_from=lambda pkt: pkt.count)
    ]

    def answers(self, other):
        return isinstance(other, OBD_S0A)
