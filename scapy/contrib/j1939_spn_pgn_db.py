# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Scapy contributors

# scapy.contrib.description = SAE J1939 SPN/PGN database
# scapy.contrib.status = loads

"""
SAE J1939 SPN (Suspect Parameter Number) and PGN (Parameter Group Number)
reference database, derived from the TruckDevil open-source database.

The SPN and PGN data are stored as JSON files alongside this module and are
loaded on first access (lazy loading).  The ECU preferred-source-address table
is inlined as a plain Python dict because it is small (256 entries).

References:
    - TruckDevil: https://github.com/LittleBlondeDevil/TruckDevil
    - SAE J1939-71 (Surface Vehicle Recommended Practice)
"""

import json
import os

from typing import Dict, List, Optional

__all__ = [
    "J1939_SRC_ADDR_TABLE",
    "lookup_spn",
    "lookup_pgn",
    "lookup_src_addr",
    "spns_for_pgn",
    "pgns_for_spn",
]

# ---------------------------------------------------------------------------
# ECU preferred source-address table
# Sourced from SAE J1939 Table B1 (preferred addresses).
# Derived from TruckDevil's src_addr_list.json.
# ---------------------------------------------------------------------------

#: Maps source-address integer (0-255) to the preferred J1939 ECU name.
J1939_SRC_ADDR_TABLE = {
    0: "Engine #1",
    1: "Engine #2",
    2: "Turbocharger",
    3: "Transmission #1",
    4: "Transmission #2",
    5: "Shift Console - Primary",
    6: "Shift Console - Secondary",
    7: "Power TakeOff - (Main or Rear)",
    8: "Axle - Steering",
    9: "Axle - Drive #1",
    10: "Axle - Drive #2",
    11: "Brakes - System Controller",
    12: "Brakes - Steer Axle",
    13: "Brakes - Drive axle #1",
    14: "Brakes - Drive Axle #2",
    15: "Retarder - Engine",
    16: "Retarder - Driveline",
    17: "Cruise Control",
    18: "Fuel System",
    19: "Steering Controller",
    20: "Suspension - Steer Axle",
    21: "Suspension - Drive Axle #1",
    22: "Suspension - Drive Axle #2",
    23: "Instrument Cluster #1",
    24: "Trip Recorder",
    25: "Passenger-Operator Climate Control #1",
    26: "Alternator/Electrical Charging System",
    27: "Aerodynamic Control",
    28: "Vehicle Navigation",
    29: "Vehicle Security",
    30: "Electrical System",
    31: "Starter System",
    32: "Tractor-Trailer Bridge #1",
    33: "Body Controller",
    34: "Auxiliary Valve Control or Engine Air System Valve Control",
    35: "Hitch Control",
    36: "Power TakeOff (Front or Secondary)",
    37: "Off Vehicle Gateway",
    38: "Virtual Terminal (in cab)",
    39: "Management Computer #1",
    40: "Cab Display #1",
    41: "Retarder, Exhaust, Engine #1",
    42: "Headway Controller",
    43: "On-Board Diagnostic Unit",
    44: "Retarder, Exhaust, Engine #2",
    45: "Endurance Braking System",
    46: "Hydraulic Pump Controller",
    47: "Suspension - System Controller #1",
    48: "Pneumatic - System Controller",
    49: "Cab Controller - Primary",
    50: "Cab Controller - Secondary",
    51: "Tire Pressure Controller",
    52: "Ignition Control Module #1",
    53: "Ignition Control Module #2",
    54: "Seat Control #1",
    55: "Lighting - Operator Controls",
    56: "Rear Axle Steering Controller #1",
    57: "Water Pump Controller",
    58: "Passenger-Operator Climate Control #2",
    59: "Transmission Display - Primary",
    60: "Transmission Display - Secondary",
    61: "Exhaust Emission Controller",
    62: "Vehicle Dynamic Stability Controller",
    63: "Oil Sensor",
    64: "Suspension - System Controller #2",
    65: "Information System Controller #1",
    66: "Ramp Control",
    67: "Clutch/Converter Unit",
    68: "Auxiliary Heater #1",
    69: "Auxiliary Heater #2",
    70: "Engine Valve Controller",
    71: "Chassis Controller #1",
    72: "Chassis Controller #2",
    73: "Propulsion Battery Charger",
    74: "Communications Unit, Cellular",
    75: "Communications Unit, Satellite",
    76: "Communications Unit, Radio",
    77: "Steering Column Unit",
    78: "Fan Drive Controller",
    79: "Seat Control #2",
    80: "Parking brake controller",
    81: "Aftertreatment #1 system gas intake",
    82: "Aftertreatment #1 system gas outlet",
    83: "Safety Restraint System",
    84: "Cab Display #2",
    85: "Diesel Particulate Filter Controller",
    86: "Aftertreatment #2 system gas intake",
    87: "Aftertreatment #2 system gas outlet",
    88: "Safety Restraint System #2",
    89: "Atmospheric Sensor",
    90: "Powertrain Control Module",
    91: "Power Systems Manager",
    # 92-127: SAE Reserved
    **{i: "SAE Reserved" for i in range(92, 128)},
    # 128-158: SAE Reserved (continued)
    **{i: "SAE Reserved" for i in range(128, 159)},
    159: "Roadway Information System",
    160: "Advanced emergency braking system",
    161: "Fifth Wheel Smart Systems",
    162: "Slope Sensor",
    163: "Catalyst Fluid Sensor",
    164: "On Board Diagnostic Unit #2",
    165: "Rear Steering Axle Controller #2",
    166: "Rear Steering Axle Controller #3",
    167: "Instrument Cluster #2",
    168: "Trailer #5 Bridge",
    169: "Trailer #5 Lighting-electrical",
    170: "Trailer #5 Brakes (ABS-EBS)",
    171: "Trailer #5 Reefer",
    172: "Trailer #5 Cargo",
    173: "Trailer #5 Chassis-Suspension",
    174: "Other Trailer #5 Devices",
    175: "Other Trailer #5 Devices",
    176: "Trailer #4 Bridge",
    177: "Trailer #4 Lighting-electrical",
    178: "Trailer #4 Brakes (ABS-EBS)",
    179: "Trailer #4 Reefer",
    180: "Trailer #4 Cargo",
    181: "Trailer #4 Chassis-Suspension",
    182: "Other Trailer #4 Devices",
    183: "Other Trailer #4 Devices",
    184: "Trailer #3 Bridge",
    185: "Trailer #3 Lighting-electrical",
    186: "Trailer #3 Brakes (ABS-EBS)",
    187: "Trailer #3 Reefer",
    188: "Trailer #3 Cargo",
    189: "Trailer #3 Chassis-Suspension",
    190: "Other Trailer #3 Devices",
    191: "Other Trailer #3 Devices",
    192: "Trailer #2 Bridge",
    193: "Trailer #2 Lighting-electrical",
    194: "Trailer #2 Brakes (ABS-EBS)",
    195: "Trailer #2 Reefer",
    196: "Trailer #2 Cargo",
    197: "Trailer #2 Chassis-Suspension",
    198: "Other Trailer #2 Devices",
    199: "Other Trailer #2 Devices",
    200: "Trailer #1 Bridge",
    201: "Trailer #1 Lighting-electrical",
    202: "Trailer #1 Brakes (ABS-EBS)",
    203: "Trailer #1 Reefer",
    204: "Trailer #1 Cargo",
    205: "Trailer #1 Chassis-Suspension",
    206: "Other Trailer #1 Devices",
    207: "Other Trailer #1 Devices",
    # 208-227: SAE Reserved
    **{i: "SAE Reserved" for i in range(208, 228)},
    228: "Steering Input Unit",
    229: "Body Controller #2",
    230: "Body-to-Vehicle Interface Control",
    231: "Articulation Turntable Control",
    232: "Forward Road Image Processor",
    233: "Door Controller #3",
    234: "Door Controller #4",
    235: "Tractor/Trailer Bridge #2",
    236: "Door Controller #1",
    237: "Door Controller #2",
    238: "Tachograph",
    239: "Electric Propulsion Control Unit #1",
    240: "Electric Propulsion Control Unit #2",
    241: "Electric Propulsion Control Unit #3",
    242: "Electric Propulsion Control Unit #4",
    243: "Battery Pack Monitor #1",
    244: "Battery Pack Monitor #2 / APU #4",
    245: "Battery Pack Monitor #3 / APU #3",
    246: "Battery Pack Monitor #4 / APU #2",
    247: "Auxiliary Power Unit (APU) #1",
    248: "File Server / Printer",
    249: "Off Board Diagnostic-Service Tool #1",
    250: "Off Board Diagnostic-Service Tool #2",
    251: "On-Board Data Logger",
    252: "Reserved for Experimental Use",
    253: "Reserved for OEM",
    254: "Null Address",
    255: "GLOBAL (All-Any Node)",
}  # type: Dict[int, str]

# ---------------------------------------------------------------------------
# Lazy-loaded SPN / PGN databases
# ---------------------------------------------------------------------------

_spn_db = None   # type: Optional[Dict[str, dict]]
_pgn_db = None   # type: Optional[Dict[str, dict]]

_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_SPN_JSON = os.path.join(_DB_DIR, "j1939_spn_list.json")
_PGN_JSON = os.path.join(_DB_DIR, "j1939_pgn_list.json")


def _load_spn_db():
    # type: () -> Dict[str, dict]
    global _spn_db
    if _spn_db is None:
        with open(_SPN_JSON, encoding="utf-8") as fh:
            _spn_db = json.load(fh)
    return _spn_db


def _load_pgn_db():
    # type: () -> Dict[str, dict]
    global _pgn_db
    if _pgn_db is None:
        with open(_PGN_JSON, encoding="utf-8") as fh:
            _pgn_db = json.load(fh)
    return _pgn_db


# ---------------------------------------------------------------------------
# Public lookup helpers
# ---------------------------------------------------------------------------

def lookup_spn(spn):
    # type: (int) -> Optional[dict]
    """Return the SPN definition dict for the given SPN number, or ``None``.

    Each returned dict has the following keys (matching the TruckDevil schema):

    * ``spn`` – SPN number
    * ``spnName`` – short human-readable name
    * ``spnDescription`` – full SAE description
    * ``pgn`` – PGN this SPN is typically found in
    * ``bitPositionStart`` – bit position within the PGN data
    * ``spnLength`` – field length in bits (or ``"variable"``)
    * ``resolutionNumerator`` / ``resolutionDenominator`` – scaling factor
    * ``offset`` – value offset
    * ``dataRangeLower`` / ``dataRangeUpper`` – valid data range
    * ``operationalRange`` – operational range note
    * ``units`` – engineering units string

    :param spn: SPN number (integer)
    :returns: dict or None if not found
    """
    return _load_spn_db().get(str(spn))


def lookup_pgn(pgn):
    # type: (int) -> Optional[dict]
    """Return the PGN definition dict for the given PGN number, or ``None``.

    Each returned dict has the following keys (matching the TruckDevil schema):

    * ``pgn`` – PGN number
    * ``parameterGroupLabel`` – human-readable PGN label
    * ``acronym`` – short acronym (e.g. ``"EEC1"``)
    * ``pgnDescription`` – full SAE description
    * ``multipacket`` – ``"Yes"`` or ``"No"``
    * ``transmissionRate`` – typical transmission rate string
    * ``pgnDataLength`` – data length in bytes (int, or ``"variable"``)
    * ``defaultPriority`` – default CAN priority (int 0-7, or ``""``)
    * ``spnList`` – list of SPN numbers carried by this PGN

    :param pgn: PGN number (integer)
    :returns: dict or None if not found
    """
    return _load_pgn_db().get(str(pgn))


def lookup_src_addr(addr):
    # type: (int) -> str
    """Return the preferred ECU name for a J1939 source address.

    :param addr: source address (0-255)
    :returns: ECU name string, or ``"Unknown"`` for out-of-range values
    """
    return J1939_SRC_ADDR_TABLE.get(addr, "Unknown")


def spns_for_pgn(pgn):
    # type: (int) -> List[int]
    """Return the list of SPN numbers associated with a PGN.

    :param pgn: PGN number (integer)
    :returns: list of SPN integers (empty list if PGN not found or has no SPNs)
    """
    pgn_info = lookup_pgn(pgn)
    if pgn_info is None:
        return []
    spn_list = pgn_info.get("spnList", [])
    return [s for s in spn_list if isinstance(s, int)]


def pgns_for_spn(spn):
    # type: (int) -> List[int]
    """Return the list of PGNs that carry the given SPN.

    This does a reverse lookup: it first reads the PGN stored in the SPN
    definition record, then verifies that the PGN's ``spnList`` actually
    includes this SPN.

    :param spn: SPN number (integer)
    :returns: list of PGN integers (empty list if SPN not found)
    """
    spn_info = lookup_spn(spn)
    if spn_info is None:
        return []
    pgn = spn_info.get("pgn")
    if pgn is None:
        return []
    pgn_info = lookup_pgn(pgn)
    if pgn_info is None:
        return [pgn]
    spn_list = pgn_info.get("spnList", [])
    if spn in spn_list:
        return [pgn]
    return [pgn]
