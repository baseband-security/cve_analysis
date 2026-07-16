_SUBSYSTEM_OVERRIDES: dict[str, frozenset] = {
    '2G': frozenset({
    }),
    '3G': frozenset({
    }),
    '4G/LTE': frozenset({
    }),
    '5G/NR': frozenset({
    }),
    'IMS': frozenset({
        'CVE-2024-25073',
        'CVE-2024-28068',
        'CVE-2018-5891'
    }),
    'SMS': frozenset({
    }),
    'SIM': frozenset({
    }),
    'Local': frozenset({
        'CVE-2024-34673',
        'CVE-2024-20132',
        'CVE-2024-20131',
        'CVE-2024-20133',
        'CVE-2024-20151',
        'CVE-2023-52346',
        'CVE-2022-48381',
        'CVE-2022-48380',
        'CVE-2022-48389',
        'CVE-2022-47485',
        'CVE-2023-52345'
    }),
    'Upper Levels': frozenset({
    }),
}

KEYWORD_MAP = [
    # 2G / GSM / GERAN
# 2G / GSM / GERAN
    (r'\b2g\b|\bgsm\b|\bgeran\b',                                         ('2G', 'Modem', None, None)),
    (r'\b2g rrm\b',                                                        ('2G', 'Access Stratum', 'RRM', 'Radio Resource Management')),
    (r'\b2g rr\b|\bradio resource\b',                                      ('2G', 'Access Stratum', 'RR', 'Radio Resource')),
    (r'\bgprs\b',                                                          ('2G', 'Access Stratum', 'GPRS', 'Packet Data')),
    (r'\bpacket neighbour cell data\b|\bpncd\b',                           ('2G', 'Access Stratum', 'GPRS', 'PNCD')),
    (r'\botasp\b',                                                         ('2G', 'Provisioning', 'OTASP', 'Over The Air Service Provisioning')),
    (r'\btraffic channel neighbor list\b|\btcnlu\b',                       ('2G', 'RRC', 'Traffic Channel Neighbour List', None)),
    # (r'\b(?:2g |3g )?mobility management\b', ('2G', 'MM', 'Mobility Management', None)),

    # 3G / UMTS / WCDMA
    (r'\b3g\b|\bumts\b|\bwcdma\b',                                        ('3G', 'Modem', None, None)),
    (r'\b3g cc\b',                                                         ('3G', 'Access Stratum', 'Call Control', 'Combined FACILITY')),
    (r'\bsupplementary service\b|\bss (?:module|component|message)\b',     ('3G', 'CC', 'Supplementary Services', None)),

    # 4G / LTE / EPS
    (r'\blte\b|\b4g\b|\beps\b',                                           ('4G/LTE', 'Modem', None, None)),
    (r'\bemm\b|\beps mobility\b',                                          ('4G/LTE', 'NAS', 'EMM', 'EPS Mobility Management')),
    (r'\bnas\b',                                                           ('4G/LTE', 'NAS', 'NAS', 'Non-Access Stratum')),
    (r'\bsecurity mode command\b',                                         ('4G/LTE', 'NAS', 'Security', 'Security Mode Command')),
    (r'\bguti\b',                                                          ('4G/LTE', 'NAS', 'Mobility', 'GUTI Reallocation')),
    (r'\bnl1\b',                                                           ('4G/LTE', 'Access Stratum', 'L1', 'NAS Layer 1')),
    (r'\bsib1\b|\bsystem information block 1\b',                           ('4G/LTE', 'Access Stratum', 'SIB1', 'System Information Block 1')),
    (r'\binvalid sib\b|\bsib with incorrect values\b',                     ('4G/LTE', 'Access Stratum', 'SIB', 'Invalid SIB Processing')),
    (r'\bmib\b',                                                           ('4G/LTE', 'Access Stratum', 'MIB', 'Master Information Block')),
    (r'\bdcch\b',                                                          ('4G/LTE', 'Access Stratum', 'DCCH', 'Dedicated Control Channel')),
    (r'\blr12a\b',                                                         ('4G/LTE', 'Modem', 'LR12A', None)),
    (r'\blr13\b',                                                          ('4G/LTE', 'Modem', 'LR13', None)),
    (r'\btlb\b|\btracking area\b',                                         ('4G/LTE', 'NAS', 'Tracking Area / TLB', None)),
    (r'\bosi\b|\bother system info\b',                                     ('4G/LTE', 'RRC', 'OSI Scheduling', None)),
    (r'\bsib12\b',                                                         ('4G/LTE', 'RRC', 'SIB12', None)),
    (r'\brohc\b|\bheader compression\b',                                   ('4G/LTE', 'PDCP', 'ROHC', None)),
    (r'\bpdcp\b',                                                          ('4G/LTE', 'L2', 'PDCP', None)),
    (r'\brlc\b|\brlc am\b|\brlc um\b',                                    ('4G/LTE', 'L2', 'RLC', None)),
    (r'\bcross[- ]carrier scheduling\b|\bcarrier aggregation\b',           ('4G/LTE', 'RRC', 'Carrier Aggregation', None)),
    (r'\buplink scheduling\b',                                             ('4G/LTE', 'MAC', 'Uplink Scheduler', None)),
    (r'\bsession management\b|\bsm module\b',                              ('4G/LTE', 'NAS', 'Session Management', None)),
    (r'\blwm2m\b|\bbootstrap request\b',                                   ('4G/LTE', 'OMA-DM', 'LwM2M', None)),
    (r'\bsor transparent container\b|\bsteering of roaming\b',             ('4G/LTE', 'NAS', 'SOR', None)),
    (r'\bdownlink data indication\b',                                      ('4G/LTE', 'RRC', 'Downlink Data Indication', None)),
    (r'\brrc connection setup\b',                                          ('4G/LTE', 'Access Stratum', 'RRC', 'Connection Setup')),
    (r'\brrc reconfiguration\b',                                           ('4G/LTE', 'Access Stratum', 'RRC', 'Reconfiguration')),

    # 5G / NR
    (r'\b5g\b|\bnew radio\b',                                             ('5G/NR', 'Modem', None, None)),
    (r'\bnr15\b',                                                          ('5G/NR', 'Modem', 'NR15', None)),
    (r'\bnr16\b',                                                          ('5G/NR', 'Modem', 'NR16', None)),
    (r'\bnr17\b',                                                          ('5G/NR', 'Modem', 'NR17', None)),
    (r'\brrc\b',                                                           ('5G/NR', 'Access Stratum', 'RRC', 'Radio Resource Control')),
    (r'\brrc setup\b',                                                     ('5G/NR', 'Access Stratum', 'RRC', 'Connection Setup')),
    (r'\brrc reconfiguration\b',                                           ('5G/NR', 'Access Stratum', 'RRC', 'Reconfiguration')),
    (r'\bradio bearer\b',                                                  ('5G/NR', 'Access Stratum', 'RRC', 'Radio Bearer')),
    (r'\bsib5\b',                                                          ('5G/NR', 'Access Stratum', 'SIB5', 'System Information Block 5')),
    (r'\bmac rar\b',                                                       ('5G/NR', 'MAC', 'RAR', 'Random Access Response')),
    (r'\bbeam switch\b|\bbeam management\b',                               ('5G/NR', 'PHY', 'Beam Management', 'Beam Switching')),
    (r'\bbwp\b',                                                           ('5G/NR', 'PHY', 'Bandwidth Part', 'BWP')),
    (r'\bsubcarrier spacing\b|\bscs configuration\b',                      ('5G/NR', 'PHY', 'Subcarrier Spacing', 'SCS')),
    (r'\bnon.standalone\b|\bnsa mode\b',                                   ('5G/NR', 'Interworking', 'NSA', 'Non-Standalone')),
    (r'\bnr to lte handover\b|\bnr.lte handover\b',                        ('5G/NR', 'Interworking', 'Mobility', 'NR-LTE Handover')),
    (r'\bnrmm\b|\bregistration accept\b|\b5g mm\b',                        ('5G/NR', 'NAS', 'Registration / MM', None)),
    (r'\bpdu session\b',                                                   ('5G/NR', 'NAS', 'PDU Session', None)),

    # IMS / VoLTE / VoWiFi / SIP / SDP / RTP / RCS
    (r'\bims\b',                                                           ('IMS', 'Core', 'IMS', 'IP Multimedia Subsystem')),
    (r'\bvolte\b',                                                         ('IMS', 'VoLTE', 'VoLTE', 'Voice over LTE')),
    (r'\bvowifi\b',                                                        ('IMS', 'VoWiFi', 'VoWiFi', 'Voice over WiFi')),
    (r'\bims call\b',                                                      ('IMS', 'Call Control', 'IMS Call', None)),
    (r'\bims sms\b',                                                       ('IMS', 'SMS', 'IMS SMS', None)),
    (r'\bims ua\b',                                                        ('IMS', 'User Agent', 'IMS UA', None)),
    (r'\bsip\b',                                                           ('IMS', 'SIP', 'SIP Message', None)),
    (r'\bsip min-se\b',                                                    ('IMS', 'SIP Headers', 'Min-SE', None)),
    (r'\bsip (?:status line|response line)\b',                             ('IMS', 'SIP Headers', 'Status Line', None)),
    (r'\bsip via\b',                                                       ('IMS', 'SIP Headers', 'Via Header', None)),
    (r'\bsip multipart\b|\bmultipart.*sip\b',                              ('IMS', 'SIP Body', 'Multipart', None)),
    (r'\bsip session-expires\b|\bsession.expires\b',                       ('IMS', 'SIP Headers', 'Session-Expires', None)),
    (r'\bsip retry-after\b|\bretry.after.*sip\b',                          ('IMS', 'SIP Headers', 'Retry-After', None)),
    (r'\bsip uri\b',                                                       ('IMS', 'SIP URI', 'SIP URI', None)),
    (r'\bsdp\b',                                                           ('IMS', 'SDP', 'SDP', 'Session Description Protocol')),
    (r'\bfmtp\b',                                                          ('IMS', 'SDP', 'FMTP', None)),
    (r'\bvideo configuration attribute\b|\bsdp.*video\b',                  ('IMS', 'SDP', 'Video Config', None)),
    (r'\brtcp\b',                                                          ('IMS', 'RTP', 'RTCP', None)),
    (r'\brtp\b',                                                           ('IMS', 'RTP', 'RTP', 'Real-time Transport Protocol')),
    (r'\brcs\b|\brich communication\b',                                    ('IMS', 'RCS', 'RCS', None)),
    (r'\bike\b',                                                           ('IMS', 'VoWiFi', 'IKE', 'Internet Key Exchange')),
    (r'\brp-originator\b|\brp-destination\b',                        ('SMS', 'RP', 'RP Address', 'Originator/Destination')),
    (r'\bcc \(call control\)\b|\bcc module\b',                       ('IMS', 'Call Control', 'CC', 'Call Control Module')),
    (r'\bmm packets?\b',                                             ('4G/LTE', 'NAS', 'MM Packet', 'Mobility Management Packet')),
    (r'\bsecurity mode downgrade\b|\bman-in-the-middle.*downgrade\b', ('IMS', 'Security', 'MITM', 'Security Mode Downgrade')),
    (r'\brp-originator\b|\brp-destination\b',                        ('SMS', 'RP', 'RP Address', 'Originator/Destination')),
    (r'\bcc \(call control\)\b|\bcc module\b',                       ('IMS', 'Call Control', 'CC', 'Call Control Module')),
    (r'\bmm packets?\b',                                             ('4G/LTE', 'NAS', 'MM Packet', 'Mobility Management Packet')),
    (r'\bsecurity mode downgrade\b|\bman-in-the-middle.*downgrade\b', ('IMS', 'Security', 'MITM', 'Security Mode Downgrade')),

    (r'\bwmi_request_stats_cmdid\b',                                 ('Local', 'IPC', 'WMI Command', 'WMI_REQUEST_STATS_CMDID')),
    (r'\bfilter rule\b',                                             ('Local', 'IPC', 'Filter Rule', 'Application Client Filter')),
    (r'\bqmi msg\b',                                                 ('Local', 'IPC', 'QMI', 'QMI Message')),  # Already exists, but keep for completeness

    # Upper Levels — Networking
    (r'\bdns\b',                                                           ('Upper Levels', 'Networking', 'DNS', 'Domain Name System')),
    (r'\bcoap\b',                                                          ('Upper Levels', 'Networking', 'CoAP', 'Constrained Application Protocol')),
    (r'\bppp\b',                                                           ('Upper Levels', 'Networking', 'PPP', 'Point-to-Point Protocol')),
    (r'\bigmp\b',                                                          ('Upper Levels', 'Networking', 'IGMP', 'Internet Group Management Protocol')),
    (r'\bipv4\b|\bip header\b',                                            ('Upper Levels', 'Networking', 'IPv4', None)),
    (r'\bipv6\b',                                                          ('Upper Levels', 'Networking', 'IPv6', None)),
    (r'\btcp\b',                                                           ('Upper Levels', 'Networking', 'TCP', None)),
    (r'\budp\b',                                                           ('Upper Levels', 'Networking', 'UDP', None)),
    (r'\bhttp\b',                                                          ('Upper Levels', 'Networking', 'HTTP', None)),

    # Upper Levels — Security
    (r'\bdtls\b|\bhello-verify\b',                                         ('Upper Levels', 'Security', 'DTLS', 'Datagram TLS')),
    (r'\btls\b',                                                           ('Upper Levels', 'Security', 'TLS', 'Transport Layer Security')),
    (r'\bas security exchange\b|\bas security\b',                          ('Upper Levels', 'Security', 'AS Security', None)),
    # (r'\bciphering key\b',                                                 ('Upper Levels', 'Security', 'Ciphering Key', None)),
    (r'\bigmpv2\b|\bigmp packet\b',                                  ('Upper Levels', 'Networking', 'IGMPv2', 'Packet Parsing')),
    (r'\bip packets? with padding\b',                                ('Upper Levels', 'Networking', 'IPv4/IPv6', 'Padding Handling')),
    (r'\bchecksum of packet\b',                                      ('Upper Levels', 'Networking', 'Checksum', 'Packet Validation')),
    (r'\bpackets? received from local network\b',                    ('Upper Levels', 'Networking', 'Network RX', 'Local Network Packet')),
    # Upper Levels — Diagnostics
    (r'\bdpl\b',                                                           ('Upper Levels', 'Diagnostics', 'DPL', 'Diagnostic Packet Logging')),

    # Local — Hardware / Memory
    (r'\bdma\b',                                                           ('Local', 'Hardware', 'DMA', 'Direct Memory Access')),
    (r'\bdsm\b|\bdsm items\b',                                             ('Local', 'Memory', 'DSM Allocator', None)),

    # Local — IPC
    (r'\bccci\b',                                                          ('Local', 'Inter-Processor', 'CCCI', 'Modem IPC')),
    (r'\bqmi\b',                                                           ('Local', 'IPC', 'QMI', 'Qualcomm MSM Interface')),
    (r'\bwmi\b|\bwmi_request_stats\b',                                     ('Local', 'IPC', 'WMI Interface', None)),
    (r'\bfdal\b',                                                          ('Local', 'IPC', 'FDAL', None)),
    (r'\bmodem interface driver\b',                                        ('Local', 'IPC', 'Modem Interface Driver', None)),
    # Upper Levels — Networking (continued)
    (r'\bnetwork interface\b|\bnetwork interface binding\b',   ('Upper Levels', 'Networking', 'Network Interface', 'Binding / Resource Allocation')),
    (r'\bcfr\b|\bdma buffer release\b', ('Local', 'Hardware', 'CFR', 'DMA Buffer Management')),

    # Local — Diagnostics
    (r'\bdiag\b',                                                          ('Local', 'Diagnostics', 'DIAG', 'Diagnostic Interface')),
    (r'\bftm\b',                                                           ('Local', 'Diagnostics', 'FTM', 'Factory Test Mode')),
    (r'\bhistogram dimension\b|\bmodem stats\b',                           ('Local', 'Diagnostics', 'Modem Stats', None)),
    (r'\bSystem execution privileges needed\b',                           ('Local', 'n/a', 'n/a', None)),
    # Local — Filesystem
    (r'\befs\b',                                                           ('Local', 'Filesystem', 'EFS', 'Embedded File System')),

    # Local — Security
    (r'\bsmmu\b|\bmodem crypto engine\b|\bhypervisor\b',                   ('Local', 'Security', 'SMMU / Crypto Engine', None)),
    (r'\bhlos\b|\bmodem image.*kernel\b|\bmodem owned region\b',           ('Local', 'Security', 'HLOS-Modem Isolation', None)),
    (r'\bmodem segment\b|\bmodem.*authenticat\b',                          ('Local', 'Security', 'Modem Segment Auth', None)),
    (r'\bcryptographic key.*debug\b|\bkey.*modem debug\b',                 ('Local', 'Security', 'Key Leakage', None)),

    # SMS / SIM
    (r'\btp-udhi\b|\btp-ud\b|\budl\b|\bsms tp\b',                         ('SMS', 'TP', 'SMS TP Layer', None)),
    (r'\brp-data\b|\bsms rp\b',                                            ('SMS', 'RP', 'SMS RP Layer', None)),
    (r'\bwms message\b|\braw sms\b',                                       ('SMS', 'WMS', 'SMS Parsing', None)),
    (r'\buim\b',                                                           ('SIM', 'UIM', 'UIM', 'User Identity Module')),
    (r'\bsim\b',                                                           ('SIM', 'SIM', 'SIM', 'Subscriber Identity Module')),
    (r'\bgstk\b',                                                          ('SIM', 'SAT', 'GSTK', 'Generic SIM Toolkit')),
    (r'\bpkcs15\b',                                                        ('SIM', 'File', 'PKCS15', 'SIM File Parsing')),
    (r'\bapdu\b',                                                          ('SIM', 'APDU', 'APDU', 'Smartcard APDU')),
    (r'\busat\b',                                                          ('SIM', 'SAT', 'USAT', None)),
]

IMPACT_PATTERNS = {
    'RCE': [
        r'\bremote code execution\b',
        r'\barbitrary code execution\b',
        r'(?<!no )\bcode execution\b',
        r'\bremote escalation of privilege\b',
    ],
    'PrivEsc': [
        r'\bescalation of privilege\b',
        r'\bprivilege escalation\b',
        r'\belevation of privilege\b',
    ],
    'RCE/DoS': [
        r'\bmemory corruption\b',
        r'\bout[- ]of[- ]bounds write\b', r'\bcwe[-: ]*787\b',
        r'\bcwe[-: ]*119\b', r'\bimproper restriction of operations within the bounds of a memory buffer\b',
        r'\bbuffer overflow\b', r'\bclassic buffer overflow\b', r'\bcwe[-: ]*120\b',
        r'\bheap[- ]based buffer overflow\b', r'\bheap overflow\b', r'\bcwe[-: ]*122\b',
        r'\bstack[- ]based buffer overflow\b', r'\bstack overflow\b', r'\bcwe[-: ]*121\b',
        r'\buse after free\b', r'\buse-after-free\b', r'\bcwe[-: ]*416\b',
        r'\bdouble free\b', r'\bcwe[-: ]*415\b',
        r'\binteger overflow to buffer overflow\b', r'\bcwe[-: ]*680\b',
        r'\bout[- ]of[- ]range pointer offset\b', r'\bcwe[-: ]*823\b',
        r'\bimproper validation of array index\b', r'\bcwe[-: ]*129\b',
        r'\brelease of invalid pointer\b', r'\bcwe[-: ]*763\b',
        r'\barbitrary write\b',
    ],
    'DoS': [
        r'\bdenial of service\b', r'\btransient dos\b',
        r'\breachable assertion\b', r'\bcwe[-: ]*617\b',
        r'\bnull pointer dereference\b', r'\bcwe[-: ]*476\b',
        r'\binfinite loop\b', r'\bloop with unreachable exit condition\b', r'\bcwe[-: ]*835\b',
        r'\buncontrolled resource consumption\b', r'\bcwe[-: ]*400\b',
        r'\ballocation of resources without limits\b', r'\bcwe[-: ]*770\b',
        r'\bbuffer over-read\b', r'\bout[- ]of[- ]bounds read\b', r'\bcwe[-: ]*125\b', r'\bcwe[-: ]*126\b',
        r'\binformation disclosure\b', r'\binformation exposure\b',
        r'\buncaught exception\b', r'\bcwe[-: ]*248\b',
        r'\bimproper authentication\b', r'\bimproper authorization\b', r'\bimproper access control\b',
        r'\bconfiguration\b', r'\bcwe-noinfo\b', r'\bn/a\b',
    ],
}

# IMPACT_ORDER = ['RCE', 'PrivEsc', 'RCE/DoS', 'DoS']

_RCE_CVE_IDS: frozenset = frozenset({
    "CVE-2010-3832", "CVE-2018-4148",
    "CVE-2020-25279", "CVE-2021-25478", "CVE-2021-25479", "CVE-2023-21517",
    "CVE-2023-26072", "CVE-2023-26073", "CVE-2023-26074", "CVE-2023-26075",
    "CVE-2023-26076", "CVE-2023-26496", "CVE-2023-26497", "CVE-2023-26498",
    "CVE-2023-41111", "CVE-2023-41112", "CVE-2023-50807", "CVE-2024-39890",
    "CVE-2025-54329","CVE-2023-24033", ""
    "CVE-2021-32484", "CVE-2021-32485", "CVE-2021-32486", "CVE-2021-32487",
    "CVE-2022-21744", "CVE-2022-20083", "CVE-2024-20082", "CVE-2024-20154",
    "CVE-2025-20708", "CVE-2025-20704", "CVE-2025-20725", "CVE-2025-20726",
    "CVE-2025-20727",
    "CVE-2022-20170",
    "CVE-2022-25682", "CVE-2022-25695", "CVE-2022-25727", "CVE-2022-33259",
    "CVE-2023-22385", "CVE-2023-24852"
})

_EXCLUDED_CVE_IDS: frozenset = frozenset({
    "CVE-2021-25487",
})

import json
import re
import os
import sys
from collections import defaultdict
from datetime import datetime
from math import pi

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# HARDCODED CVE → SUBSYSTEM OVERRIDES
# ─────────────────────────────────────────────────────────────────────────────

_CVE_SUBSYSTEM_MAP: dict[str, list[str]] = {}
for _sub, _ids in _SUBSYSTEM_OVERRIDES.items():
    for _cid in _ids:
        _CVE_SUBSYSTEM_MAP.setdefault(_cid, []).append(_sub)

# ─────────────────────────────────────────────────────────────────────────────
# KEYWORD MAP  (domain-level only; sublayer fields kept for future use)
# ─────────────────────────────────────────────────────────────────────────────

CELLULAR_RATS = {'2G', '3G', '4G/LTE', '5G/NR'}
ALL_ATOMS     = {'2G', '3G', '4G/LTE', '5G/NR', 'IMS', 'SMS', 'SIM', 'Upper Levels', 'Local', 'Multi-RAT', 'Unknown'}

RAT_ORDER_ATOMS = ['2G', '3G', '4G/LTE', '5G/NR', 'IMS', 'SMS', 'SIM', 'Upper Levels', 'Local', 'Multi-RAT', 'Unknown']

# Base colours for atomic subsystems
_ATOM_COLORS = {
    '2G':           '#58a6ff',
    '3G':           '#79c0ff',
    '4G/LTE':       '#56d364',
    '5G/NR':        '#f78166',
    'IMS':          '#ffa657',
    'SMS':          '#ff7b72',
    'SIM':          '#a5d6ff',
    'Upper Levels': '#4fc4cf',
    'Local':        '#8b949e',
    'Unknown':      '#ec019e',
    'Multi-RAT':    '#d4a017',
}

# ─────────────────────────────────────────────────────────────────────────────
# LABEL FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _atoms_from_desc(description: str) -> list[str]:
    """Return sorted list of atomic subsystem labels matched by keywords."""
    if not description:
        return []
    desc_lower = description.lower()
    found = set()
    for pattern, hierarchy in KEYWORD_MAP:
        if re.search(pattern, desc_lower):
            domain = hierarchy[0]
            found.add(domain)

    if not found and classify_impact("", description=description) == "PrivEsc":
        found.add("Local")

    return sorted(found, key=lambda x: RAT_ORDER_ATOMS.index(x) if x in RAT_ORDER_ATOMS else 99)


def get_primary_label(atoms: list[str], cve_id: str = '') -> str:
    """Return the subsystem label for a CVE.
    Single match → that subsystem.
    Multiple matches → 'Multi-RAT'.
    No match → 'Unknown'.
    Hardcoded overrides follow the same rule."""
    if cve_id and cve_id in _CVE_SUBSYSTEM_MAP:
        forced = _CVE_SUBSYSTEM_MAP[cve_id]
        if len(forced) > 1:
            return 'Multi-RAT'
        return forced[0]
    if not atoms:
        return 'Unknown'
    if len(atoms) > 1:
        return 'Multi-RAT'
    return atoms[0]


def get_all_atoms(atoms: list[str], cve_id: str = '') -> list[str]:
    """Return all matched subsystems. Used only by the co-occurrence matrix."""
    if cve_id and cve_id in _CVE_SUBSYSTEM_MAP:
        return sorted(_CVE_SUBSYSTEM_MAP[cve_id],
                      key=lambda x: RAT_ORDER_ATOMS.index(x) if x in RAT_ORDER_ATOMS else 99)
    return atoms if atoms else ['Unknown']


def label_color(label: str) -> str:
    return _ATOM_COLORS.get(label, '#888888')


def build_label_order(raw_data: list[dict]) -> list[str]:
    present = {d['label'] for d in raw_data}
    return [l for l in RAT_ORDER_ATOMS if l in present]

# ─────────────────────────────────────────────────────────────────────────────
# DATA EXTRACTION (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────

def extract_from_malformed(file_path):
    results = []
    with open(file_path, 'r', encoding='utf-8') as f:
        chunk = f.read()
    try:
        data = json.loads(chunk)
        if isinstance(data, dict):
            data = [data]
        for record in data:
            cve_id    = record.get('cveMetadata', {}).get('cveId', 'N/A')
            desc_list = record.get('containers', {}).get('cna', {}).get('descriptions', [])
            adp       = record.get('containers', {}).get('adp', [{}])
            cna       = record.get('containers', {}).get('cna', {})
            if 'problemTypes' not in adp[0].keys():
                impact = cna.get('problemTypes', [{}])[0].get('descriptions', 'n/a') if 'problemTypes' in cna else 'n/a'
            else:
                impact = adp[0].get('problemTypes', [{}])[0].get('descriptions', 'n/a')

            desc_value = next((d['value'] for d in desc_list if d.get('lang') == 'en'), 'N/A')
            date       = record.get('cveMetadata', {}).get('datePublished', {})
            results.append((cve_id, desc_value, impact, date))
    except json.JSONDecodeError:
        print(f"Skipping invalid chunk: {chunk[:100]}...")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# IMPACT CLASSIFICATION (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

IMPACT_ORDER = ['RCE', 'PrivEsc', 'RCE/DoS', 'DoS']


def classify_impact(cwe_text: str, description: str = '', cveid: str = '') -> str:
    if cveid in _EXCLUDED_CVE_IDS:
        return 'PrivEsc'
    if cveid in _RCE_CVE_IDS:
        return 'RCE'
    text = f"{cwe_text} {description}".lower()
    for category in IMPACT_ORDER:
        for pattern in IMPACT_PATTERNS.get(category, []):
            if re.search(pattern, text, re.I):
                return category
    return 'DoS'

# ─────────────────────────────────────────────────────────────────────────────
# TYPST INTEGRATION (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

TYPST_FILE = 'cve_table.typ'
_TYPST_RECORDS: dict = {}

def parse_typst_cves(typst_path: str) -> dict:
    with open(typst_path, 'r', encoding='utf-8') as f:
        content = f.read()
    records = {}
    pattern = re.compile(r'\(\s*id:\s*"([^"]+)"(.*?)\n\s*\)', re.DOTALL)
    field_patterns = {
        'vendor':     re.compile(r'vendor:\s*"((?:[^"\\]|\\.)*)"'),
        'protocol':   re.compile(r'protocol:\s*"((?:[^"\\]|\\.)*)"'),
        'impact':     re.compile(r'impact:\s*"((?:[^"\\]|\\.)*)"'),
        'root_cause': re.compile(r'root_cause:\s*"((?:[^"\\]|\\.)*)"'),
        'fw_range':   re.compile(r'fw_range:\s*"((?:[^"\\]|\\.)*)"'),
        'cvss':       re.compile(r'cvss:\s*"((?:[^"\\]|\\.)*)"'),
    }
    for m in pattern.finditer(content):
        cve_id = m.group(1)
        body   = m.group(2)
        record = {'cve_id': cve_id}
        for field, pat in field_patterns.items():
            fm = pat.search(body)
            record[field] = fm.group(1).strip() if fm else None
        records[cve_id] = record
    return records

def normalise_vendor(raw: str) -> str:
    v = raw.lower()
    if any(x in v for x in ('samsung', 'exynos', 'pixel', 'google')):
        return 'Samsung'
    if 'qualcomm' in v: return 'Qualcomm'
    if 'mediatek' in v: return 'MediaTek'
    if 'unisoc'   in v: return 'Unisoc'
    if 'apple'    in v: return 'Apple'
    return raw

# ─────────────────────────────────────────────────────────────────────────────
# DATA LOADING — each CVE gets exactly ONE label
# ─────────────────────────────────────────────────────────────────────────────

JSON_FILES = {
    'Qualcomm': 'saved_json/cve_qualcomm_clean.json',
    'Samsung':  'saved_json/cve_samsung_clean.json',
    'MediaTek': 'saved_json/cve_mediatek_clean.json',
    'Unisoc':   'saved_json/cve_unisoc_clean.json',
}

def load_raw_data(json_files: dict) -> list:
    raw_data = []
    seen_ids = set()

    for vendor, fnames in json_files.items():
        if isinstance(fnames, str):
            fnames = [fnames]
        for fname in fnames:
            if not os.path.exists(fname):
                print(f"[WARN] {fname} not found — skipping")
                continue
            for cve_id, desc, impact, date_str in extract_from_malformed(fname):
                if not date_str:
                    continue
                try:
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                except Exception:
                    try:
                        dt = datetime.strptime(date_str[:10], '%Y-%m-%d')
                    except Exception:
                        continue

                seen_ids.add(cve_id)
                impact_str = impact[0]['description'] if isinstance(impact, list) and impact else str(impact)

                # Enrich description from Typst if available
                typst = _TYPST_RECORDS.get(cve_id, {})
                protocol = typst.get('protocol', '')
                enriched_desc = f"{protocol}. {desc}".strip('. ') if protocol else desc

                atoms  = _atoms_from_desc(enriched_desc + " " + impact_str)
                # print(atoms)
                label  = get_primary_label(atoms, cve_id)
                all_atoms = get_all_atoms(atoms, cve_id)
                classified = classify_impact(impact_str, enriched_desc, cve_id)

                # Upgrade impact from Typst
                typst_impact = typst.get('impact', '')
                if typst_impact and classified == 'DoS':
                    reclassified = classify_impact('', typst_impact, cve_id)
                    if reclassified != 'DoS':
                        classified = reclassified

                if classified == "RCE":
                    print(all_atoms, cve_id, desc)

                # non memory bugs
                for excluded in ("CWE-327", "CWE-757", "CWE-326", "CWE-295", "CWE-331", "CWE-295", "CWE-285", "CWE-287"):
                    if excluded in impact_str:
                        label = "excluded"

                if "excluded" == label:
                    continue

                # print(impact_str)

                raw_data.append({
                    'cve_id': cve_id,
                    'vendor': vendor,
                    'date':   dt,
                    'year':   dt.year,
                    'month':  dt.strftime('%Y-%m'),
                    'impact': classified,
                    'label':     label,
                    'all_atoms': all_atoms,
                    'desc':   desc,
                    'typst_enrichment': typst,
                })

    # Typst-only CVEs
    for cve_id, typst in _TYPST_RECORDS.items():
        if cve_id in seen_ids:
            continue
        year_match = re.search(r'CVE-(\d{4})-', cve_id)
        if not year_match:
            continue
        year = int(year_match.group(1))
        dt   = datetime(year, 1, 1)
        raw_impact = typst.get('impact', '')
        root_cause = typst.get('root_cause', '')
        desc       = f"{typst.get('protocol', '')}. {root_cause}".strip('. ')
        atoms      = _atoms_from_desc(desc)
        label      = get_primary_label(atoms, cve_id)
        all_atoms  = get_all_atoms(atoms, cve_id)
        classified = classify_impact(root_cause, raw_impact, cve_id)
        vendor     = normalise_vendor(typst.get('vendor', ''))

        # non memory bugs
        for excluded in ("Information Disclosure", "Lack of modern mitigations", "CWE-327", "CWE-757", "CWE-326", "CWE-295", "CWE-331", "CWE-295", "CWE-285", "CWE-287"):
            if excluded in raw_impact:
                label = "excluded"

        if "excluded" == label:
            continue

        print(raw_impact)

        raw_data.append({
            'cve_id': cve_id, 'vendor': vendor, 'date': dt,
            'year': year, 'month': dt.strftime('%Y-%m'),
            'impact': classified, 'label': label, 'all_atoms': all_atoms,
            'desc': desc, 'typst_enrichment': typst, '_typst_only': True,
        })

    typst_only = sum(1 for d in raw_data if d.get('_typst_only'))
    print(f"  + {typst_only} Typst-only CVEs added")
    return raw_data

# ─────────────────────────────────────────────────────────────────────────────
# STYLE
# ─────────────────────────────────────────────────────────────────────────────

DARK_BG   = '#0d1117'
PANEL_BG  = '#161b22'
GRID_COL  = '#21262d'
TEXT_COL  = '#e6edf3'
MUTED_COL = '#8b949e'

IMPACT_COLORS = {
    'RCE':     '#ff4d4d',
    'PrivEsc': '#bf00ff',
    'RCE/DoS': '#ff9900',
    'DoS':     '#3fb950',
}
VENDOR_COLORS = {
    'Qualcomm': '#58a6ff',
    'Samsung':  '#3fb950',
    'MediaTek': '#f78166',
    'Unisoc':   '#4400ff',
    'Apple':    '#aaaaaa',
}

plt.rcParams.update({'font.family': 'monospace', 'figure.facecolor': DARK_BG, 'text.color': TEXT_COL})

def style_ax(ax, title=''):
    ax.set_facecolor(PANEL_BG)
    ax.tick_params(colors=MUTED_COL, labelsize=8)
    ax.xaxis.label.set_color(MUTED_COL)
    ax.yaxis.label.set_color(MUTED_COL)
    ax.title.set_color(TEXT_COL)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID_COL)
    ax.grid(color=GRID_COL, linewidth=0.5, linestyle='--')
    if title:
        pass #ax.set_title(title, fontsize=11, pad=8)

def legend_kwargs():
    return dict(framealpha=0.2, facecolor=PANEL_BG, edgecolor=GRID_COL, labelcolor=TEXT_COL)

def jan_axis(months_sorted):
    ticks  = [i for i, m in enumerate(months_sorted) if m.endswith('-01')]
    labels = [m[:4] for m in months_sorted if m.endswith('-01')]
    return ticks, labels


# ─────────────────────────────────────────────────────────────────────────────
# CHARTS — all use record['label'] as a single atomic key
# ─────────────────────────────────────────────────────────────────────────────

def plot_month_impact(raw_data, months_sorted, impact_types, output='pic/cve_by_month_impact.png'):
    month_impact = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        month_impact[d['month']][d['impact']] += 1

    x = np.arange(len(months_sorted))
    fig, ax = plt.subplots(figsize=(14, 5))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, 'CVEs per Month — by Impact Classification')
    bottoms = np.zeros(len(months_sorted))
    for imp in impact_types:
        vals = np.array([month_impact[m][imp] for m in months_sorted], dtype=float)
        ax.bar(x, vals, bottom=bottoms, color=IMPACT_COLORS[imp], label=imp, width=0.8)
        bottoms += vals
    ax.set_xticks(x)
    ax.set_xticklabels(months_sorted, rotation=60, ha='right', fontsize=7)
    ax.set_ylabel('CVE Count')
    ax.legend(**legend_kwargs())
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


def plot_year_label(raw_data, years_sorted, labels_ordered, output='pic/cve_by_year_rat.png'):
    """Stacked bar chart per year by subsystem. Each CVE counted exactly once."""
    year_label = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        year_label[d['year']][d['label']] += 1

    x = np.arange(len(years_sorted))
    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, 'CVEs per Year by Subsystem')

    from matplotlib.patches import Patch
    legend_handles = []
    bottoms = np.zeros(len(years_sorted))
    for lbl in labels_ordered:
        vals = np.array([year_label[y].get(lbl, 0) for y in years_sorted], dtype=float)
        col  = label_color(lbl)
        ax.bar(x, vals, bottom=bottoms, color=col, width=0.6)
        legend_handles.append(Patch(facecolor=col, label=lbl))
        bottoms += vals

    ax.legend(handles=legend_handles, **legend_kwargs(), loc='upper left', fontsize=7, ncol=2)
    ax.set_xticks(x)
    ax.set_xticklabels([str(y) for y in years_sorted], fontsize=9)
    ax.set_ylabel('CVE Count')
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")
    return year_label


def plot_heatmap_label_year(year_label, labels_ordered, years_sorted, output='pic/cve_heatmap_rat_year.png'):
    heatmap = np.zeros((len(labels_ordered), len(years_sorted)), dtype=int)
    for ri, lbl in enumerate(labels_ordered):
        for yi, yr in enumerate(years_sorted):
            heatmap[ri, yi] = year_label[yr][lbl]

    fig, ax = plt.subplots(figsize=(10, max(5, len(labels_ordered) * 0.5)))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(PANEL_BG)
    # ax.set_title('Heatmap: Subsystem vs Year (each CVE counted once)', color=TEXT_COL, fontsize=11, pad=8)
    im   = ax.imshow(heatmap, aspect='auto', cmap='YlOrRd', interpolation='nearest')
    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.ax.yaxis.set_tick_params(color=MUTED_COL)
    cbar.outline.set_edgecolor(GRID_COL)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=MUTED_COL, fontsize=8)
    ax.set_xticks(range(len(years_sorted)))
    ax.set_xticklabels([str(y) for y in years_sorted], color=MUTED_COL, fontsize=8)
    ax.set_yticks(range(len(labels_ordered)))
    ax.set_yticklabels(labels_ordered, color=MUTED_COL, fontsize=8)
    thresh = heatmap.max() * 0.5
    for ri in range(len(labels_ordered)):
        for yi in range(len(years_sorted)):
            val = heatmap[ri, yi]
            if val:
                ax.text(yi, ri, str(val), ha='center', va='center',
                        fontsize=7, color='white' if val > thresh else '#333')
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID_COL)
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


def plot_impact_by_vendor(raw_data, vendors, impact_types, output='pic/cve_impact_by_vendor.png'):
    fig, axes = plt.subplots(1, len(vendors), figsize=(5 * len(vendors), 4))
    fig.patch.set_facecolor(DARK_BG)
    if len(vendors) == 1:
        axes = [axes]
    for ax, vendor in zip(axes, vendors):
        style_ax(ax, vendor)
        vcves  = [d for d in raw_data if d['vendor'] == vendor]
        counts = {imp: sum(1 for d in vcves if d['impact'] == imp) for imp in impact_types}
        total  = sum(counts.values()) or 1
        bars   = ax.barh(impact_types, [counts[i] / total * 100 for i in impact_types],
                         color=[IMPACT_COLORS[i] for i in impact_types], height=0.5)
        ax.set_xlim(0, 100)
        ax.set_xlabel('% of CVEs')
        for bar, imp in zip(bars, impact_types):
            pct = counts[imp] / total * 100
            ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                    f'{pct:.1f}%  (n={counts[imp]})', va='center', fontsize=8, color=TEXT_COL)
        ax.set_title(f'{vendor}\n({len(vcves)} CVEs)', color=TEXT_COL, fontsize=10)
    # fig.suptitle('Impact Distribution by Vendor', color=TEXT_COL, fontsize=12, y=1.02)
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


def plot_vendor_trend(raw_data, vendors, months_sorted, output='pic/cve_trend_by_vendor.png'):
    vendor_month = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        vendor_month[d['vendor']][d['month']] += 1
    ticks, labels_x = jan_axis(months_sorted)
    x = np.arange(len(months_sorted))
    fig, ax = plt.subplots(figsize=(16, 5))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, 'Monthly CVE Count per Vendor')
    for vendor in vendors:
        vals  = [vendor_month[vendor].get(m, 0) for m in months_sorted]
        color = VENDOR_COLORS.get(vendor, '#aaaaaa')
        ax.plot(x, vals, label=vendor, color=color, linewidth=2,
                marker='o', markersize=2.5, markerfacecolor=color, alpha=0.9)
        ax.fill_between(x, vals, alpha=0.07, color=color)
    for pos in ticks:
        ax.axvline(pos, color=GRID_COL, linewidth=0.6, linestyle='--', alpha=0.6)
    ax.set_xticks(ticks)
    ax.set_xticklabels(labels_x, fontsize=9)
    ax.set_ylabel('CVE Count')
    ax.legend(**legend_kwargs())
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")
    return vendor_month


def plot_cumulative_growth(vendor_month, vendors, months_sorted, output='pic/cve_cumulative_growth.png'):
    ticks, labels_x = jan_axis(months_sorted)
    x = np.arange(len(months_sorted))
    fig, ax = plt.subplots(figsize=(16, 5))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, 'Cumulative CVE Discovery per Vendor')
    for pos in ticks:
        ax.axvline(pos, color=GRID_COL, linewidth=0.6, linestyle='--', alpha=0.6)
    for vendor in vendors:
        monthly    = [vendor_month[vendor].get(m, 0) for m in months_sorted]
        cumulative = np.cumsum(monthly)
        color      = VENDOR_COLORS.get(vendor, '#aaaaaa')
        ax.plot(x, cumulative, label=vendor, color=color, linewidth=2.5)
        ax.fill_between(x, cumulative, alpha=0.06, color=color)
        ax.annotate(f"{vendor}  {int(cumulative[-1])}",
                    xy=(x[-1], cumulative[-1]), xytext=(6, 0),
                    textcoords='offset points', color=color,
                    fontsize=8, va='center', fontfamily='monospace')
    ax.set_xticks(ticks)
    ax.set_xticklabels(labels_x, fontsize=9)
    ax.set_ylabel('Cumulative CVEs')
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(**legend_kwargs())
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


def plot_bubble_timeline(raw_data, months_sorted, impact_types, output='pic/cve_bubble_timeline.png'):
    month_impact   = defaultdict(lambda: defaultdict(int))
    severity_order = {imp: i for i, imp in enumerate(impact_types)}
    for d in raw_data:
        month_impact[d['month']][d['impact']] += 1
    x = np.arange(len(months_sorted))
    sizes, colors = [], []
    for m in months_sorted:
        imp_counts = month_impact[m]
        total = sum(imp_counts.values())
        if total == 0:
            sizes.append(0); colors.append('#6e7681'); continue
        dominant = max(imp_counts.items(), key=lambda kv: (kv[1], -severity_order[kv[0]]))[0]
        sizes.append(total)
        colors.append(IMPACT_COLORS.get(dominant, '#aaaaaa'))
    scale_factor = 200 / np.sqrt(max(sizes) if sizes else 1)
    radii = [np.sqrt(s) * scale_factor for s in sizes]
    fig, ax = plt.subplots(figsize=(16, 5))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, 'Monthly CVE Volume & Dominant Impact')
    ax.scatter(x, [1] * len(months_sorted), s=radii, c=colors,
               alpha=0.8, edgecolors='white', linewidth=0.5)
    ax.set_ylim(0.5, 1.5)
    ax.set_yticks([])
    ax.set_xticks(x)
    ax.set_xticklabels(months_sorted, rotation=60, ha='right', fontsize=7)
    ax.set_xlabel('Month')
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(facecolor=IMPACT_COLORS[imp], label=imp) for imp in impact_types],
              loc='upper left', **legend_kwargs())
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


def plot_vendor_radar(raw_data, vendors, labels_ordered, output='pic/cve_radar_vendor.png'):
    """Radar chart with log-scaled radial axis so small subsystems remain readable.
    Counts are normalised per vendor then mapped via log1p so the shape shows
    relative specialisation while log expansion spreads out low values."""
    atoms_only = [l for l in RAT_ORDER_ATOMS if l not in ('Unknown', 'Multi-RAT')]
    n = len(atoms_only)
    if n < 3:
        return

    vendor_atom = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        for p in d['all_atoms']:
            if p in ALL_ATOMS:
                vendor_atom[d['vendor']][p] += 1

    angles = [i / float(n) * 2 * pi for i in range(n)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(DARK_BG)

    # compute global log max so all vendors share the same radial scale
    all_log_vals = []
    for vendor in vendors:
        total = sum(vendor_atom[vendor].values()) or 1
        all_log_vals += [np.log1p(vendor_atom[vendor].get(a, 0) / total * 100)
                         for a in atoms_only]
    log_max = max(all_log_vals) if all_log_vals else 1.0

    for vendor in vendors:
        total = sum(vendor_atom[vendor].values())
        if total == 0:
            continue
        raw  = [vendor_atom[vendor].get(a, 0) / total * 100 for a in atoms_only]
        vals = [np.log1p(v) / log_max for v in raw]
        vals += vals[:1]
        color = VENDOR_COLORS.get(vendor, '#aaaaaa')
        ax.plot(angles, vals, linewidth=2, color=color, label=vendor)
        ax.fill(angles, vals, alpha=0.1, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(atoms_only, fontsize=9, color=MUTED_COL)
    ax.set_ylim(0, 1)

    # radial grid lines at meaningful percentage thresholds
    pct_ticks = [1, 5, 10, 25, 50]
    r_ticks   = [np.log1p(p) / log_max for p in pct_ticks]
    r_labels  = [str(p) + '%' for p in pct_ticks]
    ax.set_yticks(r_ticks)
    ax.set_yticklabels(r_labels, fontsize=7, color=MUTED_COL)

    ax.legend(loc='upper right', bbox_to_anchor=(1.2, 1.0), **legend_kwargs())
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


def plot_alluvial(raw_data, labels_ordered, impact_types, output='pic/cve_rat_impact_flow.png'):
    """Horizontal stacked bars by impact. Each CVE counted exactly once in its label."""
    label_impact = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        label_impact[d['label']][d['impact']] += 1

    labels = [l for l in labels_ordered if sum(label_impact[l].values()) > 0]
    totals = [sum(label_impact[l].values()) for l in labels]
    idx    = np.argsort(totals)[::-1]
    labels = [labels[i] for i in idx]
    totals = [totals[i] for i in idx]

    fig, ax = plt.subplots(figsize=(11, max(6, len(labels) * 0.5)))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, 'Impact Breakdown per Subsystem')

    left = np.zeros(len(labels))
    for imp in impact_types:
        vals = np.array([label_impact[l].get(imp, 0) for l in labels], dtype=float)
        ax.barh(labels, vals, left=left, color=IMPACT_COLORS[imp], label=imp, height=0.6)
        left += vals

    ax.set_xlabel('Number of CVEs')
    ax.legend(**legend_kwargs())
    for i, total in enumerate(totals):
        if total > 0:
            ax.text(total + 0.5, i, str(total), va='center', fontsize=8, color=TEXT_COL)
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")



def plot_cooccurrence(raw_data, labels_ordered, output='pic/cve_protocol_cooccurrence.png'):
    """
    Co-occurrence matrix built from record['all_atoms'], so every subsystem
    pair a CVE belongs to is captured, even though that CVE appears in only
    one bucket in every other chart.
    """
    from itertools import combinations
    label_index = {l: i for i, l in enumerate(labels_ordered)}
    n = len(labels_ordered)
    cooccur = np.zeros((n, n), dtype=int)

    for d in raw_data:
        atoms_in_cve = [a for a in d['all_atoms'] if a in label_index]
        for a in atoms_in_cve:
            cooccur[label_index[a], label_index[a]] += 1
        for a1, a2 in combinations(sorted(atoms_in_cve), 2):
            i, j = label_index[a1], label_index[a2]
            cooccur[i, j] += 1
            cooccur[j, i] += 1

    fig, ax = plt.subplots(figsize=(max(9, n * 0.8), max(7, n * 0.7)))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(PANEL_BG)
    im   = ax.imshow(cooccur, aspect='auto', cmap='Blues', interpolation='nearest')
    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.ax.yaxis.set_tick_params(color=MUTED_COL)
    cbar.outline.set_edgecolor(GRID_COL)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=MUTED_COL, fontsize=8)
    ax.set_xticks(range(n))
    ax.set_xticklabels(labels_ordered, rotation=45, ha='right', color=MUTED_COL, fontsize=8)
    ax.set_yticks(range(n))
    ax.set_yticklabels(labels_ordered, color=MUTED_COL, fontsize=8)
    thresh = cooccur.max() * 0.5
    for i in range(n):
        for j in range(n):
            val = cooccur[i, j]
            if val:
                ax.text(j, i, str(val), ha='center', va='center',
                        fontsize=7, color='white' if val > thresh else '#333')
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID_COL)
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")

def print_chart_percentages(raw_data, labels_ordered, impact_types, vendors):
    """Print percentage breakdowns for each chart category to stdout."""
    from collections import defaultdict
 
    total = len(raw_data)
    sep   = '-' * 60
 
    # ── 1. By subsystem label ────────────────────────────────────────────────
    print(sep)
    print("CVEs BY SUBSYSTEM")
    print(sep)
    label_counts = defaultdict(int)
    for d in raw_data:
        label_counts[d['label']] += 1
    for lbl in labels_ordered:
        n = label_counts.get(lbl, 0)
        print(f"  {lbl:<18}  {n:>4}  ({n/total*100:5.1f}%)")
    print(f"  {'TOTAL':<18}  {total:>4}")
 
    # ── 2. By impact ─────────────────────────────────────────────────────────
    print()
    print(sep)
    print("CVEs BY IMPACT")
    print(sep)
    impact_counts = defaultdict(int)
    for d in raw_data:
        impact_counts[d['impact']] += 1
    for imp in impact_types:
        n = impact_counts.get(imp, 0)
        print(f"  {imp:<18}  {n:>4}  ({n/total*100:5.1f}%)")
 
    # ── 3. By vendor ─────────────────────────────────────────────────────────
    print()
    print(sep)
    print("CVEs BY VENDOR")
    print(sep)
    vendor_counts = defaultdict(int)
    for d in raw_data:
        vendor_counts[d['vendor']] += 1
    for v in vendors:
        n = vendor_counts.get(v, 0)
        print(f"  {v:<18}  {n:>4}  ({n/total*100:5.1f}%)")
 
    # ── 4. Impact breakdown per subsystem ────────────────────────────────────
    print()
    print(sep)
    print("IMPACT BREAKDOWN PER SUBSYSTEM")
    print(sep)
    label_impact = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        label_impact[d['label']][d['impact']] += 1
    header = f"  {'Subsystem':<18}" + "".join(f"  {imp:>10}" for imp in impact_types) + f"  {'Total':>6}"
    print(header)
    for lbl in labels_ordered:
        n_total = sum(label_impact[lbl].values())
        if n_total == 0:
            continue
        row = f"  {lbl:<18}"
        for imp in impact_types:
            n = label_impact[lbl].get(imp, 0)
            row += f"  {n:>4}({n/n_total*100:4.0f}%)"
        row += f"  {n_total:>6}"
        print(row)
 
    # ── 5. Impact breakdown per vendor ───────────────────────────────────────
    print()
    print(sep)
    print("IMPACT BREAKDOWN PER VENDOR")
    print(sep)
    vendor_impact = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        vendor_impact[d['vendor']][d['impact']] += 1
    print(header.replace('Subsystem', 'Vendor   '))
    for v in vendors:
        n_total = sum(vendor_impact[v].values())
        if n_total == 0:
            continue
        row = f"  {v:<18}"
        for imp in impact_types:
            n = vendor_impact[v].get(imp, 0)
            row += f"  {n:>4}({n/n_total*100:4.0f}%)"
        row += f"  {n_total:>6}"
        print(row)
 
    # ── 6. Subsystem breakdown per vendor ────────────────────────────────────
    print()
    print(sep)
    print("SUBSYSTEM BREAKDOWN PER VENDOR")
    print(sep)
    vendor_label = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        vendor_label[d['vendor']][d['label']] += 1
    for v in vendors:
        v_total = sum(vendor_label[v].values())
        if v_total == 0:
            continue
        print(f"  {v}  (n={v_total})")
        for lbl in labels_ordered:
            n = vendor_label[v].get(lbl, 0)
            if n == 0:
                continue
            print(f"    {lbl:<18}  {n:>4}  ({n/v_total*100:5.1f}%)")
 
    # ── 7. Year totals ───────────────────────────────────────────────────────
    print()
    print(sep)
    print("CVEs BY YEAR")
    print(sep)
    year_counts = defaultdict(int)
    for d in raw_data:
        year_counts[d['year']] += 1
    for yr in sorted(year_counts):
        n = year_counts[yr]
        print(f"  {yr}  {n:>4}  ({n/total*100:5.1f}%)")
 
    # ── 8. Monthly CVE count by impact  [mirrors plot_month_impact] ──────────
    print()
    print(sep)
    print("CVEs BY MONTH × IMPACT  (mirrors: cve_by_month_impact.png)")
    print(sep)
    month_impact = defaultdict(lambda: defaultdict(int))
    all_months   = sorted({d['month'] for d in raw_data})
    for d in raw_data:
        month_impact[d['month']][d['impact']] += 1
    imp_header = f"  {'Month':<10}" + "".join(f"  {imp:>10}" for imp in impact_types) + f"  {'Total':>6}"
    print(imp_header)
    for m in all_months:
        m_total = sum(month_impact[m].values())
        row = f"  {m:<10}"
        for imp in impact_types:
            n = month_impact[m].get(imp, 0)
            row += f"  {n:>4}({n/m_total*100:4.0f}%)" if m_total else f"  {'':>9}"
        row += f"  {m_total:>6}"
        print(row)
 
    # ── 9. Monthly CVE count per vendor  [mirrors plot_vendor_trend] ─────────
    print()
    print(sep)
    print("CVEs BY MONTH × VENDOR  (mirrors: cve_trend_by_vendor.png)")
    print(sep)
    vendor_month_counts = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        vendor_month_counts[d['vendor']][d['month']] += 1
    vendors_sorted = sorted({d['vendor'] for d in raw_data})
    vhdr = f"  {'Month':<10}" + "".join(f"  {v:>12}" for v in vendors_sorted)
    print(vhdr)
    for m in all_months:
        row = f"  {m:<10}"
        for v in vendors_sorted:
            n      = vendor_month_counts[v].get(m, 0)
            v_tot  = sum(vendor_month_counts[v].values()) or 1
            row   += f"  {n:>4}({n/v_tot*100:4.0f}%)"
        print(row)
 
    # ── 10. Subsystem × year heatmap  [mirrors plot_heatmap_label_year] ──────
    print()
    print(sep)
    print("SUBSYSTEM × YEAR  (mirrors: cve_heatmap_rat_year.png)")
    print(sep)
    year_label_counts = defaultdict(lambda: defaultdict(int))
    years_sorted = sorted({d['year'] for d in raw_data})
    for d in raw_data:
        year_label_counts[d['year']][d['label']] += 1
    yr_header = f"  {'Subsystem':<18}" + "".join(f"  {str(yr):>8}" for yr in years_sorted)
    print(yr_header)
    for lbl in labels_ordered:
        row_vals = [year_label_counts[yr].get(lbl, 0) for yr in years_sorted]
        if not any(row_vals):
            continue
        row = f"  {lbl:<18}"
        for yr, n in zip(years_sorted, row_vals):
            yr_total = sum(year_label_counts[yr].values()) or 1
            row += f"  {n:>3}({n/yr_total*100:3.0f}%)"
        print(row)
 
    # ── 11. Monthly CVE count per subsystem ──────────────────────────────────
    print()
    print(sep)
    print("CVEs BY MONTH × SUBSYSTEM")
    print(sep)
    month_label = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        month_label[d['month']][d['label']] += 1
    ml_header = f"  {'Month':<10}" + "".join(f"  {lbl:>14}" for lbl in labels_ordered) + f"  {'Total':>6}"
    print(ml_header)
    for m in all_months:
        m_total = sum(month_label[m].values())
        if m_total == 0:
            continue
        row = f"  {m:<10}"
        for lbl in labels_ordered:
            n = month_label[m].get(lbl, 0)
            row += f"  {n:>4}({n/m_total*100:4.0f}%)" if m_total else f"  {'':>13}"
        row += f"  {m_total:>6}"
        print(row)
 
    # ── 12. Bubble timeline — monthly totals + dominant impact ──────────────
    #        [mirrors plot_bubble_timeline]
    print()
    print(sep)
    print("MONTHLY TOTALS + DOMINANT IMPACT  (mirrors: cve_bubble_timeline.png)")
    print(sep)
    severity_order = {imp: i for i, imp in enumerate(impact_types)}
    print(f"  {'Month':<10}  {'Total':>5}  {'Dominant Impact':<12}")
    for m in all_months:
        imp_counts = month_impact[m]
        m_total    = sum(imp_counts.values())
        if m_total == 0:
            continue
        dominant = max(
            imp_counts.items(),
            key=lambda kv: (kv[1], -severity_order[kv[0]])
        )[0]
        print(f"  {m:<10}  {m_total:>5}  {dominant:<12}")
 
    # ── 13. Subsystem % per vendor from all_atoms  [mirrors plot_subsystem_per_vendor] ──
    print()
    print(sep)
    print("SUBSYSTEM % PER VENDOR — atom-level  (mirrors: cve_subsystem_per_vendor.png)")
    print(sep)
    atom_counts  = defaultdict(lambda: defaultdict(int))
    all_subs_set = list(labels_ordered) + ['Unknown']
    for d in raw_data:
        for atom in d['all_atoms']:
            if atom in all_subs_set:
                atom_counts[d['vendor']][atom] += 1
    atom_totals = {v: sum(atom_counts[v].values()) or 1 for v in vendors_sorted}
    for v in vendors_sorted:
        v_total = atom_totals[v]
        print(f"  {v}  (atom-hits={v_total})")
        for sub in all_subs_set:
            n = atom_counts[v].get(sub, 0)
            if n == 0:
                continue
            print(f"    {sub:<18}  {n:>4}  ({n/v_total*100:5.1f}%)")
 
    print(sep)


def plot_subsystem_per_vendor(raw_data, vendors, labels_ordered,
                               output='pic/cve_subsystem_per_vendor.png'):
    """
    Stacked 100% horizontal bar — one bar per vendor.
    Segments: one per known subsystem (all_atoms) + one 'Unknown' segment.
    A CVE tagged to multiple subsystems is counted in each, so the
    percentages are relative to the total atom-hits for that vendor
    (not the CVE count), making cross-vendor proportions comparable.
    """
    subsystems_known = list(labels_ordered)   # Unknown excluded by build_label_order
    all_subs = subsystems_known + ['Unknown']

    # ── counts: vendor → subsystem → n (from all_atoms) ──────────────────
    counts = defaultdict(lambda: defaultdict(int))
    for d in raw_data:
        for atom in d['all_atoms']:
            if atom in all_subs:
                counts[d['vendor']][atom] += 1

    # denominator = total atom-hits per vendor (not unique CVEs)
    totals = {v: sum(counts[v].values()) or 1 for v in vendors}

    # ── figure ────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, max(3, len(vendors) * 0.9 + 1.2)))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, '')

    y = np.arange(len(vendors))
    bar_h = 0.55

    lefts = np.zeros(len(vendors))

    from matplotlib.patches import Patch
    legend_handles = []

    for sub in subsystems_known:
        color = _ATOM_COLORS.get(sub, '#888888')
        pcts  = np.array([counts[v][sub] / totals[v] * 100 for v in vendors])

        ax.barh(y, pcts, left=lefts, height=bar_h,
                color=color, edgecolor=DARK_BG, linewidth=0.4)

        # label inside segment if wide enough
        for yi, (pct, left) in enumerate(zip(pcts, lefts)):
            if pct >= 4.5:
                ax.text(left + pct / 2, yi, f'{pct:.0f}%',
                        ha='center', va='center',
                        fontsize=6.5, color='white', fontweight='bold')

        legend_handles.append(Patch(facecolor=color, label=sub))
        lefts += pcts

    # Unknown segment — always last, distinct pink
    unknown_color = _ATOM_COLORS.get('Unknown', '#ec019e')
    pcts_unk = np.array([counts[v]['Unknown'] / totals[v] * 100 for v in vendors])
    ax.barh(y, pcts_unk, left=lefts, height=bar_h,
            color=unknown_color, edgecolor=DARK_BG, linewidth=0.4,
            hatch='//', alpha=0.85)
    for yi, (pct, left) in enumerate(zip(pcts_unk, lefts)):
        if pct >= 4.5:
            ax.text(left + pct / 2, yi, f'{pct:.0f}%',
                    ha='center', va='center',
                    fontsize=6.5, color='white', fontweight='bold')
    legend_handles.append(
        Patch(facecolor=unknown_color, hatch='//', edgecolor='white',
              linewidth=0.4, label='Unknown'))

    # ── axes ──────────────────────────────────────────────────────────────
    ax.set_xlim(0, 100)
    ax.set_xticks(range(0, 101, 10))
    ax.set_xticklabels([f'{x}%' for x in range(0, 101, 10)],
                       fontsize=8, color=MUTED_COL)
    ax.set_yticks(y)
    ax.set_yticklabels(vendors, fontsize=10)
    for tick, vendor in zip(ax.get_yticklabels(), vendors):
        tick.set_color(VENDOR_COLORS.get(vendor, TEXT_COL))

    ax.invert_yaxis()
    ax.set_xlabel('% of subsystem tags  (multi-label CVEs counted per tag)',
                  color=MUTED_COL, fontsize=8)

    # total CVE count annotation at right edge
    cve_counts = defaultdict(set)
    for d in raw_data:
        cve_counts[d['vendor']].add(d['cve_id'])
    for yi, vendor in enumerate(vendors):
        n = len(cve_counts[vendor])
        ax.text(101, yi, f'n={n}', ha='left', va='center',
                fontsize=7.5, color=MUTED_COL)

    ax.legend(handles=legend_handles, **legend_kwargs(),
              loc='lower center', bbox_to_anchor=(0.5, -0.22),
              ncol=6, fontsize=7.5,
              title='Subsystem', title_fontsize=7.5)

    fig.suptitle('Subsystem distribution per vendor  (% of subsystem tags)',
                 color=TEXT_COL, fontsize=10, y=1.01)

    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f'Saved: {output}')

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

import csv
def plot_sublabels_within_rat(raw_data, output='pic/cve_sublabels_within_rat.png'):
    """
    For each top-level RAT/domain (4G/LTE, IMS, 2G, ...), break down the
    CVEs into their fine-grained sublayer/component labels as matched by
    KEYWORD_MAP — e.g. within 4G/LTE: NAS, RRC, PDCP, L2, OMA-DM, ...;
    within IMS: VoLTE, SIP, SDP, RTP, VoWiFi, ...; within 2G: GPRS,
    Access Stratum (RR/RRM), Provisioning (OTASP), ...
 
    Unlike all_atoms (which only tracks top-level domains for the
    Multi-RAT/co-occurrence logic), this uses the new 'sublabels' field
    captured directly from the KEYWORD_MAP hierarchy tuples, so it shows
    real protocol/component names rather than just domain names.
 
    One horizontal 100%-stacked bar per RAT. Bars include every RAT that
    has at least one matched sublabel (a CVE can contribute to multiple
    RATs at once if it matched patterns from more than one domain — same
    as how Multi-RAT is computed elsewhere, but here we don't collapse
    to a single 'Multi-RAT' bucket; each domain gets its own bar).
 
    Dumps two TSVs:
      - cve_sublabels_within_rat.tsv            : RAT × sublabel matrix
      - cve_sublabels_within_rat_top_terms.tsv  : flat ranked list of every
                                                    (RAT, sublabel) pair with count
    """
    # rat -> sublabel -> count (counts CVEs, deduplicated per CVE per pair)
    rat_sub = defaultdict(lambda: defaultdict(int))
 
    n_with_sublabels = sum(1 for d in raw_data if d.get('label'))
    print(f"[plot_sublabels_within_rat] {n_with_sublabels}/{len(raw_data)} "
          f"records have a non-empty 'sublabels' field")
    if n_with_sublabels == 0:
        print("[plot_sublabels_within_rat] WARNING: no records have 'sublabels' — "
              "check that load_raw_data is populating it (see _sublabels_from_desc / "
              "get_all_sublabels). Skipping chart + TSV.")
        return
 
    for d in raw_data:
        seen_pairs_this_cve = set()
        for (domain, sub) in d.get('label', []):
            if (domain, sub) in seen_pairs_this_cve:
                continue
            seen_pairs_this_cve.add((domain, sub))
            rat_sub[domain][sub] += 1
 
    rats = [r for r in RAT_ORDER_ATOMS if r in rat_sub and r not in ('Multi-RAT',)]
    rat_totals = {r: sum(rat_sub[r].values()) for r in rats}
    rats = sorted(rats, key=lambda r: rat_totals[r], reverse=True)
 
    if not rats:
        print("[plot_sublabels_within_rat] WARNING: 'sublabels' was present but "
              "produced no RAT buckets after filtering. Skipping chart + TSV.")
        return
 
    # ── Dump TSV #1: RAT × sublabel matrix ──────────────────────────────────
    all_sublabels_per_rat = {r: sorted(rat_sub[r].keys(), key=lambda s: -rat_sub[r][s]) for r in rats}
    tsv_path = output.replace('.png', '.tsv')
    with open(tsv_path, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow(['RAT', 'Sublabel', 'Count', 'PctWithinRAT'])
        for r in rats:
            total = rat_totals[r]
            for sub in all_sublabels_per_rat[r]:
                n = rat_sub[r][sub]
                writer.writerow([r, sub, n, f"{n / total * 100:.1f}"])
    print(f"Saved: {tsv_path}")
 
    # ── Dump TSV #2: flat ranked list across all RATs ───────────────────────
    top_terms_path = output.replace('.png', '_top_terms.tsv')
    flat = []
    for r in rats:
        for sub, n in rat_sub[r].items():
            flat.append((r, sub, n))
    flat.sort(key=lambda x: -x[2])
    with open(top_terms_path, 'w', newline='') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow(['RAT', 'Sublabel', 'Count'])
        for r, sub, n in flat:
            writer.writerow([r, sub, n])
    print(f"Saved: {top_terms_path}")
 
    # ── Figure ───────────────────────────────────────────────────────────────
    # Distinct color per sublabel within a RAT (cycled), legend grouped per RAT
    cmap_cycle = plt.cm.tab20.colors + plt.cm.tab20b.colors
 
    fig, ax = plt.subplots(figsize=(12, max(4, len(rats) * 0.75 + 1.6)))
    fig.patch.set_facecolor(DARK_BG)
    style_ax(ax, '')
 
    y     = np.arange(len(rats))
    bar_h = 0.58
 
    for yi, r in enumerate(rats):
        total = rat_totals[r]
        subs_sorted = all_sublabels_per_rat[r]
        left = 0.0
        for ci, sub in enumerate(subs_sorted):
            n = rat_sub[r][sub]
            pct = n / total * 100
            color = cmap_cycle[ci % len(cmap_cycle)]
            ax.barh(yi, pct, left=left, height=bar_h,
                    color=color, edgecolor=DARK_BG, linewidth=0.4)
            if pct >= 6.0:
                ax.text(left + pct / 2, yi, sub,
                        ha='center', va='center', fontsize=6.3,
                        color='white', fontweight='bold', rotation=0)
            left += pct
 
    # right-side: CVE count + top 3 sublabels as text
    for yi, r in enumerate(rats):
        top3 = sorted(rat_sub[r].items(), key=lambda x: -x[1])[:3]
        top3_str = ', '.join(f"{s}:{n}" for s, n in top3)
        ax.text(101.5, yi, f"n={rat_totals[r]}  ({top3_str})",
                ha='left', va='center', fontsize=6.5, color=MUTED_COL)
 
    ax.set_xlim(0, 100)
    ax.set_xticks(range(0, 101, 10))
    ax.set_xticklabels([f'{x}%' for x in range(0, 101, 10)], fontsize=8, color=MUTED_COL)
    ax.set_yticks(y)
    ax.set_yticklabels(rats, fontsize=9)
    for tick, r in zip(ax.get_yticklabels(), rats):
        tick.set_color(_ATOM_COLORS.get(r, TEXT_COL))
 
    ax.invert_yaxis()
    ax.set_xlabel('Share of sublayer/component labels within RAT (%)',
                  color=MUTED_COL, fontsize=9)
 
    fig.suptitle('Fine-grained subsystem labels within each RAT\n(e.g. NAS/RRC within 4G/LTE, VoLTE/SIP within IMS)',
                 color=TEXT_COL, fontsize=10, y=1.03)
 
    plt.tight_layout()
    fig.savefig(output, dpi=150, bbox_inches='tight')
    print(f"Saved: {output}")


if __name__ == '__main__':
    os.makedirs('pic', exist_ok=True)

    if os.path.exists(TYPST_FILE):
        _TYPST_RECORDS.update(parse_typst_cves(TYPST_FILE))
        print(f"Parsed {len(_TYPST_RECORDS)} records from {TYPST_FILE}")
    else:
        print(f"[WARN] {TYPST_FILE} not found — no Typst enrichment")

    raw_data = load_raw_data(JSON_FILES)
    if not raw_data:
        print("No data loaded.")
        sys.exit(0)
    print(f"Loaded {len(raw_data)} CVEs total.")

    # Print multi-subsystem CVE breakdown for transparency
    multi_counts = defaultdict(int)
    for d in raw_data:
        if len(d['all_atoms']) > 1:
            multi_counts[' + '.join(d['all_atoms'])] += 1
    if multi_counts:
        print("\nCVEs spanning multiple subsystems (shown in co-occurrence only):")
        for lbl, cnt in sorted(multi_counts.items(), key=lambda x: -x[1]):
            print(f"  {lbl}: {cnt}")

    months_sorted  = sorted({d['month'] for d in raw_data})
    years_sorted   = sorted({d['year']  for d in raw_data})
    vendors        = sorted({d['vendor'] for d in raw_data})
    labels_ordered = build_label_order(raw_data)
    impact_types   = IMPACT_ORDER

    print(f"\nLabel order ({len(labels_ordered)} labels): {labels_ordered}")

    plot_month_impact(raw_data, months_sorted, impact_types)
    year_label = plot_year_label(raw_data, years_sorted, labels_ordered)
    plot_heatmap_label_year(year_label, labels_ordered, years_sorted)
    plot_impact_by_vendor(raw_data, vendors, impact_types)
    vendor_month = plot_vendor_trend(raw_data, vendors, months_sorted)
    plot_cumulative_growth(vendor_month, vendors, months_sorted)
    plot_cooccurrence(raw_data, labels_ordered)
    plot_vendor_radar(raw_data, vendors, labels_ordered)
    plot_alluvial(raw_data, labels_ordered, impact_types)
    print_chart_percentages(raw_data, labels_ordered, impact_types, vendors)
    # plot_sublabels_within_rat(raw_data)