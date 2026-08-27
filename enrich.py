#!/usr/bin/env python3
"""
Evidence-aware baseband memory-safety CVE enrichment.

This is the Version-B research pipeline.  It deliberately separates:

* public impact claims from demonstrated exploitability;
* write-capable memory corruption from crash/read-only failures;
* attack surface (IMS/telephony, SIM, IP, local/diagnostic, cellular control plane) from RAT;
* evidence stated in a vendor CVE from evidence supplied by a paper or write-up.

The script consumes the four local CVE JSON files plus cve_table.typ.  It emits a
filtered, memory-safety-only dataset, an audit of every legacy RCE candidate, a
machine-readable summary answering the Version-B questions, CSV, and figures.

No network request is made at runtime.  Identifier-specific NVD links are generated
deterministically; research-source URLs and the small set of strictly verified RCE
decisions are curated below so that a run is reproducible.  URLs inherited from the
input JSON are quarantined as unverified candidates and are not evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


SCHEMA_VERSION = "2.9"
SOURCE_AUDIT_DATE = "2026-08-27"
REPOSITORY_ROOT = Path(__file__).resolve().parent
DEFAULT_TYPST = REPOSITORY_ROOT / "cve_table.typ"
DEFAULT_INPUT_DIR = Path("fetched_json")
DEFAULT_OUTPUT = Path("outputs")
JSON_FILENAMES = {
    "Qualcomm": "cve_qualcomm_clean.json",
    "Samsung": "cve_samsung_clean.json",
    "MediaTek": "cve_mediatek_clean.json",
    "Unisoc": "cve_unisoc_clean.json",
}

IMPACT_RCE = "RCE"
IMPACT_WRITE = "Write Primitive"
IMPACT_DOS = "DoS"
IMPACT_ORDER = (IMPACT_RCE, IMPACT_WRITE, IMPACT_DOS)

# Evidence levels describe how much is publicly known, not how critical the bug
# is.  Impact and exploitability remain represented by their dedicated fields.
EVIDENCE_LEVELS = ("E1", "E2", "E3", "E4", "E5")
EVIDENCE_LEVEL_SUMMARIES = {
    "E1": "A vendor or CVE record states the weakness or potential outcome.",
    "E2": "Public evidence reproduces the failure or identifies a function/message-level root cause.",
    "E3": "Public evidence characterizes an attacker-relevant memory primitive.",
    "E4": "Public evidence demonstrates control-flow redirection.",
    "E5": "Public evidence demonstrates or explicitly confirms arbitrary code execution under stated attack conditions.",
}

SCOPE_CELLULAR = "Cellular Control Plane"
SCOPE_TELEPHONY = "IMS/Telephony"
SCOPE_SIM = "SIM/UICC"
SCOPE_IP = "IP/User Plane"
SCOPE_LOCAL_DIAG = "Local/IPC & Diagnostic"
SCOPE_UNKNOWN = "Unknown"
SCOPE_ORDER = (
    SCOPE_CELLULAR,
    SCOPE_TELEPHONY,
    SCOPE_SIM,
    SCOPE_IP,
    SCOPE_LOCAL_DIAG,
    SCOPE_UNKNOWN,
)

BUG_FAMILY_BOUNDS_WRITE = "Bounds write / overflow"
BUG_FAMILY_BOUNDS_READ = "Bounds read"
BUG_FAMILY_NULL = "Null dereference"
BUG_FAMILY_LIFETIME_POINTER = "Lifetime / pointer misuse"
BUG_FAMILY_ASSUMED = "Assumed memory bug"
BUG_FAMILY_ORDER = (
    BUG_FAMILY_BOUNDS_WRITE,
    BUG_FAMILY_BOUNDS_READ,
    BUG_FAMILY_NULL,
    BUG_FAMILY_LIFETIME_POINTER,
    BUG_FAMILY_ASSUMED,
)


def bug_family(bug_class: str) -> str:
    """Collapse precise classes into families suitable for surface comparison."""
    if bug_class in {
        "assumed-memory-bug",
        "memory-corruption-unspecified",
        "unknown-memory-operation-rce",
    }:
        return BUG_FAMILY_ASSUMED
    if bug_class in {
        "out-of-bounds-write",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "buffer-overflow",
        "classic-buffer-overflow",
        "array-index-write",
        "write-what-where",
    }:
        return BUG_FAMILY_BOUNDS_WRITE
    if bug_class in {"out-of-bounds-read", "uninitialized-memory-read"}:
        return BUG_FAMILY_BOUNDS_READ
    if bug_class in {"null-pointer-dereference", "invalid-memory-access"}:
        return BUG_FAMILY_NULL
    if bug_class in {
        "use-after-free",
        "double-free",
        "invalid-free",
        "out-of-range-pointer",
    }:
        return BUG_FAMILY_LIFETIME_POINTER
    raise ValueError(f"unmapped bug class: {bug_class}")


def source(
    title: str,
    url: str,
    kind: str = "research",
    *,
    role: str = "technical-evidence",
) -> dict[str, str]:
    """Create a manually reviewed source used as evidence by this pipeline.

    These sources are deliberately distinct from URLs inherited from the input
    CVE JSON.  A source is placed here only after checking that the document
    supports the CVE mapping encoded in VERIFIED_RCE or RESEARCH_EVIDENCE.
    """
    return {
        "title": title,
        "url": url,
        "type": kind,
        "role": role,
        "association": "manually-curated-for-this-cve",
        "verification": "content-reviewed",
        "checked_date": SOURCE_AUDIT_DATE,
    }


def nvd_source(cve_id: str) -> dict[str, str]:
    """Return a stable, identifier-specific database link.

    This is a deterministic canonical-link construction, not a claim that the
    generator fetched the page.  Runtime generation remains offline.
    """
    return {
        "title": f"NVD record for {cve_id}",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "type": "vulnerability-database",
        "role": "canonical-cve-record",
        "association": "identifier-specific-canonical-url",
        "verification": "canonical-link-generated",
        "checked_date": "",
    }


SRC_WEINMANN = source(
    "Baseband Attacks: Remote Exploitation of Memory Corruptions in Cellular Protocol Stacks",
    "https://www.usenix.org/conference/woot12/workshop-program/presentation/weinmann",
)
SRC_PIXEL = source(
    "Over the Air, Under the Radar: Attacking and Securing the Pixel Modem",
    "https://i.blackhat.com/BH-US-23/Presentations/US-23-Karimi-Over-the-Air-Under-the-Radar.pdf",
)
SRC_BREAKING_BAND = source(
    "Breaking Band: Reverse Engineering and Exploiting the Shannon Baseband",
    "https://comsecuris.com/slides/recon2016-breaking_band.pdf",
)
SRC_P0 = source(
    "Multiple Internet to Baseband Remote Code Execution Vulnerabilities in Exynos Modems",
    "https://projectzero.google/2023/03/multiple-internet-to-baseband-remote-rce.html",
)
SRC_FIRMWIRE = source(
    "FirmWire: Transparent Dynamic Analysis for Cellular Baseband Firmware",
    "https://doi.org/10.14722/ndss.2022.23136",
)
SRC_BASEBRIDGE = source(
    "BaseBridge: Bridging the Gap Between Over-the-Air and Emulation Testing",
    "https://doi.org/10.1109/SP61157.2025.00142",
)
SRC_TASZK_CSN1 = source(
    "Exploiting CSN.1 Bugs in MediaTek Basebands",
    "https://labs.taszk.io/articles/post/mtk_baseband_csn1_exploitation/",
)
SRC_TASZK_32484 = source(
    "CVE-2021-32484: MediaTek GSM RRM E-UTRAN Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/65_mtk_hof_1/",
)
SRC_TASZK_32485 = source(
    "CVE-2021-32485: MediaTek GSM RRM UTRAN Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/66_mtk_hof_2/",
)
SRC_TASZK_32486 = source(
    "CVE-2021-32486: MediaTek GSM RRM Extended-EARFCN Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/67_mtk_hof_3/",
)
SRC_TASZK_32487 = source(
    "CVE-2021-32487: MediaTek GSM RRM Channel-Release Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/68_mtk_hof_4/",
)
SRC_TASZK_PNCD = source(
    "CVE-2022-21744: MediaTek Baseband GPRS PNCD Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/84_mtk_pncd_bof/",
)
SRC_TASZK_FULL_CHAIN_2 = source(
    "Full Chain Baseband Exploits, Part 2",
    "https://labs.taszk.io/articles/post/full_chain_bb_part2/",
)
SRC_TASZK_21517 = source(
    "CVE-2023-21517: Samsung Baseband LTE ESM TFT Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/85_ss_esm_bof/",
)
SRC_TASZK_RLC = source(
    "Exploiting New Attack Surfaces in Radio Layer 2 for Baseband RCE",
    "https://labs.taszk.io/articles/post/there_will_be_bugs/",
)
SRC_TASZK_RLC_DEMO = source(
    "Full Chain Baseband Exploits, Part 1",
    "https://labs.taszk.io/articles/post/full_chain_bb_part1/",
)

SRC_TASZK_41111 = source(
    "CVE-2023-41111: Samsung Baseband RLC Data Re-Assembly Buffer Overflow",
    "https://labs.taszk.io/blog/post/93_rlc_bof/",
)
SRC_TASZK_41112 = source(
    "CVE-2023-41112: Samsung Baseband RLC Data Re-Assembly Heap Buffer Overflow",
    "https://labs.taszk.io/blog/post/94_rlc_heap_bof/",
)
SRC_TASZK_20725 = source(
    "CVE-2025-20725: MediaTek Baseband Heap Overflow in inet_msg_unpack_addr",
    "https://labs.taszk.io/blog/post/101_mtk_arbitrary_heap_inet_msg_unpack_addr/",
)
SRC_TASZK_20726 = source(
    "CVE-2025-20726: MediaTek Baseband Heap Overflow in inet_msg_unpack_uri_with_len",
    "https://labs.taszk.io/blog/post/103_heap_inet_msg_unpack_uri_with_len/",
)
SRC_TASZK_20727 = source(
    "CVE-2025-20727: MediaTek Baseband Heap Overflow in SIP Authentication-Info",
    "https://labs.taszk.io/blog/post/104_heap_inet_param_struct_free_fn/",
)

SRC_APPLE_2010_3832 = source(
    "About the security content of iOS 4.2",
    "https://support.apple.com/en-ca/103588",
    "vendor-advisory",
    role="vendor-description-and-impact",
)


CURATED_ADVISORIES: dict[str, list[dict[str, str]]] = {
    "CVE-2010-3832": [SRC_APPLE_2010_3832],
}


# RCE means public confirmation of baseband compromise or demonstrated control-flow
# redirection.  "Could lead to RCE", a high CVSS score, or an OOB write alone is not
# sufficient. E4 requires demonstrated control-flow redirection; E5 requires
# demonstrated or explicitly confirmed arbitrary code execution under stated
# conditions.
VERIFIED_RCE: dict[str, dict[str, Any]] = {
    "CVE-2010-3832": {
        "reason": "The WOOT paper injects and executes arbitrary baseband code via the TMSI overflow.",
        "sources": [SRC_WEINMANN],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Rogue base station; pre-authentication GSM",
        "rats": ["2G"],
    },
    "CVE-2015-8546": {
        "reason": (
            "Breaking Band demonstrates saved-PC control, staged payload delivery, "
            "and execution through a hooked Layer-3 handler for the stack overflow."
        ),
        "sources": [SRC_BREAKING_BAND],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Rogue base station; 2G OTA; call-control state",
        "rats": ["2G"],
    },
    "CVE-2022-20170": {
        "reason": "Google's Black Hat chain delivers staged shellcode after a fully controlled heap overwrite.",
        "sources": [SRC_PIXEL],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Rogue base station; 2G OTA; no user interaction",
        "rats": ["2G"],
    },
    "CVE-2022-21744": {
        "reason": (
            "TASZK explicitly identifies CVE-2022-21744 as an RCE in its full-chain "
            "baseband exploitation write-up and documents the exploit primitives."
        ),
        "sources": [SRC_TASZK_PNCD, SRC_TASZK_FULL_CHAIN_2],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Rogue base station; 2G GPRS PNCD; no user interaction",
        "rats": ["2G"],
    },
    "CVE-2023-24033": {
        "reason": "Project Zero states that tests confirmed Internet-to-baseband compromise.",
        "sources": [SRC_P0],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": False,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Internet-to-baseband; phone number only; no user interaction",
    },
    "CVE-2023-26496": {
        "reason": "Project Zero states that tests confirmed Internet-to-baseband compromise.",
        "sources": [SRC_P0],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": False,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Internet-to-baseband; phone number only; no user interaction",
    },
    "CVE-2023-26497": {
        "reason": "Project Zero states that tests confirmed Internet-to-baseband compromise.",
        "sources": [SRC_P0],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": False,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Internet-to-baseband; phone number only; no user interaction",
    },
    "CVE-2023-26498": {
        "reason": "Project Zero states that tests confirmed Internet-to-baseband compromise.",
        "sources": [SRC_P0],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": False,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Internet-to-baseband; phone number only; no user interaction",
    },
    "CVE-2024-20039": {
        "reason": "BaseBridge redirects the program counter to a chosen valid function and reproduces the case OTA.",
        "sources": [SRC_BASEBRIDGE],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": False,
        "reachability": "Cellular OTA; registered/connected state in the published reproduction",
        "rats": ["4G/LTE"],
    },
    "CVE-2023-41111": {
        "reason": "TASZK publishes a working chained baseband exploit and demonstrates runtime compromise.",
        "sources": [SRC_TASZK_41111, SRC_TASZK_RLC, SRC_TASZK_RLC_DEMO],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Cellular OTA; unauthenticated 2G Layer 2",
        "rats": ["2G"],
    },
    "CVE-2023-41112": {
        "reason": "TASZK publishes a working chained baseband exploit and demonstrates runtime compromise.",
        "sources": [SRC_TASZK_41112, SRC_TASZK_RLC, SRC_TASZK_RLC_DEMO],
        "component_identified": True,
        "reproduced_failure": True,
        "primitive_characterized": True,
        "control_flow_redirection": True,
        "arbitrary_code_execution": True,
        "reachability": "Cellular OTA; unauthenticated 2G Layer 2; chained with CVE-2023-41111",
        "rats": ["2G"],
    },
}


def ev(
    summary: str,
    sources: list[dict[str, str]],
    *,
    reproduced: bool = False,
    primitive: bool = False,
) -> dict[str, Any]:
    return {
        "reason": summary,
        "sources": sources,
        "component_identified": True,
        "reproduced_failure": reproduced,
        "primitive_characterized": primitive,
        "control_flow_redirection": False,
        "arbitrary_code_execution": False,
    }


# Non-RCE cases for which public research adds more than a short vendor advisory.
RESEARCH_EVIDENCE: dict[str, dict[str, Any]] = {
    **{
        cve: ev(
            "FirmWire reproduces the OTA failure and identifies the corruptible stack/heap object or saved PC.",
            [SRC_FIRMWIRE],
            reproduced=True,
            primitive=True,
        )
        for cve in ("CVE-2020-25279", "CVE-2021-25477", "CVE-2021-25478", "CVE-2021-25479")
    },
    **{
        cve: ev(
            "TASZK recovers the vulnerable decoder and develops heap-corruption primitives; no public working code-execution proof is claimed here.",
            [direct_source, SRC_TASZK_CSN1],
            primitive=True,
        )
        for cve, direct_source in {
            "CVE-2021-32484": SRC_TASZK_32484,
            "CVE-2021-32485": SRC_TASZK_32485,
            "CVE-2021-32486": SRC_TASZK_32486,
            "CVE-2021-32487": SRC_TASZK_32487,
        }.items()
    },
    "CVE-2023-21517": ev(
        "TASZK documents the LTE ESM heap overflow and its attacker-controlled fields.",
        [SRC_TASZK_21517],
        primitive=True,
    ),
    "CVE-2024-20154": ev(
        "BaseBridge reproduces the stack overwrite OTA and shows that it reaches the stored return address; execution only reaches zero in the published test.",
        [SRC_BASEBRIDGE],
        reproduced=True,
        primitive=True,
    ),
    "CVE-2024-20150": ev(
        "BaseBridge reproduces the fault OTA and turns the overwrite into an attacker-selected pointer read/crash primitive.",
        [SRC_BASEBRIDGE],
        reproduced=True,
        primitive=True,
    ),
    "CVE-2025-20725": ev(
        "TASZK publishes a triggering SIP payload and characterizes an arbitrary heap overflow.",
        [SRC_TASZK_20725],
        reproduced=True,
        primitive=True,
    ),
    "CVE-2025-20726": ev(
        "TASZK publishes triggering SIP inputs and characterizes the heap overwrite.",
        [SRC_TASZK_20726],
        reproduced=True,
        primitive=True,
    ),
    "CVE-2025-20727": ev(
        "TASZK publishes triggering SIP inputs and characterizes the avoidable heap-footer overwrite.",
        [SRC_TASZK_20727],
        reproduced=True,
        primitive=True,
    ),
}


# The prior script classified these 45 records as RCE.  The new audit output retains
# the complete candidate list so every demotion is explicit and source-traceable.
LEGACY_RCE_CANDIDATES = frozenset(
    """
    CVE-2010-3832 CVE-2015-8546 CVE-2020-25279 CVE-2021-25478 CVE-2021-25479
    CVE-2021-32484 CVE-2021-32485 CVE-2021-32486 CVE-2021-32487
    CVE-2022-20083 CVE-2022-20170 CVE-2022-21744 CVE-2022-25682
    CVE-2022-25695 CVE-2022-25727 CVE-2022-33259 CVE-2023-21517
    CVE-2023-22385 CVE-2023-24033 CVE-2023-26072 CVE-2023-26073
    CVE-2023-26074 CVE-2023-26075 CVE-2023-26076 CVE-2023-26496
    CVE-2023-26497 CVE-2023-26498 CVE-2023-32874 CVE-2023-41111
    CVE-2023-41112 CVE-2023-50807 CVE-2024-20039 CVE-2024-20082
    CVE-2024-20154 CVE-2024-39890 CVE-2025-20634 CVE-2025-20704
    CVE-2025-20708 CVE-2025-20725 CVE-2025-20726 CVE-2025-20727
    CVE-2025-31718 CVE-2025-54329 CVE-2026-20432 CVE-2026-20433
    CVE-2026-20434
    """.split()
)


RESEARCH_REF_PREFIXES = (
    "firmwire",
    "taszk",
    "p0_",
    "woot",
    "pixel_pres",
    "cracking_",
    "logic_",
    "lisowski_",
    "overcoming_",
    "otabase",
    "csw",
    "zeropath",
)


WRITE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("heap-buffer-overflow", (r"heap[- ](?:based )?(?:buffer )?overflow", r"cwe[-: ]*122")),
    ("stack-buffer-overflow", (r"stack[- ](?:based )?(?:buffer )?overflow", r"cwe[-: ]*121")),
    ("out-of-bounds-write", (r"out[- ]of[- ]bounds write", r"\boob write\b", r"cwe[-: ]*787")),
    ("use-after-free", (r"use[- ]after[- ]free", r"cwe[-: ]*416")),
    ("double-free", (r"double free", r"cwe[-: ]*415")),
    ("invalid-free", (r"release of invalid pointer", r"cwe[-: ]*763")),
    ("out-of-range-pointer", (r"out[- ]of[- ]range pointer", r"cwe[-: ]*823")),
    ("array-index-write", (r"improper validation of array index", r"cwe[-: ]*129")),
    ("classic-buffer-overflow", (r"classic buffer overflow", r"cwe[-: ]*120")),
    ("buffer-overflow", (r"integer overflow to (?:a )?buffer overflow", r"cwe[-: ]*680", r"\bbuffer overflow\b")),
    ("write-what-where", (r"arbitrary write", r"write[- ]what[- ]where")),
)

GENERIC_MEMORY_RULES = (r"\bmemory corruption\b", r"\bmemory corruptions\b")

READ_DOS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("out-of-bounds-read", (r"out[- ]of[- ]bounds read", r"buffer over[- ]read", r"cwe[-: ]*125", r"cwe[-: ]*126")),
    ("null-pointer-dereference", (r"null pointer dereference", r"null[- ]ptr", r"cwe[-: ]*476")),
    ("uninitialized-memory-read", (r"uninitialized (?:heap )?(?:data|memory)",)),
    ("invalid-memory-access", (r"invalid memory (?:access|read)",)),
)

EXCLUDED_NON_MEMORY = (
    r"cwe[-: ]*327",
    r"cwe[-: ]*326",
    r"cwe[-: ]*295",
    r"cwe[-: ]*287",
    r"cwe[-: ]*285",
    r"cwe[-: ]*331",
    r"cwe[-: ]*757",
    r"improper authentication",
    r"improper authorization",
    r"improper access control",
    r"certificate validation",
    r"risky cryptographic algorithm",
    r"algorithm downgrade",
)


SCOPE_RULES: dict[str, tuple[str, ...]] = {
    SCOPE_TELEPHONY: (
        r"\bims\b", r"\bvolte\b", r"\bvowifi\b", r"\bsip\b", r"\bsdp\b",
        r"\brtp\b", r"\brtcp\b", r"\bikev2?\b", r"\bsms\b",
        r"short message", r"\bwms\b", r"sms ua",
    ),
    SCOPE_SIM: (
        r"\bsim\b", r"\buicc\b", r"\buim\b", r"\bgstk\b", r"\busat\b",
        r"\bapdu\b", r"sim toolkit", r"pkcs.?15",
    ),
    SCOPE_IP: (
        r"\bdns\b", r"\budp\b", r"\btcp\b", r"\bicmp", r"\bigmp",
        r"\bipv[46]\b", r"\bppp\b", r"\bcoap\b", r"\btls\b", r"\bdtls\b",
    ),
    SCOPE_LOCAL_DIAG: (
        r"\bdiag(?:nostic)?\b", r"\befs\b", r"management command",
        r"\bipc\b", r"\bqmi\b", r"\bccci\b", r"\bwmi\b", r"\bsmmu\b",
        r"\bdma\b", r"application processor", r"\bhost interface\b",
    ),
    SCOPE_CELLULAR: (
        r"\brrc\b", r"\bnas\b", r"\bemm\b", r"\besm\b", r"\bnrmm\b",
        r"\brrm\b", r"\brlc\b", r"\bpdcp\b", r"\bmac\b", r"\bllc\b",
        r"call control", r"\bgsm\b", r"\bgprs\b", r"\blte\b", r"\b5g\b",
        r"\bnr\b", r"\bumts\b", r"\bwcdma\b", r"cellular", r"base station",
    ),
}

RAT_RULES: dict[str, tuple[str, ...]] = {
    "2G": (r"\b2g\b", r"\bgsm\b", r"\bgeran\b", r"\bgprs\b", r"\bedge\b", r"csn\.?1"),
    "3G": (r"\b3g\b", r"\bumts\b", r"\bwcdma\b", r"\butran\b"),
    "4G/LTE": (r"\b4g\b", r"\blte\b", r"\beps\b", r"\bemm\b", r"\besm\b"),
    "5G/NR": (r"\b5g\b", r"\bnr\b", r"\bnrmm\b", r"\b5g mm\b", r"\b5g sm\b"),
}

PROTOCOL_RULES: dict[str, tuple[str, ...]] = {
    "RRC": (r"\brrc\b", r"radio resource control"),
    "NAS": (r"\bnas\b", r"non[- ]access stratum"),
    "MM": (r"\bmobility management\b", r"\bemm\b", r"\bnrmm\b", r"\bgsm mm\b"),
    "SM": (r"\bsession management\b", r"\besm\b", r"\b5g sm\b"),
    "RRM": (r"\brrm\b", r"radio resource management"),
    "Call Control": (r"\bcall control\b", r"\bcc message\b", r"\bgsm cc\b"),
    "RLC": (r"\brlc\b",),
    "PDCP": (r"\bpdcp\b",),
    "MAC": (r"\bmac\b", r"random access response", r"\brar\b"),
    "IMS/SIP": (r"\bims\b", r"\bsip\b", r"\bvolte\b", r"\bvowifi\b"),
    "SDP": (r"\bsdp\b", r"session description"),
    "SMS": (r"\bsms\b", r"short message", r"\bwms\b"),
    "SIM/UICC": (r"\bsim\b", r"\buicc\b", r"\buim\b", r"\bgstk\b", r"\busat\b", r"\bapdu\b"),
    "IP stack": (r"\bdns\b", r"\budp\b", r"\btcp\b", r"\bicmp", r"\bigmp", r"\bipv[46]\b"),
}

PRIMARY_SCOPE_PRIORITY = (
    SCOPE_TELEPHONY,
    SCOPE_SIM,
    SCOPE_IP,
    SCOPE_LOCAL_DIAG,
    SCOPE_CELLULAR,
)


@dataclass
class RawRecord:
    cve_id: str
    vendor: str
    date_published: str
    description: str
    cwe_text: str
    references: list[str]
    raw: dict[str, Any]


def clean(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def meaningful(value: Any) -> bool:
    return clean(value).lower() not in {"", "n/a", "na", "-", "—", "unknown", "none"}


def first_match(text: str, rules: Iterable[tuple[str, tuple[str, ...]]]) -> str | None:
    for label, patterns in rules:
        if any(re.search(pattern, text, re.I) for pattern in patterns):
            return label
    return None


def all_matches(text: str, rules: dict[str, tuple[str, ...]]) -> list[str]:
    return [
        label for label, patterns in rules.items()
        if any(re.search(pattern, text, re.I) for pattern in patterns)
    ]


def parse_date(raw: str) -> tuple[str, int | None]:
    if not raw:
        return "", None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.date().isoformat(), dt.year
    except ValueError:
        match = re.search(r"\b(20\d{2}|19\d{2})\b", raw)
        return raw[:10], int(match.group(1)) if match else None


def containers(record: dict[str, Any]) -> list[dict[str, Any]]:
    root = record.get("containers", {})
    result = []
    if isinstance(root.get("cna"), dict):
        result.append(root["cna"])
    result.extend(x for x in (root.get("adp") or []) if isinstance(x, dict))
    return result


def extract_problem_types(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for container in containers(record):
        for group in container.get("problemTypes", []) or []:
            if not isinstance(group, dict):
                continue
            descriptions = group.get("descriptions", []) or []
            if isinstance(descriptions, dict):
                descriptions = [descriptions]
            for item in descriptions:
                if isinstance(item, dict) and meaningful(item.get("description")):
                    values.append(clean(item["description"]))
                elif meaningful(item):
                    values.append(clean(item))
    return list(dict.fromkeys(values))


def extract_references(record: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for container in containers(record):
        for item in container.get("references", []) or []:
            if isinstance(item, dict) and meaningful(item.get("url")):
                urls.append(clean(item["url"]))
    return list(dict.fromkeys(urls))


def extract_description(record: dict[str, Any]) -> str:
    for container in containers(record):
        descriptions = container.get("descriptions", []) or []
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en" and meaningful(item.get("value")):
                return clean(item["value"])
    return ""


def load_json_records(paths: dict[str, Path]) -> dict[str, RawRecord]:
    records: dict[str, RawRecord] = {}
    for vendor, path in paths.items():
        if not path.exists():
            raise FileNotFoundError(f"Missing dataset file: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            data = [data]
        for item in data:
            cve_id = clean(item.get("cveMetadata", {}).get("cveId"))
            if not cve_id:
                continue
            date, _ = parse_date(clean(item.get("cveMetadata", {}).get("datePublished")))
            candidate = RawRecord(
                cve_id=cve_id,
                vendor=vendor,
                date_published=date,
                description=extract_description(item),
                cwe_text="; ".join(extract_problem_types(item)),
                references=extract_references(item),
                raw=item,
            )
            if cve_id not in records or len(candidate.description) > len(records[cve_id].description):
                records[cve_id] = candidate
    return records


def parse_typst_records(path: Path) -> dict[str, dict[str, Any]]:
    content = path.read_text(encoding="utf-8")
    records: dict[str, dict[str, Any]] = {}
    record_pattern = re.compile(r'\(\s*id:\s*"([^"]+)"(.*?)\n\s*\)', re.DOTALL)
    fields = {
        name: re.compile(rf'{name}:\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
        for name in ("vendor", "protocol", "impact", "root_cause", "fw_range", "cvss")
    }
    for match in record_pattern.finditer(content):
        cve_id, body = match.group(1), match.group(2)
        entry: dict[str, Any] = {"cve_id": cve_id}
        for name, pattern in fields.items():
            field = pattern.search(body)
            entry[name] = clean(field.group(1)) if field else ""
        entry["reference_keys"] = list(dict.fromkeys(re.findall(r"#cite\(<([^>]+)>\)", body)))
        # Later duplicate entries replace earlier entries in the original pipeline.
        records[cve_id] = entry
    return records


def normalize_vendor(value: str) -> str:
    text = value.lower()
    if any(x in text for x in ("samsung", "exynos", "pixel", "google")):
        return "Samsung"
    if "qualcomm" in text:
        return "Qualcomm"
    if "mediatek" in text:
        return "MediaTek"
    if "unisoc" in text:
        return "Unisoc"
    if "apple" in text:
        return "Apple"
    return clean(value) or "Unknown"


def source_type(url: str) -> str:
    host = urlparse(url).netloc.lower().removeprefix("www.")
    if any(domain in host for domain in (
        "projectzero.google", "googleprojectzero.blogspot", "blackhat.com",
        "taszk.io", "comsecuris.com", "ndss-symposium.org", "usenix.org",
        "mariusmue.com", "doi.org", "arxiv.org",
    )):
        return "research"
    if any(domain in host for domain in (
        "mediatek.com", "qualcomm.com", "samsung.com", "samsungmobile.com",
        "source.android.com", "apple.com", "unisoc.com",
    )):
        return "vendor-advisory"
    if any(domain in host for domain in ("nvd.nist.gov", "cve.org", "mitre.org")):
        return "vulnerability-database"
    return "other"


def reference_candidates(cve_id: str, urls: list[str]) -> list[dict[str, Any]]:
    """Preserve inherited URLs without misrepresenting them as evidence.

    Input records frequently contain obsolete indexes, product landing pages,
    and at least one URL whose path names a different CVE.  URL structure can
    identify obvious conflicts, but it cannot prove page contents.  Therefore
    every inherited URL is quarantined here and is never used to justify an
    impact or evidence level.
    """
    candidates: list[dict[str, Any]] = []
    for url in dict.fromkeys(urls):
        url_cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", url, re.I)))
        url_cves = [item.upper() for item in url_cves]
        if cve_id in url_cves:
            signal = "identifier-present-in-url"
        elif url_cves:
            signal = "conflicting-identifier-in-url"
        else:
            signal = "no-identifier-in-url"
        candidates.append({
            "url": url,
            "inferred_type": source_type(url),
            "mapping_signal": signal,
            "cve_ids_in_url": url_cves,
            "status": "unverified-input-reference-not-used-as-evidence",
        })
    return candidates


def merge_sources(cve_id: str, evidence: dict[str, Any]) -> list[dict[str, str]]:
    """Build the evidence source list from canonical and curated sources only."""
    result = [nvd_source(cve_id)]
    result.extend(CURATED_ADVISORIES.get(cve_id, []))
    result.extend(evidence.get("sources", []))
    dedup: dict[str, dict[str, str]] = {}
    for item in result:
        annotated = dict(item)
        annotated["supports_cve"] = cve_id
        dedup[annotated["url"]] = annotated
    return list(dedup.values())


def output_sources(sources: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    """Return the intentionally minimal source representation used in JSON output."""
    return [{"title": item["title"], "url": item["url"]} for item in sources]


def output_record(record: dict[str, Any]) -> dict[str, Any]:
    """Remove internal source-provenance metadata from an emitted CVE record."""
    return {
        **{
            key: value
            for key, value in record.items()
            if key != "input_reference_candidates"
        },
        "sources": output_sources(record["sources"]),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_patch_id(text: str) -> str:
    match = re.search(r"\bPatch ID:\s*([A-Za-z0-9_-]+)", text, re.I)
    return match.group(1) if match else ""


def classify_memory(text: str, cve_id: str) -> tuple[str | None, str | None, str]:
    """Return (impact, bug_class, exclusion_reason)."""
    if cve_id in VERIFIED_RCE:
        write_class = first_match(text, WRITE_RULES)
        if write_class:
            return IMPACT_RCE, write_class, ""
        if any(re.search(pattern, text, re.I) for pattern in GENERIC_MEMORY_RULES):
            return IMPACT_RCE, "memory-corruption-unspecified", ""
        # Confirmed execution is an impact observation, not proof of a public
        # read/write primitive. Keep the RCE impact while marking the underlying
        # memory operation as assumed when the root cause is not disclosed.
        return IMPACT_RCE, "unknown-memory-operation-rce", ""

    write_class = first_match(text, WRITE_RULES)
    read_class = first_match(text, READ_DOS_RULES)
    generic_memory = any(re.search(pattern, text, re.I) for pattern in GENERIC_MEMORY_RULES)
    explicitly_non_memory = any(re.search(pattern, text, re.I) for pattern in EXCLUDED_NON_MEMORY)

    # A write primitive requires an explicit write/overflow/lifetime signal.
    # Bare "memory corruption" wording does not identify a primitive, so it is
    # grouped with assumed memory bugs and receives conservative DoS impact.
    # Specific operations always win.
    if write_class:
        return IMPACT_WRITE, write_class, ""
    if read_class:
        return IMPACT_DOS, read_class, ""
    if generic_memory:
        return IMPACT_DOS, "memory-corruption-unspecified", ""
    if explicitly_non_memory:
        return None, None, "non-memory weakness"
    # Project policy: absence of a public root cause is treated as an assumed
    # memory bug rather than an exclusion.  The impact remains the conservative
    # DoS class because no write-capable primitive or execution is public.
    return IMPACT_DOS, "assumed-memory-bug", ""


def primitive_control(text: str, impact: str) -> str:
    if impact == IMPACT_RCE:
        return "demonstrated control-flow/code execution"
    if re.search(r"attacker[- ]controlled|fully controls|arbitrary (?:heap )?(?:write|overflow)", text, re.I):
        return "attacker-controlled"
    if impact == IMPACT_WRITE:
        return "write-capable; degree of byte/address control not public"
    return "read/crash only"


def classify_scope(text: str, typst: dict[str, Any]) -> tuple[list[str], str, list[str], list[str], str]:
    scopes = all_matches(text, SCOPE_RULES)
    rats = all_matches(text, RAT_RULES)
    protocols = all_matches(text, PROTOCOL_RULES)
    primary = next((scope for scope in PRIMARY_SCOPE_PRIORITY if scope in scopes), SCOPE_UNKNOWN)

    protocol_annotation = clean(typst.get("protocol"))
    if meaningful(protocol_annotation):
        evidence_basis = "manual protocol annotation plus public description"
    elif primary != SCOPE_UNKNOWN:
        evidence_basis = "inferred from public description/CWE keywords"
    else:
        evidence_basis = "unknown"
    return scopes or [SCOPE_UNKNOWN], primary, rats, protocols, evidence_basis


def default_evidence() -> dict[str, Any]:
    return {
        "reason": "",
        "sources": [],
        "component_identified": False,
        "reproduced_failure": False,
        "primitive_characterized": False,
        "control_flow_redirection": False,
        "arbitrary_code_execution": False,
    }


def evidence_for(cve_id: str) -> dict[str, Any]:
    if cve_id in VERIFIED_RCE:
        return VERIFIED_RCE[cve_id]
    if cve_id in RESEARCH_EVIDENCE:
        return RESEARCH_EVIDENCE[cve_id]
    return default_evidence()


def infer_reachability(primary_scope: str, text: str, evidence: dict[str, Any]) -> str:
    if evidence.get("reachability"):
        return evidence["reachability"]
    if re.search(r"rogue base station", text, re.I):
        return "Rogue base station; authentication/state not fully specified"
    if re.search(r"no user interaction", text, re.I) and re.search(r"\bremote\b|network", text, re.I):
        return "Remote; no user interaction; protocol state not public"
    if primary_scope == SCOPE_SIM:
        return "SIM/UICC-originated or physical/compromised-card path"
    if primary_scope == SCOPE_LOCAL_DIAG:
        return "Local or intra-device"
    if primary_scope == SCOPE_TELEPHONY:
        return "IMS/telephony path; registration/authentication state not consistently public"
    if primary_scope == SCOPE_CELLULAR:
        return "Cellular OTA or network-originated; state not public"
    return "Unknown"


def root_detail(typst: dict[str, Any], bug_class: str, protocols: list[str]) -> str:
    root = clean(typst.get("root_cause"))
    if meaningful(root) and re.search(r"\b(function|handler|parser|decoder|codec|0x[0-9a-f]+|_[a-z0-9_]+)\b", root, re.I):
        return "function/message-level"
    if protocols:
        return "component/protocol-level"
    if bug_class:
        return "generic bug-class"
    return "absent"


def classify_evidence_level(
    component_identified: bool,
    reproduced_failure: bool,
    primitive_characterized: bool,
    control_flow_redirection: bool,
    arbitrary_code_execution: bool,
) -> str:
    """Classify the strongest public evidence while keeping impact independent."""
    if arbitrary_code_execution:
        return "E5"
    if control_flow_redirection:
        return "E4"
    if primitive_characterized:
        return "E3"
    if reproduced_failure or component_identified:
        return "E2"
    return "E1"


def enrich_record(raw: RawRecord, typst: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    manual_protocol = clean(typst.get("protocol"))
    manual_root = clean(typst.get("root_cause"))
    manual_impact = clean(typst.get("impact"))
    combined = " ".join(
        part for part in (
            manual_protocol, manual_root, manual_impact, raw.description, raw.cwe_text
        ) if meaningful(part)
    )
    impact, bug_class, exclusion = classify_memory(combined.lower(), raw.cve_id)
    evidence = evidence_for(raw.cve_id)
    all_sources = merge_sources(raw.cve_id, evidence)
    research_ref_keys = [
        key for key in typst.get("reference_keys", [])
        if key.lower().startswith(RESEARCH_REF_PREFIXES)
    ]

    base = {
        "cve_id": raw.cve_id,
        "vendor": normalize_vendor(raw.vendor or clean(typst.get("vendor"))),
        "date_published": raw.date_published,
        "year": parse_date(raw.date_published)[1] or int(raw.cve_id.split("-")[1]),
        "description": raw.description,
        "cwe": raw.cwe_text,
        "manual_enrichment": {
            "protocol": manual_protocol,
            "impact": manual_impact,
            "root_cause": manual_root,
            "firmware_range": clean(typst.get("fw_range")),
            "cvss": clean(typst.get("cvss")),
            "reference_keys": typst.get("reference_keys", []),
        },
        "sources": all_sources,
        # Retained internally for the provenance audit only. These inherited
        # URLs are removed by output_record() and never support classification.
        "input_reference_candidates": reference_candidates(raw.cve_id, raw.references),
        "research_reference_keys": research_ref_keys,
    }

    if not impact or not bug_class:
        excluded = {
            **base,
            "excluded_reason": exclusion,
        }
        return None, excluded

    scopes, primary_scope, rats, protocols, scope_basis = classify_scope(combined, typst)
    for rat in evidence.get("rats", []):
        if rat not in rats:
            rats.append(rat)
    has_external = any(item["type"] == "research" for item in all_sources) or bool(
        research_ref_keys
    )
    root_cause_detail = root_detail(typst, bug_class, protocols)
    component_identified = evidence.get("component_identified", False) or root_cause_detail in {
        "function/message-level",
        "component/protocol-level",
    }
    primitive_characterized = evidence.get("primitive_characterized", False)
    evidence_level = classify_evidence_level(
        component_identified,
        evidence.get("reproduced_failure", False),
        primitive_characterized,
        evidence.get("control_flow_redirection", False),
        evidence.get("arbitrary_code_execution", False),
    )
    record = {
        **base,
        "impact": impact,
        "bug_class": bug_class,
        "bug_family": bug_family(bug_class),
        "memory_safety_basis": (
            "assumed_when_public_evidence_absent"
            if bug_class in {"assumed-memory-bug", "unknown-memory-operation-rce"}
            else "explicit_public_memory_safety_evidence"
        ),
        "primitive_control": primitive_control(combined, impact),
        "scopes": scopes,
        "primary_scope": primary_scope,
        "rats": rats,
        "protocols": protocols,
        "scope_evidence": scope_basis,
        "reachability": infer_reachability(primary_scope, combined, evidence),
        "root_cause_detail": root_cause_detail,
        "evidence": {
            "level": evidence_level,
            "summary": evidence.get("reason") or EVIDENCE_LEVEL_SUMMARIES[evidence_level],
            "component_identified": component_identified,
            "reproduced_failure": evidence.get("reproduced_failure", False),
            "primitive_characterized": primitive_characterized,
            "control_flow_redirection": evidence.get("control_flow_redirection", False),
            "arbitrary_code_execution": evidence.get("arbitrary_code_execution", False),
        },
        "source_beyond_vendor_advisory": has_external,
        "patch": {
            "identifier": extract_patch_id(raw.description),
            "firmware_range_public": meaningful(typst.get("fw_range")),
            "public_patch_diff": False,
        },
    }
    return record, {}


def synthetic_raw(cve_id: str, typst: dict[str, Any]) -> RawRecord:
    year = int(cve_id.split("-")[1])
    return RawRecord(
        cve_id=cve_id,
        vendor=normalize_vendor(clean(typst.get("vendor"))),
        date_published=f"{year}-01-01",
        description="",
        cwe_text="",
        references=[],
        raw={},
    )


def counter_dict(values: Iterable[Any], order: Iterable[Any] | None = None) -> dict[str, int]:
    counts = Counter(values)
    if order:
        result = {str(key): counts[key] for key in order if counts[key]}
        result.update({str(key): value for key, value in sorted(counts.items()) if str(key) not in result})
        return result
    return {str(key): value for key, value in sorted(counts.items())}


def percentage(count: int, total: int) -> float:
    return round(count / total * 100, 1) if total else 0.0


def build_summary(
    records: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    input_count: int,
) -> dict[str, Any]:
    total = len(records)
    known_scope = sum(r["primary_scope"] != SCOPE_UNKNOWN for r in records)
    protocol_known = sum(bool(r["protocols"]) for r in records)
    bug_known = sum(
        r["bug_class"] not in {
            "memory-corruption-unspecified",
            "unknown-memory-operation-rce",
            "assumed-memory-bug",
        }
        for r in records
    )
    explicit_memory = sum(
        r["memory_safety_basis"] == "explicit_public_memory_safety_evidence"
        for r in records
    )
    assumed_memory = total - explicit_memory
    external = sum(r["source_beyond_vendor_advisory"] for r in records)
    reproduced = sum(r["evidence"]["reproduced_failure"] for r in records)
    primitive = sum(r["evidence"]["primitive_characterized"] for r in records)
    control_or_exec = sum(
        r["evidence"]["control_flow_redirection"] or r["evidence"]["arbitrary_code_execution"]
        for r in records
    )
    patch_id = sum(bool(r["patch"]["identifier"]) for r in records)
    firmware = sum(r["patch"]["firmware_range_public"] for r in records)
    manual_scope = sum(r["scope_evidence"].startswith("manual") for r in records)
    inferred_scope = sum(r["scope_evidence"].startswith("inferred") for r in records)

    by_year_impact: dict[str, dict[str, int]] = {}
    for year in sorted({r["year"] for r in records}):
        by_year_impact[str(year)] = counter_dict(
            (r["impact"] for r in records if r["year"] == year), IMPACT_ORDER
        )

    scope_profiles: dict[str, dict[str, Any]] = {}
    for scope in SCOPE_ORDER:
        scoped = [record for record in records if record["primary_scope"] == scope]
        if not scoped:
            continue
        top_classes = Counter(record["bug_class"] for record in scoped).most_common(6)
        scope_profiles[scope] = {
            "count": len(scoped),
            "percent_of_filtered_dataset": percentage(len(scoped), total),
            "impact": counter_dict((record["impact"] for record in scoped), IMPACT_ORDER),
            "write_capable_or_rce": {
                "count": sum(record["impact"] != IMPACT_DOS for record in scoped),
                "percent_within_scope": percentage(
                    sum(record["impact"] != IMPACT_DOS for record in scoped),
                    len(scoped),
                ),
            },
            "bug_family": counter_dict(
                (record["bug_family"] for record in scoped),
                BUG_FAMILY_ORDER,
            ),
            "top_bug_classes": [
                {"bug_class": bug_class_name, "count": count}
                for bug_class_name, count in top_classes
            ],
            "protocol_hits": counter_dict(
                protocol for record in scoped for protocol in record["protocols"]
            ),
            "vendor_disclosures": counter_dict(record["vendor"] for record in scoped),
        }

    coverage = {
        "known_primary_scope": {"count": known_scope, "percent": percentage(known_scope, total)},
        "specific_protocol": {"count": protocol_known, "percent": percentage(protocol_known, total)},
        "specific_bug_class": {"count": bug_known, "percent": percentage(bug_known, total)},
        "explicit_public_memory_safety_evidence": {
            "count": explicit_memory,
            "percent": percentage(explicit_memory, total),
        },
        "assumed_memory_bug": {
            "count": assumed_memory,
            "percent": percentage(assumed_memory, total),
        },
        "source_beyond_vendor_advisory": {"count": external, "percent": percentage(external, total)},
        "public_reproduced_failure": {"count": reproduced, "percent": percentage(reproduced, total)},
        "public_primitive_characterization": {"count": primitive, "percent": percentage(primitive, total)},
        "public_control_flow_or_code_execution": {"count": control_or_exec, "percent": percentage(control_or_exec, total)},
        "patch_identifier": {"count": patch_id, "percent": percentage(patch_id, total)},
        "affected_or_fixed_firmware_range": {"count": firmware, "percent": percentage(firmware, total)},
        "public_patch_diff": {"count": 0, "percent": 0.0},
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "source_audit_date": SOURCE_AUDIT_DATE,
        "input_unique_cves": input_count,
        "included_memory_safety_cves": total,
        "excluded_non_memory_or_insufficient_evidence": len(excluded),
        "impact": counter_dict((r["impact"] for r in records), IMPACT_ORDER),
        "primary_scope": counter_dict((r["primary_scope"] for r in records), SCOPE_ORDER),
        "vendor": counter_dict((r["vendor"] for r in records)),
        "year": counter_dict((r["year"] for r in records)),
        "rat_hits": counter_dict((rat for r in records for rat in r["rats"]), RAT_RULES.keys()),
        "bug_class": counter_dict((r["bug_class"] for r in records)),
        "bug_family": counter_dict((r["bug_family"] for r in records), BUG_FAMILY_ORDER),
        "protocol_hits": counter_dict((protocol for r in records for protocol in r["protocols"])),
        "reachability": counter_dict((r["reachability"] for r in records)),
        "evidence_level": counter_dict(
            (r["evidence"]["level"] for r in records), EVIDENCE_LEVELS
        ),
        "source_type_hits": counter_dict(
            source["type"] for record in records for source in record["sources"]
        ),
        "scope_assignment_basis": {
            "manual_annotation_plus_description": manual_scope,
            "description_keyword_inference": inferred_scope,
            "unknown": total - manual_scope - inferred_scope,
        },
        "memory_safety_basis": counter_dict(r["memory_safety_basis"] for r in records),
        "coverage": coverage,
        "year_by_impact": by_year_impact,
        "scope_profiles": scope_profiles,
        "direction_questions": {
            "q1_source_beyond_short_vendor_advisory": coverage["source_beyond_vendor_advisory"],
            "q2_vendor_only_vs_research_source": {
                "research_enriched": external,
                "vendor_or_database_only": total - external,
            },
            "q3_triggering_protocol_or_input_surface": {
                "known_primary_scope": coverage["known_primary_scope"],
                "specific_protocol": coverage["specific_protocol"],
            },
            "q4_specific_memory_bug_class": coverage["specific_bug_class"],
            "q5_public_crash_or_failure_reproduction": coverage["public_reproduced_failure"],
            "q6_public_attacker_controlled_primitive": coverage["public_primitive_characterization"],
            "q7_public_control_flow_or_arbitrary_execution": coverage["public_control_flow_or_code_execution"],
            "q8_patch_reconstruction": {
                "patch_identifier": coverage["patch_identifier"],
                "firmware_range": coverage["affected_or_fixed_firmware_range"],
                "public_patch_diff": coverage["public_patch_diff"],
            },
            "q9_scope_label_basis": {
                "manual_annotation_plus_description": manual_scope,
                "description_keyword_inference": inferred_scope,
                "unknown": total - manual_scope - inferred_scope,
            },
            "q10_reliable_figures": [
                "publication trend by impact",
                "impact by primary scope",
                "memory-bug families by primary scope",
                "overall memory-bug class distribution",
                "measured public-evidence coverage",
                "RAT hit counts (multi-valued, not mutually exclusive)",
                "vendor disclosure counts with an explicit non-ranking caveat",
            ],
        },
        "taxonomy_notes": {
            "RCE": "Requires public confirmation of compromise or demonstrated control-flow/code execution.",
            "Write Primitive": (
                "Attacker-influenced input causes a write-capable memory effect. Absolute "
                "address/value control is not required: a deterministic single-byte or null-byte "
                "overwrite qualifies even when the immediate observed outcome is an assertion or "
                "baseband crash. This class does not assert code execution."
            ),
            "DoS": "Explicit read/crash memory-safety class or assumed memory bug without public write-capable corruption.",
            "Assumed memory bug": (
                "No read/write/lifetime primitive is public. This family includes both records "
                "with only generic memory-corruption wording and records retained under the "
                "missing-memory-evidence assumption. Impact remains independent: an otherwise "
                "confirmed RCE stays RCE; other unknown-primitive cases receive conservative DoS."
            ),
            **EVIDENCE_LEVEL_SUMMARIES,
            "evidence_independence": "Evidence level measures information completeness, not impact or criticality.",
            "scope": "Primary attack surface is separate from multi-valued RAT and protocol annotations; Multi-RAT is not a catch-all scope.",
            "scope_comparison": "Counts measure disclosures in this corpus, not per-device or per-line-of-code vulnerability rates.",
            "missing_memory_evidence": "If a record is not explicitly non-memory and no public memory-safety root cause exists, retain it in the Assumed memory bug family. Use conservative DoS unless independent public evidence confirms RCE.",
        },
    }


def build_rce_audit(
    records: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    included_by_id = {r["cve_id"]: r for r in records}
    excluded_by_id = {r["cve_id"]: r for r in excluded}
    rows: list[dict[str, Any]] = []
    for cve_id in sorted(LEGACY_RCE_CANDIDATES):
        if cve_id in included_by_id:
            record = included_by_id[cve_id]
            sources = record["sources"]
            reviewed_sources = [
                item for item in sources if item["verification"] == "content-reviewed"
            ]
            rows.append({
                "cve_id": cve_id,
                "legacy_label": "RCE",
                "final_impact": record["impact"],
                "evidence_level": record["evidence"]["level"],
                "decision": (
                    "retained: public control-flow/code-execution evidence"
                    if record["impact"] == IMPACT_RCE
                    else "demoted: public evidence supports a write primitive but not demonstrated RCE"
                    if record["impact"] == IMPACT_WRITE
                    else "demoted: retained as assumed memory bug; no public RCE or memory root-cause evidence"
                    if record["bug_class"] == "assumed-memory-bug"
                    else "demoted: public evidence supports a memory-safety crash/read outcome"
                ),
                "reason": (
                    "No public memory-safety root cause; retained under the declared missing-evidence "
                    "memory-bug assumption with conservative DoS impact."
                    if record["bug_class"] == "assumed-memory-bug"
                    else record["evidence"]["summary"]
                ),
                "sources": output_sources(sources),
                "source_checked_online": bool(reviewed_sources),
                "source_checked_date": SOURCE_AUDIT_DATE if reviewed_sources else "",
                "source_review_status": (
                    "one-or-more technical/advisory sources content-reviewed"
                    if reviewed_sources
                    else "canonical CVE link only; no technical source content review"
                ),
            })
        else:
            record = excluded_by_id.get(cve_id, {})
            sources = record.get("sources", [])
            reviewed_sources = [
                item for item in sources if item["verification"] == "content-reviewed"
            ]
            rows.append({
                "cve_id": cve_id,
                "legacy_label": "RCE",
                "final_impact": "Excluded",
                "evidence_level": "not-applicable",
                "decision": "excluded: no public memory-safety root cause in the supplied record",
                "reason": record.get("excluded_reason", "record not present"),
                "sources": output_sources(sources),
                "source_checked_online": bool(reviewed_sources),
                "source_checked_date": SOURCE_AUDIT_DATE if reviewed_sources else "",
                "source_review_status": (
                    "one-or-more technical/advisory sources content-reviewed"
                    if reviewed_sources
                    else "canonical CVE link only; no technical source content review"
                ),
            })
    return rows


def build_source_provenance_audit(
    records: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize source status without performing network I/O."""
    all_records = records + excluded
    candidate_rows = [
        {
            "cve_id": record["cve_id"],
            **candidate,
        }
        for record in all_records
        for candidate in record.get("input_reference_candidates", [])
    ]
    signal_counts = Counter(row["mapping_signal"] for row in candidate_rows)
    reviewed_associations = [
        {
            "cve_id": record["cve_id"],
            "title": item["title"],
            "url": item["url"],
            "type": item["type"],
            "role": item["role"],
            "checked_date": item["checked_date"],
        }
        for record in all_records
        for item in record["sources"]
        if item["verification"] == "content-reviewed"
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "audit_date": SOURCE_AUDIT_DATE,
        "runtime_network_access": False,
        "policy": {
            "sources": (
                "Only identifier-specific canonical CVE links and manually content-reviewed "
                "technical/vendor documents are admitted as evidence sources."
            ),
            "input_reference_candidates": (
                "URLs inherited from source JSON are retained for traceability but are unverified "
                "and never used to justify classification or evidence levels."
            ),
            "online_checked_meaning": (
                "content-reviewed denotes a manual content/relevance review on audit_date; "
                "canonical-link-generated does not claim an HTTP check."
            ),
        },
        "counts": {
            "records": len(all_records),
            "records_with_canonical_nvd_source": sum(
                any(item["role"] == "canonical-cve-record" for item in record["sources"])
                for record in all_records
            ),
            "content_reviewed_source_associations": len(reviewed_associations),
            "input_reference_candidates": len(candidate_rows),
            "candidate_mapping_signals": dict(sorted(signal_counts.items())),
        },
        "obvious_conflicting_input_mappings": [
            row for row in candidate_rows
            if row["mapping_signal"] == "conflicting-identifier-in-url"
        ],
        "content_reviewed_source_associations": reviewed_associations,
    }


def validate_outputs(
    records: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    audit: list[dict[str, Any]],
) -> None:
    record_ids = [record["cve_id"] for record in records]
    excluded_ids = [record["cve_id"] for record in excluded]
    assert len(record_ids) == len(set(record_ids)), "included CVE IDs are not unique"
    assert len(excluded_ids) == len(set(excluded_ids)), "excluded CVE IDs are not unique"
    assert not set(record_ids).intersection(excluded_ids), "included/excluded overlap"
    assert all(record["impact"] in IMPACT_ORDER for record in records)
    assert all(record["primary_scope"] in SCOPE_ORDER for record in records)
    assert all(record["evidence"]["level"] in EVIDENCE_LEVELS for record in records)
    assert all(
        record["evidence"]["level"]
        == classify_evidence_level(
            record["evidence"]["component_identified"],
            record["evidence"]["reproduced_failure"],
            record["evidence"]["primitive_characterized"],
            record["evidence"]["control_flow_redirection"],
            record["evidence"]["arbitrary_code_execution"],
        )
        for record in records
    ), "evidence levels must depend only on component and primitive knowledge"
    assert all(
        record["impact"] == IMPACT_DOS
        for record in records
        if record["bug_class"] == "assumed-memory-bug"
    )
    assert all(
        record["impact"] == IMPACT_DOS
        for record in records
        if record["bug_class"] == "memory-corruption-unspecified"
    ), "unspecified memory-corruption wording must not imply a write primitive"
    assert all(
        record["impact"] == IMPACT_RCE
        for record in records
        if record["bug_class"] == "unknown-memory-operation-rce"
    ), "an unknown primitive must not erase independently verified RCE impact"
    assert all(
        record["impact"] == IMPACT_WRITE
        for record in records
        if record["bug_class"] == "buffer-overflow"
    ), "explicit buffer overflows must retain write-primitive impact"
    assert {record["cve_id"] for record in records if record["impact"] == IMPACT_RCE} == set(VERIFIED_RCE)
    assert len(audit) == len(LEGACY_RCE_CANDIDATES)
    assert all(row["sources"] for row in audit), "every legacy RCE candidate needs a public source"
    assert all(
        any(item["type"] == "research" for item in record["sources"])
        for record in records if record["impact"] == IMPACT_RCE
    ), "every retained RCE needs a research/technical source"
    assert all(
        any(
            item["role"] == "canonical-cve-record"
            and item["supports_cve"] == record["cve_id"]
            for item in record["sources"]
        )
        for record in records + excluded
    ), "every record needs an identifier-specific canonical CVE source"


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fields = (
        "cve_id", "vendor", "date_published", "year", "impact", "bug_class", "bug_family",
        "memory_safety_basis",
        "primitive_control", "primary_scope", "scopes", "rats", "protocols",
        "scope_evidence", "reachability", "root_cause_detail", "evidence_level",
        "source_beyond_vendor_advisory", "source_urls",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            writer.writerow({
                **{field: record.get(field, "") for field in fields},
                "scopes": "; ".join(record["scopes"]),
                "rats": "; ".join(record["rats"]),
                "protocols": "; ".join(record["protocols"]),
                "evidence_level": record["evidence"]["level"],
                "source_urls": "; ".join(item["url"] for item in record["sources"]),
            })


def plot_outputs(records: list[dict[str, Any]], output: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[WARN] matplotlib unavailable; JSON and CSV outputs were still generated.")
        return

    colors = {
        IMPACT_RCE: "#b2182b",
        IMPACT_WRITE: "#ef8a62",
        IMPACT_DOS: "#4d9221",
    }

    years = sorted({r["year"] for r in records})
    bottoms = [0] * len(years)
    fig, ax = plt.subplots(figsize=(9, 4.8))
    for impact in IMPACT_ORDER:
        values = [sum(r["year"] == year and r["impact"] == impact for r in records) for year in years]
        ax.bar(years, values, bottom=bottoms, label=impact, color=colors[impact])
        bottoms = [a + b for a, b in zip(bottoms, values)]
    ax.set_ylabel("Filtered memory-safety CVEs")
    ax.set_xlabel("Publication year")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(output / "memory_cves_by_year_impact.png", dpi=180)
    plt.close(fig)

    scopes = [scope for scope in SCOPE_ORDER if any(r["primary_scope"] == scope for r in records)]
    left = [0] * len(scopes)
    fig, ax = plt.subplots(figsize=(9, 5.2))
    for impact in IMPACT_ORDER:
        values = [
            sum(r["primary_scope"] == scope and r["impact"] == impact for r in records)
            for scope in scopes
        ]
        ax.barh(scopes, values, left=left, label=impact, color=colors[impact])
        left = [a + b for a, b in zip(left, values)]
    ax.invert_yaxis()
    ax.set_xlabel("Filtered memory-safety CVEs")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(output / "memory_cves_impact_by_scope.png", dpi=180)
    plt.close(fig)

    family_colors = {
        BUG_FAMILY_BOUNDS_WRITE: "#b2182b",
        BUG_FAMILY_BOUNDS_READ: "#ef8a62",
        BUG_FAMILY_NULL: "#fddbc7",
        BUG_FAMILY_LIFETIME_POINTER: "#4393c3",
        BUG_FAMILY_ASSUMED: "#cccccc",
    }
    left = [0] * len(scopes)
    fig, ax = plt.subplots(figsize=(9, 5.2))
    for family in BUG_FAMILY_ORDER:
        values = [
            sum(
                record["primary_scope"] == scope and record["bug_family"] == family
                for record in records
            )
            for scope in scopes
        ]
        ax.barh(scopes, values, left=left, label=family, color=family_colors[family])
        left = [a + b for a, b in zip(left, values)]
    ax.invert_yaxis()
    ax.set_xlabel("Filtered memory-safety CVEs")
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(output / "memory_bug_families_by_scope.png", dpi=180)
    plt.close(fig)

    top_bug_classes = Counter(record["bug_class"] for record in records).most_common(10)
    labels = [label.replace("-", " ") for label, _ in reversed(top_bug_classes)]
    values = [value for _, value in reversed(top_bug_classes)]
    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    ax.barh(labels, values, color="#4393c3")
    ax.set_xlabel("Filtered memory-safety CVEs")
    for index, value in enumerate(values):
        ax.text(value + 0.5, index, str(value), va="center")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(output / "memory_bug_classes.png", dpi=180)
    plt.close(fig)

    coverage_labels = (
        ("CVE records", len(records)),
        ("Scope known", sum(r["primary_scope"] != SCOPE_UNKNOWN for r in records)),
        ("External research source", sum(r["source_beyond_vendor_advisory"] for r in records)),
        ("Reproduced failure", sum(r["evidence"]["reproduced_failure"] for r in records)),
        ("Primitive characterized", sum(r["evidence"]["primitive_characterized"] for r in records)),
        ("Control flow / code execution", sum(
            r["evidence"]["control_flow_redirection"] or r["evidence"]["arbitrary_code_execution"]
            for r in records
        )),
    )
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    labels, values = zip(*coverage_labels)
    ax.barh(labels, values, color=["#5b5b5b", "#4393c3", "#92c5de", "#f4a582", "#d6604d", "#b2182b"])
    ax.invert_yaxis()
    ax.set_xlabel("CVEs")
    for index, value in enumerate(values):
        ax.text(value + max(values) * 0.01, index, str(value), va="center")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(output / "public_evidence_coverage.png", dpi=180)
    plt.close(fig)


def run(
    input_dir: Path,
    typst_path: Path,
    output: Path,
    make_plots: bool = True,
) -> dict[str, Any]:
    json_files = {
        vendor: input_dir / filename
        for vendor, filename in JSON_FILENAMES.items()
    }
    raw_records = load_json_records(json_files)
    typst_records = parse_typst_records(typst_path)

    # Preserve enrichment-only CVEs as in the original pipeline.
    for cve_id, typst in typst_records.items():
        if cve_id not in raw_records:
            raw_records[cve_id] = synthetic_raw(cve_id, typst)

    records: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for cve_id in sorted(raw_records):
        enriched, rejected = enrich_record(raw_records[cve_id], typst_records.get(cve_id, {}))
        if enriched:
            records.append(enriched)
        else:
            excluded.append(rejected)

    records.sort(key=lambda item: (item["date_published"], item["cve_id"]))
    excluded.sort(key=lambda item: item["cve_id"])
    summary = build_summary(records, excluded, len(raw_records))
    audit = build_rce_audit(records, excluded)
    validate_outputs(records, excluded, audit)
    source_audit = build_source_provenance_audit(records, excluded)

    output.mkdir(parents=True, exist_ok=True)
    (output / "baseband_memory_cves.json").write_text(
        json.dumps([output_record(record) for record in records], indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (output / "excluded_non_memory_cves.json").write_text(
        json.dumps([output_record(record) for record in excluded], indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    (output / "classification_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output / "rce_candidate_audit.json").write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output / "source_provenance_audit.json").write_text(
        json.dumps(source_audit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "analysis_release": "evidence-aware-taxonomy-v2.9",
        "source_audit_date": SOURCE_AUDIT_DATE,
        "description": "Assumption-inclusive, evidence-aware baseband memory-safety CVE dataset.",
        "implementation": {
            "enrich.py": {"sha256": sha256_file(Path(__file__))},
            "policy": (
                "Deterministic local classification, explicit missing-evidence memory-bug "
                "assumption, identifier-specific canonical links, and curated public-source decisions."
            ),
        },
        "inputs": {
            **{
                f"fetched_json/{path.name}": {"sha256": sha256_file(path)}
                for path in json_files.values()
            },
            "cve_table.typ": {"sha256": sha256_file(typst_path)},
        },
        "counts": {
            "input_unique_cves": len(raw_records),
            "included_memory_safety_cves": len(records),
            "excluded": len(excluded),
        },
        "impact_policy": summary["taxonomy_notes"],
        "validation": {
            "all_checks_passed": True,
            "unique_ids": True,
            "included_excluded_disjoint": True,
            "assumed_memory_bugs_receive_conservative_dos": True,
            "retained_rces_equal_curated_verified_set": True,
            "all_retained_rces_have_research_sources": True,
            "all_legacy_rce_candidates_have_public_sources": True,
            "all_records_have_identifier_specific_canonical_sources": True,
            "inherited_input_urls_are_not_used_as_evidence": True,
        },
    }
    (output / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_csv(output / "baseband_memory_cves.csv", records)
    if make_plots:
        plot_outputs(records, output)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="directory containing freshly acquired cve_*_clean.json files",
    )
    parser.add_argument("--typst", type=Path, default=DEFAULT_TYPST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    summary = run(args.input_dir, args.typst, args.output, make_plots=not args.no_plots)
    print(f"Input unique CVEs: {summary['input_unique_cves']}")
    print(f"Included memory-safety CVEs: {summary['included_memory_safety_cves']}")
    print(f"Excluded: {summary['excluded_non_memory_or_insufficient_evidence']}")
    print("Impact:")
    for label, count in summary["impact"].items():
        print(f"  {label}: {count}")
    print("Primary scope:")
    for label, count in summary["primary_scope"].items():
        print(f"  {label}: {count}")
    print(f"Outputs: {args.output.resolve()}")


if __name__ == "__main__":
    main()
