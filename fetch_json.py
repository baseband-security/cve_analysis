#!/usr/bin/env python3
"""Discover and fetch baseband CVEs for the four chipset-vendor collections.

The old version scraped one fragile OpenCVE query for ``description:modem``.
This replacement combines three higher-recall sources:

1. a local checkout or ZIP of the official CVE List V5 corpus;
2. Android Security Bulletin tables, whose vendor/component context recovers
   records such as CVE-2022-20210 that do not identify Unisoc in CVE metadata;
3. official vendor security-index and advisory pages.

Output files retain canonical CVE JSON 5 records and are directly consumable by
``enrich.py``.  ``discovery_audit.json`` explains why each record was assigned
to a vendor and treated as baseband-related.
"""

from __future__ import annotations

import argparse
import calendar
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Iterator


VENDORS = ("Qualcomm", "Samsung", "MediaTek", "Unisoc")
OUTPUT_NAMES = {
    "Qualcomm": "cve_qualcomm_clean.json",
    "Samsung": "cve_samsung_clean.json",
    "MediaTek": "cve_mediatek_clean.json",
    "Unisoc": "cve_unisoc_clean.json",
}

CVE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
ANDROID_BULLETIN = "https://source.android.com/docs/security/bulletin/{day}?hl=en"

VENDOR_SITE_ROOTS = {
    "Qualcomm": (
        "https://www.qualcomm.com/company/product-security/bulletins",
    ),
    "Samsung": (
        "https://semiconductor.samsung.com/support/quality-support/product-security-updates/",
    ),
    "MediaTek": (
        "https://corp.mediatek.com/product-security-bulletin",
    ),
    "Unisoc": (
        "https://www.unisoc.com/en/support/product-security-bulletin/",
        "https://www.unisoc.com/en/support/announcement/",
    ),
}

# A small regression list is intentional.  These are not substitutes for
# crawling; they prevent already-identified coverage gaps from reappearing.
KNOWN_CONTEXTUAL_CVES = {
    "Qualcomm": {
        "CVE-2018-13900": {
            "context": "Android Security Bulletin: Qualcomm components; Component: Modem",
            "source": "https://source.android.com/docs/security/bulletin/2019-02-01",
        },
    },
    "MediaTek": {
        cve_id: {
            "context": "Android Security Bulletin: MediaTek components; Component: Modem (Nucleus NET TCP/IP)",
            "source": "https://source.android.com/docs/security/bulletin/2022-01-01",
        }
        for cve_id in (
            "CVE-2021-31345",
            "CVE-2021-31346",
            "CVE-2021-31889",
            "CVE-2021-31890",
        )
    },
    "Unisoc": {
        "CVE-2022-20210": {
            "context": "Android Security Bulletin: Unisoc components; Component: Modem",
            "source": "https://source.android.com/docs/security/bulletin/2022-06-01",
        },
    },
}

VENDOR_PATTERNS = {
    "Qualcomm": (
        ("vendor:qualcomm", re.compile(r"\bqualcomm\b", re.I)),
        ("product:snapdragon", re.compile(r"\bsnapdragon\b", re.I)),
    ),
    "Samsung": (
        ("vendor:samsung", re.compile(r"\bsamsung\b", re.I)),
        ("product:exynos", re.compile(r"\bexynos\b", re.I)),
    ),
    "MediaTek": (
        ("vendor:mediatek", re.compile(r"\bmediatek\b", re.I)),
        ("vendor:mtk", re.compile(r"\bmtk(?:sa)?[-_ ]?\d", re.I)),
    ),
    "Unisoc": (
        ("vendor:unisoc", re.compile(r"\bunisoc\b", re.I)),
        ("vendor:spreadtrum", re.compile(r"\bspreadtrum\b", re.I)),
    ),
}

# These are intentionally operation/surface terms, not generic words such as
# "firmware" or "remote".  The fetch stage should be high-recall, while avoiding
# obvious Wi-Fi/GPU/audio CVEs from the same silicon vendors.
BASEBAND_PATTERNS = (
    ("baseband", re.compile(r"\bbase[ -]?band\b", re.I)),
    ("modem", re.compile(r"\bmodems?\b", re.I)),
    ("cellular", re.compile(r"\bcellular\b|\bmobile station\b", re.I)),
    ("3gpp", re.compile(r"\b3gpp\b", re.I)),
    ("radio-protocol", re.compile(
        r"\b(?:rrc|rlc|pdcp|nas|nrmm)\b|"
        r"\b(?:emm|esm|gmm|rrm)\b.{0,40}\b(?:nas|message|lte|cellular|modem)\b|"
        r"radio resource control|non[- ]access stratum", re.I
    )),
    ("radio-generation", re.compile(
        r"\b(?:2g|3g|4g|5g|gsm|gprs|umts|wcdma|lte|volte|vowifi)\b", re.I
    )),
    ("ims-telephony", re.compile(
        r"\bin ims\b|\bims (?:service|stack|message|call|registration|parser|sip|sdp|rcs)\b|"
        r"IP multimedia subsystem|"
        r"\bsip (?:invite|message|parser|stack)\b|\bsdp (?:parser|message)\b", re.I
    )),
    ("sms-protocol", re.compile(
        r"\bsms (?:tpdu|tp-ud|message|protocol|parser)\b|short message service", re.I
    )),
    ("sim-uicc", re.compile(
        r"\b(?:uicc|usim)\b|\bsim toolkit\b|\bsim proactive\b|"
        r"\bproactive command\b", re.I
    )),
    ("modem-interface", re.compile(
        r"\b(?:qmi|qcril|wms)\b|radio interface layer|modem interface", re.I
    )),
)

# Context from a bulletin row can fill missing vendor metadata, but only these
# signals are by themselves strong enough to fill a missing baseband statement
# in the canonical CVE record. Generic VoWiFi/VoLTE generation terms are not:
# vendor Android services sometimes carry those labels while running on the AP.
DEFINITIVE_CONTEXT_SIGNALS = {
    "baseband", "modem", "cellular", "3gpp", "radio-protocol",
    "ims-telephony", "sms-protocol", "sim-uicc", "modem-interface",
}

INTERESTING_LINK = re.compile(
    r"cve-|security|bulletin|advisory|announcement|product-security|vulnerab", re.I
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def canonical_cve_id(value: str) -> str:
    match = CVE_RE.search(value.upper())
    return match.group(0) if match else ""


def cna(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("containers", {}).get("cna", {})


def record_id(record: dict[str, Any]) -> str:
    return canonical_cve_id(record.get("cveMetadata", {}).get("cveId", ""))


def published(record: dict[str, Any]) -> str:
    return str(record.get("cveMetadata", {}).get("datePublished", ""))


def english_descriptions(record: dict[str, Any]) -> list[str]:
    return [
        str(item.get("value", ""))
        for item in cna(record).get("descriptions", [])
        if str(item.get("lang", "en")).lower().startswith("en")
    ]


def record_search_text(record: dict[str, Any]) -> str:
    """Return CNA-owned text useful for vendor and baseband matching."""
    block = cna(record)
    metadata = record.get("cveMetadata", {})
    values: list[str] = [
        str(metadata.get("assignerShortName", "")),
        str(block.get("providerMetadata", {}).get("shortName", "")),
        str(block.get("title", "")),
        *english_descriptions(record),
    ]
    for affected in block.get("affected", []):
        values.extend((
            str(affected.get("vendor", "")),
            str(affected.get("product", "")),
            str(affected.get("packageName", "")),
            " ".join(map(str, affected.get("platforms", []))),
            " ".join(map(str, affected.get("modules", []))),
        ))
        for version in affected.get("versions", []):
            values.append(str(version.get("version", "")))
    for problem in block.get("problemTypes", []):
        for description in problem.get("descriptions", []):
            values.append(str(description.get("description", "")))
    for reference in block.get("references", []):
        values.extend((
            str(reference.get("url", "")),
            str(reference.get("name", "")),
            " ".join(map(str, reference.get("tags", []))),
        ))
    return "\n".join(value for value in values if value)


def record_baseband_text(record: dict[str, Any]) -> str:
    """Return component evidence without broad affected-chipset inventories.

    Qualcomm records commonly attach hundreds of products and versions spanning
    several subsystems. Those fields identify the vendor, but a modem model in
    that inventory does not prove that the CVE's vulnerable component is modem
    code. Baseband matching therefore uses descriptions, titles, problem types,
    explicit module/package names, and narrowly named products only.
    """
    block = cna(record)
    values: list[str] = [str(block.get("title", "")), *english_descriptions(record)]
    for affected in block.get("affected", []):
        values.extend((
            str(affected.get("packageName", "")),
            " ".join(map(str, affected.get("modules", []))),
        ))
        product = str(affected.get("product", ""))
        if re.search(r"\b(?:modem|base[ -]?band)\b", product, re.I) and product.lower() != "snapdragon":
            values.append(product)
    for problem in block.get("problemTypes", []):
        for description in problem.get("descriptions", []):
            values.append(str(description.get("description", "")))
    return "\n".join(value for value in values if value)


def signal_matches(text: str, patterns: Iterable[tuple[str, re.Pattern[str]]]) -> list[str]:
    return [name for name, pattern in patterns if pattern.search(text)]


def vendor_matches(record: dict[str, Any]) -> dict[str, list[str]]:
    text = record_search_text(record)
    return {
        vendor: signal_matches(text, VENDOR_PATTERNS[vendor])
        for vendor in VENDORS
        if signal_matches(text, VENDOR_PATTERNS[vendor])
    }


def baseband_matches(text_or_record: str | dict[str, Any]) -> list[str]:
    text = record_baseband_text(text_or_record) if isinstance(text_or_record, dict) else text_or_record
    return signal_matches(text, BASEBAND_PATTERNS)


def eligible_baseband_signals(vendor: str, signals: Iterable[str]) -> bool:
    """Reject known ambiguous matches while retaining high recall elsewhere."""
    signal_set = set(signals)
    if not signal_set:
        return False
    # Samsung's product/mobile CVEs frequently mention a handset's 3G/4G/5G
    # marketing name without touching cellular firmware. Other explicit modem,
    # protocol, IMS, SMS, or SIM signals remain eligible.
    if vendor == "Samsung" and signal_set == {"radio-generation"}:
        return False
    return True


def choose_vendor(record: dict[str, Any]) -> tuple[str, list[str]]:
    """Choose one vendor, preferring CNA/affected identity over loose text."""
    matches = vendor_matches(record)
    if not matches:
        return "", []
    identity = "\n".join((
        str(record.get("cveMetadata", {}).get("assignerShortName", "")),
        str(cna(record).get("providerMetadata", {}).get("shortName", "")),
        "\n".join(str(item.get("vendor", "")) for item in cna(record).get("affected", [])),
    ))
    identity_hits = {
        vendor: signal_matches(identity, VENDOR_PATTERNS[vendor])
        for vendor in matches
    }
    ranked = sorted(
        matches,
        key=lambda vendor: (bool(identity_hits[vendor]), len(identity_hits[vendor]), len(matches[vendor])),
        reverse=True,
    )
    selected = ranked[0]
    return selected, matches[selected]


@dataclass
class Candidate:
    cve_id: str
    vendor: str
    vendor_signals: set[str] = field(default_factory=set)
    baseband_signals: set[str] = field(default_factory=set)
    discovery_methods: set[str] = field(default_factory=set)
    source_urls: set[str] = field(default_factory=set)
    contexts: set[str] = field(default_factory=set)
    was_existing: bool = False

    def merge(
        self,
        *,
        vendor_signals: Iterable[str] = (),
        baseband_signals: Iterable[str] = (),
        method: str = "",
        source: str = "",
        context: str = "",
        existing: bool = False,
    ) -> None:
        self.vendor_signals.update(vendor_signals)
        self.baseband_signals.update(baseband_signals)
        if method:
            self.discovery_methods.add(method)
        if source:
            self.source_urls.add(source)
        if context:
            self.contexts.add(re.sub(r"\s+", " ", context).strip())
        self.was_existing = self.was_existing or existing


class PageParser(HTMLParser):
    """Collect headings, table rows, links, and visible text without bs4."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.heading = ""
        self._heading_tag = ""
        self._heading_parts: list[str] = []
        self._in_cell = False
        self._cell_parts: list[str] = []
        self._row_cells: list[str] = []
        self.rows: list[tuple[str, list[str]]] = []
        self.links: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"h1", "h2", "h3", "h4"}:
            self._heading_tag = tag
            self._heading_parts = []
        elif tag == "tr":
            self._row_cells = []
        elif tag in {"td", "th"}:
            self._in_cell = True
            self._cell_parts = []
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._heading_tag:
            self.heading = re.sub(r"\s+", " ", " ".join(self._heading_parts)).strip()
            self._heading_tag = ""
        elif tag in {"td", "th"} and self._in_cell:
            cell = re.sub(r"\s+", " ", " ".join(self._cell_parts)).strip()
            self._row_cells.append(cell)
            self._in_cell = False
        elif tag == "tr" and self._row_cells:
            self.rows.append((self.heading, self._row_cells[:]))

    def handle_data(self, data: str) -> None:
        value = data.strip()
        if not value:
            return
        self.text_parts.append(value)
        if self._heading_tag:
            self._heading_parts.append(value)
        if self._in_cell:
            self._cell_parts.append(value)

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)


def parse_page(html: str) -> PageParser:
    parser = PageParser()
    parser.feed(html)
    return parser


def vendor_from_context(text: str) -> str:
    for vendor in VENDORS:
        if signal_matches(text, VENDOR_PATTERNS[vendor]):
            return vendor
    return ""


def contextual_candidates(
    html: str,
    source_url: str,
    method: str,
    default_vendor: str = "",
    allow_page_fallback: bool = True,
) -> list[tuple[str, str, str, list[str]]]:
    """Extract CVE/vendor pairs only when the same row identifies a baseband surface."""
    page = parse_page(html)
    found: list[tuple[str, str, str, list[str]]] = []
    for heading, cells in page.rows:
        row = " | ".join(cells)
        ids = unique(canonical_cve_id(match.group(0)) for match in CVE_RE.finditer(row))
        if not ids:
            continue
        context = f"{heading} | {row}".strip(" |")
        vendor = vendor_from_context(heading) or vendor_from_context(row) or default_vendor
        signals = baseband_matches(context)
        if vendor and signals:
            found.extend((cve_id, vendor, context, signals) for cve_id in ids)

    # Individual advisory pages often use cards rather than a table.  Only use
    # page-wide context when exactly one CVE appears, preventing one occurrence
    # of "modem" on an index page from pulling in every unrelated vendor CVE.
    page_ids = unique(canonical_cve_id(match.group(0)) for match in CVE_RE.finditer(page.text))
    if allow_page_fallback and len(page_ids) == 1:
        vendor = vendor_from_context(page.text) or default_vendor
        signals = baseband_matches(page.text)
        item = (page_ids[0], vendor, page.text[:1000], signals)
        if vendor and signals and not any(row[0] == page_ids[0] and row[1] == vendor for row in found):
            found.append(item)
    return found


class Fetcher:
    def __init__(self, delay: float = 0.15, retries: int = 3) -> None:
        self.delay = max(0.0, delay)
        self.retries = max(1, retries)
        self.last_request = 0.0
        self.headers = {
            "User-Agent": "baseband-cve-research-fetcher/3.0 (+https://www.cve.org/)",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.5",
            "Accept-Encoding": "gzip",
        }

    def get_bytes(self, url: str) -> bytes:
        error: Exception | None = None
        for attempt in range(self.retries):
            wait = self.delay - (time.monotonic() - self.last_request)
            if wait > 0:
                time.sleep(wait)
            request = urllib.request.Request(url, headers=self.headers)
            try:
                with urllib.request.urlopen(request, timeout=45) as response:
                    self.last_request = time.monotonic()
                    raw = response.read()
                    if response.headers.get("Content-Encoding", "").lower() == "gzip":
                        raw = gzip.decompress(raw)
                    return raw
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                self.last_request = time.monotonic()
                error = exc
                if isinstance(exc, urllib.error.HTTPError) and exc.code in {400, 401, 403, 404}:
                    break
                time.sleep(min(2 ** attempt, 8))
        raise RuntimeError(f"failed to fetch {url}: {error}")

    def get_text(self, url: str) -> str:
        return self.get_bytes(url).decode("utf-8", errors="replace")

    def get_json(self, url: str) -> dict[str, Any]:
        value = json.loads(self.get_text(url))
        if not isinstance(value, dict):
            raise RuntimeError(f"expected JSON object from {url}")
        return value


def iter_json_records(path: Path) -> Iterator[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    values = value if isinstance(value, list) else [value]
    for record in values:
        if isinstance(record, dict) and record_id(record):
            yield record


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(root: Path) -> str:
    """Read a checkout's HEAD without invoking Git or modifying the source."""
    git_path = root / ".git"
    if git_path.is_file():
        value = git_path.read_text(encoding="utf-8").strip()
        if value.startswith("gitdir:"):
            git_path = (root / value.split(":", 1)[1].strip()).resolve()
    head_path = git_path / "HEAD"
    if not head_path.is_file():
        return ""
    head = head_path.read_text(encoding="utf-8").strip()
    if not head.startswith("ref:"):
        return head
    ref = head.split(None, 1)[1]
    loose_ref = git_path / ref
    if loose_ref.is_file():
        return loose_ref.read_text(encoding="utf-8").strip()
    packed = git_path / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "^")):
                commit, name = line.split(" ", 1)
                if name == ref:
                    return commit
    return ""


def iter_cve_list_directory(root: Path) -> Iterator[dict[str, Any]]:
    cves = root / "cves"
    search_root = cves if cves.is_dir() else root
    for path in search_root.rglob("CVE-*.json"):
        try:
            yield from iter_json_records(path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: skipping {path}: {exc}", file=sys.stderr)


def iter_cve_list_zip(path: Path) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not re.search(r"(?:^|/)cves/\d{4}/\d+x/CVE-\d{4}-\d+\.json$", name):
                continue
            try:
                value = json.loads(archive.read(name))
                if isinstance(value, dict) and record_id(value):
                    yield value
            except (KeyError, json.JSONDecodeError) as exc:
                print(f"warning: skipping {name}: {exc}", file=sys.stderr)


def load_existing(directory: Path, selected: set[str]) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {vendor: {} for vendor in selected}
    for vendor in selected:
        path = directory / OUTPUT_NAMES[vendor]
        if not path.is_file():
            continue
        for record in iter_json_records(path):
            result[vendor][record_id(record)] = record
    return result


def merge_record(fresh: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
    """Prefer current canonical JSON while preserving local manual enrichment."""
    merged = dict(fresh)
    if existing and "typst_enrichment" in existing and "typst_enrichment" not in merged:
        merged["typst_enrichment"] = existing["typst_enrichment"]
    return merged


def month_days(start_year: int, end_year: int) -> Iterator[str]:
    today = date.today()
    for year in range(start_year, end_year + 1):
        # Monthly Android Security Bulletins begin in August 2015.
        first_month = 8 if year == 2015 else 1
        if year < 2015:
            continue
        last_month = today.month if year == today.year else 12
        for month in range(first_month, last_month + 1):
            yield f"{year:04d}-{month:02d}-01"


def add_candidate(
    candidates: dict[tuple[str, str], Candidate],
    cve_id: str,
    vendor: str,
    **kwargs: Any,
) -> Candidate:
    key = (vendor, canonical_cve_id(cve_id))
    if not key[1]:
        raise ValueError(f"invalid CVE ID: {cve_id}")
    candidate = candidates.setdefault(key, Candidate(cve_id=key[1], vendor=vendor))
    candidate.merge(**kwargs)
    return candidate


def discover_android(
    fetcher: Fetcher,
    candidates: dict[tuple[str, str], Candidate],
    selected: set[str],
    start_year: int,
    end_year: int,
) -> int:
    count = 0
    for day in month_days(start_year, end_year):
        url = ANDROID_BULLETIN.format(day=day)
        try:
            html = fetcher.get_text(url)
        except RuntimeError as exc:
            # Not every month has a bulletin.  Missing pages are expected.
            print(f"android bulletin skipped: {exc}", file=sys.stderr)
            continue
        for cve_id, vendor, context, signals in contextual_candidates(
            html, url, "android-bulletin", allow_page_fallback=False
        ):
            if vendor not in selected:
                continue
            add_candidate(
                candidates, cve_id, vendor,
                vendor_signals=[f"bulletin-section:{vendor.lower()}"],
                baseband_signals=signals,
                method="android-bulletin",
                source=url,
                context=context,
            )
            count += 1
    return count


def allowed_vendor_url(vendor: str, url: str) -> bool:
    host = urllib.parse.urlparse(url).netloc.lower()
    allowed = {
        urllib.parse.urlparse(root).netloc.lower()
        for root in VENDOR_SITE_ROOTS[vendor]
    }
    return host in allowed or any(host.endswith("." + item) for item in allowed)


def discover_vendor_sites(
    fetcher: Fetcher,
    candidates: dict[tuple[str, str], Candidate],
    selected: set[str],
    max_pages: int,
) -> int:
    discoveries = 0
    for vendor in sorted(selected):
        queue = list(VENDOR_SITE_ROOTS[vendor])
        seen: set[str] = set()
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            normalized = url.split("#", 1)[0]
            if normalized in seen or not allowed_vendor_url(vendor, normalized):
                continue
            seen.add(normalized)
            try:
                html = fetcher.get_text(normalized)
            except RuntimeError as exc:
                print(f"vendor page skipped: {exc}", file=sys.stderr)
                continue
            page = parse_page(html)
            for cve_id, context_vendor, context, signals in contextual_candidates(
                html, normalized, "vendor-site", default_vendor=vendor
            ):
                # The page is on a hard-coded official vendor domain.  This is
                # stronger vendor attribution than missing CNA metadata.
                assigned_vendor = context_vendor or vendor
                if assigned_vendor != vendor:
                    continue
                add_candidate(
                    candidates, cve_id, vendor,
                    vendor_signals=[f"official-domain:{vendor.lower()}"],
                    baseband_signals=signals,
                    method="vendor-site",
                    source=normalized,
                    context=context,
                )
                discoveries += 1
            for href in page.links:
                linked = urllib.parse.urljoin(normalized, href).split("#", 1)[0]
                if (
                    allowed_vendor_url(vendor, linked)
                    and INTERESTING_LINK.search(linked)
                    and linked not in seen
                    and linked not in queue
                ):
                    queue.append(linked)
    return discoveries


def record_sort_key(record: dict[str, Any]) -> tuple[str, str]:
    return (published(record), record_id(record))


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vendor", action="append", choices=("all", *VENDORS), default=[],
        help="vendor to generate; repeatable (default: all)",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--cve-list-dir", type=Path, help="official cvelistV5 checkout")
    source.add_argument("--cve-list-zip", type=Path, help="official cvelistV5 baseline/archive ZIP")
    parser.add_argument(
        "--merge-dir", type=Path, default=root / "saved_json",
        help="existing curated vendor JSON to preserve and merge (default: saved_json)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=root / "fetched_json",
        help="destination for vendor JSON and discovery audit (default: fetched_json)",
    )
    parser.add_argument(
        "--android-bulletins", action=argparse.BooleanOptionalAction, default=True,
        help="crawl Android Security Bulletin vendor/component tables (default: on)",
    )
    parser.add_argument(
        "--vendor-sites", action=argparse.BooleanOptionalAction, default=True,
        help="crawl official vendor security pages (default: on)",
    )
    parser.add_argument("--offline", action="store_true", help="disable all HTTP requests")
    parser.add_argument("--since-year", type=int, default=2010)
    parser.add_argument("--until-year", type=int, default=date.today().year)
    parser.add_argument("--max-vendor-pages", type=int, default=300)
    parser.add_argument("--request-delay", type=float, default=0.15)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--strict-fetch", action="store_true",
        help="fail instead of auditing CVE IDs whose canonical record cannot be fetched",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = set(args.vendor)
    selected = set(VENDORS) if not requested or "all" in requested else requested
    if args.since_year > args.until_year:
        raise SystemExit("--since-year must not be after --until-year")

    candidates: dict[tuple[str, str], Candidate] = {}
    canonical: dict[str, dict[str, Any]] = {}
    existing = load_existing(args.merge_dir, selected)

    for vendor in selected:
        for cve_id, record in existing[vendor].items():
            canonical.setdefault(cve_id, record)
            add_candidate(
                candidates, cve_id, vendor,
                vendor_signals=["existing-vendor-collection"],
                baseband_signals=baseband_matches(record) or ["existing-curated-baseband"],
                method="existing-curated-dataset",
                existing=True,
            )

    # Keep identified regression cases even when a live Android crawl is
    # unavailable. Adding them before a full-corpus scan also lets that scan
    # retain their canonical records without holding every unrelated CVE.
    for vendor in selected:
        for cve_id, hint in KNOWN_CONTEXTUAL_CVES.get(vendor, {}).items():
            add_candidate(
                candidates, cve_id, vendor,
                vendor_signals=[f"curated-context:{vendor.lower()}"],
                baseband_signals=baseband_matches(hint["context"]),
                method="known-coverage-regression",
                source=hint["source"],
                context=hint["context"],
            )

    scanned = 0
    iterator: Iterable[dict[str, Any]] = ()
    if args.cve_list_dir:
        iterator = iter_cve_list_directory(args.cve_list_dir)
    elif args.cve_list_zip:
        iterator = iter_cve_list_zip(args.cve_list_zip)

    preselected_ids = {cve_id for _, cve_id in candidates}
    for record in iterator:
        scanned += 1
        cve_id = record_id(record)
        if record.get("cveMetadata", {}).get("state") not in {None, "PUBLISHED"}:
            continue
        record_year_text = published(record)[:4] or cve_id.split("-")[1]
        try:
            record_year = int(record_year_text)
        except ValueError:
            continue
        if not args.since_year <= record_year <= args.until_year:
            continue
        vendor, vendor_signals = choose_vendor(record)
        signals = baseband_matches(record)
        if vendor in selected and eligible_baseband_signals(vendor, signals):
            canonical[cve_id] = record
            add_candidate(
                candidates, cve_id, vendor,
                vendor_signals=vendor_signals,
                baseband_signals=signals,
                method="official-cve-list-v5",
            )
        elif cve_id in preselected_ids:
            canonical[cve_id] = record

    fetcher = Fetcher(args.request_delay, args.retries)
    source_counts: Counter[str] = Counter()
    if not args.offline and args.android_bulletins:
        source_counts["android-bulletin-row-matches"] = discover_android(
            fetcher, candidates, selected, args.since_year, args.until_year
        )
    if not args.offline and args.vendor_sites:
        source_counts["vendor-site-page-matches"] = discover_vendor_sites(
            fetcher, candidates, selected, args.max_vendor_pages
        )

    missing: list[dict[str, str]] = []
    for candidate in sorted(candidates.values(), key=lambda item: item.cve_id):
        if candidate.cve_id in canonical:
            continue
        if args.offline:
            missing.append({
                "cve_id": candidate.cve_id,
                "vendor": candidate.vendor,
                "reason": "canonical record unavailable in offline inputs",
            })
            continue
        try:
            record = fetcher.get_json(CVE_API.format(cve_id=candidate.cve_id))
            if record_id(record) != candidate.cve_id:
                raise RuntimeError("CVE API returned a mismatched record")
            canonical[candidate.cve_id] = record
        except RuntimeError as exc:
            missing.append({
                "cve_id": candidate.cve_id,
                "vendor": candidate.vendor,
                "reason": str(exc),
            })
            if args.strict_fetch:
                raise

    output_records: dict[str, list[dict[str, Any]]] = {vendor: [] for vendor in selected}
    audit_rows: list[dict[str, Any]] = []
    rejected_contextual: list[dict[str, Any]] = []
    for candidate in sorted(candidates.values(), key=lambda item: (item.vendor, item.cve_id)):
        record = canonical.get(candidate.cve_id)
        if not record:
            continue
        canonical_signals = set(baseband_matches(record))
        context_is_definitive = bool(candidate.baseband_signals & DEFINITIVE_CONTEXT_SIGNALS)
        corpus_selected = "official-cve-list-v5" in candidate.discovery_methods
        if (
            not candidate.was_existing
            and not corpus_selected
            and not eligible_baseband_signals(candidate.vendor, canonical_signals)
            and not context_is_definitive
        ):
            rejected_contextual.append({
                "cve_id": candidate.cve_id,
                "vendor": candidate.vendor,
                "reason": "context was baseband-adjacent but neither definitive nor corroborated by canonical CVE text",
                "context_signals": sorted(candidate.baseband_signals),
                "discovery_methods": sorted(candidate.discovery_methods),
                "source_urls": sorted(candidate.source_urls),
            })
            continue
        old = existing[candidate.vendor].get(candidate.cve_id)
        output_records[candidate.vendor].append(merge_record(record, old))
        audit_rows.append({
            "cve_id": candidate.cve_id,
            "vendor": candidate.vendor,
            "new_to_existing_collection": not candidate.was_existing,
            "vendor_signals": sorted(candidate.vendor_signals),
            "baseband_signals": sorted(candidate.baseband_signals),
            "canonical_baseband_signals": sorted(canonical_signals),
            "discovery_methods": sorted(candidate.discovery_methods),
            "source_urls": sorted(candidate.source_urls),
            "contexts": sorted(candidate.contexts),
        })

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for vendor in sorted(selected):
        records_by_id = {record_id(record): record for record in output_records[vendor]}
        records = sorted(records_by_id.values(), key=record_sort_key, reverse=True)
        destination = args.output_dir / OUTPUT_NAMES[vendor]
        destination.write_text(
            json.dumps(records, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    audit = {
        "schema_version": "1.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "canonical_record_source": "official CVE List V5 or CVE Services API",
            "vendor_context_sources": "CNA fields, Android bulletin table sections, and official vendor domains",
            "baseband_rule": "at least one explicit baseband/modem/cellular/protocol/interface signal",
            "existing_records": "preserved as previously curated inputs",
            "warning": "This is a high-recall acquisition set; enrich.py performs the later memory-safety filter.",
        },
        "inputs": {
            "cve_list_dir": str(args.cve_list_dir) if args.cve_list_dir else "",
            "cve_list_git_revision": git_revision(args.cve_list_dir) if args.cve_list_dir else "",
            "cve_list_zip": str(args.cve_list_zip) if args.cve_list_zip else "",
            "cve_list_zip_sha256": sha256_file(args.cve_list_zip) if args.cve_list_zip else "",
            "merge_dir": str(args.merge_dir),
            "official_cve_records_scanned": scanned,
            "android_bulletins": bool(args.android_bulletins and not args.offline),
            "vendor_sites": bool(args.vendor_sites and not args.offline),
            "since_year": args.since_year,
            "until_year": args.until_year,
        },
        "source_match_counts": dict(sorted(source_counts.items())),
        "output_counts": {
            vendor: len({record_id(record) for record in output_records[vendor]})
            for vendor in sorted(selected)
        },
        "new_record_counts": dict(Counter(
            row["vendor"] for row in audit_rows if row["new_to_existing_collection"]
        )),
        "missing_canonical_records": missing,
        "rejected_contextual_candidates": rejected_contextual,
        "records": audit_rows,
    }
    (args.output_dir / "discovery_audit.json").write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Official CVE records scanned: {scanned}")
    for vendor in sorted(selected):
        old_count = len(existing[vendor])
        new_count = audit["output_counts"][vendor]
        print(f"{vendor}: {new_count} records ({new_count - old_count:+d} versus merge input)")
    print(f"Missing canonical records: {len(missing)}")
    print(f"Outputs: {args.output_dir.resolve()}")
    return 0 if not (args.strict_fetch and missing) else 1


if __name__ == "__main__":
    raise SystemExit(main())
