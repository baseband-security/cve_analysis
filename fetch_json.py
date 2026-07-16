# #!/usr/bin/env python3

import sys
import re
import urllib.request

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.6367.155 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;"
        "q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
}

import urllib.request
import urllib.error
import gzip
import zlib
import time

def fetch_html(url: str) -> str:
    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw       = resp.read()
            enc       = resp.headers.get("Content-Encoding", "")
            final_url = resp.geturl()

            if enc == "gzip":
                raw = gzip.decompress(raw)
            elif enc == "deflate":
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)

            html = raw.decode("utf-8", errors="replace")

            if "challenge" in final_url or "login" in final_url:
                raise RuntimeError(
                    f"Redirected to {final_url!r} — save the page from your browser instead."
                )
            if len(html) < 2000 and (
                "captcha" in html.lower()
                or "cloudflare" in html.lower()
                or "access denied" in html.lower()
            ):
                raise RuntimeError(
                    "Bot-challenge page received — save the CVE page from your browser instead."
                )

            return html

    except urllib.error.HTTPError as e:
        time.sleep(5)
        fetch_html(url)
    except urllib.error.URLError as e:
        time.sleep(5)
        fetch_html(url)

#!/usr/bin/env python3

import re

def extract_opencve_links(html):
    matches = re.findall(
        r'(?:href=")?(?:https?://www\.opencve\.io)?/cve/(CVE-\d{4}-\d+)',
        html
    )

    results = []
    for cve in matches:
        url = f"https://www.opencve.io/cve/{cve}"
        results.append(url)

    return results


import json
import re
import sys
from bs4 import BeautifulSoup
 
 
# ── helpers ──────────────────────────────────────────────────────────────────
def _extract_plain_json(soup: BeautifulSoup) -> list[dict]:
    results = []
    # OpenCVE uses specific IDs for different JSON sources
    modal_ids = ["modal-mitre-json"]
    
    for modal_id in modal_ids:
        modal = soup.find("div", id=modal_id)
        if modal:
            # The actual JSON-like content is inside a div with class "rainbow"
            # We need to strip the "»" toggle characters and labels like "(string)"
            json_container = modal.find("div", class_="modal-body codejson")
            if json_container:
                # This is complex because of the extra UI elements (toggles, type labels)
                # You might need a more surgical approach to remove 'rainbowToggle' 
                # and 'rainbowType' spans before calling get_text()
                for extra in json_container.find_all("span", class_="rainbowType"):
                    extra.decompose()
                for toggle in json_container.find_all("a", class_="rainbowToggle"):
                    toggle.decompose()
                
                raw = json_container.get_text(strip=True)
                try:
                    results.append(json.loads(raw))
                except json.JSONDecodeError:
                    # If it's still not valid JSON, further cleaning is needed
                    pass
    return results
 
 
def _cna_block(blobs: list[dict]) -> dict | None:
    """
    Return the best blob that contains containers.cna.
    Prefer blobs where cna.affected is non-empty — some page variants put an
    ADP-only blob first whose cna has no affected/versions data.
    """
    fallback = None
    for b in blobs:
        if "containers" in b and "cna" in b.get("containers", {}):
            affected = b["containers"]["cna"].get("affected", [])
            if affected:          # has real data — use immediately
                return b
            if fallback is None:  # remember first cna blob as fallback
                fallback = b
    return fallback
 
 
def _nvd_block(blobs: list[dict]) -> dict | None:
    """Return the blob that looks like the NVD flat record (has 'metrics' at top level)."""
    for b in blobs:
        if "metrics" in b and "cvssMetricV31" in b.get("metrics", {}):
            return b
    return None
 
 
# ── field extractors ──────────────────────────────────────────────────────────
 
def extract_cve_id(soup: BeautifulSoup) -> str:
    # Page <title> always starts with the CVE id
    title = soup.find("title")
    if title:
        m = re.match(r"(CVE-[\d-]+)", title.get_text())
        if m:
            return m.group(1)
    # Fallback: navbar link
    a = soup.find("a", class_="navbar-title-cve-link")
    return a.get_text(strip=True) if a else "CVE-UNKNOWN"
 
 
def extract_description(blobs: list[dict], soup: BeautifulSoup) -> str:
    # 1. Try cna.descriptions
    cna = _cna_block(blobs)
    if cna:
        for d in cna["containers"]["cna"].get("descriptions", []):
            if d.get("lang", "en") == "en":
                return d["value"].strip()
 
    # 2. Fallback to the visible description div
    div = soup.find("div", id="cve-description-text")
    if div:
        return div.get_text(strip=True)
 
    return "N/A"
 
 
def extract_cvss(blobs: list[dict], soup: BeautifulSoup) -> dict:
    """
    Returns a dict with keys: version, score, severity, vector,
    attack_vector, attack_complexity, privileges_required,
    user_interaction, scope, confidentiality, integrity, availability.
    Falls back to the visible score badge if JSON is missing.
    """
 
    def _from_cvss_obj(obj: dict) -> dict:
        return {
            "version":             obj.get("version", ""),
            "score":               obj.get("baseScore", ""),
            "severity":            obj.get("baseSeverity", ""),
            "vector":              obj.get("vectorString", ""),
            "attack_vector":       obj.get("attackVector", ""),
            "attack_complexity":   obj.get("attackComplexity", ""),
            "privileges_required": obj.get("privilegesRequired", ""),
            "user_interaction":    obj.get("userInteraction", ""),
            "scope":               obj.get("scope", ""),
            "confidentiality":     obj.get("confidentialityImpact", ""),
            "integrity":           obj.get("integrityImpact", ""),
            "availability":        obj.get("availabilityImpact", ""),
        }
 
    # Try cna metrics
    cna = _cna_block(blobs)
    if cna:
        for m in cna["containers"]["cna"].get("metrics", []):
            for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
                if key in m:
                    return _from_cvss_obj(m[key])
 
    # Try NVD blob
    nvd = _nvd_block(blobs)
    if nvd:
        for entry in nvd.get("metrics", {}).get("cvssMetricV31", []):
            return _from_cvss_obj(entry.get("cvssData", {}))
 
    # Fallback: scrape the badge text
    badge = soup.find("span", class_="label-danger")
    if badge:
        text = badge.get_text(strip=True)   # e.g. "7.5 High"
        parts = text.split()
        return {"score": parts[0] if parts else "?",
                "severity": parts[1] if len(parts) > 1 else "?",
                "version": "3.1", "vector": "", "attack_vector": "",
                "attack_complexity": "", "privileges_required": "",
                "user_interaction": "", "scope": "", "confidentiality": "",
                "integrity": "", "availability": ""}
 
    return {}
 
 
# Snapdragon platform tokens — when the product field is really a platform list
_PLATFORM_KEYWORDS = re.compile(
    r"snapdragon|\biot\b|wearable|compute|connectivity|voice|music|\bauto\b|mobile|industrial",
    re.I,
)
 
def extract_vendor_product_platforms(blobs: list[dict]) -> tuple[str, str, list[str]]:
    """
    Returns (vendor, product, platforms) from cna.affected[0].
    Some older Qualcomm CVEs put the platform list in the product field instead
    of a single product name — detect and normalise that case.
    """
    cna = _cna_block(blobs)
    if cna:
        affected = cna["containers"]["cna"].get("affected", [])
        if affected:
            a0       = affected[0]
            vendor   = a0.get("vendor", "")
            product  = a0.get("product", "")
            platforms = list(a0.get("platforms", []))
 
            # If product contains commas and looks like a list of platform names,
            # split it out and use "Snapdragon" as the canonical product name.
            if "," in product and _PLATFORM_KEYWORDS.search(product):
                platforms = platforms or [p.strip() for p in product.split(",") if p.strip()]
                product = "Snapdragon"
 
            return (vendor, product, platforms)
    return ("", "", [])
 
 
def extract_affected_versions(blobs: list[dict]) -> list[str]:
    """
    Return deduplicated list of affected items from ALL entries in cna.affected[].
    Each entry may carry either a versions[] list (chipset/firmware names) or a
    plain product name with no versions — we collect both so nothing is missed.
    """
    cna = _cna_block(blobs)
    if not cna:
        return []
    affected = cna["containers"]["cna"].get("affected", [])
    seen = set()
    items = []
 
    def _add(name: str):
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            items.append(name)
 
    for entry in affected:
        versions = entry.get("versions", [])
        if versions:
            # Normal case: explicit version list
            for v in versions:
                if v.get("status") == "affected":
                    _add(v["version"])
        else:
            # No versions list — add the product name itself
            product = entry.get("product", "").strip()
            # Skip if product is a comma-separated platform list (handled elsewhere)
            if product and "," not in product:
                _add(product)
 
    return items
 
 
def extract_cwe(blobs: list[dict], soup: BeautifulSoup) -> tuple[str, str]:
    """
    Returns (cweId, description).  Search order:
      1. cna.problemTypes   type=CWE           (preferred)
      2. adp[].problemTypes type=CWE           (CISA ADP Vulnrichment fallback)
      3. cna.problemTypes   type=text          (older Qualcomm style, mine CWE-NNN from text)
      4. HTML scrape
    """
    cna = _cna_block(blobs)
 
    # 1. cna with explicit CWE type
    if cna:
        for pt in cna["containers"]["cna"].get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("type") == "CWE" and d.get("cweId"):
                    cwe_id  = d["cweId"]
                    cwe_desc = re.sub(rf"^{re.escape(cwe_id)}\s*", "", d.get("description", "")).strip()
                    return cwe_id, cwe_desc
 
    # 2. ADP blocks (CISA ADP Vulnrichment carries the proper CWE id)
    if cna:
        for adp in cna["containers"].get("adp", []):
            for pt in adp.get("problemTypes", []):
                for d in pt.get("descriptions", []):
                    if d.get("type") == "CWE" and d.get("cweId"):
                        cwe_id  = d["cweId"]
                        cwe_desc = re.sub(rf"^{re.escape(cwe_id)}\s*", "", d.get("description", "")).strip()
                        return cwe_id, cwe_desc
 
    # 3. cna type=text fallback — try to extract "CWE-NNN" from the description string
    if cna:
        for pt in cna["containers"]["cna"].get("problemTypes", []):
            for d in pt.get("descriptions", []):
                desc_text = d.get("description", "").strip()
                m = re.search(r"(CWE-\d+)", desc_text)
                if m:
                    return m.group(1), desc_text
                if desc_text:
                    return "", desc_text  # plain text, no id
 
    # 4. Fallback: scrape the weaknesses table/link
    a = soup.find("a", href=re.compile(r"/cve/\?weakness=CWE-"))
    if a:
        cwe_id = a.get_text(strip=True)
        return cwe_id, cwe_id
    return ("", "")
 
 
def extract_title(blobs: list[dict], soup: BeautifulSoup) -> str:
    cna = _cna_block(blobs)
    if cna:
        # 1. Explicit title field
        t = cna["containers"]["cna"].get("title", "")
        if t:
            return t
        # 2. Derive from cna.problemTypes text
        #    e.g. "Improper Validation of Array Index in MODEM"
        for pt in cna["containers"]["cna"].get("problemTypes", []):
            for d in pt.get("descriptions", []):
                text = d.get("description", "").strip()
                # Skip bare CWE identifiers like "CWE-129"
                if text and not re.match(r"^CWE-\d+$", text):
                    return text
 
    # 3. Fallback: navbar subtitle
    small = soup.find("small")
    if small:
        return small.get_text(strip=True).lstrip("- ").strip()
    return ""
 
 
def extract_published(blobs: list[dict], soup: BeautifulSoup) -> str:
    cna = _cna_block(blobs)
    if cna:
        return cna.get("cveMetadata", {}).get("datePublished", "")[:10]
 
    span = soup.find("span", class_="cve-summary-label",
                     string=re.compile("Published"))
    if span:
        val = span.find_next_sibling("span", class_="cve-summary-value")
        if val:
            return val.get_text(strip=True)
    return ""
 
 
def extract_references(blobs: list[dict], soup: BeautifulSoup) -> list[dict]:
    """Return list of {url, tags} dicts."""
    cna = _cna_block(blobs)
    if cna:
        refs = cna["containers"]["cna"].get("references", [])
        if refs:
            return [{"url": r.get("url", ""), "tags": r.get("tags", [])} for r in refs]
 
    # Fallback: scrape reference table
    table = soup.find("div", id="cve-references")
    if not table:
        return []
    return [{"url": a["href"], "tags": []} for a in table.find_all("a", href=True)
            if a["href"].startswith("http")]
 
 
# ── impact / root-cause heuristics ───────────────────────────────────────────
 
def _infer_impact(description: str, cwe_id: str) -> str:
    """
    Best-effort impact label from description text and CWE.
    Returns one of: DoS, RCE, Info Disclosure, Privilege Escalation, or a
    combination like "DoS / RCE".  Defaults to "—" when unclear.
    """
    desc = description.lower()
    cwe  = cwe_id.upper()
 
    impacts = []
    if re.search(r"\bremote code exec|arbitrary code|rce\b|code execution", desc):
        impacts.append("RCE")
    elif re.search(r"memory corruption|use.after.free|buffer overflow|heap overflow|stack overflow|out.of.bounds write", desc):
        impacts.append("DoS / RCE?")
    elif re.search(r"\bdos\b|denial.of.service|transient dos|reboot|crash|hang|deadlock|infinite loop|null pointer|assertion", desc):
        impacts.append("DoS")
    elif re.search(r"information disclosure|memory leak|out.of.bounds read|data leak|sensitive data", desc):
        impacts.append("Info Disclosure")
    elif re.search(r"privilege escalat|elevat|local privilege|root access", desc):
        impacts.append("Privilege Escalation")
 
    # CWE-based fallback
    if not impacts:
        if cwe in ("CWE-125", "CWE-126", "CWE-127"):
            impacts.append("Info Disclosure")
        elif cwe in ("CWE-787", "CWE-122", "CWE-121"):
            impacts.append("DosS / RCE?")
        elif cwe in ("CWE-617", "CWE-400", "CWE-770"):
            impacts.append("DoS")
 
    return " / ".join(impacts) if impacts else "—"
 
 
def _infer_protocol(description: str, platforms: list[str]) -> str:
    """
    Highly verbose protocol inference targeting specific 3GPP layers, 
    signaling protocols, and mobile generations.
    """
    text = (description + " " + " ".join(platforms)).lower()
 
    # Ordered from most specific (layers/protocols) to most general (generations)
    checks = [
        # ── SIM / UICC / Proactive Commands ─────────────────────────────────
        (r"\bproactive\s+command\b|\bsim\s+proactive\b",           "SIM Proactive Command"),
        (r"\bgstk\b|\bsat\b|\bpkcs15\b|\bsim\s+file\b|\buicc\b",  "SIM Toolkit/GSTK"),
        (r"\bsim\b",                                               "SIM Toolkit/GSTK"),

        # ── Session Description Protocol ─────────────────────────────────────
        (r"\bsdp\b|\bsession\s+description\b|\bfmtp\b|\bchatroom\s+attr\b"
         r"|\baccept-type\b|\bvideo\s+config\b",                   "IMS SDP"),

        # ── SIP / VoLTE / VoWiFi ────────────────────────────────────────────
        (r"\bsip\s+invite\b|\bsip\s+message\b|\bsip\s+xml\b",     "VoLTE IMS / SIP"),
        (r"\bvolte\b|\bvowifi\b|\bike\b|\bims\s+stack\b"
         r"|\bims\s+sms\b|\bims\s+call\b",                        "IMS/VoLTE"),
        (r"\bsip\b|\brtp\b|\brtcp\b",                             "SIP/VoIP"),
        (r"\bims\b",                                               "IMS/VoLTE"),

        # ── NAS sub-layers (most specific first) ─────────────────────────────
        (r"\b5g\s+mm\b|\bnr\s*mm\b|\bnrmm\b"
         r"|\b5g\s+nas\s+mm\b",                                    "NAS (5G MM)"),
        (r"\b5g\s+sm\b|\bnr\s*sm\b"
         r"|\b5g\s+nas\s+sm\b",                                    "NAS (5G SM)"),
        (r"\bsae\s*qm\b|\besm\b|\beps\s+session\b"
         r"|\btraffic\s+flow\s+template\b|\btft\b",                "LTE NAS / ESM"),
        (r"\bemm\b|\beps\s+mobility\b",                            "LTE NAS / EMM"),
        (r"\bcall\s+control\b|\b\bcc\s+module\b|\bcc\b.*\bnas\b"
         r"|\bnas\b.*\bcc\b",                                      "NAS (CC)"),
        (r"\bsession\s+management\b|\bsm\s+module\b|\bnas\b.*\bsm\b"
         r"|\bsm\b.*\bnas\b",                                      "NAS (SM)"),
        (r"\bmobility\s+management\b|\bmm\s+module\b|\bnas\b.*\bmm\b"
         r"|\bmm\b.*\bnas\b|\btau\s+accept\b|\btau\b.*\bnas\b",   "NAS / MM"),
        (r"\bdownlink\s+nas\s+transport\b|\bnrmm\b",               "NAS (NRMM)"),
        (r"\breplay\s+protect\b|\bnas\s+layer\b|\bnas\s+message\b"
         r"|\bnas\s+packet\b|\bnon.access\s+stratum\b",            "NAS"),
        (r"\bnas\b",                                               "NAS"),

        # ── RRC ──────────────────────────────────────────────────────────────
        (r"\brrc\s+reconfig\b|\breconfiguration\b.*\brrc\b",       "RRC Reconfiguration"),
        (r"\brrc\s+setup\b|\bnr\s+rrc\s+connection\s+setup\b",    "RRC / Connection Setup"),
        (r"\bmcch\b",                                              "RRC (MCCH)"),
        (r"\brrc\b",                                               "RRC"),

        # ── Layer 2 (RLC / MAC / LLC) ────────────────────────────────────────
        (r"\brlc\b.*\bllc\b|\bllc\b.*\brlc\b"
         r"|\bpdu\s+fragment\b|\bfragment\s+reassembl\b",          "L2 (RLC/LLC)"),
        (r"\brlc\b",                                               "RLC"),
        (r"\bmac\s+rar\b|\bphy\b|\bnl1\b",                        "MAC/PHY"),

        # ── IP layer ─────────────────────────────────────────────────────────
        (r"\bipv6\b.*\bfragment\b|\bipv4\b.*\bfragment\b"
         r"|\bip\s+fragment\b",                                    "IP (Fragment Handling)"),
        (r"\bicmp\b",                                              "IP / ICMP"),
        (r"\btcp\b",                                               "IP / TCP"),
        (r"\budp\b",                                               "IP / UDP"),
        (r"\bipv6\b|\bipv4\b|\bip\s+packet\b|\bip\s+header\b"
         r"|\bip\s+layer\b|\bip\s+stack\b|\bip\s+type\b"
         r"|\bip\s+addr\b",                                        "IP"),
        (r"\bdns\b",                                               "IP / DNS"),
        (r"\bppp\b",                                               "PPP"),
        (r"\bigmp\b",                                              "IP / IGMP"),
        (r"\bdtls\b|\btls\b",                                      "DTLS/TLS"),
        (r"\bcoap\b",                                              "CoAP"),
        (r"\blwm2m\b",                                             "LwM2M"),
        (r"\bhttp\b",                                              "HTTP"),

        # ── 2G specific sub-layers ────────────────────────────────────────────
        (r"\bpncd\b|\bpacket\s+neighbour\s+cell\b",               "2G GPRS RR (PNCD)"),
        (r"\bcsn\.?1\b|\brr\s+channel\s+release\b"
         r"|\bfdd_csrr\b|\bcell\s+select\b.*\brelease\b",         "2G RRM / GSM RR"),
        (r"\be.utran\s+individual\s+priority\b|\bearfcn\b",        "2G/3G RRM (E-UTRAN IPP)"),
        (r"\bgsm\b.*\bcc\b|\bcc\b.*\bgsm\b|\bcall\s+control\b.*\bgsm\b"
         r"|\bgcm\b.*\bsetup\b|\bgsm\s+setup\b",                  "GSM CC"),
        (r"\bgprs\b",                                              "2G (GPRS)"),
        (r"\b2g\b|\bgsm\b|\bgprs\b|\bedge\b",                     "2G (GSM)"),

        # ── 3G specific ───────────────────────────────────────────────────────
        (r"\b3g\b.*\brrm\b|\brrm\b.*\b3g\b"
         r"|\bumts\b.*\brrm\b",                                    "3G RRM"),
        (r"\b3g\b|\bumts\b|\bwcdma\b|\bhspa\b",                   "3G"),

        # ── 5G specific ───────────────────────────────────────────────────────
        (r"\b5g\b.*\brrc\b|\bnr\s+rrc\b",                         "5G / RRC"),
        (r"\b5g\b|\bnr\b|\bnextgen\b|\bnrsa\b|\bnsa\s+rrc\b",     "5G"),

        # ── 4G (LTE) ─────────────────────────────────────────────────────────
        (r"\blte\b|\b4g\b|\be.?utra\b|\beutra\b",                 "4G (LTE)"),

        # ── Cryptographic / Security Negotiation ──────────────────────────────
        (r"\bika\b|\bike\s+downgrade\b|\bvowifi\s+ike\b",         "VoWiFi IKE"),
        (r"\bauth.*\bagreement\b|\baka\b|\b5g.?aka\b",            "5G AKA"),
        (r"\bciphering\s+key\b|\bciphering\b|\bintegrity\b"
         r"|\bsecurity\s+mode\s+command\b|\blte\s+security\b",    "LTE Security"),
        (r"\bcryptograph\b|\bencrypt\b|\brisky\s+algorithm\b"
         r"|\bbroken.*algorithm\b|\balgorithm\s+downgrade\b",     "Cryptographic Protocol"),
        (r"\btls\s+handshake\b|\bdtls\s+handshake\b",             "DTLS/TLS Handshake"),
        (r"\bcertificate\s+validat\b",                            "Certificate Validation"),

        # ── OTASP / OTA messaging ─────────────────────────────────────────────
        (r"\botasp\b",                                             "OTASP"),
        (r"\bota\b",                                               "OTA"),

        # ── SMS ───────────────────────────────────────────────────────────────
        (r"\bsms\b|\bwms\b|\bshort\s+message\b",                  "SMS"),

        # ── Connection establishment ──────────────────────────────────────────
        (r"\bconnection\s+establish\b",                           "Connection Setup"),

        # ── Other Wireless ────────────────────────────────────────────────────
        (r"\bwi-?fi\b|802\.11|\bwlan\b",                          "Wi-Fi"),
        (r"\bbluetooth\b|\bble\b",                                 "Bluetooth"),
        (r"\bnfc\b",                                               "NFC"),
        (r"\bgps\b|\bgnss\b",                                      "GNSS/GPS"),

        # ── Wired / Hardware ──────────────────────────────────────────────────
        (r"\busb\b",                                               "USB"),
        (r"\baudio\b|\bcodec\b|\badsp\b",                         "Audio/DSP"),

        # ── Diag / Internal interfaces ────────────────────────────────────────
        (r"\bdiag\b|\bftm\b",                                      "Diag/FTM"),
        (r"\bqmi\b",                                               "QMI"),
        (r"\bwmi\b",                                               "WMI"),
    ]

    # Iterate and return the first specific match found
    for pattern, label in checks:
        if re.search(pattern, text):
            return label

    return "N/A"
 
 
def _build_root_cause(cwe_id: str, cwe_desc: str, description: str) -> str:
    """
    Combine the CWE label with the full CVE description.
    """
    # Strip redundant "CWE-NNN " prefix from cwe_desc if present
    clean_cwe = re.sub(r"^CWE-\d+\s*", "", cwe_desc).strip() or cwe_desc
    return f"{cwe_id} {clean_cwe}, {description.strip()}"
 
 
# ── bib-key generator ─────────────────────────────────────────────────────────
 
def _make_bib_key(vendor: str, advisory_url: str, published: str) -> str:
    """
    Derive a short, collision-resistant bib key from the vendor name + advisory URL.
    Examples:
      qualcomm  + september-2024-bulletin  →  qualcomm_psb_september2024
      mediatek  + MTKSA-2025-0047          →  mediatek_sa_2025_0047
      samsung   + cve-2023-41112           →  samsung_CVE-2023-41112
    """
    vendor_slug = re.sub(r"[^a-z0-9]", "", vendor.lower())
 
    # Try to extract a meaningful slug from the URL path
    path = advisory_url.rstrip("/").split("/")[-1]
    # Remove common extensions
    path = re.sub(r"\.(html?|pdf|aspx?)$", "", path, flags=re.I)
 
    # Detect "month-year-bulletin" pattern  →  psb_<month><year>
    m = re.match(r"([a-z]+-\d{4})-bulletin", path, re.I)
    if m:
        slug = "psb_" + m.group(1).replace("-", "")
        return f"{vendor_slug}_{slug}"
 
    # Detect SA / advisory ID patterns (e.g. MTKSA-2025-0047, SA-2024-0012)
    m = re.search(r"([a-z]*sa[-_]?\d{4}[-_]\d+)", path, re.I)
    if m:
        slug = "sa_" + re.sub(r"[^a-z0-9]", "_", m.group(1).lower())
        return f"{vendor_slug}_{slug}"
 
    # If the path itself looks like a CVE id, use that
    m = re.search(r"(CVE-\d{4}-\d+)", path, re.I)
    if m:
        return f"{vendor_slug}_{m.group(1)}"
 
    # Generic fallback: vendor + year
    year = published[:4] if published else "0000"
    slug = re.sub(r"[^a-z0-9_]", "_", path.lower())[:30].strip("_")
    return f"{vendor_slug}_{slug or year}"
 
 
# ── output formatters ─────────────────────────────────────────────────────────
 
def _q(s: object) -> str:
    """Wrap in Typst double-quotes, escaping internal ones."""
    return '"' + str(s).replace('"', '\\"') + '"'
 
bib = []
bib_keys = []

def _parse_soup(soup: BeautifulSoup) -> str:
    """Core parser — takes an already-built BeautifulSoup object."""
    blobs = _extract_plain_json(soup)

    return blobs
 
    cve_id                   = extract_cve_id(soup)
    description              = extract_description(blobs, soup)
    cvss                     = extract_cvss(blobs, soup)
    vendor, product, platforms = extract_vendor_product_platforms(blobs)
    versions                 = extract_affected_versions(blobs)
    cwe_id, cwe_desc         = extract_cwe(blobs, soup)
    published                = extract_published(blobs, soup)
    refs                     = extract_references(blobs, soup)
    title                    = extract_title(blobs, soup)
 
    advisory_url  = next((r["url"] for r in refs), "")
    bib_key       = _make_bib_key(vendor, advisory_url, published) if advisory_url else cve_id.lower().replace("-", "")
    score_str     = str(cvss.get("score", "")) if cvss else ""
    fw_range      = ", ".join(versions)
    impact        = _infer_impact(description, cwe_id)
    protocol      = _infer_protocol(description, platforms)
    root_cause    = _build_root_cause(cwe_id, cwe_desc, description) if cwe_id else description
 
    # ── Typst tuple ───────────────────────────────────────────────────────────
    year      = published[:4] if published else "????"
    org_name  = vendor  # used in bib author field
 
    tuple_lines = [
        "(",
        f"    id: {_q(cve_id)},",
        f"    refs: [#cite(<{bib_key}>)],",
        f"    vendor: {_q(vendor)},",
        f"    protocol: {_q(protocol)},",
        f"    impact: {_q(impact)},",
        f"    root_cause: {_q(root_cause)},",
        f"    fw_range: {_q(fw_range)},",
        f"    cvss: {_q(score_str)},",
        "    ratio: \"—\",",
        "),",
    ]
    tuple_str = "\n".join(tuple_lines)
 
    # ── BibTeX entry ──────────────────────────────────────────────────────────
    urldate   = "2025-04-15"   # today-ish; user can adjust
    bib_title = f"{cve_id} Security Advisory" + (f" — {title}" if title else "")
 
    if bib_key in bib_keys:
        return "".join(tuple_str)

    bib_lines = [
        f"@misc{{{bib_key},\n",
        f"  author       = {{{{{org_name}}}}},\n",
        f"  title        = {{{{{bib_title}}}}},\n",
        f"  year         = {year},\n",
        f"  url          = {{{advisory_url}}},\n",
        f"  urldate      = {{{urldate}}},\n",
        f"  language     = {{en}}\n",
        "}\n",
    ]
    bib.append("".join(bib_lines))
    bib_keys.append(bib_key)
 
    return "".join(tuple_str)
 
 
def build_tuple(html_path: str) -> str:
    """Parse a local HTML file."""
    with open(html_path, encoding="utf-8", errors="replace") as fh:
        soup = BeautifulSoup(fh, "html.parser")
    return _parse_soup(soup)
 
 
def build_tuple_from_html(html: str) -> str:
    """Parse an HTML string directly (e.g. from fetch_html)."""
    soup = BeautifulSoup(html, "html.parser")
    return _parse_soup(soup)
 
 
# ── URL fetcher ──────────────────────────────────────────────────────────────
 
import urllib.request
import urllib.error
import tempfile
import os
 
# OpenCVE CVE page URL pattern
_OPENCVE_URL = "https://app.opencve.io/cve/{cve_id}"
 
# Headers that mimic a real Chrome 124 browser on Windows 11
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.6367.155 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;"
        "q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
}
 
 
def fetch_html(url: str) -> str:
    """
    Fetch a URL and return the decoded HTML string.
 
    Handles:
      - gzip / deflate content-encoding
      - HTTP errors with a clear message
      - Bot-challenge detection (Cloudflare / login redirects)
    """
    import gzip, zlib
 
    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw       = resp.read()
            enc       = resp.headers.get("Content-Encoding", "").lower()
            final_url = resp.geturl()
 
            # Decompress — must handle all three encodings we advertise
            if enc == "gzip":
                raw = gzip.decompress(raw)
            elif enc == "deflate":
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            elif enc == "br":
                try:
                    import brotli
                    raw = brotli.decompress(raw)
                except ImportError:
                    # brotli not installed — retry without br in Accept-Encoding
                    no_br_headers = {**_HEADERS, "Accept-Encoding": "gzip, deflate"}
                    req2 = urllib.request.Request(url, headers=no_br_headers)
                    with urllib.request.urlopen(req2, timeout=30) as resp2:
                        raw2 = resp2.read()
                        enc2 = resp2.headers.get("Content-Encoding", "").lower()
                        if enc2 == "gzip":
                            raw2 = gzip.decompress(raw2)
                        elif enc2 == "deflate":
                            try:
                                raw2 = zlib.decompress(raw2)
                            except zlib.error:
                                raw2 = zlib.decompress(raw2, -zlib.MAX_WBITS)
                        raw = raw2
 
            html = raw.decode("utf-8", errors="replace")
 
            # Detect bot-challenge / login redirect
            if "challenge" in final_url or "login" in final_url:
                raise RuntimeError(
                    f"Redirected to {final_url!r} — OpenCVE requires a login session. "
                    "Save the page manually (browser → Save As) and pass the .html file instead."
                )
            if len(html) < 2000 and (
                "captcha" in html.lower()
                or "cloudflare" in html.lower()
                or "access denied" in html.lower()
            ):
                raise RuntimeError(
                    "Got a bot-challenge / access-denied page. "
                    "Save the CVE page from your browser and pass the .html file instead."
                )
 
            return html
 
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} fetching {url}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error fetching {url}: {e.reason}") from e
 
 
def fetch_and_parse(cve_id_or_url: str) -> str:
    """
    Accept either a CVE id (CVE-2024-23358) or a full URL, fetch the page,
    write to a temp file, and run build_tuple on it.
    """
    if cve_id_or_url.startswith("http"):
        url = cve_id_or_url
    else:
        cve_id = cve_id_or_url.strip().upper()
        url = _OPENCVE_URL.format(cve_id=cve_id)
 
    print(f"Fetching {url} …", file=sys.stderr)
    html = fetch_html(url)
    return build_tuple_from_html(html)


import glob
import sys

all_cves = []

urls = []

records = []

if not len(sys.argv[1]) or not len(sys.argv[2]):
    print(f"Usage: {sys.argv[0]} <vendor> <amount_of_pages_to_fetch>")
    print(f"Example: python3 {sys.argv[0]} unisoc 3")

import json

for i in range(1,int(sys.argv[2])):
    urls.append(f"https://app.opencve.io/cve/?q=description%3Amodem+AND+vendor%3{sys.argv[1]}&page=" + str(i))

for url in urls:
    print(f"Fetching {url} …", file=sys.stderr)
    try:
        html = fetch_html(url)
    except Exception as exc:
        print(f"  ERROR: {exc}", file=sys.stderr)
        continue

    all_cves += extract_opencve_links(html)

all_cves = list(dict.fromkeys(all_cves))

print(all_cves, len(all_cves))

with open('cve_unisoc.json', 'w') as f:
    for u in all_cves:
        f.write(json.dumps(fetch_and_parse(u), indent=2))
