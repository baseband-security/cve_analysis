"""
typst_to_json.py
~~~~~~~~~~~~~~~~
Reads cve_table.typ and for every CVE entry:

  1. If the CVE already exists in one of the four vendor JSON files
     → writes / overwrites the `typst_enrichment` block on that record.

  2. If the CVE is missing from all JSON files and the vendor maps to one
     of the four files (Samsung/Google/Pixel/Exynos → samsung,
     Qualcomm → qualcomm, MediaTek → mediatek, Unisoc → unisoc)
     → fetches the real CVE 5.1 record from app.opencve.io and appends
       it to the correct file with `typst_enrichment` already attached.

  3. Apple / unknown vendors → skipped with a notice.

Run from the directory containing the four vendor JSON files:

    python typst_to_json.py
    python typst_to_json.py --typst path/to/cve_table.typ
    python typst_to_json.py --json-dir ./data --out-dir ./out
"""

import gzip
import json
import os
import re
import sys
import time
import zlib
import urllib.error
import urllib.request
from bs4 import BeautifulSoup

# ── config ────────────────────────────────────────────────────────────────────

TYPST_FILE = "cve_table.typ"

VENDOR_FILES = {
    "Samsung":  "cve_samsung_clean.json",
    "Qualcomm": "cve_qualcomm_clean.json",
    "MediaTek": "cve_mediatek_clean.json",
    "Unisoc":   "cve_unisoc_clean.json",
}

OPENCVE_URL = "https://app.opencve.io/cve/{cve_id}"

REQUEST_DELAY = 1.5   # seconds between HTTP requests

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.6367.155 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
}

# ── typst parser ──────────────────────────────────────────────────────────────

def parse_typst(path):
    with open(path, encoding="utf-8") as f:
        content = f.read()
    record_re = re.compile(r'\(\s*id:\s*"([^"]+)"(.*?)\n\s*\)', re.DOTALL)
    field_re  = {
        k: re.compile(rf'{k}:\s*"((?:[^"\\]|\\.)*)"')
        for k in ("vendor", "protocol", "impact", "root_cause", "fw_range", "cvss")
    }
    records = {}
    for m in record_re.finditer(content):
        cid, body = m.group(1), m.group(2)
        rec = {}
        for field, pat in field_re.items():
            fm = pat.search(body)
            rec[field] = fm.group(1).strip() if fm else None
        records[cid] = rec
    return records

# ── vendor routing ────────────────────────────────────────────────────────────

def route_vendor(raw):
    v = (raw or "").lower()
    if any(x in v for x in ("samsung", "exynos", "pixel", "google")):
        return "Samsung"
    if "qualcomm" in v:
        return "Qualcomm"
    if "mediatek" in v:
        return "MediaTek"
    if "unisoc" in v:
        return "Unisoc"
    return None

# ── opencve fetcher ───────────────────────────────────────────────────────────

def fetch_html(url, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                enc = resp.headers.get("Content-Encoding", "").lower()
                if enc == "gzip":
                    raw = gzip.decompress(raw)
                elif enc == "deflate":
                    try:
                        raw = zlib.decompress(raw)
                    except zlib.error:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
                return raw.decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"    attempt {attempt+1}/{retries} failed: {exc}", file=sys.stderr)
            if attempt < retries - 1:
                time.sleep(4 * (attempt + 1))
    return None


def parse_opencve(html):
    soup  = BeautifulSoup(html, "html.parser")
    modal = soup.find("div", id="modal-mitre-json")
    if not modal:
        return None
    container = modal.find("div", class_="modal-body codejson")
    if container:
        for tag in container.find_all("span", class_="rainbowType"):
            tag.decompose()
        for tag in container.find_all("a", class_="rainbowToggle"):
            tag.decompose()
        raw = container.get_text(strip=True)
    else:
        pre = modal.find("pre")
        raw = pre.get_text() if pre else ""
    if not raw:
        return None
    try:
        blob = json.loads(raw)
        if "containers" in blob and "cna" in blob["containers"]:
            return blob
    except json.JSONDecodeError:
        pass
    return None


def fetch_cve(cve_id):
    url  = OPENCVE_URL.format(cve_id=cve_id)
    html = fetch_html(url)
    if html is None:
        return None
    return parse_opencve(html)

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--typst",    default=TYPST_FILE)
    ap.add_argument("--json-dir", default=".")
    ap.add_argument("--out-dir",  default=None)
    args = ap.parse_args()

    json_dir = args.json_dir
    out_dir  = args.out_dir or json_dir

    # 1. parse typst
    if not os.path.exists(args.typst):
        sys.exit(f"[ERROR] {args.typst} not found")
    typst = parse_typst(args.typst)
    print(f"Parsed {len(typst)} CVE entries from {args.typst}")

    # 2. load all vendor JSON files into memory
    vendor_data = {}
    cve_to_vendor = {}   # cve_id → canonical vendor key
    for vendor, fname in VENDOR_FILES.items():
        path = os.path.join(json_dir, fname)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                vendor_data[vendor] = json.load(f)
        else:
            print(f"[WARN] {path} not found — starting empty for {vendor}")
            vendor_data[vendor] = []
        for rec in vendor_data[vendor]:
            cid = rec.get("cveMetadata", {}).get("cveId", "")
            if cid:
                cve_to_vendor[cid] = vendor

    # 3. build a fast lookup: cve_id → index within vendor list
    vendor_index = {}   # vendor → {cve_id: list_index}
    for vendor, records in vendor_data.items():
        vendor_index[vendor] = {}
        for i, rec in enumerate(records):
            cid = rec.get("cveMetadata", {}).get("cveId", "")
            if cid:
                vendor_index[vendor][cid] = i

    # 4. process each typst entry
    updated = 0
    fetched = 0
    skipped = 0
    failed  = 0
    first_fetch = True

    for cve_id, typst_rec in typst.items():
        enrichment = {
            k: typst_rec.get(k)
            for k in ("vendor", "protocol", "impact", "root_cause", "fw_range", "cvss")
        }

        if cve_id in cve_to_vendor:
            # ── already in a JSON file: update typst_enrichment ───────────────
            vendor = cve_to_vendor[cve_id]
            idx    = vendor_index[vendor][cve_id]
            vendor_data[vendor][idx]["typst_enrichment"] = enrichment
            updated += 1

        else:
            # ── missing: route vendor then fetch from OpenCVE ─────────────────
            canonical = route_vendor(typst_rec.get("vendor", ""))
            if canonical is None:
                print(f"  SKIP  {cve_id}  (vendor={typst_rec.get('vendor')} — no target file)")
                skipped += 1
                continue

            if not first_fetch:
                time.sleep(REQUEST_DELAY)
            first_fetch = False

            print(f"  FETCH {cve_id} → {canonical} ...", end=" ", flush=True)
            record = fetch_cve(cve_id)

            if record is None:
                print("FAILED")
                failed += 1
                continue

            record["typst_enrichment"] = enrichment
            vendor_data[canonical].append(record)
            # update index so duplicates are caught
            vendor_index[canonical][cve_id] = len(vendor_data[canonical]) - 1
            cve_to_vendor[cve_id] = canonical
            fetched += 1
            print("OK")

    # 5. write updated files
    os.makedirs(out_dir, exist_ok=True)
    for vendor, fname in VENDOR_FILES.items():
        dst = os.path.join(out_dir, fname)
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(vendor_data[vendor], f, indent=2, ensure_ascii=False)
        print(f"  Wrote {dst}  ({len(vendor_data[vendor])} records)")

    print(f"\nDone — {updated} updated, {fetched} fetched+appended, "
          f"{skipped} skipped (no vendor file), {failed} fetch failed.")


if __name__ == "__main__":
    main()