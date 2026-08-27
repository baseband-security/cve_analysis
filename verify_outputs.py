#!/usr/bin/env python3
"""Verify a generated schema-3.1 baseband CVE artifact directory."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


EXPECTED_IMPACT = {
    "RCE": 11,
    "Write Primitive": 194,
    "DoS": 385,
}
EXPECTED_BUG_FAMILY = {
    "Bounds write / overflow": 181,
    "Bounds read": 63,
    "Null dereference": 28,
    "Lifetime / pointer misuse": 23,
    "Low information CVE": 295,
}
EXPECTED_SCOPE = {
    "Cellular Control Plane": 220,
    "IMS/Telephony": 100,
    "SIM/UICC": 15,
    "IP/User Plane": 34,
    "Local/IPC & Diagnostic": 24,
    "Unknown": 197,
}
PLOTS = (
    "memory_bug_classes.png",
    "memory_bug_families_by_scope.png",
    "memory_cves_by_year_impact.png",
    "memory_cves_impact_by_scope.png",
    "public_evidence_coverage.png",
)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=Path("outputs"),
        help="generated output directory (default: outputs)",
    )
    parser.add_argument(
        "--allow-no-plots",
        action="store_true",
        help="do not require PNG figures (for enrich.py --no-plots runs)",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("fetched_json"),
        help="directory containing the acquisition JSON used by enrich.py",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    output = args.output.resolve()
    required = (
        "baseband_memory_cves.json",
        "baseband_memory_cves.csv",
        "excluded_non_memory_cves.json",
        "classification_summary.json",
        "source_provenance_audit.json",
        "dataset_manifest.json",
    )
    for filename in required:
        path = output / filename
        assert path.is_file() and path.stat().st_size > 0, f"missing output: {path}"
    assert not (output / "rce_candidate_audit.json").exists(), "obsolete RCE audit still present"

    records = load_json(output / "baseband_memory_cves.json")
    excluded = load_json(output / "excluded_non_memory_cves.json")
    summary = load_json(output / "classification_summary.json")
    source_audit = load_json(output / "source_provenance_audit.json")
    manifest = load_json(output / "dataset_manifest.json")
    with (output / "baseband_memory_cves.csv").open(encoding="utf-8", newline="") as handle:
        csv_records = list(csv.DictReader(handle))

    ids = [record["cve_id"] for record in records]
    csv_ids = [record["cve_id"] for record in csv_records]
    excluded_ids = [record["cve_id"] for record in excluded]

    assert summary["schema_version"] == manifest["schema_version"] == "3.1"
    assert source_audit["schema_version"] == "3.1"
    assert manifest["analysis_release"] == "evidence-aware-taxonomy-v3.1"
    assert summary["input_unique_cves"] == 622
    assert len(records) == len(csv_records) == 590
    assert len(excluded) == 32
    assert len(ids) == len(set(ids)), "included CVE IDs are not unique"
    assert set(ids) == set(csv_ids), "CSV and JSON CVE sets differ"
    assert set(ids).isdisjoint(excluded_ids), "included and excluded CVEs overlap"
    assert Counter(record["impact"] for record in records) == Counter(EXPECTED_IMPACT)
    assert Counter(record["bug_family"] for record in records) == Counter(EXPECTED_BUG_FAMILY)
    assert Counter(record["primary_scope"] for record in records) == Counter(EXPECTED_SCOPE)
    assert Counter(record["memory_safety_basis"] for record in records) == Counter({
        "explicit_public_memory_safety_evidence": 315,
        "low_information_cve": 275,
    })
    assert all(
        record["impact"] == "DoS"
        for record in records
        if record["bug_class"] == "low-information-cve"
    )
    assert all(
        record["impact"] == "DoS"
        for record in records
        if record["bug_class"] == "memory-corruption-unspecified"
    )
    assert all(
        record["impact"] == "RCE"
        for record in records
        if record["bug_class"] == "unknown-memory-operation-rce"
    )
    assert all(
        record["impact"] == "Write Primitive"
        for record in records
        if record["bug_class"] == "buffer-overflow"
    )
    assert sum(record["impact"] == "RCE" for record in records) == 11
    assert all(
        record["source_beyond_vendor_advisory"]
        for record in records
        if record["impact"] == "RCE"
    )
    assert Counter(record["evidence"]["band"] for record in records) == Counter({
        "advisory-only": 348,
        "technical-characterization": 231,
        "exploitation-evidence": 11,
    })
    assert all(
        record["evidence"]["band"]
        == (
            "exploitation-evidence"
            if record["evidence"]["arbitrary_code_execution"]
            or record["evidence"]["control_flow_redirection"]
            else "technical-characterization"
            if record["evidence"]["primitive_characterized"]
            or record["evidence"]["reproduced_failure"]
            or record["evidence"]["component_identified"]
            else "advisory-only"
        )
        for record in records
    )
    assert all(isinstance(record["affected_chipsets"], list) for record in records)
    assert sum(bool(record["affected_chipsets"]) for record in records) > 500
    assert {"root_cause", "affected_chipsets", "evidence_band"}.issubset(csv_records[0])
    pncd = next(record for record in records if record["cve_id"] == "CVE-2022-21744")
    assert pncd["impact"] == "RCE"
    assert pncd["evidence"]["band"] == "exploitation-evidence"
    assert "MT6873" in pncd["affected_chipsets"]
    assert any(
        source["url"] == "https://labs.taszk.io/articles/post/full_chain_bb_part2/"
        for source in pncd["sources"]
    )
    assert all(
        any(
            source["title"] == f"NVD record for {record['cve_id']}"
            and source["url"].endswith(record["cve_id"])
            for source in record["sources"]
        )
        for record in records + excluded
    )
    assert all(
        set(source) == {"title", "url"}
        for item in records + excluded
        for source in item["sources"]
    )
    assert all(
        "input_reference_candidates" not in record
        and "source_types" not in record
        for record in records + excluded
    )
    assert source_audit["counts"]["records_with_canonical_nvd_source"] == 622
    assert source_audit["counts"]["input_reference_candidates"] == 816
    assert {
        row["cve_id"] for row in source_audit["obvious_conflicting_input_mappings"]
    } == {"CVE-2016-4030", "CVE-2025-57834"}
    assert all(manifest["validation"].values()), "manifest contains a failed check"

    for relative, metadata in manifest["inputs"].items():
        input_path = (
            args.input_dir.resolve() / Path(relative).name
            if relative.startswith("fetched_json/")
            else root / relative
        )
        assert input_path.is_file(), f"missing manifest input: {input_path}"
        assert sha256(input_path) == metadata["sha256"], f"input hash mismatch: {relative}"
    assert sha256(root / "enrich.py") == manifest["implementation"]["enrich.py"]["sha256"]

    if not args.allow_no_plots:
        for filename in PLOTS:
            path = output / filename
            assert path.is_file() and path.stat().st_size > 0, f"missing plot: {path}"

    print("Artifact verification: PASS")
    print(f"Schema: {summary['schema_version']}")
    print(f"Input / included / excluded: 622 / {len(records)} / {len(excluded)}")
    print(f"Impact: {dict(Counter(record['impact'] for record in records))}")
    print(f"Output directory: {output}")


if __name__ == "__main__":
    main()
