#!/usr/bin/env python3
"""Regression tests for the baseband CVE acquisition pipeline."""

from __future__ import annotations

import unittest

import fetch_json


def record(cve_id: str, vendor: str, description: str, product: str = "chipset") -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve_id, "assignerShortName": vendor},
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": vendor},
                "descriptions": [{"lang": "en", "value": description}],
                "affected": [{"vendor": vendor, "product": product, "versions": []}],
            }
        },
    }


class FetchJsonTests(unittest.TestCase):
    def test_samsung_shannon_2015_rce_is_discoverable(self) -> None:
        item = record(
            "CVE-2015-8546", "mitre",
            "A stack-based buffer overflow in the Samsung Shannon333 "
            "baseband process is exploitable for remote code execution "
            "through a fake base station.",
            "Shannon333 chipset",
        )
        vendor, _ = fetch_json.choose_vendor(item)
        self.assertEqual(vendor, "Samsung")
        self.assertIn("baseband", fetch_json.baseband_matches(item))

    def test_android_unisoc_modem_row_recovers_known_gap(self) -> None:
        html = """
        <h3>Unisoc components</h3>
        <table><tr><th>CVE</th><th>Severity</th><th>Component</th></tr>
        <tr><td>CVE-2022-20210</td><td>Critical</td><td>Modem</td></tr></table>
        """
        found = fetch_json.contextual_candidates(html, "bulletin", "android-bulletin")
        self.assertEqual(found[0][0], "CVE-2022-20210")
        self.assertEqual(found[0][1], "Unisoc")
        self.assertIn("modem", found[0][3])

    def test_vendor_and_baseband_record_match(self) -> None:
        item = record(
            "CVE-2025-00001", "MediaTek",
            "In Modem, malformed NAS input causes an out-of-bounds write.",
            "MediaTek chipset",
        )
        vendor, signals = fetch_json.choose_vendor(item)
        self.assertEqual(vendor, "MediaTek")
        self.assertTrue(signals)
        self.assertIn("modem", fetch_json.baseband_matches(item))
        self.assertIn("radio-protocol", fetch_json.baseband_matches(item))

    def test_samsung_exynos_modem_without_samsung_assigner(self) -> None:
        item = record(
            "CVE-2025-00002", "mitre",
            "An issue in the RRC parser affects Exynos Modem 5300.",
            "Exynos Modem 5300",
        )
        vendor, _ = fetch_json.choose_vendor(item)
        self.assertEqual(vendor, "Samsung")
        self.assertIn("modem", fetch_json.baseband_matches(item))

    def test_samsung_handset_generation_name_is_not_baseband(self) -> None:
        item = record(
            "CVE-2025-00007", "Samsung",
            "A local UI issue affects the Samsung Example 5G handset.",
            "Example 5G",
        )
        signals = fetch_json.baseband_matches(item)
        self.assertEqual(signals, ["radio-generation"])
        self.assertFalse(fetch_json.eligible_baseband_signals("Samsung", signals))

    def test_unrelated_wifi_record_is_not_baseband(self) -> None:
        item = record(
            "CVE-2025-00003", "Qualcomm",
            "Memory corruption in Wi-Fi firmware while parsing an 802.11 frame.",
            "Snapdragon",
        )
        vendor, _ = fetch_json.choose_vendor(item)
        self.assertEqual(vendor, "Qualcomm")
        self.assertEqual(fetch_json.baseband_matches(item), [])

    def test_affected_version_inventory_is_not_component_evidence(self) -> None:
        item = record(
            "CVE-2025-00006", "Qualcomm",
            "Memory corruption in Wi-Fi firmware while parsing an 802.11 frame.",
            "Snapdragon",
        )
        item["containers"]["cna"]["affected"][0]["versions"] = [
            {"status": "affected", "version": "Snapdragon X75 5G Modem"}
        ]
        self.assertEqual(fetch_json.baseband_matches(item), [])

    def test_official_domain_can_supply_missing_vendor_name(self) -> None:
        html = """
        <table><tr><th>CVE</th><th>Affected component</th></tr>
        <tr><td>CVE-2025-00005</td><td>Modem RRC parser</td></tr></table>
        """
        found = fetch_json.contextual_candidates(
            html, "official-page", "vendor-site", default_vendor="Samsung"
        )
        self.assertEqual(found[0][1], "Samsung")
        self.assertIn("modem", found[0][3])

    def test_android_page_navigation_is_not_component_context(self) -> None:
        html = """
        <nav>Qualcomm components Cellular security</nav>
        <h1>Android Security Bulletin</h1><p>CVE-2025-00008</p>
        """
        found = fetch_json.contextual_candidates(
            html, "bulletin", "android-bulletin", allow_page_fallback=False
        )
        self.assertEqual(found, [])

    def test_fresh_record_preserves_manual_enrichment(self) -> None:
        fresh = record("CVE-2025-00004", "Unisoc", "In Modem, a crash can occur.")
        old = {**fresh, "typst_enrichment": {"scope": "Cellular Control Plane"}}
        merged = fetch_json.merge_record(fresh, old)
        self.assertEqual(merged["typst_enrichment"], old["typst_enrichment"])


if __name__ == "__main__":
    unittest.main()
