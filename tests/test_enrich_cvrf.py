import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "enrich_cvrf.py"
SPEC = importlib.util.spec_from_file_location("enrich_cvrf", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_build_records_maps_product_and_vector():
    document = {
        "ProductTree": {"Branch": [{"FullProductName": {"ProductID": "p1", "Value": "Windows Server 2016"}}]},
        "Vulnerability": [{
            "CVE": "CVE-TEST-1",
            "Title": {"Value": "Windows DNS Server test vulnerability"},
            "ProductStatuses": [{"Status": "Known Affected", "ProductID": ["p1"]}],
            "Threats": [
                {"Type": "3", "Description": {"Value": "Critical"}},
                {"Type": "1", "Description": {"Value": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Unlikely"}},
            ],
            "CVSSScoreSets": [{"BaseScore": 9.8, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }],
    }
    records = MODULE.build_records(document, "2026-Sep", {})
    assert len(records) == 1
    assert records[0]["products"][0]["name"] == "Windows Server 2016"
    # Product and release tags are derived from the structured product tree.
    assert {"microsoft", "server", "server-2016"}.issubset(set(records[0]["product_tags"]))
    # "dns" is a workload judgement. With no inference overlay supplied there is no
    # judgement to record, and the parser must not invent one by matching the title -
    # which is precisely what the old TAG_RULES regex did.
    assert records[0]["tags"] == []
    assert "dns" not in records[0]["product_tags"]
    assert records[0]["attack"]["vector"] == "network"
    assert records[0]["severity"] == "Critical"
    assert records[0]["products"][0]["product_id"] == "p1"
    assert records[0]["threat"]["exploitation_assessment"] == "unlikely"
    assert records[0]["cvss"]["base_score"] == 9.8


if __name__ == "__main__":
    test_build_records_maps_product_and_vector()
    print("CVRF enrichment tests passed")


def test_resolve_severity_preserves_unknown_when_vendor_publishes_nothing():
    """A Chromium passthrough advisory has no MSRC severity and no CVSS score.

    Before this fix the parser coerced the missing score to 0 and fell through
    to "Low", publishing browser use-after-free bugs as negligible.
    """
    assert MODULE.resolve_severity("", None) == ("Unknown", "absent")
    assert MODULE.resolve_severity(None, None) == ("Unknown", "absent")


def test_resolve_severity_uses_vendor_text_without_a_score():
    assert MODULE.resolve_severity("Important", None) == ("Important", "vendor")
    assert MODULE.resolve_severity("Critical", None) == ("Critical", "vendor")
    assert MODULE.resolve_severity("Low", None) == ("Low", "vendor")


def test_resolve_severity_uses_score_without_vendor_text():
    assert MODULE.resolve_severity("", 9.8) == ("Critical", "cvss")
    assert MODULE.resolve_severity("", 7.8) == ("Important", "cvss")
    assert MODULE.resolve_severity("", 5.4) == ("Moderate", "cvss")
    assert MODULE.resolve_severity("", 2.3) == ("Low", "cvss")


def test_missing_score_is_none_not_zero():
    document = {
        "ProductTree": {"Branch": [{"FullProductName": {"ProductID": "p1", "Value": "Microsoft Edge (Chromium-based)"}}]},
        "Vulnerability": [{
            "CVE": "CVE-TEST-CHROMIUM",
            "Title": {"Value": "Chromium: CVE-TEST-CHROMIUM Use after free in V8"},
            "ProductStatuses": [{"Status": "Known Affected", "ProductID": ["p1"]}],
            "Threats": [],
            "CVSSScoreSets": [],
        }],
    }
    records = MODULE.build_records(document, "2026-Sep", {})
    assert records[0]["cvss"]["base_score"] is None
    assert records[0]["severity"] == "Unknown"
    assert records[0]["severity_basis"] == "absent"


def test_product_tags_derive_from_structured_products_not_prose():
    """Release tags come from the product tree, not from matching the title.

    The old regex matched "windows server 2025" anywhere in a concatenated blob of
    title, product names and notes. Deriving from products[] is both more accurate
    and incapable of leaking into the risk path.
    """
    products = [
        {"product_id": "1", "name": "Windows Server 2025"},
        {"product_id": "2", "name": "Windows 11 Version 24H2 for x64-based Systems"},
    ]
    tags = MODULE.derive_product_tags(products)
    assert "server-2025" in tags
    assert "windows-11" in tags
    assert "server" in tags
    assert "endpoint" in tags
    assert "microsoft" in tags


def test_product_tags_ignore_title_prose():
    """A title mentioning a product does not create a release tag."""
    products = [{"product_id": "1", "name": "Windows Server 2012"}]
    tags = MODULE.derive_product_tags(products)
    assert "server-2025" not in tags
    assert "windows-11" not in tags
    assert "server" in tags


def test_derivation_emits_no_judgement_tags():
    """Impact, delivery and workload tags are the model's job, never derived."""
    products = [{"product_id": "1", "name": "Windows Server 2025 DNS Remote Code Execution"}]
    tags = set(MODULE.derive_product_tags(products))
    forbidden = {
        "remote-code-execution", "elevation-of-privilege", "security-feature-bypass",
        "information-disclosure", "denial-of-service", "spoofing",
        "user-content", "email", "web", "remote-service", "local-access", "dns",
    }
    assert not (tags & forbidden), f"derivation leaked judgement tags: {sorted(tags & forbidden)}"


def test_no_regex_tag_rules_remain():
    """The prose-matching tag table must not come back."""
    assert not hasattr(MODULE, "TAG_RULES")
    assert not hasattr(MODULE, "infer_tags")
