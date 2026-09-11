"""Every Tier 1 check must reject something it was built to catch.

Cases are drawn from real failures observed in the 2026-09 dev runs, not invented.
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("tv", ROOT / "scripts" / "tag_validators.py")
TV = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(TV)
NS = TV.load_namespaces(ROOT / "data" / "tag-taxonomy.json")
WORKLOAD = NS["workload"]
JUDGE = NS["workload"] | NS["delivery"] | NS["impact"]


def record(title, ui="required", vector="network", products=()):
    return {"cve": "CVE-TEST", "title": title,
            "products": [{"product_id": "1", "name": n} for n in products],
            "attack": {"vector": vector, "privileges_required": "none", "user_interaction": ui}}


def overlay(*pairs):
    return {"tags": [{"tag": t, "evidence": e} for t, e in pairs]}


# --- workload recall: the eight real misses from cycle 4 ---
@pytest.mark.parametrize("title,expected", [
    ("Windows Remote Desktop Remote Code Execution Vulnerability", "remote-desktop"),
    ("Windows Services for NFS ONCRPC XDR Driver Remote Code Execution", "nfs"),
    ("Windows Kerberos Denial of Service Vulnerability", "identity"),
    ("Windows Shell Remote Code Execution Vulnerability", "windows-shell"),
    ("Windows SMB Server Network Transport Driver Elevation of Privilege", "file-services"),
    ("Windows DNS Server Remote Code Execution Vulnerability", "dns"),
])
def test_recall_flags_a_named_role_that_was_not_tagged(title, expected):
    findings = TV.check_workload_recall(record(title), overlay())
    assert any(f["tag"] == expected and f["code"] == "workload-recall-miss" for f in findings), \
        f"expected a {expected} recall miss for {title!r}"


def test_recall_is_silent_when_the_role_was_tagged():
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    assert TV.check_workload_recall(r, overlay(("dns", "Windows DNS Server"))) == []


def test_recall_is_silent_when_no_role_is_named():
    """Chromium passthroughs name no role. Abstaining is correct, not a miss."""
    r = record("Chromium: CVE-2026-84350 Use after free in TabStrip")
    assert TV.check_workload_recall(r, overlay()) == []


# --- workload precision ---
def test_precision_flags_a_tag_with_no_corroboration():
    r = record("Microsoft Exchange Server Elevation of Privilege Vulnerability")
    findings = TV.check_workload_precision(r, overlay(("identity", "Exchange implies directory")), WORKLOAD)
    assert [f["code"] for f in findings] == ["workload-uncorroborated"]


def test_precision_accepts_a_corroborated_tag():
    r = record("Windows DHCP Server Denial of Service Vulnerability")
    assert TV.check_workload_precision(r, overlay(("dhcp", "Windows DHCP Server")), WORKLOAD) == []


# --- delivery vs CVSS: the real CVE-2026-69380 contradiction ---
def test_delivery_flags_user_content_against_ui_none():
    r = record("Microsoft Exchange Server Elevation of Privilege Vulnerability", ui="none")
    findings = TV.check_delivery_consistency(r, overlay(("user-content", "crafted message"), ("email", "mail flow")))
    assert len(findings) == 2
    assert {f["tag"] for f in findings} == {"user-content", "email"}


def test_delivery_flags_local_access_against_network_vector():
    r = record("Something", ui="required", vector="network")
    findings = TV.check_delivery_consistency(r, overlay(("local-access", "requires local logon")))
    assert findings and findings[0]["code"] == "delivery-contradicts-cvss"


def test_delivery_accepts_a_consistent_tag():
    r = record("Excel Remote Code Execution", ui="required", vector="local")
    assert TV.check_delivery_consistency(r, overlay(("user-content", "user opens a crafted file"))) == []


# --- evidence presence and grounding ---
def test_missing_evidence_is_flagged():
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    findings = TV.check_evidence_present(r, overlay(("dns", "  ")), JUDGE)
    assert findings and findings[0]["code"] == "evidence-missing"


def test_evidence_citing_its_own_reasoning_is_flagged():
    """The signature of a fabricated citation: no lexical contact with the source."""
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    findings = TV.check_evidence_grounded(r, overlay(("dns", "generally accepted industry practice")), JUDGE)
    assert findings and findings[0]["code"] == "evidence-ungrounded"


def test_evidence_quoted_from_the_record_passes():
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    assert TV.check_evidence_grounded(r, overlay(("dns", "Windows DNS Server")), JUDGE) == []


def test_pre_change_bare_string_tags_are_tolerated():
    """Older runs stored tags as plain strings; the validators must not crash."""
    assert TV.asserted({"tags": ["dns", "remote-code-execution"]}) == {"dns": "", "remote-code-execution": ""}
