"""Deterministic CVRF parsing: severity, product tags, and filter reachability.

    python3 tests/test_enrich_cvrf.py

Plain python, no test framework. Until 2026-09-11 the `if __name__ == "__main__"`
block sat in the middle of this file and called exactly one of its test functions,
so seven of eight ran nowhere. The runner is now at the bottom and names every
case, which is why the count it prints is worth reading.

The product-name cases below arrived from tests/test_product_filter_coverage.py,
which was written in pytest style and therefore never ran either.
"""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "enrich_cvrf.py"
SPEC = importlib.util.spec_from_file_location("enrich_cvrf", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PUBLISHED = ROOT / "data" / "2026-Sep.jsonl"


def products(*names):
    return [{"product_id": str(index), "name": name} for index, name in enumerate(names)]


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
    tags = MODULE.derive_product_tags(products(
        "Windows Server 2025",
        "Windows 11 Version 24H2 for x64-based Systems",
    ))
    assert "server-2025" in tags
    assert "windows-11" in tags
    assert "server" in tags
    assert "endpoint" in tags
    assert "microsoft" in tags


def test_product_tags_ignore_title_prose():
    """A title mentioning a product does not create a release tag."""
    tags = MODULE.derive_product_tags(products("Windows Server 2012"))
    assert "server-2025" not in tags
    assert "windows-11" not in tags
    assert "server" in tags


def test_derivation_emits_no_judgement_tags():
    """Impact, delivery and workload tags are the model's job, never derived."""
    tags = set(MODULE.derive_product_tags(products("Windows Server 2025 DNS Remote Code Execution")))
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


# --- filter reachability -----------------------------------------------------
#
# An administrator's core question is "does this affect anything I run". A record
# tagged only `microsoft` cannot be reached by any product selector, so it is
# invisible to that question no matter how good its risk assessment is. Measured
# 2026-09-11: 64 of 1185 records (5.4%) were generic-only, including all 23
# Microsoft Edge advisories and every Exchange Server record.

PRODUCT_NAME_TAGS = [
    ("Microsoft Edge (Chromium-based)", "edge"),
    ("Microsoft Exchange Server 2019 Cumulative Update 15", "exchange"),
    ("Microsoft Exchange Server Subscription Edition RTM", "exchange"),
    ("Visual Studio Code", "vscode"),
    ("Microsoft Visual Studio 2026 version 18.9", "visual-studio"),
    ("Microsoft Teams for Android", "teams"),
    (".NET 10.0 installed on Linux", "dotnet"),
    ("Microsoft Dynamics 365 (on-premises) version 9.1", "dynamics-365"),
    ("Power Automate for Desktop", "power-platform"),
    ("Microsoft Entra ID", "entra-id"),
    ("Microsoft Fabric", "fabric"),
    ("Windows Server 2022", "server-2022"),
    ("Windows 11 Version 24H2 for x64-based Systems", "windows-11"),
]


def test_product_name_yields_its_filter_tag():
    for name, expected in PRODUCT_NAME_TAGS:
        assert expected in MODULE.derive_product_tags(products(name)), \
            f"{name!r} must yield the {expected!r} filter tag"


def test_vscode_does_not_claim_the_visual_studio_ide_tag():
    """"Visual Studio Code" contains "visual studio" as a substring."""
    tags = MODULE.derive_product_tags(products("Visual Studio Code"))
    assert "vscode" in tags
    assert "visual-studio" not in tags


def test_both_tags_when_both_products_are_present():
    tags = MODULE.derive_product_tags(products("Visual Studio Code", "Microsoft Visual Studio 2026 version 18.9"))
    assert {"vscode", "visual-studio"} <= set(tags)


def test_published_records_are_reachable_by_a_specific_filter():
    if not PUBLISHED.exists():
        raise AssertionError(f"{PUBLISHED} is missing; the reachability check cannot be skipped silently")
    with PUBLISHED.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    generic = [r["cve"] for r in records if not (set(r.get("product_tags") or []) - {"microsoft"})]
    reachable = (len(records) - len(generic)) / len(records)
    assert reachable >= 0.99, (
        f"only {reachable:.1%} of records are reachable by a specific product filter; "
        f"generic-only: {generic[:15]}"
    )


# (title, tags it must yield). Every rule in WORKLOAD_COMPONENT_RULES needs a case
# here; test_every_workload_rule_has_a_fixture enforces that, so a rule cannot be
# added without one.
WORKLOAD_TITLE_TAGS = [
    ("Remote Desktop Services Remote Code Execution Vulnerability", {"remote-desktop"}),
    ("Remote Desktop Client Remote Code Execution Vulnerability", {"remote-desktop"}),
    ("Windows Remote Desktop Protocol Information Disclosure Vulnerability", {"remote-desktop"}),
    ("Remote Desktop Gateway Service Elevation of Privilege Vulnerability", {"remote-desktop"}),
    ("Windows Active Directory Domain Services Elevation of Privilege Vulnerability", {"identity"}),
    ("Active Directory Certificate Services (AD CS) Elevation of Privilege Vulnerability", {"identity"}),
    ("Active Directory Federation Services (AD FS) Spoofing Vulnerability", {"identity"}),
    ("Windows Kerberos Elevation of Privilege Vulnerability", {"identity"}),
    ("Windows Key Distribution Center Denial of Service Vulnerability", {"identity"}),
    ("Windows Netlogon Spoofing Vulnerability", {"identity"}),
    ("Microsoft Local Security Authority (LSA) Server Elevation of Privilege Vulnerability", {"identity"}),
    ("Windows DNS Server Remote Code Execution Vulnerability", {"dns"}),
    ("Windows DHCP Server Remote Code Execution Vulnerability", {"dhcp"}),
    ("Windows Hyper-V Elevation of Privilege Vulnerability", {"hyper-v"}),
    ("Microsoft Exchange Server Spoofing Vulnerability", {"exchange"}),
    ("Internet Information Services Denial of Service Vulnerability", {"web-server"}),
    ("Windows IIS Server Elevation of Privilege Vulnerability", {"web-server"}),
]

# Near misses. Each contains a rule phrase as a substring and must NOT earn the tag.
WORKLOAD_TITLE_NON_TAGS = [
    # Contains "Exchange". It is an IPsec key negotiation component, not Exchange Server.
    ("Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability", "exchange"),
    # Not the Remote Desktop Connection Broker. A loose substring rule over the whole
    # title flagged this one, which is how the precision half of this fix was found.
    ("Windows Network Connection Broker Information Disclosure Vulnerability", "remote-desktop"),
    ("Windows Routing and Remote Access Service (RRAS) Remote Code Execution Vulnerability", "remote-desktop"),
]


def test_workload_title_yields_its_filter_tag():
    for title, expected in WORKLOAD_TITLE_TAGS:
        derived = set(MODULE.derive_workload_tags(title))
        assert expected <= derived, f"{title!r} must yield {sorted(expected)}, got {sorted(derived)}"


def test_near_miss_titles_do_not_earn_the_tag():
    for title, forbidden in WORKLOAD_TITLE_NON_TAGS:
        derived = set(MODULE.derive_workload_tags(title))
        assert forbidden not in derived, f"{title!r} must not claim {forbidden!r}"


def test_every_workload_rule_has_a_fixture():
    """A rule with no fixture is a rule nobody has seen work or fail."""
    covered = set()
    for title, expected in WORKLOAD_TITLE_TAGS:
        covered |= expected
    declared = {tag for tag, _, _ in MODULE.WORKLOAD_COMPONENT_RULES}
    assert declared == covered, (
        f"rules without a fixture: {sorted(declared - covered)}; "
        f"fixtures for rules that no longer exist: {sorted(covered - declared)}"
    )


def test_a_title_of_unknown_shape_yields_nothing():
    """No component, no tag. Guessing at one is the prose matching this avoids."""
    for title in ("Chromium: CVE-2026-1234 Use after free in V8",
                  "Remote Desktop Services",
                  "",
                  "Remote Code Execution Vulnerability"):
        assert MODULE.derive_workload_tags(title) == [], f"{title!r} must yield no workload tag"


def test_workload_tags_reach_the_product_tag_set():
    """The rule must be wired into derive_product_tags, not merely defined."""
    tags = MODULE.derive_product_tags(
        products("Windows Server 2022"),
        "Remote Desktop Services Remote Code Execution Vulnerability")
    assert "remote-desktop" in tags, (
        "a Remote Desktop advisory whose product tree names only the OS SKU must still "
        "carry the remote-desktop filter tag")


def test_published_records_carry_their_deterministic_workload_tag():
    if not PUBLISHED.exists():
        raise AssertionError(f"{PUBLISHED} is missing; this check cannot be skipped silently")
    with PUBLISHED.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    missing = []
    for record in records:
        expected = set(MODULE.derive_workload_tags(record.get("title") or ""))
        carried = set(record.get("product_tags") or []) | set(record.get("tags") or [])
        if expected - carried:
            missing.append((record["cve"], sorted(expected - carried)))
    assert not missing, (
        f"{len(missing)} published records name a workload component in their title but "
        f"cannot be reached by its filter: {missing[:10]}")


CASES = [
    test_build_records_maps_product_and_vector,
    test_resolve_severity_preserves_unknown_when_vendor_publishes_nothing,
    test_resolve_severity_uses_vendor_text_without_a_score,
    test_resolve_severity_uses_score_without_vendor_text,
    test_missing_score_is_none_not_zero,
    test_product_tags_derive_from_structured_products_not_prose,
    test_product_tags_ignore_title_prose,
    test_derivation_emits_no_judgement_tags,
    test_no_regex_tag_rules_remain,
    test_product_name_yields_its_filter_tag,
    test_vscode_does_not_claim_the_visual_studio_ide_tag,
    test_both_tags_when_both_products_are_present,
    test_published_records_are_reachable_by_a_specific_filter,

    test_workload_title_yields_its_filter_tag,
    test_near_miss_titles_do_not_earn_the_tag,
    test_every_workload_rule_has_a_fixture,
    test_a_title_of_unknown_shape_yields_nothing,
    test_workload_tags_reach_the_product_tag_set,
    test_published_records_carry_their_deterministic_workload_tag,
]


def run_tests():
    failures = []
    for case in CASES:
        try:
            case()
        except AssertionError as error:
            failures.append(f"{case.__name__}: {error}")
        except Exception as error:  # noqa: BLE001 - a crash is a failure, not an error to hide
            failures.append(f"{case.__name__}: {type(error).__name__}: {error}")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(CASES) - len(failures)}/{len(CASES)} CVRF enrichment tests passed")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    run_tests()
