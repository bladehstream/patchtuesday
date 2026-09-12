#!/usr/bin/env python3
"""Self-test for span_verify.py (Tier 1). Plain python, no test framework.

    python3 scripts/span_verify_self_test.py

The verifier must accept real citations and reject invented ones. Both halves
matter and they fail in opposite directions: a verifier tuned too strictly
discards sound verdicts (the previous checker threw away 549 of 1496 in the
2026-09-11 full run), and one tuned too loosely accepts word salad assembled from
the record's own vocabulary, which is exactly the shape a fabricated citation has.

Cases are taken verbatim from that run. Previously carried as
tests/test_span_verify.py in pytest style, which nothing in this repository ever
ran.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import span_verify as sv  # noqa: E402

RECORD = {
    "cve": "CVE-2026-62694",
    "title": "Windows Installer Elevation of Privilege Vulnerability",
    "products": ["Windows Server 2025", "Windows 11 Version 24H2 for x64-based Systems"],
    "attack": {"vector": "local", "privileges_required": "low", "user_interaction": "none"},
    "vendor_guidance": {"notes": [
        {"title": "Description", "type": 2,
         "value": "<p>Use after free in Windows Installer allows an authorized attacker to elevate privileges locally.</p>\n"},
        {"title": "FAQ", "type": 4,
         "value": "<p>An attacker who successfully exploited this vulnerability could gain SYSTEM privileges.</p>"}]}}

REAL_CITATIONS = [
    'Use after free in Windows Installer allows an authorized attacker to elevate privileges locally.',
    'Title: "Windows Installer Elevation of Privilege Vulnerability"; Description: "Use after free in Windows Installer allows an authorized attacker to elevate privileges locally."',
    '"Use after free in Windows Installer allows an authorized attacker" + "elevate privileges locally"',
    'allows an authorized attacker to elevate privileges locally ... An attacker who successfully exploited this vulnerability',
    'An attacker who successfully exploited this vulnerability could gain SYSTEM privileges',
]

INVENTED_CITATIONS = [
    'the advisory describes DHCP lease handling on the affected server',
    'generally accepted industry practice for this component class',
    'the vendor confirms this is exploited in the wild by ransomware operators',
]


def real_citations_verify():
    for span in REAL_CITATIONS:
        assert sv.verify(span, RECORD)["verified"], f"should verify: {span[:60]}"


def invented_citations_do_not_verify():
    for span in INVENTED_CITATIONS:
        assert not sv.verify(span, RECORD)["verified"], f"should NOT verify: {span[:60]}"


def word_salad_from_record_vocabulary_is_rejected():
    """Words that all appear in the record, recombined into a claim it never makes."""
    span = "Windows Installer privileges vulnerability attacker free authorized elevate"
    assert not sv.verify(span, RECORD)["verified"]


def html_in_the_source_does_not_block_a_match():
    assert sv.verify("Use after free in Windows Installer allows an authorized attacker", RECORD)["verified"]


def empty_span_does_not_verify():
    assert not sv.verify("", RECORD)["verified"]


def partial_composite_is_reported():
    span = ('Description: "Use after free in Windows Installer allows an authorized attacker to elevate privileges"; '
            '"the vendor states active exploitation has been observed"')
    result = sv.verify(span, RECORD)
    assert result["verified"] and not result["fully_verified"]
    assert result["matched"] == 1 and result["components"] == 2


def short_structured_field_citation_verifies():
    """'"vector": "local"' is a legitimate quotation of a structured field."""
    assert sv.verify('"vector": "local"', RECORD)["verified"]
    assert sv.verify('"user_interaction": "none"', RECORD)["verified"]


def short_but_absent_field_citation_does_not_verify():
    assert not sv.verify('"vector": "physical"', RECORD)["verified"]


CASES = [
    ("real citations verify", real_citations_verify),
    ("invented citations do not verify", invented_citations_do_not_verify),
    ("word salad from record vocabulary is rejected", word_salad_from_record_vocabulary_is_rejected),
    ("HTML in the source does not block a match", html_in_the_source_does_not_block_a_match),
    ("an empty span does not verify", empty_span_does_not_verify),
    ("a partial composite is reported as partial", partial_composite_is_reported),
    ("a short structured-field citation verifies", short_structured_field_citation_verifies),
    ("a short but absent field citation does not verify", short_but_absent_field_citation_does_not_verify),
]


def main() -> None:
    failures = []
    for label, case in CASES:
        try:
            case()
        except AssertionError as error:
            failures.append(f"{label}: {error}")
        except Exception as error:  # noqa: BLE001 - a crash is a failure, not an error to hide
            failures.append(f"{label}: {type(error).__name__}: {error}")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(CASES) - len(failures)}/{len(CASES)} span verifier checks behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
