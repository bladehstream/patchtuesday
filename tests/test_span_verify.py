"""The span verifier must accept real citations and reject invented ones.

Cases taken verbatim from the 2026-09-11 full run, where the previous checker
discarded 549 of 1496 verdicts.
"""
import importlib.util, json
from pathlib import Path
import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("sv", ROOT / "scripts" / "span_verify.py")
SV = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(SV)

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

@pytest.mark.parametrize("span", [
  'Use after free in Windows Installer allows an authorized attacker to elevate privileges locally.',
  'Title: "Windows Installer Elevation of Privilege Vulnerability"; Description: "Use after free in Windows Installer allows an authorized attacker to elevate privileges locally."',
  '"Use after free in Windows Installer allows an authorized attacker" + "elevate privileges locally"',
  'allows an authorized attacker to elevate privileges locally ... An attacker who successfully exploited this vulnerability',
  'An attacker who successfully exploited this vulnerability could gain SYSTEM privileges',
])
def test_real_citations_verify(span):
    assert SV.verify(span, RECORD)["verified"], f"should verify: {span[:60]}"

@pytest.mark.parametrize("span", [
  'the advisory describes DHCP lease handling on the affected server',
  'generally accepted industry practice for this component class',
  'the vendor confirms this is exploited in the wild by ransomware operators',
])
def test_invented_citations_do_not_verify(span):
    assert not SV.verify(span, RECORD)["verified"], f"should NOT verify: {span[:60]}"

def test_word_salad_from_record_vocabulary_is_rejected():
    """Words that all appear in the record, recombined into a claim it never makes."""
    span = "Windows Installer privileges vulnerability attacker free authorized elevate"
    assert not SV.verify(span, RECORD)["verified"]

def test_html_in_the_source_does_not_block_a_match():
    assert SV.verify("Use after free in Windows Installer allows an authorized attacker", RECORD)["verified"]

def test_empty_span_does_not_verify():
    assert not SV.verify("", RECORD)["verified"]

def test_partial_composite_is_reported():
    span = 'Description: "Use after free in Windows Installer allows an authorized attacker to elevate privileges"; "the vendor states active exploitation has been observed"'
    r = SV.verify(span, RECORD)
    assert r["verified"] and not r["fully_verified"]
    assert r["matched"] == 1 and r["components"] == 2


def test_short_structured_field_citation_verifies():
    """'"vector": "local"' is a legitimate quotation of a structured field."""
    assert SV.verify('"vector": "local"', RECORD)["verified"]
    assert SV.verify('"user_interaction": "none"', RECORD)["verified"]


def test_short_but_absent_field_citation_does_not_verify():
    assert not SV.verify('"vector": "physical"', RECORD)["verified"]
