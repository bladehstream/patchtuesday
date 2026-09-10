"""The direction gate must reject the exact shape that got past every other check.

CVE-2026-18149: a malicious server attacks an HTTP client. Traffic is outbound.
Both the previous assessor and a fresh Haiku run credited "remove external
exposure" against it. A CVSS-vector check cannot catch that - AV:N holds in both
directions - so this fixture exists to prove the direction check does.
"""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("merge_inference", ROOT / "scripts" / "merge_inference.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RULES = MODULE.direction_rules(ROOT / "data" / "mitigation-catalog.json")


def overlay(direction, control="remove_external_exposure", likelihood_steps=1, path_block=False):
    return {
        "attack_path": {"direction": direction, "evidence": "test fixture"},
        "mitigation_candidates": [{
            "id": control,
            "relevance": "relevant",
            "confidence": "medium",
            "effect": {"likelihood_steps": likelihood_steps, "consequence_steps": 0, "path_block": path_block},
            "evidence": "removing public exposure reduces unsolicited attack reachability",
        }],
    }


def test_rejects_ingress_control_credited_against_outbound_attack():
    """The real failure, reproduced. This must raise."""
    with pytest.raises(ValueError, match="outbound"):
        MODULE.check_direction("CVE-2026-18149", overlay("outbound"), RULES)


def test_rejects_path_block_too_not_only_likelihood_steps():
    with pytest.raises(ValueError, match="outbound"):
        MODULE.check_direction("CVE-TEST", overlay("outbound", likelihood_steps=0, path_block=True), RULES)


def test_allows_the_same_control_against_an_inbound_attack():
    MODULE.check_direction("CVE-TEST", overlay("inbound"), RULES)


def test_allows_zero_credit_in_any_direction():
    """Naming a control without crediting it is not a claim, so it is permitted."""
    MODULE.check_direction("CVE-TEST", overlay("outbound", likelihood_steps=0), RULES)


def test_allows_direction_agnostic_controls_against_outbound():
    MODULE.check_direction("CVE-TEST", overlay("outbound", control="edr_exploit_prevention"), RULES)


def test_requires_a_direction_at_all():
    with pytest.raises(ValueError, match="attack_path.direction"):
        MODULE.check_direction("CVE-TEST", {"mitigation_candidates": []}, RULES)


def test_rejects_an_invalid_direction():
    bad = overlay("sideways")
    with pytest.raises(ValueError, match="attack_path.direction"):
        MODULE.check_direction("CVE-TEST", bad, RULES)


def test_catalogue_declares_direction_for_every_control():
    catalogue = json.loads((ROOT / "data" / "mitigation-catalog.json").read_text(encoding="utf-8"))
    for entry in catalogue:
        assert entry.get("applies_to_direction"), f"{entry['id']} must declare applies_to_direction"
        assert set(entry["applies_to_direction"]) <= set(MODULE.ATTACK_DIRECTIONS)
