import importlib.util, json
from pathlib import Path
import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("mi", ROOT / "scripts" / "merge_inference.py")
MI = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MI)
RULES = MI.direction_rules(ROOT / "data" / "mitigation-catalog.json")

def overlay(direction, control="remove_external_exposure", steps=1, block=False):
    return {"attack_path": {"direction": direction, "evidence": "fixture"},
            "mitigation_candidates": [{"id": control, "relevance": "relevant", "confidence": "medium",
              "effect": {"likelihood_steps": steps, "consequence_steps": 0, "path_block": block},
              "evidence": "closing public ingress reduces reachability"}]}

def test_zeroes_credit_and_keeps_the_assessment():
    o = overlay("outbound")
    v = MI.enforce_direction("CVE-2026-18149", o, RULES)
    assert len(v) == 1 and v[0]["code"] == "direction-contradiction"
    e = o["mitigation_candidates"][0]["effect"]
    assert e["likelihood_steps"] == 0 and e["path_block"] is False
    assert o["mitigation_candidates"][0]["relevance"] == "not-relevant"
    assert o["mitigation_candidates"][0]["direction_override"] is True
    assert o["attack_path"]["direction"] == "outbound"   # assessment survives

def test_records_what_was_claimed_before_zeroing():
    v = MI.enforce_direction("CVE-TEST", overlay("outbound", steps=2), RULES)
    assert v[0]["claimed"]["likelihood_steps"] == 2

def test_path_block_zeroed_too():
    o = overlay("outbound", steps=0, block=True)
    assert len(MI.enforce_direction("CVE-TEST", o, RULES)) == 1
    assert o["mitigation_candidates"][0]["effect"]["path_block"] is False

def test_leaves_valid_credit_alone():
    o = overlay("inbound")
    assert MI.enforce_direction("CVE-TEST", o, RULES) == []
    assert o["mitigation_candidates"][0]["effect"]["likelihood_steps"] == 1

def test_direction_agnostic_control_untouched():
    o = overlay("outbound", control="edr_exploit_prevention")
    assert MI.enforce_direction("CVE-TEST", o, RULES) == []

def test_missing_direction_still_raises():
    with pytest.raises(ValueError, match="attack_path.direction"):
        MI.enforce_direction("CVE-TEST", {"mitigation_candidates": []}, RULES)
