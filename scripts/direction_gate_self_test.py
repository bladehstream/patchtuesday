#!/usr/bin/env python3
"""Self-test for the attack-direction gate in merge_inference.py. Plain python.

    python3 scripts/direction_gate_self_test.py

CVE-2026-18149 is why the gate exists. Undici's flaw is a malicious SERVER
attacking an HTTP CLIENT, so the traffic is outbound. Both the previous assessor
and a fresh Haiku run credited "remove external exposure" against it, reasoning
that closing public ingress reduces reachability. It does not - nothing is
connecting in. A CVSS-vector check cannot catch that, because AV:N holds in both
directions. Only direction can, which makes this the fixture that proves the gate
is doing work no other check does.

The gate under test is `enforce_direction`: per the 2026-09-10 granularity
decision it zeroes the unsupported credit and records the contradiction rather
than rejecting a whole assessment over one bad control. A missing or invalid
direction still raises, because there is then nothing to check any control
against.

Previously carried as tests/test_direction_enforcement.py and
tests/test_direction_validator.py in pytest style, which nothing in this
repository ever ran.

WIRING. Until 2026-09-11 every case below passed while `merge_inference.main()`
never called the gate, so the CVE-2026-18149 class of error reached a published
record with all nine checks green. A gate that is defined, correct and uncalled is
the failure mode here, which makes "is it called?" a fixture in its own right - the
last three cases drive scripts/merge_inference.py end to end over a real published
record and fail if the call site in main() is removed.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import merge_inference as mi  # noqa: E402

CATALOGUE = ROOT / "data" / "mitigation-catalog.json"
MERGE = ROOT / "scripts" / "merge_inference.py"
PUBLISHED = ROOT / "data" / "2026-Sep.jsonl"
RULES = mi.direction_rules(CATALOGUE)


def overlay(direction, control="remove_external_exposure", steps=1, block=False):
    return {"attack_path": {"direction": direction, "evidence": "fixture"},
            "mitigation_candidates": [{
                "id": control, "relevance": "relevant", "confidence": "medium",
                "effect": {"likelihood_steps": steps, "consequence_steps": 0, "path_block": block},
                "evidence": "closing public ingress reduces reachability"}]}


def expect_value_error(function, expected_text):
    try:
        function()
    except ValueError as error:
        assert expected_text in str(error), f"expected {expected_text!r} in {error}"
    else:
        raise AssertionError(f"expected a ValueError containing {expected_text!r}")


def zeroes_credit_and_keeps_the_assessment():
    """The real failure, reproduced: an ingress control credited against outbound."""
    o = overlay("outbound")
    violations = mi.enforce_direction("CVE-2026-18149", o, RULES)
    assert len(violations) == 1 and violations[0]["code"] == "direction-contradiction"
    effect = o["mitigation_candidates"][0]["effect"]
    assert effect["likelihood_steps"] == 0 and effect["path_block"] is False
    assert o["mitigation_candidates"][0]["relevance"] == "not-relevant"
    assert o["mitigation_candidates"][0]["direction_override"] is True
    assert o["attack_path"]["direction"] == "outbound", "the assessment must survive"


def records_what_was_claimed_before_zeroing():
    violations = mi.enforce_direction("CVE-TEST", overlay("outbound", steps=2), RULES)
    assert violations[0]["claimed"]["likelihood_steps"] == 2


def path_block_is_zeroed_too_not_only_likelihood_steps():
    o = overlay("outbound", steps=0, block=True)
    assert len(mi.enforce_direction("CVE-TEST", o, RULES)) == 1
    assert o["mitigation_candidates"][0]["effect"]["path_block"] is False


def leaves_valid_credit_alone():
    o = overlay("inbound")
    assert mi.enforce_direction("CVE-TEST", o, RULES) == []
    assert o["mitigation_candidates"][0]["effect"]["likelihood_steps"] == 1


def direction_agnostic_control_is_untouched():
    o = overlay("outbound", control="edr_exploit_prevention")
    assert mi.enforce_direction("CVE-TEST", o, RULES) == []


def zero_credit_is_not_a_claim_in_any_direction():
    """Naming a control without crediting it is not a claim, so it is permitted."""
    o = overlay("outbound", steps=0)
    assert mi.enforce_direction("CVE-TEST", o, RULES) == []


def missing_direction_raises():
    expect_value_error(lambda: mi.enforce_direction("CVE-TEST", {"mitigation_candidates": []}, RULES),
                       "attack_path.direction")


def invalid_direction_raises():
    expect_value_error(lambda: mi.enforce_direction("CVE-TEST", overlay("sideways"), RULES),
                       "attack_path.direction")


def catalogue_declares_a_direction_for_every_control():
    """A control with no declared direction defaults to "acts in all four", which
    silently disables the gate for it. The catalogue must leave none undeclared."""
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    assert catalogue, "the mitigation catalogue must not be empty"
    for entry in catalogue:
        declared = entry.get("applies_to_direction")
        assert declared, f"{entry['id']} must declare applies_to_direction"
        assert set(declared) <= set(mi.ATTACK_DIRECTIONS), \
            f"{entry['id']} declares directions outside {mi.ATTACK_DIRECTIONS}: {declared}"


def only_one_direction_gate_exists():
    """`check_direction` was the superseded raise-on-contradiction variant.

    Two implementations of one rule is how the rule came to sit uncalled: the
    self-test exercised one, the runbook described the other, and `main()` called
    neither. Removed 2026-09-11; this fixture fails if it comes back.
    """
    assert hasattr(mi, "enforce_direction"), "the surviving gate is enforce_direction"
    assert not hasattr(mi, "check_direction"), \
        "check_direction was removed in favour of enforce_direction; do not reintroduce it"


# --- wiring: the gate must be reached, not merely defined -------------------


def a_real_published_record() -> dict:
    """A real network-vector record with a framework assessment already accepted.

    Built from published data rather than an invented shape, so the fixture has to
    get past every other gate in merge_inference the way a real overlay does.
    """
    with PUBLISHED.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if ((record.get("attack") or {}).get("vector") == "network"
                    and (record.get("inference") or {}).get("framework_assessment")):
                return record
    raise AssertionError(f"no network-vector assessed record in {PUBLISHED}")


def run_merge(work: Path, direction: str, extra_args: list[str] | None = None):
    """Write a one-record baseline and overlay, then run the real merge script."""
    record = a_real_published_record()
    source = {k: v for k, v in record.items()
              if k not in ("inference", "mitigation_candidates", "priority", "review")}
    overlay_record = {
        "cve": record["cve"],
        "cvss_basis": {
            "base_score": (source.get("cvss") or {}).get("base_score"),
            "vector": (source.get("cvss") or {}).get("vector"),
            "attack_vector": (source.get("attack") or {}).get("vector"),
            "privileges_required": (source.get("attack") or {}).get("privileges_required"),
            "user_interaction": (source.get("attack") or {}).get("user_interaction"),
        },
        "tags": [],
        # The CVE-2026-18149 shape: an ingress-only control credited against a
        # non-ingress attack path. Nothing else in the pipeline rejects this.
        "mitigation_candidates": [{
            "id": "remove_external_exposure", "relevance": "relevant",
            "confidence": "medium",
            "effect": {"likelihood_steps": 1, "consequence_steps": 0, "path_block": False},
            "evidence": "closing public ingress reduces reachability",
        }],
        "framework_assessment": record["inference"]["framework_assessment"],
    }
    if direction is not None:
        overlay_record["attack_path"] = {"direction": direction, "evidence": "fixture"}

    baseline = work / "baseline.jsonl"
    baseline.write_text(json.dumps(source, separators=(",", ":")) + "\n", encoding="utf-8")
    inference = work / "inference.jsonl"
    inference.write_text(json.dumps(overlay_record, separators=(",", ":")) + "\n", encoding="utf-8")
    output = work / "merged.jsonl"

    result = subprocess.run(
        [sys.executable, str(MERGE), "--baseline", str(baseline),
         "--inference", str(inference), "--output", str(output), *(extra_args or [])],
        capture_output=True, text=True, cwd=str(ROOT),
    )
    merged = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()] \
        if output.is_file() else []
    return result, merged


def main_calls_the_gate():
    """Remove the `enforce_direction(...)` call from main() and this goes red."""
    body = inspect.getsource(mi.main)
    assert "enforce_direction(" in body, \
        "merge_inference.main() must call enforce_direction; a gate nobody calls is not a gate"


def merging_a_contradiction_removes_the_credit_end_to_end():
    """The whole script, over a real record. The fixture the published data needed.

    This is what fails if the call site in main() is deleted: the merge still
    succeeds, but the record comes out of it still carrying the credit.
    """
    with tempfile.TemporaryDirectory() as raw:
        result, merged = run_merge(Path(raw), "outbound")
        assert result.returncode == 0, f"merge should succeed, not reject the record:\n{result.stderr}"
        assert len(merged) == 1, f"expected one merged record, got {len(merged)}"
        candidate = merged[0]["mitigation_candidates"][0]
        assert candidate["effect"]["likelihood_steps"] == 0, \
            "the contradicting credit must be zeroed in the merged record"
        assert candidate["effect"]["path_block"] is False
        assert candidate["relevance"] == "not-relevant"
        assert candidate["direction_override"] is True, \
            "the merged record must say the credit was overridden, not just drop it"


def the_violation_is_surfaced_in_output_and_record():
    """Violations must be readable both on the day and afterwards."""
    with tempfile.TemporaryDirectory() as raw:
        result, merged = run_merge(Path(raw), "outbound")
        combined = result.stdout + result.stderr
        assert "direction-contradiction" in combined, \
            f"the merge summary must name the violation; got:\n{combined}"
        assert "remove_external_exposure" in combined, \
            "the merge summary must name the control whose credit was removed"
        gate = merged[0]["inference"]["direction_gate"]
        assert gate["status"] == "violations-found", f"unexpected gate status {gate}"
        assert gate["violations"][0]["code"] == "direction-contradiction"
        assert gate["violations"][0]["claimed"]["likelihood_steps"] == 1, \
            "the record must retain what was claimed before the credit was zeroed"


def a_clean_record_still_says_the_gate_ran():
    """`clean` and `never checked` must not look the same on a published record."""
    with tempfile.TemporaryDirectory() as raw:
        result, merged = run_merge(Path(raw), "inbound")
        assert result.returncode == 0, result.stderr
        candidate = merged[0]["mitigation_candidates"][0]
        assert candidate["effect"]["likelihood_steps"] == 1, "valid credit must survive the merge"
        assert merged[0]["inference"]["direction_gate"]["status"] == "clean"


def an_overlay_with_no_direction_is_rejected_by_default():
    with tempfile.TemporaryDirectory() as raw:
        result, _ = run_merge(Path(raw), None)
        assert result.returncode != 0, "an overlay asserting no direction must not merge silently"
        assert "attack_path.direction" in (result.stdout + result.stderr)


def a_legacy_overlay_is_recorded_unchecked_never_clean():
    """--allow-missing-direction must never produce a record that reads as passed."""
    with tempfile.TemporaryDirectory() as raw:
        result, merged = run_merge(Path(raw), None, ["--allow-missing-direction"])
        assert result.returncode == 0, result.stderr
        gate = merged[0]["inference"]["direction_gate"]
        assert gate["status"] == "unchecked", f"expected unchecked, got {gate}"
        assert "UNCHECKED" in (result.stdout + result.stderr), \
            "an unchecked month must say so in the merge summary"


CASES = [
    ("credit is zeroed and the assessment survives", zeroes_credit_and_keeps_the_assessment),
    ("the claim is recorded before zeroing", records_what_was_claimed_before_zeroing),
    ("path_block is zeroed too", path_block_is_zeroed_too_not_only_likelihood_steps),
    ("valid credit is left alone", leaves_valid_credit_alone),
    ("a direction-agnostic control is untouched", direction_agnostic_control_is_untouched),
    ("zero credit is not a claim", zero_credit_is_not_a_claim_in_any_direction),
    ("a missing direction raises", missing_direction_raises),
    ("an invalid direction raises", invalid_direction_raises),
    ("every catalogue control declares a direction", catalogue_declares_a_direction_for_every_control),
    ("only one direction gate exists", only_one_direction_gate_exists),
    # Wiring. These fail if the gate stops being reached, even though the gate
    # itself is still perfectly correct - which was the state of the repository
    # for the whole of the September cycle.
    ("main() calls the gate", main_calls_the_gate),
    ("merging a contradiction removes the credit end to end", merging_a_contradiction_removes_the_credit_end_to_end),
    ("the violation is surfaced in output and on the record", the_violation_is_surfaced_in_output_and_record),
    ("a clean record still says the gate ran", a_clean_record_still_says_the_gate_ran),
    ("an overlay with no direction is rejected by default", an_overlay_with_no_direction_is_rejected_by_default),
    ("a legacy overlay is recorded unchecked, never clean", a_legacy_overlay_is_recorded_unchecked_never_clean),
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
    print(f"{len(CASES) - len(failures)}/{len(CASES)} direction gate checks behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
