#!/usr/bin/env python3
"""Validate a manual inference overlay and merge it onto programmatic source facts.

Gates run per record, in order: cvss_basis fidelity, framework assessment, tag
vocabulary, per-candidate credit rules, path compatibility, and last the
attack-direction gate (`enforce_direction`). The direction gate runs last so the
model's claims are validated as authored before any credit is zeroed.

The direction gate does not fail a record. It removes credit a control cannot
possibly have earned in the asserted direction, marks the control
`direction_override: true`, and reports the contradiction - on the record as
`inference.direction_gate` and in this script's stdout summary. An overlay that
asserts no direction at all is rejected, because there is then nothing to check any
control against; `--allow-missing-direction` downgrades that to a recorded
UNCHECKED state for legacy overlays, and is never a clean result.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
RISK_MODEL_VERSION = "2026.09.1"
# Must stay in step with RISK_MODEL.baselineModels in risk-model.js. A vocabulary
# that drifts between the Python validator and the JS engine fails silently: the
# model asserts a baseline the validator rejects, or the engine selects one the
# schema never allowed.
BASELINE_MODELS = {"no-customer-action", "active-exploitation", "critical-preauth-network-rce", "critical-technical", "elevated-high-severity", "standard-remediation", "unknown-severity"}
LIKELIHOODS = ["Low evidence", "Plausible", "Elevated", "Active"]
ACTIONS = ["Defer and review", "Scheduled", "Out-of-cycle", "Immediate"]
REQUIRED_FACTORS = {"applicability", "threat_evidence", "exploitability", "technical_impact", "workload_context", "remediation_context", "uncertainty"}
REQUIRED_COMMUNICATION = {"summary", "why_this_action", "control_limitations", "reassessment_triggers"}


def read_jsonl(path: Path) -> list[dict]:
    output = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            output.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path} line {line_no}: {exc}") from exc
    return output


ATTACK_DIRECTIONS = ["inbound", "outbound", "local", "adjacent"]


def direction_rules(path: Path) -> dict[str, list[str]]:
    """Which attack directions each control can plausibly interrupt.

    Declared in the catalogue as data, not hardcoded here, so adding a control
    means adding its direction applicability alongside its credit rule.
    """
    catalogue = json.loads(path.read_text(encoding="utf-8"))
    return {
        item["id"]: item.get("applies_to_direction", list(ATTACK_DIRECTIONS))
        for item in catalogue
    }


def enforce_direction(cve: str, overlay: dict, rules: dict[str, list[str]]) -> list[dict]:
    """Zero credit that contradicts the asserted attack direction, and flag it.

    Granularity decision, 2026-09-10: rejecting an entire assessment over one bad
    control credit is the wrong response. The assessment's other work - direction,
    impact, factors, the remaining controls - may be sound, and discarding it buys
    nothing. The conservative action is to remove the unsupported discount and
    surface the contradiction for review, leaving the record with LESS credit than
    the model claimed rather than none at all.

    A missing or invalid direction is different and still raises: without a
    direction there is nothing to check any control against, so the assessment
    cannot be validated at all.

    Returns the list of violations, each already zeroed in place.
    """
    path_info = overlay.get("attack_path") or {}
    direction = path_info.get("direction")
    if direction not in ATTACK_DIRECTIONS:
        raise ValueError(f"{cve}: attack_path.direction must be one of {ATTACK_DIRECTIONS}, got {direction!r}")

    violations = []
    for candidate in overlay.get("mitigation_candidates") or []:
        effect = candidate.get("effect") or {}
        credited = (effect.get("likelihood_steps") or 0) > 0 or effect.get("path_block")
        if not credited:
            continue
        allowed = rules.get(candidate.get("id"), list(ATTACK_DIRECTIONS))
        if direction in allowed:
            continue
        violations.append({
            "code": "direction-contradiction",
            "control": candidate.get("id"),
            "direction": direction,
            "applies_to_direction": allowed,
            "claimed": {
                "likelihood_steps": effect.get("likelihood_steps"),
                "path_block": effect.get("path_block"),
            },
            "evidence": candidate.get("evidence", ""),
            "message": (
                f"{candidate.get('id')} was credited against an {direction} attack path "
                f"but only acts on {allowed}. Credit removed; assessment retained."
            ),
        })
        effect["likelihood_steps"] = 0
        effect["path_block"] = False
        candidate["relevance"] = "not-relevant"
        candidate["direction_override"] = True
    return violations


# `check_direction` used to live here: the same rule, but raising on the first
# contradicting credit and so discarding the whole assessment over one bad control.
# Removed 2026-09-11 in favour of `enforce_direction` above, for three reasons.
# First, the 2026-09-10 granularity decision: an assessment's direction, impact,
# factors and remaining controls may be sound, and throwing them away buys nothing
# the conservative action does not already buy - removing the unsupported discount
# leaves the record with LESS credit than the model claimed, which is the safe side.
# Second, raising on one record aborts the merge of the whole month, so in practice
# the gate would have been disabled rather than fixed. Third, two implementations of
# one rule is what let the rule sit uncalled: `direction_gate_self_test.py` exercised
# `enforce_direction`, the runbook described `check_direction`, and neither was wired
# into `main()`. One gate, one call site, one test. Do not reintroduce the variant.


def allowed_tags(path: Path) -> set[str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {tag for values in document["namespaces"].values() for tag in values}


def allowed_mitigations(path: Path) -> set[str]:
    return {item["id"] for item in json.loads(path.read_text(encoding="utf-8"))}


def validate_candidate(candidate: dict, allowed: set[str], cve: str) -> None:
    mitigation_id = candidate.get("id")
    if mitigation_id not in allowed:
        raise ValueError(f"{cve}: unknown mitigation {mitigation_id}")
    if candidate.get("relevance") not in {"relevant", "not-relevant", "unknown"}:
        raise ValueError(f"{cve}: invalid relevance for {mitigation_id}")
    if candidate.get("confidence") not in {"high", "medium", "low"}:
        raise ValueError(f"{cve}: invalid confidence for {mitigation_id}")
    effect = candidate.get("effect") or {}
    for field in ("likelihood_steps", "consequence_steps"):
        if effect.get(field, 0) not in {0, 1, 2}:
            raise ValueError(f"{cve}: {field} must be 0, 1, or 2")
    if candidate.get("relevance") != "relevant" and any(
        (effect.get("likelihood_steps", 0), effect.get("consequence_steps", 0), effect.get("path_block", False))
    ):
        raise ValueError(f"{cve}: non-relevant or unknown mitigations cannot claim assessment credit")
    if effect.get("path_block") and not (
        candidate.get("confidence") == "high"
        and mitigation_id in {"service_disabled_vendor_guidance", "vendor_workaround"}
    ):
        raise ValueError(f"{cve}: path_block requires a high-confidence vendor workaround or service disablement")
    if effect.get("likelihood_steps", 0) == 2 and not effect.get("path_block"):
        raise ValueError(f"{cve}: two likelihood steps require an exact path block")
    if not str(candidate.get("evidence") or "").strip():
        raise ValueError(f"{cve}: evidence is required for {mitigation_id}")


def validate_cvss_basis(overlay: dict, baseline: dict) -> None:
    cve = baseline["cve"]
    basis = overlay.get("cvss_basis")
    if not isinstance(basis, dict):
        raise ValueError(f"{cve}: cvss_basis is required")
    expected = {
        "base_score": baseline.get("cvss", {}).get("base_score"),
        "vector": baseline.get("cvss", {}).get("vector"),
        "attack_vector": baseline.get("attack", {}).get("vector"),
        "privileges_required": baseline.get("attack", {}).get("privileges_required"),
        "user_interaction": baseline.get("attack", {}).get("user_interaction"),
    }
    if basis != expected:
        raise ValueError(f"{cve}: cvss_basis does not match normalized MSRC data")


def validate_path_compatibility(overlay: dict, baseline: dict) -> None:
    cve = baseline["cve"]
    vector = baseline.get("attack", {}).get("vector")
    privileges = baseline.get("attack", {}).get("privileges_required")
    tags = set(overlay.get("tags") or [])
    for candidate in overlay.get("mitigation_candidates") or []:
        mitigation_id = candidate["id"]
        likelihood_credit = (candidate.get("effect") or {}).get("likelihood_steps", 0)
        if not likelihood_credit:
            continue
        if mitigation_id in {"remove_external_exposure", "segmentation_acl", "exploit_specific_ips", "waf_virtual_patch", "isolation_airgap"} and vector not in {"network", "adjacent"}:
            raise ValueError(f"{cve}: {mitigation_id} cannot reduce likelihood for attack vector {vector}")
        if mitigation_id in {"email_web_filtering", "office_protected_view"} and "user-content" not in tags:
            raise ValueError(f"{cve}: {mitigation_id} requires an evidence-backed user-content tag")
        if mitigation_id in {"strong_authentication", "least_privilege_pam"} and privileges not in {"low", "high"}:
            raise ValueError(f"{cve}: {mitigation_id} cannot reduce likelihood when privileges required is {privileges}")
        if mitigation_id in {"edr_detection_response", "immutable_backups"}:
            raise ValueError(f"{cve}: {mitigation_id} cannot reduce exploit likelihood")


def critical_pre_auth_network_rce(record: dict) -> bool:
    return (
        float(record.get("cvss", {}).get("base_score") or 0) >= 9
        and record.get("attack", {}).get("vector") == "network"
        and record.get("attack", {}).get("privileges_required") == "none"
        and record.get("attack", {}).get("user_interaction") == "none"
        and "remote-code-execution" in set(record.get("tags") or [])
    )


def public_threat_likelihood(record: dict) -> int:
    """Return the minimum evidence band implied by public, machine-sourced facts."""
    threat = record.get("threat", {})
    if threat.get("kev") or threat.get("exploitation_detected"):
        return 3
    likelihood = {
        "detected": 3,
        "more-likely": 2,
        "less-likely": 1,
        "unlikely": 0,
        "unknown": 1,
    }.get(threat.get("exploitation_assessment"), 1)
    epss = threat.get("epss")
    if epss is not None:
        if float(epss) >= 0.10:
            likelihood = max(likelihood, 2)
        elif float(epss) >= 0.01:
            likelihood = max(likelihood, 1)
    return likelihood


def validate_framework_assessment(overlay: dict, baseline: dict) -> None:
    cve = baseline["cve"]
    assessment = overlay.get("framework_assessment")
    if not isinstance(assessment, dict):
        raise ValueError(f"{cve}: framework_assessment is required")
    if assessment.get("risk_model_version") != RISK_MODEL_VERSION:
        raise ValueError(f"{cve}: risk model version must be {RISK_MODEL_VERSION}")
    if assessment.get("baseline_model") not in BASELINE_MODELS:
        raise ValueError(f"{cve}: unknown baseline model")
    if assessment.get("baseline_likelihood") not in LIKELIHOODS:
        raise ValueError(f"{cve}: invalid baseline likelihood")
    if assessment.get("baseline_action") not in ACTIONS:
        raise ValueError(f"{cve}: invalid baseline action")
    if assessment.get("confidence") not in {"high", "medium", "low"}:
        raise ValueError(f"{cve}: invalid framework confidence")
    factors = assessment.get("factors") or {}
    missing_factors = REQUIRED_FACTORS - set(factors)
    if missing_factors or any(not str(factors.get(field) or "").strip() for field in REQUIRED_FACTORS):
        raise ValueError(f"{cve}: incomplete framework factors {sorted(missing_factors)}")
    communication = assessment.get("risk_communication") or {}
    missing_communication = REQUIRED_COMMUNICATION - set(communication)
    if missing_communication or any(not communication.get(field) for field in REQUIRED_COMMUNICATION):
        raise ValueError(f"{cve}: incomplete risk communication {sorted(missing_communication)}")

    action_index = ACTIONS.index(assessment["baseline_action"])
    likelihood_index = LIKELIHOODS.index(assessment["baseline_likelihood"])
    threat = baseline.get("threat", {})
    if baseline.get("customer_action_required") is False:
        if assessment["baseline_model"] != "no-customer-action" or action_index != 0:
            raise ValueError(f"{cve}: Microsoft no-customer-action guidance requires the no-customer-action model")
    elif threat.get("kev") or threat.get("exploitation_detected"):
        if assessment["baseline_model"] != "active-exploitation" or action_index != 3 or likelihood_index != 3:
            raise ValueError(f"{cve}: confirmed exploitation requires Active and Immediate")
    elif critical_pre_auth_network_rce(baseline):
        if action_index < 2:
            raise ValueError(f"{cve}: critical pre-authentication network RCE requires at least Out-of-cycle")
        if public_threat_likelihood(baseline) >= 2 and assessment["baseline_model"] != "critical-preauth-network-rce":
            raise ValueError(f"{cve}: elevated critical pre-authentication network RCE requires its archetype")
    if baseline.get("customer_action_required") is not False and threat.get("exploitation_assessment") == "more-likely" and likelihood_index < 2:
        raise ValueError(f"{cve}: Microsoft More Likely cannot be assessed below Elevated")
    if baseline.get("customer_action_required") is not False and likelihood_index < public_threat_likelihood(baseline):
        raise ValueError(f"{cve}: framework likelihood cannot undercut current public threat evidence")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--inference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--taxonomy", type=Path, default=ROOT / "data" / "tag-taxonomy.json")
    parser.add_argument("--mitigations", type=Path, default=ROOT / "data" / "mitigation-catalog.json")
    parser.add_argument("--include-unreviewed", action="store_true", help="Include every baseline record, not only inference overlays")
    parser.add_argument("--require-complete", action="store_true", help="Reject a release unless every source CVE has an inference overlay")
    parser.add_argument(
        "--allow-missing-direction", action="store_true",
        help=("Record an overlay with no attack_path.direction as direction-UNCHECKED "
              "instead of rejecting it. Only for legacy overlays written before the "
              "direction contract existed (the 2026-Sep Luna overlay is the whole of "
              "that set). The gate cannot run on such a record, so its mitigation "
              "credit is unverified and every record says so in its own inference block."),
    )
    args = parser.parse_args()

    baseline = {item["cve"]: item for item in read_jsonl(args.baseline)}
    tags_allowed = allowed_tags(args.taxonomy)
    mitigations_allowed = allowed_mitigations(args.mitigations)
    direction_applicability = direction_rules(args.mitigations)
    merged = []
    seen = set()
    direction_violations: list[dict] = []
    direction_unchecked: list[dict] = []
    for overlay in read_jsonl(args.inference):
        cve = overlay.get("cve")
        if cve not in baseline:
            raise ValueError(f"Inference CVE is absent from baseline: {cve}")
        if cve in seen:
            raise ValueError(f"Duplicate inference CVE: {cve}")
        seen.add(cve)
        validate_cvss_basis(overlay, baseline[cve])
        validate_framework_assessment(overlay, baseline[cve])
        inferred_tags = set(overlay.get("tags") or [])
        unknown_tags = inferred_tags - tags_allowed
        if unknown_tags:
            raise ValueError(f"{cve}: unknown tags {sorted(unknown_tags)}")
        candidates = overlay.get("mitigation_candidates") or []
        for candidate in candidates:
            validate_candidate(candidate, mitigations_allowed, cve)
        validate_path_compatibility(overlay, baseline[cve])

        # The attack-direction gate. Runs LAST of the per-record checks, so the
        # model's claims are validated exactly as authored before anything is
        # zeroed - otherwise enforce_direction would sand off a credit that
        # validate_candidate should have rejected outright and the weaker gate
        # would mask the stronger one.
        #
        # This is the call site the CVE-2026-18149 class of error gets past when it
        # is absent. `enforce_direction` was defined, tested and never called from
        # here until 2026-09-11; `scripts/direction_gate_self_test.py` now has a
        # fixture that fails if these lines are removed.
        gate: dict
        try:
            violations = enforce_direction(cve, overlay, direction_applicability)
        except ValueError as error:
            if not args.allow_missing_direction:
                raise
            # Not "clean". Unchecked: there is no direction, so no control credit on
            # this record has been tested against one. Recorded on the record and
            # counted separately in the summary, never folded into the pass count.
            violations = []
            gate = {"status": "unchecked", "reason": str(error)}
            direction_unchecked.append({"cve": cve, "reason": str(error)})
        else:
            gate = {"status": "violations-found" if violations else "clean",
                    "violations": violations}
            if violations:
                direction_violations.append({"cve": cve, "violations": violations})

        # `candidates` is the same list enforce_direction just mutated in place, so
        # any zeroed credit and any direction_override flag is already on it.
        record = baseline[cve]
        record["tags"] = sorted(set(record.get("tags") or []) | inferred_tags)
        record["mitigation_candidates"] = candidates
        record["inference"] = overlay.get("inference") or {}
        record["inference"]["review_status"] = "reviewed"
        record["inference"]["framework_assessment"] = overlay["framework_assessment"]
        # Written on every merged record, including the clean ones. A field that
        # appears only on violations cannot be distinguished from a gate that never
        # ran - which is the state this whole change is fixing.
        record["inference"]["direction_gate"] = gate
        merged.append(record)

    if args.require_complete and seen != set(baseline):
        missing = sorted(set(baseline) - seen)
        raise ValueError(f"Incomplete inference: {len(seen)}/{len(baseline)} CVEs reviewed; missing {missing[:10]}")

    if args.include_unreviewed:
        for cve, record in baseline.items():
            if cve in seen:
                continue
            record["mitigation_candidates"] = []
            record["inference"] = {
                "model": "none",
                "taxonomy_version": "1.0",
                "review_status": "unreviewed",
                # No overlay means no asserted direction and no credited control, so
                # there is nothing for the gate to act on. Stated, not left blank.
                "direction_gate": {"status": "not-applicable",
                                   "reason": "record carries no inference overlay"},
            }
            merged.append(record)

    # Publication order. `Unknown` sorts to the BOTTOM of the list - owner decision,
    # 2026-09-11 - and is named here rather than left to the fall-through, so the
    # decision is visible in the map and reviewable. The default is deliberately a
    # value no severity is meant to reach: a severity string that is not in this map
    # is an unhandled vocabulary change, and it must land after Unknown and be added
    # here on purpose rather than quietly inheriting Unknown's rank.
    severity_order = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3, "Unknown": 4}
    merged.sort(key=lambda item: (
        not (item.get("threat", {}).get("kev") or item.get("threat", {}).get("exploitation_detected")),
        severity_order.get(item.get("severity"), 99),
        item.get("attack", {}).get("vector") != "network",
        item.get("cve"),
    ))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(json.dumps(item, separators=(",", ":")) for item in merged) + "\n", encoding="utf-8")
    print(f"Validated {len(seen)} inference overlays; published {len(merged)} total records into {args.output}")

    # The gate's findings go to stdout as well as onto the records. A violation that
    # is only in the output file is one nobody reads on the day it is produced.
    credits_removed = sum(len(item["violations"]) for item in direction_violations)
    print(f"Direction gate: {len(seen) - len(direction_unchecked)}/{len(seen)} overlays checked; "
          f"{len(direction_violations)} record(s) with contradicting mitigation credit, "
          f"{credits_removed} credit(s) removed; {len(direction_unchecked)} unchecked")
    for item in direction_violations:
        for violation in item["violations"]:
            print(f"  direction-contradiction {item['cve']}: {violation['message']}")
    if direction_unchecked:
        print(f"  UNCHECKED: {len(direction_unchecked)} overlay(s) assert no attack direction, so no "
              "mitigation credit on them has been tested against one. Not a clean result.")
        for item in direction_unchecked[:10]:
            print(f"    {item['reason']}")
        if len(direction_unchecked) > 10:
            print(f"    ... and {len(direction_unchecked) - 10} more")


if __name__ == "__main__":
    main()
