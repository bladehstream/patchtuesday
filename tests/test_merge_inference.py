import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "merge_inference.py"
SPEC = importlib.util.spec_from_file_location("merge_inference", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


BASELINE = {
    "cve": "CVE-TEST-1",
    "severity": "Critical",
    "customer_action_required": True,
    "cvss": {"base_score": 9.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "attack": {"vector": "local", "privileges_required": "low", "user_interaction": "none"},
    "threat": {"kev": False, "exploitation_detected": False, "exploitation_assessment": "unlikely"},
    "tags": ["elevation-of-privilege"],
}


def expect_failure(function, expected_text):
    try:
        function()
    except ValueError as error:
        assert expected_text in str(error)
    else:
        raise AssertionError(f"Expected failure containing: {expected_text}")


def run_tests():
    valid_basis = {
        "base_score": 9.8,
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "attack_vector": "local",
        "privileges_required": "low",
        "user_interaction": "none",
    }
    MODULE.validate_cvss_basis({"cvss_basis": valid_basis}, BASELINE)
    expect_failure(lambda: MODULE.validate_cvss_basis({"cvss_basis": {**valid_basis, "attack_vector": "network"}}, BASELINE), "does not match")
    overlay = {
        "tags": [],
        "mitigation_candidates": [{"id": "segmentation_acl", "effect": {"likelihood_steps": 1}}],
    }
    expect_failure(lambda: MODULE.validate_path_compatibility(overlay, BASELINE), "cannot reduce likelihood")
    expect_failure(
        lambda: MODULE.validate_candidate({
            "id": "segmentation_acl",
            "relevance": "unknown",
            "confidence": "high",
            "effect": {"likelihood_steps": 1, "consequence_steps": 0, "path_block": False},
            "evidence": "Applicability has not been established.",
        }, {"segmentation_acl"}, BASELINE["cve"]),
        "cannot claim assessment credit",
    )
    valid_framework = {
        "risk_model_version": "2026.09.1",
        "baseline_model": "critical-technical",
        "baseline_likelihood": "Low evidence",
        "baseline_action": "Out-of-cycle",
        "confidence": "high",
        "factors": {field: f"Evidence for {field}" for field in MODULE.REQUIRED_FACTORS},
        "risk_communication": {
            "summary": "High technical impact with low current exploitation evidence.",
            "why_this_action": "Critical severity warrants accelerated remediation.",
            "control_limitations": "Controls do not remove the vulnerable component.",
            "reassessment_triggers": ["New exploitation evidence"],
        },
    }
    MODULE.validate_framework_assessment({"framework_assessment": valid_framework}, BASELINE)
    expect_failure(lambda: MODULE.validate_framework_assessment({"framework_assessment": {**valid_framework, "factors": {}}}, BASELINE), "incomplete framework factors")

    critical_network_rce = {
        **BASELINE,
        "attack": {"vector": "network", "privileges_required": "none", "user_interaction": "none"},
        "tags": ["remote-code-execution"],
    }
    MODULE.validate_framework_assessment({"framework_assessment": valid_framework}, critical_network_rce)
    elevated_network_rce = {
        **critical_network_rce,
        "threat": {**critical_network_rce["threat"], "exploitation_assessment": "more-likely"},
    }
    expect_failure(
        lambda: MODULE.validate_framework_assessment({"framework_assessment": {**valid_framework, "baseline_likelihood": "Elevated"}}, elevated_network_rce),
        "requires its archetype",
    )
    print("inference merge tests passed")


if __name__ == "__main__":
    run_tests()
