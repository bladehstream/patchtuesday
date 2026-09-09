import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "merge_inference.py"
SPEC = importlib.util.spec_from_file_location("merge_inference", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


BASELINE = {
    "cve": "CVE-TEST-1",
    "cvss": {"base_score": 9.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
    "attack": {"vector": "local", "privileges_required": "low", "user_interaction": "none"},
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
    print("inference merge tests passed")


if __name__ == "__main__":
    run_tests()
