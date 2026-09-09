import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "refresh_epss.py"
SPEC = importlib.util.spec_from_file_location("refresh_epss", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def run_tests():
    records = [
        {"cve": "CVE-TEST-1", "threat": {"epss": None}},
        {"cve": "CVE-TEST-2", "threat": {"epss": 0.02}},
        {"cve": "CVE-TEST-3", "threat": {"epss": None}},
    ]
    scores = {"CVE-TEST-1": {"epss": 0.0123, "percentile": 0.8, "date": "2026-09-09"}}
    changed = MODULE.refresh_records(records, scores, "2026-09-09")
    assert changed == 3
    assert records[0]["threat"]["epss_status"] == "scored"
    assert records[0]["threat"]["epss"] == 0.0123
    assert records[1]["threat"]["epss_status"] == "stale"
    assert records[1]["threat"]["epss"] == 0.02
    assert records[2]["threat"]["epss_status"] == "pending"
    assert records[2]["threat"]["epss"] is None
    print("EPSS refresh tests passed")


if __name__ == "__main__":
    run_tests()
