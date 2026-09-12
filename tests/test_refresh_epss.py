"""EPSS refresh: score application, and which datasets get refreshed at all.

    python3 tests/test_refresh_epss.py

Plain python, no test framework.

The discovery cases exist because the failure mode here is silent. A refresh that
skips a month does not error - it reports success for the months it did see, and
the skipped month's scores simply stop moving. That is why discovery now reads
data/months.json and reports any disagreement with the directory rather than
picking one and saying nothing.
"""

import importlib.util
import json
import tempfile
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "refresh_epss.py"
SPEC = importlib.util.spec_from_file_location("refresh_epss", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_refresh_records_marks_scored_stale_and_pending():
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


def manifest_dir(handle, entries, extra_files=()):
    """Build a data directory from a months.json manifest plus any stray files."""
    directory = Path(handle)
    (directory / "months.json").write_text(json.dumps(entries), encoding="utf-8")
    for entry in entries:
        if entry.get("file"):
            (directory / entry["file"]).write_text("", encoding="utf-8")
    for name in extra_files:
        (directory / name).write_text("", encoding="utf-8")
    return directory


def test_discovery_follows_the_manifest_not_a_hardcoded_list():
    """A month added to months.json is refreshed without editing anything."""
    with tempfile.TemporaryDirectory() as handle:
        directory = manifest_dir(handle, [
            {"month": "2026-Sep", "file": "2026-Sep.jsonl"},
            {"month": "2026-Oct", "file": "2026-Oct.jsonl"},
            {"month": "2026-Oct-B", "file": "2026-Oct-B.jsonl"},
        ])
        paths, warnings = MODULE.published_datasets(directory)
        assert [p.name for p in paths] == ["2026-Sep.jsonl", "2026-Oct.jsonl", "2026-Oct-B.jsonl"]
        assert warnings == []


def test_discovery_skips_the_synthetic_demo_dataset():
    with tempfile.TemporaryDirectory() as handle:
        directory = manifest_dir(handle, [
            {"month": "2026-Sep-demo", "file": "demo-2026-Sep.jsonl"},
            {"month": "2026-Sep", "file": "2026-Sep.jsonl"},
        ])
        paths, warnings = MODULE.published_datasets(directory)
        assert [p.name for p in paths] == ["2026-Sep.jsonl"]
        assert warnings == []


def test_discovery_honours_an_explicit_synthetic_flag():
    """A future vendor demo need not be named demo-*; the flag is the declared form."""
    with tempfile.TemporaryDirectory() as handle:
        directory = manifest_dir(handle, [
            {"month": "adobe-sample", "file": "adobe-sample.jsonl", "synthetic": True},
            {"month": "2026-Sep", "file": "2026-Sep.jsonl"},
        ])
        paths, _ = MODULE.published_datasets(directory)
        assert [p.name for p in paths] == ["2026-Sep.jsonl"]


def test_a_dataset_the_manifest_does_not_name_is_reported_not_ignored():
    with tempfile.TemporaryDirectory() as handle:
        directory = manifest_dir(handle,
                                 [{"month": "2026-Sep", "file": "2026-Sep.jsonl"}],
                                 extra_files=["2026-Oct.jsonl"])
        paths, warnings = MODULE.published_datasets(directory)
        assert [p.name for p in paths] == ["2026-Sep.jsonl"]
        assert any("2026-Oct.jsonl" in w for w in warnings), warnings


def test_a_manifest_entry_with_no_file_on_disk_is_reported():
    with tempfile.TemporaryDirectory() as handle:
        directory = Path(handle)
        (directory / "months.json").write_text(
            json.dumps([{"month": "2026-Oct", "file": "2026-Oct.jsonl"}]), encoding="utf-8")
        paths, warnings = MODULE.published_datasets(directory)
        assert paths == []
        assert any("2026-Oct.jsonl" in w for w in warnings), warnings


def test_a_missing_manifest_stops_the_run():
    with tempfile.TemporaryDirectory() as handle:
        try:
            MODULE.published_datasets(Path(handle))
        except SystemExit as error:
            assert "months.json" in str(error)
        else:
            raise AssertionError("a missing months.json must stop the run, not refresh nothing quietly")


def test_the_real_manifest_resolves():
    """Guards against the checked-in manifest drifting away from data/."""
    paths, warnings = MODULE.published_datasets(Path(__file__).parents[1] / "data")
    assert [p.name for p in paths] == ["2026-Sep.jsonl"], [p.name for p in paths]
    assert warnings == [], warnings


CASES = [
    test_refresh_records_marks_scored_stale_and_pending,
    test_discovery_follows_the_manifest_not_a_hardcoded_list,
    test_discovery_skips_the_synthetic_demo_dataset,
    test_discovery_honours_an_explicit_synthetic_flag,
    test_a_dataset_the_manifest_does_not_name_is_reported_not_ignored,
    test_a_manifest_entry_with_no_file_on_disk_is_reported,
    test_a_missing_manifest_stops_the_run,
    test_the_real_manifest_resolves,
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
    print(f"{len(CASES) - len(failures)}/{len(CASES)} EPSS refresh tests passed")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    run_tests()
