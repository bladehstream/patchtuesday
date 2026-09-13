"""Self-test for build_harness_sets.strata_of. Plain python, no test framework.

    python3 scripts/build_harness_sets_self_test.py

Written because the `unknown-severity` stratum went silently empty. The stratum
was selected by `record.get("severity") == "Unknown"`, and the vendor-plural
migration made `severity` an object, so the comparison became false for every
record. Nothing failed: the records did not vanish, they were classified into
whichever later stratum they happened to match, which is worse than dropping them.
Mutation-tested by restoring the old comparison and watching gate 1 go red.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_harness_sets as harness  # noqa: E402
from severity import build_severity, load_scales  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCALES = load_scales(ROOT / "data" / "severity-scales.json")
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def record(cve, severity, **fields):
    base = {
        "cve": cve,
        "severity": severity,
        "cvss": {"base_score": 7.8},
        "attack": {"vector": "local", "privileges_required": "low", "user_interaction": "none"},
        "tags": ["elevation-of-privilege"],
        "threat": {},
        "mitigation_candidates": [{"id": "placeholder"}],
    }
    base.update(fields)
    return base


unrated = build_severity(SCALES, severity="Unknown", severity_basis="absent", cvss=None, cve_program=None)
rated = build_severity(SCALES, severity="Important", severity_basis="vendor", cvss={"base_score": 7.8, "version": "3.1", "vector": "CVSS:3.1/AV:L"}, cve_program=None)

# ---------------------------------------------------------------------------
# Gate 1: a record nobody rated lands in unknown-severity.
# ---------------------------------------------------------------------------
check(unrated["normalized_band"] == "unknown", "gate 1: the fixture must actually be unrated")
check(
    harness.strata_of(record("CVE-FIXTURE-1", unrated), set()) == "unknown-severity",
    f"gate 1: an unrated record must select unknown-severity, got {harness.strata_of(record('CVE-FIXTURE-1', unrated), set())!r}",
)

# ---------------------------------------------------------------------------
# Gate 2: a rated record must not. Without this, a stratum that swallows
# everything would pass gate 1.
# ---------------------------------------------------------------------------
check(
    harness.strata_of(record("CVE-FIXTURE-2", rated), set()) != "unknown-severity",
    "gate 2: a record with a published band must not select unknown-severity",
)

# ---------------------------------------------------------------------------
# Gate 3: a dataset that skipped the migration is unknown, not silently rated.
# A flat legacy string carries no normalized band, so the honest answer is that
# nothing usable was read - the same rule as everywhere else in this project.
# ---------------------------------------------------------------------------
check(
    harness.strata_of(record("CVE-FIXTURE-3", "Important"), set()) == "unknown-severity",
    "gate 3: an unmigrated flat string must not pass as a rated record",
)

# ---------------------------------------------------------------------------
# Gate 4: the ordering that puts reference failures first is intact - a named
# hard case stays a reference failure even when it is also unrated.
# ---------------------------------------------------------------------------
check(
    harness.strata_of(record(harness.NAMED_HARD[0], unrated), set()) == "reference-failure",
    "gate 4: a named hard case outranks unknown-severity",
)

# ---------------------------------------------------------------------------
# The published month is reported, not asserted. Zero is the correct answer
# today because Google's tier now covers the 23 records that used to be
# unrated; a future month with a failed enrichment fetch should be non-zero.
# ---------------------------------------------------------------------------
published = ROOT / "data" / "2026-Sep.jsonl"
if published.is_file():
    rows = [json.loads(line) for line in published.read_text(encoding="utf-8").splitlines() if line.strip()]
    count = sum(1 for row in rows if harness.strata_of(row, set()) == "unknown-severity")
    print(f"  2026-Sep records selecting unknown-severity: {count} of {len(rows)}")

if failures:
    print(f"build_harness_sets self-test FAILED ({len(failures)})")
    for item in failures:
        print("  -", item)
    raise SystemExit(1)
print("build_harness_sets self-test passed")
