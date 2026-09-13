"""Self-test for apply_severity_correction.py. Plain python, no test framework.

    python3 scripts/apply_severity_correction_self_test.py

That script is superseded and its remaining value is entirely in refusing to run.
A guard with no fixture that it rejects is not a guard, so each refusal below has
one, and each was mutation-tested by removing the guard and watching the gate go
red. The failure it prevents is specific: copying a flat severity string over a
vendor-plural object erases the assigning CNA's band and resolves the month to
`unknown` through the band reader, which is the fail-open that script was written
to repair, in a new shape.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import apply_severity_correction as correction  # noqa: E402
from severity import build_severity, load_scales  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCALES = load_scales(ROOT / "data" / "severity-scales.json")
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def expect_exit(function, expected, label):
    try:
        function()
    except SystemExit as stop:
        if expected not in str(stop):
            failures.append(f"{label}: refused, but not for the stated reason. Got: {stop}")
    else:
        failures.append(f"{label}: did not refuse")


def flat(cve, severity="Important", basis="vendor"):
    return {"cve": cve, "severity": severity, "severity_basis": basis}


def plural(cve, band="Important"):
    record = {"cve": cve, "schema_version": "2.0", "severity_basis": "vendor"}
    record["severity"] = build_severity(SCALES, severity=band, severity_basis="vendor", cvss=None, cve_program=None)
    return record


# ---------------------------------------------------------------------------
# Gate 1: a published month on the current schema is refused outright.
# This is the one that matters. Every published month is schema 2.0.
# ---------------------------------------------------------------------------
expect_exit(
    lambda: correction.refuse_unless_legacy([plural("CVE-0000-0001")], [flat("CVE-0000-0001")]),
    "cannot write",
    "gate 1: a vendor-plural published file",
)
expect_exit(
    lambda: correction.refuse_unless_legacy([plural("CVE-0000-0001")], [flat("CVE-0000-0001")]),
    "normalize_severity.py",
    "gate 1: the refusal must name the replacement",
)

# ---------------------------------------------------------------------------
# Gate 2: a vendor-plural baseline against a flat published file is refused too.
# It would flatten on the way across, which loses the same information quietly.
# ---------------------------------------------------------------------------
expect_exit(
    lambda: correction.refuse_unless_legacy([flat("CVE-0000-0002")], [plural("CVE-0000-0002")]),
    "discarding every non-publisher band",
    "gate 2: a vendor-plural baseline",
)

# ---------------------------------------------------------------------------
# Gate 3: a half-migrated file is refused rather than guessed at.
# ---------------------------------------------------------------------------
expect_exit(
    lambda: correction.refuse_unless_legacy([flat("CVE-0000-0003"), plural("CVE-0000-0004")], [flat("CVE-0000-0003")]),
    "half-finished migration",
    "gate 3: a mixed published file",
)
expect_exit(
    lambda: correction.refuse_unless_legacy([flat("CVE-0000-0003")], [flat("CVE-0000-0003"), plural("CVE-0000-0004")]),
    "half-finished migration",
    "gate 3: a mixed baseline",
)

# ---------------------------------------------------------------------------
# Gate 4: a baseline with no severity_basis cannot say what a band came from.
# The script indexes that key directly, so this was a KeyError rather than a
# statement of the problem.
# ---------------------------------------------------------------------------
without_basis = {"cve": "CVE-0000-0005", "severity": "Important"}
expect_exit(
    lambda: correction.refuse_unless_legacy([flat("CVE-0000-0005")], [without_basis]),
    "no severity_basis",
    "gate 4: a baseline missing severity_basis",
)

# ---------------------------------------------------------------------------
# Gate 5: an empty file is an error, not a silent no-op that reports success.
# ---------------------------------------------------------------------------
expect_exit(
    lambda: correction.refuse_unless_legacy([], [flat("CVE-0000-0006")]),
    "contains no records",
    "gate 5: an empty published file",
)

# ---------------------------------------------------------------------------
# The legacy path it was actually correct for still passes, or the guards have
# simply disabled the script rather than scoped it.
# ---------------------------------------------------------------------------
try:
    correction.refuse_unless_legacy([flat("CVE-0000-0007")], [flat("CVE-0000-0007")])
except SystemExit as stop:
    failures.append(f"legacy path: a flat-to-flat correction must still be allowed, got: {stop}")

check(
    correction.severity_shape([plural("CVE-0000-0008")], "x") == "vendor-plural",
    "shape: a severity object must classify as vendor-plural",
)
check(
    correction.severity_shape([flat("CVE-0000-0009")], "x") == "flat",
    "shape: a severity string must classify as flat",
)
check(
    correction.severity_shape([{"cve": "CVE-0000-0010"}], "x") == "flat",
    "shape: a record with no severity at all is flat, not a third state",
)

if failures:
    print(f"apply_severity_correction self-test FAILED ({len(failures)})")
    for item in failures:
        print("  -", item)
    raise SystemExit(1)
print("apply_severity_correction self-test passed")
