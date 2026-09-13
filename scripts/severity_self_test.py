"""Self-test for severity.py. Plain python, no test framework.

    python3 scripts/severity_self_test.py

Each gate below has a fixture it must reject. Every one of them was mutation-
tested: the implementation was broken deliberately and the test watched to go red
before it was trusted. A gate that has only ever passed is not evidence, which
this project has learned three times.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from severity import (  # noqa: E402
    SeverityScaleError,
    TARGET_VOCABULARY,
    UNKNOWN,
    band_from_score,
    build_severity,
    cna_assessment,
    load_scales,
    normalise_band,
    normalized_band,
)

ROOT = Path(__file__).resolve().parent.parent
SCALES = load_scales(ROOT / "data" / "severity-scales.json")
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def build(severity="Important", basis="vendor", score=None, cve_program=None):
    cvss = {"base_score": score, "version": "3.1", "vector": "CVSS:3.1/AV:L"} if score is not None else None
    return build_severity(SCALES, severity=severity, severity_basis=basis, cvss=cvss, cve_program=cve_program)


def cna(assigner, band, scale="cvss-qualitative", score=None):
    return {
        "assigner": assigner,
        "url": "https://example.invalid/record.json",
        "vendor_severity": {"band": band, "scale": scale, "base_score": score, "cvss_version": "3.1", "vector": "CVSS:3.1/AV:N"},
    }


# ---------------------------------------------------------------------------
# Gate 1: a vendor band always beats a CVSS score.
# 84 Criticals and 234 Importants depend on this rule.
# ---------------------------------------------------------------------------
result = build(severity="Critical", basis="vendor", score=4.4)
check(result["normalized_band"] == "critical", f"gate 1: MSRC Critical with a 4.4 score must stay critical, got {result['normalized_band']}")
check(result["normalized_basis"] == "scale-mapping:msrc:1.0", f"gate 1: basis must name the mapping, got {result['normalized_basis']}")
check(result["normalized_band"] != "medium", "gate 1: the score must not be able to demote a published band")

# ---------------------------------------------------------------------------
# Gate 2: a Chromium band maps on its own scale, and says so.
# ---------------------------------------------------------------------------
result = build(severity="Unknown", basis="absent", cve_program=cna("Chrome", "Medium", scale="chromium"))
check(result["normalized_band"] == "medium", f"gate 2: Chromium Medium must map to medium, got {result['normalized_band']}")
check(
    result["normalized_basis"] == "scale-mapping:chromium:1.0",
    f"gate 2: basis must be scale-mapping:chromium:1.0, not a claim the vendor said 'medium', got {result['normalized_basis']}",
)
check(result["normalized_basis"] != "vendor-scale", "gate 2: 'vendor-scale' would assert the vendor used the target vocabulary")
check(
    result.get("publisher_declined", {}).get("source") == "microsoft",
    "gate 2: a publisher declining to rate is a positive fact, not an absence",
)

# ---------------------------------------------------------------------------
# Gate 3: the publisher-as-own-CNA exclusion.
# Microsoft assigns 973 of 1,185 September records; without the exclusion its own
# CVSS band is compared against its own MSRC band as if it were a second opinion.
# assignerShortName is lowercase, so the comparison must be case-insensitive.
# ---------------------------------------------------------------------------
check(cna_assessment(cna("microsoft", "HIGH")) is None, "gate 3: a lowercase 'microsoft' assigner must be excluded")
check(cna_assessment(cna("Microsoft", "HIGH")) is None, "gate 3: exclusion must not be case-sensitive")
check(cna_assessment(cna("MICROSOFT", "HIGH")) is None, "gate 3: exclusion must not be case-sensitive")
check(cna_assessment(cna("Linux", "HIGH")) is not None, "gate 3: a genuine third-party CNA must not be excluded")

self_assigned = build(severity="Moderate", basis="vendor", cve_program=cna("microsoft", "CRITICAL"))
check(
    self_assigned["normalized_band"] == "medium",
    f"gate 3: Microsoft's own CVSS band must not outrank its own MSRC band, got {self_assigned['normalized_band']}",
)
check("divergence" not in self_assigned, "gate 3: a vendor cannot disagree with itself")

# ---------------------------------------------------------------------------
# Gate 4: an empty assessment list yields unknown, never a band.
# ---------------------------------------------------------------------------
empty = build(severity="Unknown", basis="absent")
check(empty["assessments"] == [], "gate 4: nothing published means no assessments")
check(empty["normalized_band"] == UNKNOWN, f"gate 4: an empty list must resolve to unknown, got {empty['normalized_band']}")
check(empty["normalized_band"] != "low", "gate 4: absence of evidence is not a low rating")
check(empty["normalized_basis"] == "absent", f"gate 4: basis must record that nothing was published, got {empty['normalized_basis']}")
check(empty["primary"] is None, "gate 4: nobody published, so nobody is primary")

# ---------------------------------------------------------------------------
# Gate 5: an enrichment role never sets primary and never reaches the band.
# This is the Phase 0 fail-open in its new shape.
# ---------------------------------------------------------------------------
enriched = build_severity(
    SCALES,
    severity="Unknown",
    severity_basis="absent",
    cvss=None,
    cve_program={
        "assigner": "CISA-ADP",
        "vendor_severity": None,
        "adp_cvss": {"band": "CRITICAL", "base_score": 9.6},
    },
)
check(enriched["normalized_band"] == UNKNOWN, f"gate 5: a CISA-ADP score must not become the band, got {enriched['normalized_band']}")
check(enriched["primary"] is None, "gate 5: an enrichment provider must never be primary")
check(enriched["assessments"] == [], "gate 5: enrichment is not an assessment")

# ---------------------------------------------------------------------------
# Gate 6: every band in the scales file maps into the target vocabulary, and each
# scale carries only the bands that vendor actually publishes.
# ---------------------------------------------------------------------------
for name, scale in SCALES["scales"].items():
    for band, entry in (scale.get("bands") or {}).items():
        target = entry.get("maps_to")
        check(
            target in TARGET_VOCABULARY or target == UNKNOWN,
            f"gate 6: {name}:{band} maps to {target!r}, outside the vocabulary",
        )
        check(bool(entry.get("vendor_definition") or entry.get("rationale")), f"gate 6: {name}:{band} has no stated reasoning")

# Adobe publishes no Low. Mapping one would invent a band the vendor never uses.
check("Low" not in (SCALES["scales"]["adobe"].get("bands") or {}), "gate 6: Adobe must not carry a Low band")
try:
    normalise_band(SCALES, "adobe", "Low")
    failures.append("gate 6: an Adobe Low must be a parse error, not a mapping")
except SeverityScaleError:
    pass

try:
    normalise_band(SCALES, "msrc", "Spicy")
    failures.append("gate 6: an unknown band must raise rather than default")
except SeverityScaleError:
    pass

# ---------------------------------------------------------------------------
# The highest of two published bands wins, compared after normalisation.
# ---------------------------------------------------------------------------
higher = build(severity="Moderate", basis="vendor", score=4.7, cve_program=cna("Linux", "CRITICAL", score=9.3))
check(higher["normalized_band"] == "critical", f"highest wins: expected critical, got {higher['normalized_band']}")
check(higher["primary"] == "microsoft", "highest wins: primary still names the publisher")
check(higher.get("divergence", {}).get("kind") == "assessment", f"highest wins: comparable disagreement is an assessment divergence, got {higher.get('divergence')}")
check(higher.get("divergence", {}).get("spread") == 4.6, f"highest wins: spread must be 4.6, got {higher.get('divergence', {}).get('spread')}")

lower = build(severity="Critical", basis="vendor", cve_program=cna("Linux", "LOW"))
check(lower["normalized_band"] == "critical", "highest wins: a lower CNA band must not demote the publisher")

# A cross-scale disagreement is reported as `scale`, not `assessment`.
cross = build(severity="Moderate", basis="vendor", cve_program=cna("Chrome", "Critical", scale="chromium"))
check(cross.get("divergence", {}).get("kind") == "scale", f"cross-scale disagreement must be kind 'scale', got {cross.get('divergence')}")

# Agreement is not divergence.
agree = build(severity="Important", basis="vendor", cve_program=cna("Linux", "HIGH"))
check("divergence" not in agree, "two parties agreeing must not report a divergence")

# ---------------------------------------------------------------------------
# A score-derived publisher string is not a published band.
# ---------------------------------------------------------------------------
derived = build(severity="Critical", basis="cvss", score=9.1)
check(derived["assessments"] == [], "score-derived: a string derived from a score is not a vendor assessment")
check(derived["normalized_band"] == "critical", f"score-derived: 9.1 must derive critical, got {derived['normalized_band']}")
check(derived["normalized_basis"] == "cvss-derived", f"score-derived: basis must be cvss-derived, got {derived['normalized_basis']}")

# A 0.0 score asserts no impact, which is not a band.
zero = build(severity="Unknown", basis="absent", score=0.0)
check(zero["normalized_band"] == UNKNOWN, f"a 0.0 score must resolve to unknown, got {zero['normalized_band']}")
check(band_from_score(SCALES, None) == UNKNOWN, "no score must resolve to unknown")

# ---------------------------------------------------------------------------
# The reader is fail-loud: anything that is not a severity object is unknown.
# ---------------------------------------------------------------------------
check(normalized_band({"normalized_band": "high"}) == "high", "reader: an object yields its band")
check(normalized_band("Important") == UNKNOWN, "reader: a legacy string must not be silently re-mapped")
check(normalized_band(None) == UNKNOWN, "reader: absent severity is unknown")
check(normalized_band({}) == UNKNOWN, "reader: an empty object is unknown")

if failures:
    print(f"severity self-test FAILED ({len(failures)})")
    for item in failures:
        print("  -", item)
    raise SystemExit(1)
print("severity self-test passed")
