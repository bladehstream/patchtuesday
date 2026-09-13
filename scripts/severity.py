"""Vendor-plural severity: normalise bands across vendor scales.

One vendor's scale is not another's. Chromium's is defined relative to the
renderer sandbox, Microsoft's is not, and a flat string forced every vendor onto
Microsoft's vocabulary. This module is the single place that translates, and it
translates only through `data/severity-scales.json`, where each band carries the
vendor's verbatim definition and the reasoning for where it lands. A mapping that
is written down is an editorial position that can be argued with; one that lives
in code is a hidden coercion.

Three rules the rest of the project depends on, all of them measured rather than
preferred:

  A vendor's published band always beats a CVSS score. MSRC bands and Microsoft's
  own CVSS bands agree on only 67% of 2026-Sep, and a Microsoft Critical is more
  often CVSS High than CVSS Critical. Deriving the band from the score would
  demote 84 Criticals and 234 Importants against the vendor's own judgement.
  Score-derivation is the last resort and is always labelled `cvss-derived`.

  Where two parties published a band, the highest wins, compared after
  normalisation. A lower rating from one party is not evidence against a higher
  rating from another.

  Where nobody published anything, the answer is `unknown` and it carries a
  review flag. It is never `low`, and it is never a fall-through baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

TARGET_VOCABULARY = ("critical", "high", "medium", "low")
UNKNOWN = "unknown"

# Ordering for "the highest wins". `unknown` sorts below every real band so that a
# party who said nothing can never outrank a party who said something.
_RANK = {UNKNOWN: 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Roles permitted to set `primary` and to reach `normalized_band`. An enrichment
# provider is neither: CISA-ADP gives one identical 9.6 vector to three different
# Chromium tiers and rates a Chromium High at 3.1.
VENDOR_ROLES = ("publisher", "assigning-cna")


class SeverityScaleError(ValueError):
    """A band that the scales file does not define.

    Raised rather than defaulted. Adobe publishes no Low, so an Adobe Low is a
    parse error: silently mapping it would invent a band the vendor never uses.
    """


def load_scales(path: str | Path) -> dict:
    scales = json.loads(Path(path).read_text(encoding="utf-8"))
    for name, scale in scales.get("scales", {}).items():
        for band, entry in (scale.get("bands") or {}).items():
            target = entry.get("maps_to")
            if target not in TARGET_VOCABULARY and target != UNKNOWN:
                raise SeverityScaleError(f"{name}:{band} maps to {target!r}, which is outside the target vocabulary")
    return scales


def normalise_band(scales: dict, scale: str, band: str) -> str:
    """Translate one vendor's band onto the target vocabulary."""
    definition = scales.get("scales", {}).get(scale)
    if definition is None:
        raise SeverityScaleError(f"no scale named {scale!r} in the scales file")
    bands = definition.get("bands") or {}
    entry = bands.get(band)
    if entry is None:
        # Case-insensitive second pass: CVE Program records emit CRITICAL where
        # the scales file lists Critical. The band must still exist.
        for candidate, value in bands.items():
            if candidate.lower() == str(band).lower():
                entry = value
                break
    if entry is None:
        raise SeverityScaleError(f"{scale} publishes no band {band!r}; refusing to guess")
    return entry["maps_to"]


def band_from_score(scales: dict, score: float | None) -> str:
    """The fallback of last resort. Only legitimate when nobody published a band."""
    if score is None:
        return UNKNOWN
    for entry in scales["scales"]["cvss-score"]["ranges"]:
        if entry["min"] <= score <= entry["max"]:
            return entry["maps_to"]
    return UNKNOWN


def _rank(band: str) -> int:
    return _RANK.get(band, 0)


def publisher_assessment(severity: str, basis: str, cvss: dict | None) -> dict | None:
    """The publishing vendor's own band, where it published one.

    `basis` of "cvss" means the string was derived from a score rather than
    published by Microsoft, so it is not a vendor band and must not be treated as
    one. Exactly one 2026-Sep record is in that state.
    """
    if basis != "vendor" or not severity or severity == "Unknown":
        return None
    assessment = {
        "source": "microsoft",
        "role": "publisher",
        "scale": "msrc",
        "value": severity,
        "basis": "vendor",
    }
    if cvss and cvss.get("base_score") is not None:
        assessment["cvss"] = {
            "version": cvss.get("version"),
            "base_score": cvss.get("base_score"),
            "vector": cvss.get("vector"),
        }
    return assessment


def cna_assessment(cve_program: dict | None, publisher_source: str = "microsoft") -> dict | None:
    """The assigning CNA's own band, where the assigner is not the publisher.

    Microsoft is itself a CNA and assigns 973 of 1,185 September records. Its
    CVE Program baseSeverity for those is Microsoft's own CVSS band restated, not
    a second party's opinion, and comparing it against the MSRC band reports 332
    phantom disagreements instead of the real 5.

    `assignerShortName` is lowercase "microsoft", so the comparison is
    case-insensitive. An exact-case test matches nothing and lets all 973 through
    without a sound.
    """
    if not cve_program:
        return None
    assigner = cve_program.get("assigner")
    if not assigner or str(assigner).strip().lower() == publisher_source.strip().lower():
        return None
    vendor_severity = cve_program.get("vendor_severity")
    if not vendor_severity or not vendor_severity.get("band"):
        return None
    assessment = {
        "source": assigner,
        "role": "assigning-cna",
        "scale": vendor_severity.get("scale"),
        "value": vendor_severity.get("band"),
        "basis": "vendor",
    }
    if vendor_severity.get("base_score") is not None:
        assessment["cvss"] = {
            "version": vendor_severity.get("cvss_version"),
            "base_score": vendor_severity.get("base_score"),
            "vector": vendor_severity.get("vector"),
        }
    if cve_program.get("url"):
        assessment["url"] = cve_program["url"]
    return assessment


def _divergence(scales: dict, assessments: list[dict]) -> dict | None:
    """Describe a disagreement between two vendor bands.

    The two kinds are not the same problem, and the difference is whether the
    parties measured a comparable thing.

    `assessment` means they did and still disagree. All five 2026-Sep
    disagreements are this kind: Microsoft states an MSRC band but also publishes
    a CVSS 3.1 vector, and so does the upstream Linux CNA, so the two are
    directly comparable and the gap is a genuine difference of judgement.
    Microsoft scores C:N/I:N on every one while the CNA scores C:H. That is the
    more serious kind, and it is the one worth a number.

    `scale` means they did not. Chromium states a tier and publishes no CVSS at
    all, so a Chromium Critical against a Microsoft Critical has no honest scalar
    between them. Both are shown and neither is reconciled.

    Either way the record is flagged, so the disagreement is visible rather than
    resolved silently.
    """
    vendors = [a for a in assessments if a.get("role") in VENDOR_ROLES]
    if len(vendors) < 2:
        return None
    bands = {normalise_band(scales, a["scale"], a["value"]) for a in vendors}
    if len(bands) < 2:
        return None
    scores = [a.get("cvss", {}).get("base_score") for a in vendors]
    scores = [s for s in scores if s is not None]
    comparable = len(scores) >= 2
    divergence = {"kind": "assessment" if comparable else "scale"}
    if comparable:
        divergence["spread"] = round(max(scores) - min(scores), 2)
    return divergence


def build_severity(
    scales: dict,
    *,
    severity: str,
    severity_basis: str,
    cvss: dict | None,
    cve_program: dict | None,
) -> dict:
    """Assemble the vendor-plural severity object for one record."""
    assessments = []
    publisher = publisher_assessment(severity, severity_basis, cvss)
    if publisher:
        assessments.append(publisher)
    cna = cna_assessment(cve_program)
    if cna:
        assessments.append(cna)

    result: dict = {"assessments": assessments}

    # Microsoft declining to rate another CNA's CVE is policy, not a data gap, so
    # it is recorded as a positive fact rather than as an absence.
    if not publisher and cna:
        result["publisher_declined"] = {
            "source": "microsoft",
            "reason": "Microsoft does not rate CVEs assigned by another CNA",
        }

    vendors = [a for a in assessments if a.get("role") in VENDOR_ROLES]
    if vendors:
        # primary names whoever ships the fix, and is unaffected by which band
        # wins. "Who publishes the patch" and "how bad is it" stay separate.
        result["primary"] = (publisher or cna)["source"]
        ranked = sorted(vendors, key=lambda a: _rank(normalise_band(scales, a["scale"], a["value"])), reverse=True)
        winner = ranked[0]
        result["normalized_band"] = normalise_band(scales, winner["scale"], winner["value"])
        # Colon rather than "@" between scale and version: the customer-data guard
        # reads "msrc@1.0" as an email address, and it refuses to send rather than
        # redact. A cosmetic separator is not worth the first exception in a gate
        # built with no exclusions.
        result["normalized_basis"] = f"scale-mapping:{winner['scale']}:{scales['version']}"
        divergence = _divergence(scales, assessments)
        if divergence:
            result["divergence"] = divergence
        return result

    # Nobody published a band. A score is the last resort and says so.
    score = (cvss or {}).get("base_score")
    derived = band_from_score(scales, score)
    if derived != UNKNOWN:
        result["primary"] = None
        result["normalized_band"] = derived
        result["normalized_basis"] = "cvss-derived"
        return result

    result["primary"] = None
    result["normalized_band"] = UNKNOWN
    result["normalized_basis"] = "absent"
    return result


def normalized_band(severity) -> str:
    """Read the band off a record's severity, whatever shape it is in.

    Anything that is not a populated severity object resolves to `unknown`, which
    trips the existing review flag. It deliberately does not fall back to reading
    a legacy Microsoft string: that would be a second copy of the msrc scale, and
    it would let an unmigrated record pass silently as correctly-mapped data.
    """
    if isinstance(severity, dict):
        return severity.get("normalized_band") or UNKNOWN
    return UNKNOWN
