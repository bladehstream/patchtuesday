"""Rewrite a published dataset's severity onto the vendor-plural schema.

Modelled on refresh_product_tags.py, which is the existing pattern for a
deterministic rewrite of a published month. Unlike that one, this is **not**
rating-neutral: it is the migration that lets a non-Microsoft vendor's own band
reach the risk path for the first time. So it prints every band that moved and
every action that moved, rather than asserting that nothing did.

It is also the normalisation step for a fresh month, run after
apply_cve_enrichment.py has attached the assigning CNA's band. That step cannot
do this itself: `severity` is on its RESERVED list, and the enrichment is
forbidden from writing a risk-path field.

    python3 scripts/normalize_severity.py --published data/2026-Sep.jsonl --output data/2026-Sep.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from severity import UNKNOWN, build_severity, load_scales  # noqa: E402

SCHEMA_VERSION = "2.0"

# The old flat vocabulary, used only to report what moved. It is deliberately not
# used to derive anything: a legacy string is re-derived from its source facts,
# never translated in place.
LEGACY = {"Critical": "critical", "Important": "high", "Moderate": "medium", "Low": "low", "Unknown": UNKNOWN}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scales", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "severity-scales.json")
    args = parser.parse_args()

    scales = load_scales(args.scales)
    with args.published.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]

    before_counts: Counter[str] = Counter()
    after_counts: Counter[str] = Counter()
    moved = []

    for record in records:
        existing = record.get("severity")
        if isinstance(existing, dict):
            # Already migrated. Re-derive from the source facts rather than from
            # the previous output, so running twice cannot compound an error.
            legacy_band = existing.get("normalized_band") or UNKNOWN
            publisher = next((a for a in existing.get("assessments") or [] if a.get("role") == "publisher"), None)
            severity_text = publisher["value"] if publisher else "Unknown"
            severity_basis = "vendor" if publisher else record.get("severity_basis", "absent")
        else:
            legacy_band = LEGACY.get(existing, UNKNOWN)
            severity_text = existing or "Unknown"
            # A record carrying a band but no recorded basis predates the field.
            # The convention everywhere else is that such a string is the vendor's
            # own, so honour it rather than silently demoting the whole month to
            # unknown, which is what reading the missing field as "absent" did to
            # the demo dataset.
            severity_basis = record.get("severity_basis") or ("vendor" if severity_text != "Unknown" else "absent")

        resolved = build_severity(
            scales,
            severity=severity_text,
            severity_basis=severity_basis,
            cvss=record.get("cvss"),
            cve_program=record.get("cve_program"),
        )
        record["severity"] = resolved
        record["schema_version"] = SCHEMA_VERSION

        before_counts[legacy_band] += 1
        after_counts[resolved["normalized_band"]] += 1
        if legacy_band != resolved["normalized_band"]:
            moved.append((record["cve"], legacy_band, resolved["normalized_band"], resolved.get("primary")))

    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    order = ["critical", "high", "medium", "low", UNKNOWN]
    print(f"{len(records)} records -> {args.output}")
    print(f"{'band':10} {'before':>7} {'after':>7}")
    for band in order:
        print(f"{band:10} {before_counts.get(band, 0):>7} {after_counts.get(band, 0):>7}")
    print(f"\n{len(moved)} records changed band")
    for cve, was, now, primary in moved:
        print(f"  {cve}  {was} -> {now}  (primary: {primary})")

    divergent = [r for r in records if r["severity"].get("divergence")]
    print(f"\n{len(divergent)} records carry a vendor disagreement")
    for record in divergent:
        divergence = record["severity"]["divergence"]
        spread = divergence.get("spread")
        print(f"  {record['cve']}  kind={divergence['kind']}" + (f" spread={spread}" if spread is not None else ""))


if __name__ == "__main__":
    main()
