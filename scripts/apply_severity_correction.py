"""Apply corrected severity resolution to an already-published dataset.

Phase 0 of REMEDIATION_PLAN.md. The published September snapshot rated 23
records "Low" that carry neither a vendor severity nor a CVSS base score -
56% of the entire Low bucket, almost all Chromium passthrough advisories where
Microsoft defers to Google.

This script copies `severity` and `severity_basis` from a freshly enriched
baseline onto the published records. It deliberately does NOT touch the
inference overlay: Luna's stored assessment is the historical claim and is
retained as evidence per ASSESSOR_HANDOFF.md. Records whose severity
becomes Unknown are surfaced by the computed review flag in engine.js, not by
rewriting the prior model output.

**Superseded. Phase 0 is complete and every published month is schema 2.0.**

This script predates the vendor-plural severity schema. It copies a flat severity
string and a `severity_basis` from a baseline onto a published record, which was
correct when `severity` was a string. It is not correct now: a published record
carries a severity object whose band may come from a vendor other than Microsoft,
and overwriting that object with a string erases the assigning CNA's rating and
resolves the whole month to `unknown` through the band reader - the exact fail-open
this script was written to repair, reintroduced in a new shape. There is no legacy
dataset left for it to be right about.

The replacement is `scripts/normalize_severity.py`. It re-derives severity from the
source facts rather than copying a previous output, so running it twice cannot
compound an error, and it prints every band and every action that moved.

Kept rather than deleted so the Phase 0 remediation stays readable in the history.
It now refuses to run against anything it would damage and says what to run
instead. Those shape checks are the whole of its remaining value.

Usage (legacy flat-severity datasets only):
  python scripts/apply_severity_correction.py \
      --published data/2026-Sep.jsonl \
      --baseline work/phase0/baseline.jsonl \
      --output data/2026-Sep.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REPLACEMENT = "python3 scripts/normalize_severity.py --published <file> --output <file>"


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def severity_shape(records: list[dict], label: str) -> str:
    """Classify a dataset as flat or vendor-plural, and refuse a mixed one.

    A mixed file is a half-finished migration. Guessing which half is authoritative
    is how a dataset ends up internally inconsistent with nothing reporting it, so
    this halts instead.
    """
    shapes = {"vendor-plural" if isinstance(record.get("severity"), dict) else "flat" for record in records}
    if not shapes:
        raise SystemExit(f"{label} contains no records")
    if len(shapes) > 1:
        objects = [record["cve"] for record in records if isinstance(record.get("severity"), dict)]
        raise SystemExit(
            f"{label} mixes both severity schemas: {len(objects)} of {len(records)} records carry a severity "
            f"object and the rest carry a string. That is a half-finished migration, not an input. "
            f"Complete it first: {REPLACEMENT}"
        )
    return shapes.pop()


def refuse_unless_legacy(published: list[dict], baseline: list[dict]) -> None:
    """Halt before writing anything this script cannot represent.

    Checked before the first write rather than per record, because a partially
    rewritten published month is worse than one not rewritten at all.
    """
    published_shape = severity_shape(published, "--published")
    baseline_shape = severity_shape(baseline, "--baseline")
    versions = sorted({str(record["schema_version"]) for record in published if record.get("schema_version")})

    if published_shape == "vendor-plural":
        raise SystemExit(
            "--published carries vendor-plural severity objects"
            + (f" (schema_version {'/'.join(versions)})" if versions else "")
            + ", which this script cannot write. Copying a flat string over them would erase every "
            "assigning CNA's own band and leave the month reading as unknown - the fail-open this "
            f"script exists to repair. Use: {REPLACEMENT}"
        )
    if baseline_shape == "vendor-plural":
        raise SystemExit(
            "--baseline carries vendor-plural severity objects but --published is flat. This script "
            "would flatten them on the way across, discarding every non-publisher band. Migrate the "
            f"published file instead: {REPLACEMENT}"
        )

    without_basis = [record["cve"] for record in baseline if "severity_basis" not in record]
    if without_basis:
        raise SystemExit(
            f"{len(without_basis)} baseline records carry no severity_basis, so what a band was derived "
            f"from cannot be carried across: {', '.join(without_basis[:10])}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    published = read_jsonl(args.published)
    baseline = {record["cve"]: record for record in read_jsonl(args.baseline)}

    refuse_unless_legacy(published, list(baseline.values()))

    missing = [record["cve"] for record in published if record["cve"] not in baseline]
    if missing:
        raise SystemExit(
            f"{len(missing)} published CVEs are absent from the baseline, so severity cannot be "
            f"verified for them: {', '.join(missing[:10])}"
        )

    changes: list[tuple[str, str, str]] = []
    for record in published:
        source = baseline[record["cve"]]
        before = record.get("severity")
        after = source["severity"]
        if before != after:
            changes.append((record["cve"], before, after))
        record["severity"] = after
        record["severity_basis"] = source["severity_basis"]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in published:
            # Match scripts/merge_inference.py: compact separators, so the
            # diff shows only records whose content actually changed.
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    print(f"Wrote {len(published)} records to {args.output}")
    print(f"Severity changed on {len(changes)} records:")
    for cve, before, after in changes:
        print(f"  {cve}: {before} -> {after}")


if __name__ == "__main__":
    main()
