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

Usage:
  python scripts/apply_severity_correction.py \
      --published data/2026-Sep.jsonl \
      --baseline work/phase0/baseline.jsonl \
      --output data/2026-Sep.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    published = read_jsonl(args.published)
    baseline = {record["cve"]: record for record in read_jsonl(args.baseline)}

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
