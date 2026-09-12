#!/usr/bin/env python3
"""Apply a CVE Program enrichment sidecar onto a published month.

Deterministic and rating-neutral, like scripts/refresh_product_tags.py: it writes one
new `cve_program` block per record and changes nothing else. SSVC is CISA's judgement
rather than the vendor's, so it never reaches `severity`, `cvss`, `threat` or any
field the risk path reads - a fixture asserts exactly that.

A record with no enrichment entry, or an entry with no SSVC, gets
`cve_program.ssvc: null` with a stated reason. Absent is recorded as absent.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Fields the risk path reads. The enrichment must never write to any of them.
RESERVED = {"severity", "severity_basis", "cvss", "attack", "threat", "tags", "inference", "mitigation_candidates"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--enrichment", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    entries = {}
    for line in args.enrichment.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            entries[entry["cve"]] = entry

    records = [json.loads(line) for line in args.published.read_text(encoding="utf-8").splitlines() if line.strip()]
    applied = missing = without_ssvc = 0
    for record in records:
        before = {key: json.dumps(record.get(key), sort_keys=True) for key in RESERVED if key in record}
        entry = entries.get(record["cve"])
        if entry is None or entry.get("status") != "found":
            record["cve_program"] = {
                "status": (entry or {}).get("status", "not-fetched"),
                "ssvc": None,
                "ssvc_absent_reason": "no CVE Program record was retrieved for this CVE",
            }
            missing += 1
        else:
            ssvc = entry.get("ssvc")
            record["cve_program"] = {
                "status": "found",
                "assigner": entry.get("assigner"),
                "url": entry.get("url"),
                "sha256": entry.get("sha256"),
                "date_updated": entry.get("date_updated"),
                "ssvc": ssvc,
                "ssvc_provider": entry.get("ssvc_provider"),
            }
            if ssvc:
                applied += 1
            else:
                record["cve_program"]["ssvc_absent_reason"] = "the CVE Program record carries no CISA-ADP SSVC assessment"
                without_ssvc += 1
        after = {key: json.dumps(record.get(key), sort_keys=True) for key in RESERVED if key in record}
        if before != after:
            raise SystemExit(f"{record['cve']}: the enrichment modified a risk-path field; refusing to write")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    print(f"Wrote {len(records)} records to {args.output}")
    print(f"  SSVC applied:        {applied}  ({applied / len(records):.1%})")
    print(f"  record found, no SSVC: {without_ssvc}")
    print(f"  no record retrieved:   {missing}")


if __name__ == "__main__":
    main()
