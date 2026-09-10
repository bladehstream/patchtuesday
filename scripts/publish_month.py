#!/usr/bin/env python3
"""Copy a locally enriched month into the static site and update its manifest."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).parents[1]
DATA = ROOT / "data"
MANIFEST = DATA / "months.json"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--month", required=True)
    parser.add_argument("--label")
    args = parser.parse_args()
    if not args.jsonl.is_file():
        raise SystemExit(f"File not found: {args.jsonl}")
    records = [json.loads(line) for line in args.jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    count = len(records)
    if count == 0:
        raise SystemExit("JSONL file is empty")
    if len({record.get("cve") for record in records}) != count:
        raise SystemExit("Duplicate CVEs in publication input")
    if not args.month.endswith("-demo"):
        missing = [record.get("cve") for record in records if record.get("inference", {}).get("review_status") != "reviewed" or not record.get("inference", {}).get("framework_assessment")]
        if missing:
            raise SystemExit(f"Refusing partial inference publication: {count-len(missing)}/{count} complete; missing {missing[:5]}")
    filename = f"{args.month}.jsonl"
    destination = DATA / filename
    shutil.copyfile(args.jsonl, destination)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else []
    manifest = [item for item in manifest if item.get("month") != args.month]
    manifest.append({
        "month": args.month,
        "label": args.label or args.month,
        "file": filename,
        "record_count": count,
        "published_at": datetime.now(timezone.utc).isoformat(),
    })
    manifest.sort(key=lambda item: item["month"], reverse=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Published {count} records as data/{filename}")


if __name__ == "__main__":
    main()
