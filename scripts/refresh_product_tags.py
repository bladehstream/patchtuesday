"""Recompute derived product tags on a published dataset.

Product tags are pure derivation from the structured product tree, so they can be
refreshed at any time without touching judgement tags, inference, or ratings.
Run this after extending PRODUCT_TAG_RULES.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("enrich_cvrf", Path(__file__).with_name("enrich_cvrf.py"))
ENRICH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENRICH)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    with args.published.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]

    changed = 0
    for record in records:
        before = record.get("product_tags") or []
        after = ENRICH.derive_product_tags(record.get("products") or [])
        if before != after:
            changed += 1
        record["product_tags"] = after

    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    unreachable = [r["cve"] for r in records if not (set(r["product_tags"]) - {"microsoft"})]
    print(f"Wrote {len(records)} records to {args.output}")
    print(f"  product_tags changed on {changed} records")
    print(f"  reachable by at least one specific product filter: "
          f"{len(records) - len(unreachable)}/{len(records)} "
          f"({(len(records) - len(unreachable)) / len(records):.1%})")
    if unreachable:
        print(f"  still generic-only: {', '.join(unreachable)}")


if __name__ == "__main__":
    main()
