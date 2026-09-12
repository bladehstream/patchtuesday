"""Split published tags into derived product tags and model-asserted judgement tags.

The regex TAG_RULES in enrich_cvrf.py matched phrases in advisory prose and merged
the result into the same `tags` field the risk path reads - so a pattern match on a
title could feed a risk archetype. Measured on 2026-Sep the regexes contributed 164
release-tag additions and zero impact tags, so the realised harm was nil, but the
path existed.

After this migration:
  product_tags  derived from the structured products[] array. Cosmetic: UI filtering
                and search only. Never read by risk logic.
  tags          model-asserted judgement only, restricted to the workload, delivery
                and impact namespaces. These gate mitigation credit and archetypes.

Model-asserted platform and release tags are dropped rather than kept, because the
derived set is measurably more complete: in all 35 sampled cases where the regex
added a release tag the model had omitted, products[] listed the product outright.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("enrich_cvrf", Path(__file__).with_name("enrich_cvrf.py"))
ENRICH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENRICH)

JUDGEMENT_NAMESPACES = ("workload", "delivery", "impact")


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--overlay", required=True, type=Path)
    parser.add_argument("--taxonomy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    taxonomy = json.loads(args.taxonomy.read_text(encoding="utf-8"))["namespaces"]
    judgement = {tag for namespace in JUDGEMENT_NAMESPACES for tag in taxonomy[namespace]}

    overlay = {record["cve"]: set(record.get("tags") or []) for record in read_jsonl(args.overlay)}
    published = read_jsonl(args.published)

    missing = [record["cve"] for record in published if record["cve"] not in overlay]
    if missing:
        raise SystemExit(f"{len(missing)} published CVEs have no inference overlay: {', '.join(missing[:10])}")

    dropped = 0
    for record in published:
        model_tags = overlay[record["cve"]]
        record["tags"] = sorted(model_tags & judgement)
        record["product_tags"] = ENRICH.derive_product_tags(record.get("products") or [], record.get("title") or "")
        dropped += len(model_tags - judgement)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in published:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    judgement_total = sum(len(record["tags"]) for record in published)
    product_total = sum(len(record["product_tags"]) for record in published)
    print(f"Wrote {len(published)} records to {args.output}")
    print(f"  judgement tags retained: {judgement_total}")
    print(f"  product tags derived:    {product_total}")
    print(f"  model-asserted product/release tags dropped in favour of derivation: {dropped}")


if __name__ == "__main__":
    main()
