#!/usr/bin/env python3
"""Validate a manual inference overlay and merge it onto programmatic source facts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def read_jsonl(path: Path) -> list[dict]:
    output = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            output.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path} line {line_no}: {exc}") from exc
    return output


def allowed_tags(path: Path) -> set[str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {tag for values in document["namespaces"].values() for tag in values}


def allowed_mitigations(path: Path) -> set[str]:
    return {item["id"] for item in json.loads(path.read_text(encoding="utf-8"))}


def validate_candidate(candidate: dict, allowed: set[str], cve: str) -> None:
    mitigation_id = candidate.get("id")
    if mitigation_id not in allowed:
        raise ValueError(f"{cve}: unknown mitigation {mitigation_id}")
    if candidate.get("relevance") not in {"relevant", "not-relevant", "unknown"}:
        raise ValueError(f"{cve}: invalid relevance for {mitigation_id}")
    if candidate.get("confidence") not in {"high", "medium", "low"}:
        raise ValueError(f"{cve}: invalid confidence for {mitigation_id}")
    effect = candidate.get("effect") or {}
    for field in ("likelihood_steps", "consequence_steps"):
        if effect.get(field, 0) not in {0, 1, 2}:
            raise ValueError(f"{cve}: {field} must be 0, 1, or 2")
    if effect.get("path_block") and not (
        candidate.get("confidence") == "high"
        and mitigation_id in {"service_disabled_vendor_guidance", "vendor_workaround"}
    ):
        raise ValueError(f"{cve}: path_block requires a high-confidence vendor workaround or service disablement")
    if effect.get("likelihood_steps", 0) == 2 and not effect.get("path_block"):
        raise ValueError(f"{cve}: two likelihood steps require an exact path block")
    if not str(candidate.get("evidence") or "").strip():
        raise ValueError(f"{cve}: evidence is required for {mitigation_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--inference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--taxonomy", type=Path, default=ROOT / "data" / "tag-taxonomy.json")
    parser.add_argument("--mitigations", type=Path, default=ROOT / "data" / "mitigation-catalog.json")
    args = parser.parse_args()

    baseline = {item["cve"]: item for item in read_jsonl(args.baseline)}
    tags_allowed = allowed_tags(args.taxonomy)
    mitigations_allowed = allowed_mitigations(args.mitigations)
    merged = []
    seen = set()
    for overlay in read_jsonl(args.inference):
        cve = overlay.get("cve")
        if cve not in baseline:
            raise ValueError(f"Inference CVE is absent from baseline: {cve}")
        if cve in seen:
            raise ValueError(f"Duplicate inference CVE: {cve}")
        seen.add(cve)
        inferred_tags = set(overlay.get("tags") or [])
        unknown_tags = inferred_tags - tags_allowed
        if unknown_tags:
            raise ValueError(f"{cve}: unknown tags {sorted(unknown_tags)}")
        candidates = overlay.get("mitigation_candidates") or []
        for candidate in candidates:
            validate_candidate(candidate, mitigations_allowed, cve)
        record = baseline[cve]
        record["tags"] = sorted(set(record.get("tags") or []) | inferred_tags)
        record["mitigation_candidates"] = candidates
        record["inference"] = overlay.get("inference") or {}
        merged.append(record)

    severity_order = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3}
    merged.sort(key=lambda item: (
        not (item.get("threat", {}).get("kev") or item.get("threat", {}).get("exploitation_detected")),
        severity_order.get(item.get("severity"), 9),
        item.get("attack", {}).get("vector") != "network",
        item.get("cve"),
    ))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(json.dumps(item, separators=(",", ":")) for item in merged) + "\n", encoding="utf-8")
    print(f"Validated and merged {len(merged)} inference records into {args.output}")


if __name__ == "__main__":
    main()
