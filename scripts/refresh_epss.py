#!/usr/bin/env python3
"""Refresh EPSS fields in published monthly JSONL without rerunning inference."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DAILY_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
API_URL = "https://api.first.org/data/v1/epss"
MANIFEST = "months.json"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "patch-tuesday-triage/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def parse_csv(data: bytes) -> tuple[dict[str, dict[str, Any]], str | None]:
    text = data.decode("utf-8-sig")
    score_date = None
    rows = []
    for line in text.splitlines():
        if line.startswith("#"):
            match = re.search(r"score_date:([^,\s]+)", line)
            if match:
                score_date = match.group(1)[:10]
        elif line.strip():
            rows.append(line)
    scores = {}
    for row in csv.DictReader(rows):
        if row.get("cve") and row.get("epss"):
            scores[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]) if row.get("percentile") else None,
                "date": score_date,
            }
    return scores, score_date


def query_api(cves: list[str]) -> dict[str, dict[str, Any]]:
    output = {}
    for start in range(0, len(cves), 100):
        batch = cves[start:start + 100]
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        document = json.loads(fetch(f"{API_URL}?{query}"))
        for row in document.get("data", []):
            output[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]) if row.get("percentile") else None,
                "date": row.get("date"),
            }
    return output


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def is_synthetic(entry: dict[str, Any]) -> bool:
    """The demo dataset carries invented CVE identifiers, which EPSS cannot score.

    Refreshing it would stamp every synthetic record `pending` and rewrite the file
    on every run. `synthetic: true` is the declared form; the name checks are the
    fallback for the entry that predates the flag.
    """
    if entry.get("synthetic"):
        return True
    return str(entry.get("file", "")).startswith("demo-") or str(entry.get("month", "")).endswith("-demo")


def published_datasets(data_dir: Path) -> tuple[list[Path], list[str]]:
    """Resolve which datasets to refresh from `months.json`, not from a glob.

    `months.json` is what `publish_month.py` writes and what the site reads, so it
    is the one authoritative list of published datasets. Discovering files any
    other way - a glob, or a list enumerated somewhere else - means two sources of
    truth that agree today and diverge the first time the cadence changes. The
    project is moving to twice-monthly releases with non-Microsoft vendors, so
    "which files exist" and "which releases are published" stop being the same
    question.

    Returns the paths to refresh and any warnings about disagreement between the
    manifest and the directory. Disagreement is reported rather than silently
    resolved in either direction: a file on disk that no manifest entry names is
    either an unpublished draft or a manifest that was never updated, and both are
    things an operator needs to see.
    """
    manifest_path = data_dir / MANIFEST
    if not manifest_path.exists():
        raise SystemExit(f"{manifest_path} is missing; cannot determine which datasets are published")

    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    paths: list[Path] = []
    named = set()

    for entry in entries:
        filename = entry.get("file")
        if not filename:
            warnings.append(f"manifest entry {entry.get('month', '?')!r} names no file; skipped")
            continue
        named.add(filename)
        if is_synthetic(entry):
            continue
        path = data_dir / filename
        if not path.exists():
            warnings.append(f"manifest names {filename}, which is not in {data_dir}; skipped")
            continue
        paths.append(path)

    for path in sorted(data_dir.glob("*.jsonl")):
        if path.name not in named:
            warnings.append(f"{path.name} is present in {data_dir} but no {MANIFEST} entry names it; not refreshed")

    return paths, warnings


def refresh_records(records: list[dict[str, Any]], scores: dict[str, dict[str, Any]], feed_date: str | None) -> int:
    changed = 0
    for record in records:
        threat = record.setdefault("threat", {})
        before = {key: threat.get(key) for key in ("epss", "epss_percentile", "epss_date", "epss_status")}
        score = scores.get(record.get("cve"))
        if score:
            threat["epss"] = score["epss"]
            threat["epss_percentile"] = score.get("percentile")
            threat["epss_date"] = score.get("date") or feed_date
            threat["epss_status"] = "scored"
        elif threat.get("epss") is not None:
            threat["epss_status"] = "stale"
        else:
            threat["epss"] = None
            threat["epss_percentile"] = None
            threat["epss_date"] = feed_date
            threat["epss_status"] = "pending"
        after = {key: threat.get(key) for key in before}
        if before != after:
            changed += 1
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--file", action="append", type=Path)
    parser.add_argument("--epss-file", type=Path, help="Use an already downloaded uncompressed EPSS CSV")
    parser.add_argument("--skip-api", action="store_true")
    args = parser.parse_args()

    if args.file:
        files = args.file
    else:
        files, warnings = published_datasets(args.data_dir)
        for warning in warnings:
            print(f"WARNING: {warning}")
        if not files:
            raise SystemExit(f"No published datasets listed in {args.data_dir / MANIFEST}")
    records_by_file = {path: read_jsonl(path) for path in files}
    target_cves = sorted({record["cve"] for records in records_by_file.values() for record in records})

    if args.epss_file:
        csv_data = args.epss_file.read_bytes()
        source_hash = hashlib.sha256(csv_data).hexdigest()
    else:
        compressed = fetch(DAILY_URL)
        source_hash = hashlib.sha256(compressed).hexdigest()
        csv_data = gzip.decompress(compressed)
    scores, feed_date = parse_csv(csv_data)
    selected_scores = {cve: scores[cve] for cve in target_cves if cve in scores}
    missing = [cve for cve in target_cves if cve not in selected_scores]
    if missing and not args.skip_api:
        selected_scores.update(query_api(missing))

    total_changed = 0
    for path, records in records_by_file.items():
        changed = refresh_records(records, selected_scores, feed_date)
        if changed:
            for record in records:
                provenance = record.setdefault("dataset_provenance", {}).setdefault("sources", {})
                provenance["epss"] = {
                    "url": DAILY_URL,
                    "sha256": source_hash,
                    "score_date": feed_date,
                    "batch_api_fallback": not args.skip_api,
                }
            path.write_text("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n", encoding="utf-8")
            total_changed += changed
            print(f"{path}: updated {changed} of {len(records)} records")
        else:
            print(f"{path}: no EPSS changes")
    print(f"EPSS coverage: {len(selected_scores)} of {len(target_cves)} target CVEs; changed records: {total_changed}")


if __name__ == "__main__":
    main()
