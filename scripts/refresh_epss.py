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

    files = args.file or sorted(path for path in args.data_dir.glob("*.jsonl") if not path.name.startswith("demo-"))
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
