#!/usr/bin/env python3
"""Fetch public MSRC CVRF, CISA KEV, and FIRST EPSS data for local enrichment."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch(url: str, accept: str | None = None) -> bytes:
    headers = {"User-Agent": "patch-tuesday-triage/0.1"}
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--month", required=True, help="MSRC month such as 2026-Sep")
    parser.add_argument("--output-dir", type=Path, default=Path("raw"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    msrc_url = MSRC_URL.format(month=args.month)
    msrc = fetch(msrc_url, "application/json")
    kev = fetch(KEV_URL, "application/json")
    epss_gzip = fetch(EPSS_URL)
    epss = gzip.decompress(epss_gzip)

    outputs = {
        "msrc": (args.output_dir / f"{args.month}.json", msrc, msrc_url),
        "kev": (args.output_dir / "known_exploited_vulnerabilities.json", kev, KEV_URL),
        "epss": (args.output_dir / "epss_scores-current.csv", epss, EPSS_URL),
    }
    metadata = {"fetched_at": datetime.now(timezone.utc).isoformat(), "month": args.month, "sources": {}}
    for name, (path, data, url) in outputs.items():
        path.write_bytes(data)
        metadata["sources"][name] = {"url": url, "file": path.name, "bytes": len(data), "sha256": digest(data)}
    metadata_path = args.output_dir / f"{args.month}-fetch-metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
