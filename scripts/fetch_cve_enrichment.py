#!/usr/bin/env python3
"""Fetch CVE Program records and extract the CISA-ADP SSVC decision points.

Why this is a separate source and a separate field. Microsoft publishes CVSS but no
exploitation-decision data; CISA's Vulnrichment programme fills what a CNA left out,
so on 2026-Sep it added SSVC to 971 of 972 Microsoft-assigned records and an ADP CVSS
to none of them. Coverage across the whole month is 1080 of 1185 records, 91.1%.

SSVC is CISA's judgement, not the vendor's, so it lands in its own `cve_program` block
and never touches `severity`, `cvss` or `threat`. It is evidence offered to a reviewer
and to the assessor, not a rating.

The Exploitation trap, quoted from the SSVC specification: none means "There is no
evidence of active exploitation and no public proof of concept (PoC) of how to exploit
the vulnerability", and "The intent is not to predict future exploitation but only to
acknowledge the current state of affairs." It is an evidentiary status, not a
prediction. Mapping it to `unlikely` would suppress likelihood by one step on the 1054
records that carry it. It maps to `unknown`.

Source: raw.githubusercontent.com/CVEProject/cvelistV5, static JSON per CVE, no key and
no rate limit observed. 1185 records fetched in about 25 seconds at 12 concurrent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
CVE_ID = re.compile(r"^CVE-(\d{4})-(\d+)$")
DECISION_POINTS = ("Exploitation", "Automatable", "Technical Impact")


def record_url(cve: str) -> str | None:
    match = CVE_ID.match(cve or "")
    if not match:
        return None
    year, serial = match.groups()
    # The directory is the serial with its last three digits replaced by "xxx", so a
    # sub-thousand serial lands in 0xxx rather than in an empty bucket name.
    return f"{BASE}/{year}/{serial[:-3] or '0'}xxx/CVE-{year}-{serial}.json"


def extract(document: dict) -> dict:
    """Pull the assigner and the CISA-ADP SSVC options. Absent stays absent."""
    containers = document.get("containers") or {}
    result = {
        "assigner": (document.get("cveMetadata") or {}).get("assignerShortName"),
        "date_published": (document.get("cveMetadata") or {}).get("datePublished"),
        "date_updated": (document.get("cveMetadata") or {}).get("dateUpdated"),
        "ssvc": None,
        "ssvc_provider": None,
    }
    for container in containers.get("adp") or []:
        provider = ((container.get("providerMetadata") or {}).get("shortName"))
        for metric in container.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            options = {}
            for option in (other.get("content") or {}).get("options") or []:
                for key, value in option.items():
                    if key in DECISION_POINTS:
                        options[key.lower().replace(" ", "_")] = value
            if options:
                result["ssvc"] = options
                result["ssvc_provider"] = provider
                result["ssvc_timestamp"] = (other.get("content") or {}).get("timestamp")
    return result


def fetch_one(cve: str, cache: Path | None, timeout: int) -> dict:
    url = record_url(cve)
    if url is None:
        return {"cve": cve, "status": "invalid-cve-id", "url": None}
    cached = cache / f"{cve}.json" if cache else None
    if cached and cached.is_file():
        raw = cached.read_bytes()
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "patch-tuesday-triage/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            # 404 means the CVE Program has not published this record. That is a real
            # state and is reported as one; it is never treated as "no exploitation".
            return {"cve": cve, "status": "not-published" if error.code == 404 else f"http-{error.code}", "url": url}
        except Exception as error:  # noqa: BLE001 - any transport failure is a failure to report
            return {"cve": cve, "status": f"fetch-failed: {type(error).__name__}", "url": url}
        if cached:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(raw)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        return {"cve": cve, "status": f"unparseable: {error}", "url": url}
    entry = {"cve": cve, "status": "found", "url": url, "sha256": hashlib.sha256(raw).hexdigest()}
    entry.update(extract(document))
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", required=True, type=Path, help="JSONL whose records carry a cve field")
    parser.add_argument("--output", required=True, type=Path, help="Enrichment sidecar JSONL, one entry per CVE")
    parser.add_argument("--cache-dir", type=Path, help="Reuse and store raw CVE records here")
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    cves = [json.loads(line)["cve"] for line in args.records.read_text(encoding="utf-8").splitlines() if line.strip()]
    seen, ordered = set(), []
    for cve in cves:
        if cve not in seen:
            seen.add(cve)
            ordered.append(cve)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        entries = list(pool.map(lambda cve: fetch_one(cve, args.cache_dir, args.timeout), ordered))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(json.dumps(entry, separators=(",", ":")) for entry in entries) + "\n", encoding="utf-8")

    found = [entry for entry in entries if entry["status"] == "found"]
    with_ssvc = [entry for entry in found if entry.get("ssvc")]
    exploitation = {}
    for entry in with_ssvc:
        value = entry["ssvc"].get("exploitation")
        exploitation[value] = exploitation.get(value, 0) + 1
    failures = [entry for entry in entries if entry["status"] not in {"found", "not-published"}]
    print(json.dumps({
        "requested": len(ordered),
        "found": len(found),
        "not_published": sum(1 for entry in entries if entry["status"] == "not-published"),
        "failed": len(failures),
        "with_ssvc": len(with_ssvc),
        "ssvc_coverage": round(len(with_ssvc) / len(ordered), 4) if ordered else None,
        "exploitation": exploitation,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "output": str(args.output),
    }, indent=2))
    if failures:
        print(f"{len(failures)} record(s) could not be fetched; re-run before relying on coverage:")
        for entry in failures[:10]:
            print(f"  {entry['cve']}: {entry['status']}")


if __name__ == "__main__":
    main()
