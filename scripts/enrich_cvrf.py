#!/usr/bin/env python3
"""Normalize an MSRC CVRF JSON document and merge schema-constrained inference JSONL."""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TAG_RULES = {
    "windows": (r"\bwindows\b",),
    "server": (r"\bserver\b",),
    "server-2016": (r"windows server 2016",),
    "server-2019": (r"windows server 2019",),
    "server-2022": (r"windows server 2022",),
    "server-2025": (r"windows server 2025",),
    "windows-10": (r"windows 10",),
    "windows-11": (r"windows 11",),
    "dns": (r"\bdns\b", r"domain name system"),
    "dhcp": (r"\bdhcp\b", r"dynamic host configuration"),
    "sharepoint": (r"sharepoint",),
    "office": (r"\boffice\b", r"microsoft 365 apps"),
    "identity": (r"active directory", r"domain controller", r"entra"),
    "hyper-v": (r"hyper-v",),
    "print": (r"print spooler", r"printing"),
    "endpoint": (r"windows 10", r"windows 11", r"office", r"microsoft 365 apps"),
    "remote-code-execution": (r"remote code execution",),
    "elevation-of-privilege": (r"elevation of privilege",),
    "security-feature-bypass": (r"security feature bypass",),
    "information-disclosure": (r"information disclosure",),
    "denial-of-service": (r"denial of service",),
    "spoofing": (r"spoofing",),
}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def text_value(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("Value") or value.get("value") or "")
    return str(value or "")


def collect_products(node: Any, output: dict[str, str]) -> None:
    if isinstance(node, dict):
        product_id = str(node.get("ProductID") or node.get("product_id") or "")
        direct_name = text_value(node)
        if product_id and direct_name:
            output[product_id] = direct_name
        full = node.get("FullProductName") or node.get("full_product_name")
        if isinstance(full, dict):
            product_id = str(full.get("ProductID") or full.get("product_id") or "")
            name = text_value(full)
            if product_id and name:
                output[product_id] = name
        for value in node.values():
            collect_products(value, output)
    elif isinstance(node, list):
        for value in node:
            collect_products(value, output)


def product_ids(vulnerability: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    statuses = vulnerability.get("ProductStatuses") or vulnerability.get("product_statuses") or []
    for status in as_list(statuses):
        if not isinstance(status, dict):
            continue
        for key, value in status.items():
            if key.lower() in {"productid", "product_id"}:
                found.update(str(item) for item in as_list(value))
            elif isinstance(value, (dict, list)):
                found.update(product_ids({"ProductStatuses": value}))
    return found


def infer_tags(text: str) -> list[str]:
    lowered = text.lower()
    tags = [tag for tag, patterns in TAG_RULES.items() if any(re.search(pattern, lowered) for pattern in patterns)]
    return ["microsoft", *sorted(set(tags))]


def threat_description(vulnerability: dict[str, Any], threat_type: str) -> str:
    for threat in as_list(vulnerability.get("Threats")):
        if str(threat.get("Type", "")).lower() == threat_type.lower():
            return text_value(threat.get("Description"))
    return ""


def best_cvss(vulnerability: dict[str, Any]) -> dict[str, Any]:
    scores = [score for score in as_list(vulnerability.get("CVSSScoreSets")) if isinstance(score, dict)]
    if not scores:
        return {}
    return max(scores, key=lambda score: float(score.get("BaseScore") or 0))


def vector_fields(vector: str) -> dict[str, str]:
    values = dict(re.findall(r"(?:^|/)(AV|PR|UI):([A-Z])", vector or ""))
    return {
        "vector": {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}.get(values.get("AV"), "unknown"),
        "privileges_required": {"N": "none", "L": "low", "H": "high"}.get(values.get("PR"), "unknown"),
        "user_interaction": {"N": "none", "R": "required", "P": "required", "A": "required"}.get(values.get("UI"), "unknown"),
    }


def normalize_severity(value: str, base_score: float) -> str:
    lowered = value.lower()
    if "critical" in lowered or base_score >= 9:
        return "Critical"
    if "important" in lowered or "high" in lowered or base_score >= 7:
        return "Important"
    if "moderate" in lowered or "medium" in lowered or base_score >= 4:
        return "Moderate"
    return "Low"


def load_inference(path: Path | None) -> dict[str, dict[str, Any]]:
    if not path:
        return {}
    output = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not item.get("cve"):
            raise ValueError(f"Inference line {line_no} has no CVE")
        output[item["cve"]] = item
    return output


def vulnerabilities(document: dict[str, Any]) -> Iterable[dict[str, Any]]:
    return as_list(document.get("Vulnerability") or document.get("Vulnerabilities") or document.get("vulnerabilities"))


def load_kev(path: Path | None) -> set[str]:
    if not path:
        return set()
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    return {str(item.get("cveID")) for item in as_list(document.get("vulnerabilities")) if item.get("cveID")}


def load_epss(path: Path | None) -> dict[str, float]:
    if not path:
        return {}
    lines = [line for line in path.read_text(encoding="utf-8-sig").splitlines() if line and not line.startswith("#")]
    return {row["cve"]: float(row["epss"]) for row in csv.DictReader(lines) if row.get("cve") and row.get("epss")}


def load_fetch_metadata(path: Path | None) -> dict[str, Any]:
    if not path:
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    return {"fetched_at": document.get("fetched_at"), "sources": document.get("sources", {})}


def build_records(
    document: dict[str, Any],
    month: str,
    inference: dict[str, dict[str, Any]],
    kev: set[str] | None = None,
    epss: dict[str, float] | None = None,
    fetch_metadata: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    kev = kev or set()
    epss = epss or {}
    fetch_metadata = fetch_metadata or {}
    product_map: dict[str, str] = {}
    collect_products(document.get("ProductTree") or document.get("product_tree"), product_map)
    revision = text_value(document.get("DocumentTracking", {}).get("CurrentReleaseDate"))
    records = []
    for vuln in vulnerabilities(document):
        cve = str(vuln.get("CVE") or vuln.get("cve") or "UNKNOWN")
        title = text_value(vuln.get("Title")) or cve
        ids = product_ids(vuln)
        products = [{"product_id": item, "name": product_map.get(item, item)} for item in sorted(ids)]
        cvss = best_cvss(vuln)
        score = float(cvss.get("BaseScore") or 0)
        vector = str(cvss.get("Vector") or "")
        severity_text = threat_description(vuln, "3") or threat_description(vuln, "Severity")
        exploit_text = " ".join(text_value(v) for v in as_list(vuln.get("Notes"))) + " " + threat_description(vuln, "1")
        combined = " ".join([title, *[item["name"] for item in products], exploit_text])
        overlay = inference.get(cve, {})
        tags = sorted(set(infer_tags(combined) + as_list(overlay.get("tags"))))
        notes = [
            {"title": str(note.get("Title") or ""), "type": note.get("Type"), "value": text_value(note)}
            for note in as_list(vuln.get("Notes")) if isinstance(note, dict) and (note.get("Value") or note.get("value"))
        ]
        customer_action_values = [note["value"].strip().lower() for note in notes if note["title"].lower() == "customer action required"]
        customer_action_required = None if not customer_action_values else customer_action_values[-1] in {"yes", "true", "required"}
        remediations = [
            {
                "type": item.get("Type"),
                "subtype": item.get("SubType") or "",
                "url": item.get("URL") or "",
                "product_ids": as_list(item.get("ProductID")),
                "description": text_value(item.get("Description")),
            }
            for item in as_list(vuln.get("Remediations")) if isinstance(item, dict)
        ]
        record = {
            "schema_version": "1.0",
            "month": month,
            "cve": cve,
            "title": title,
            "severity": normalize_severity(severity_text, score),
            "customer_action_required": customer_action_required,
            "products": products,
            "tags": tags,
            "attack": vector_fields(vector),
            "threat": {
                "kev": cve in kev,
                "exploitation_detected": "exploitation detected" in exploit_text.lower(),
                "exploitation_assessment": "more-likely" if "more likely" in exploit_text.lower() else "less-likely" if "less likely" in exploit_text.lower() else "unknown",
                "epss": epss.get(cve),
            },
            "mitigation_candidates": as_list(overlay.get("mitigation_candidates")),
            "vendor_guidance": {"notes": notes, "remediations": remediations},
            "source": {"type": "MSRC CVRF", "revision": revision, "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"},
            "dataset_provenance": fetch_metadata,
            "inference": overlay.get("inference") or {"model": "none", "taxonomy_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat()},
        }
        if overlay.get("threat_enrichment"):
            record["threat"].update(overlay["threat_enrichment"])
        records.append(record)
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cvrf", required=True, type=Path)
    parser.add_argument("--month", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inference-jsonl", type=Path)
    parser.add_argument("--kev", type=Path)
    parser.add_argument("--epss", type=Path)
    parser.add_argument("--fetch-metadata", type=Path)
    args = parser.parse_args()
    document = json.loads(args.cvrf.read_text(encoding="utf-8-sig"))
    records = build_records(
        document,
        args.month,
        load_inference(args.inference_jsonl),
        load_kev(args.kev),
        load_epss(args.epss),
        load_fetch_metadata(args.fetch_metadata),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n", encoding="utf-8")
    print(f"Wrote {len(records)} records to {args.output}")


if __name__ == "__main__":
    main()
