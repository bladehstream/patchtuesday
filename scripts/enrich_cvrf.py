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


# Release and platform tags are derived from the STRUCTURED product list, not by
# pattern matching advisory prose. The old TAG_RULES regexes matched phrases in the
# title, which is both unreliable and a layer violation: a regex over prose has no
# business feeding a risk archetype. Measured on 2026-Sep, the regexes contributed
# 164 release-tag additions the model had omitted - and in all 35 sampled cases the
# products[] array already listed the product outright. Deriving from products[] is
# strictly more accurate than either the regex or the model.
#
# Judgement tags - impact, delivery, workload - are NOT derived here. They come from
# the inference overlay with cited evidence. See docs and CLAUDE.md.
PRODUCT_TAG_RULES: tuple[tuple[str, str], ...] = (
    # Server 2012 and 2012 R2 are distinct SKUs but one patching decision for an
    # administrator, so they share a tag. 419 records listed a 2012 product while
    # no rule existed for it, making the third-largest server population in the
    # September dataset unreachable by any filter.
    ("server-2012", "windows server 2012"),
    ("server-2016", "windows server 2016"),
    ("server-2019", "windows server 2019"),
    ("server-2022", "windows server 2022"),
    ("server-2025", "windows server 2025"),
    ("windows-10", "windows 10"),
    ("windows-11", "windows 11"),
    ("sharepoint", "sharepoint"),
    ("office", "microsoft 365 apps"),
    ("office", "microsoft office"),
    ("azure", "azure"),
    ("sql-server", "sql server"),
    ("skype-for-business", "skype for business"),
    ("copilot-studio", "copilot studio"),
    # Added 2026-09-11 after measuring filter reachability: 64 of 1185 published
    # records (5.4%) could be reached by no product filter except "microsoft",
    # making them invisible to an administrator asking "does this affect anything
    # I run". Microsoft Edge alone accounted for 23 of them.
    ("edge", "microsoft edge"),
    ("exchange", "exchange server"),
    ("teams", "microsoft teams"),
    ("vscode", "visual studio code"),
    ("visual-studio", "microsoft visual studio"),
    ("dotnet", ".net"),
    ("dynamics-365", "dynamics 365"),
    ("power-platform", "power platform"),
    ("power-platform", "power automate"),
    ("entra-id", "entra id"),
    ("fabric", "microsoft fabric"),
)

ENDPOINT_RELEASES = {"windows-10", "windows-11"}
SERVER_RELEASES = {"server-2012", "server-2016", "server-2019", "server-2022", "server-2025"}


# MSRC titles follow one shape: "<Component> <Impact class> Vulnerability". The
# component half names the workload role; the product tree does not - it lists the
# OS SKUs the component ships on ("Windows Server 2022"), so a Remote Desktop
# Services RCE and a GDI RCE have identical product trees. Measured on 2026-Sep:
# 964 of 1185 titles parse into this shape, and the component half resolves to a
# bounded vocabulary of 263 strings.
#
# This is a lookup on a delimited vendor field, not pattern matching on advisory
# prose. It answers "which component is this" - a fact Microsoft states - and never
# "how risky is this", which stays with the assessor. Leaving it to the assessor
# cost 20 of 27 Remote Desktop records and 11 of 26 identity records their filter
# tag on 2026-Sep: an administrator who ticked Remote Desktop saw 7 of 27.
IMPACT_CLASSES: tuple[str, ...] = (
    "remote code execution",
    "elevation of privilege",
    "information disclosure",
    "denial of service",
    "security feature bypass",
    "spoofing",
    "tampering",
    "cross-site scripting",
    "memory corruption",
)
TITLE_SHAPE = re.compile(
    r"\s+(?:" + "|".join(re.escape(item) for item in IMPACT_CLASSES) + r")\s+vulnerabilit(?:y|ies)\s*$",
    re.IGNORECASE,
)

# (tag, required phrases, excluded phrases). A component earns the tag when any
# required phrase appears as whole words and no excluded phrase does. Exclusions
# are not hypothetical: "Windows Internet Key Exchange (IKE) Extension" contains
# "Exchange" and is not Exchange Server.
WORKLOAD_COMPONENT_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("identity", ("active directory", "kerberos", "netlogon", "key distribution center",
                  "local security authority", "ad fs", "ad cs"), ()),
    ("remote-desktop", ("remote desktop", "terminal services"), ()),
    ("dns", ("dns",), ()),
    ("dhcp", ("dhcp",), ()),
    ("hyper-v", ("hyper-v",), ()),
    ("exchange", ("exchange",), ("key exchange",)),
    ("web-server", ("internet information services", "iis"), ()),
)


def title_component(title: str) -> str | None:
    """Return the component half of an MSRC title, or None if it is not that shape.

    A title that does not parse yields no deterministic tag at all. Guessing at a
    component from a title of unknown shape is the prose matching this function
    exists to avoid.
    """
    text = (title or "").strip()
    match = TITLE_SHAPE.search(text)
    if not match or match.start() == 0:
        return None
    return text[: match.start()].strip() or None


def _mentions(haystack: str, phrase: str) -> bool:
    return re.search(r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])", haystack) is not None


def derive_workload_tags(title: str) -> list[str]:
    """Derive workload-role tags from the component named in an MSRC title."""
    component = title_component(title)
    if component is None:
        return []
    lowered = component.lower()
    tags = set()
    for tag, required, excluded in WORKLOAD_COMPONENT_RULES:
        if any(_mentions(lowered, phrase) for phrase in excluded):
            continue
        if any(_mentions(lowered, phrase) for phrase in required):
            tags.add(tag)
    return sorted(tags)


def derive_product_tags(products: list[dict[str, Any]], title: str = "") -> list[str]:
    """Derive platform, release and deployment tags from the structured product list.

    This is parsing, not judgement: every tag here is a lookup against strings
    Microsoft published - product names in the CVRF product tree, and the component
    half of the advisory title. Nothing here reaches a risk decision; the risk path
    reads only model-asserted tags.
    """
    names = " | ".join(str(product.get("name") or "") for product in products).lower()
    tags = {"microsoft"}
    for tag, needle in PRODUCT_TAG_RULES:
        if needle in names:
            tags.add(tag)
    # "Visual Studio Code" contains "visual studio". Only claim the IDE tag when a
    # product mentions Visual Studio outside the VS Code product name.
    if "visual-studio" in tags and "vscode" in tags:
        if "microsoft visual studio" not in names.replace("visual studio code", ""):
            tags.discard("visual-studio")
    tags.update(derive_workload_tags(title))
    if "windows" in names:
        tags.add("windows")
    if tags & SERVER_RELEASES or "windows server" in names:
        tags.add("server")
    if tags & ENDPOINT_RELEASES or "microsoft 365 apps" in names or "microsoft office" in names:
        tags.add("endpoint")
    return sorted(tags)


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


SEVERITY_WORDS = ("critical", "important", "high", "moderate", "medium", "low")


def resolve_severity(value: str, base_score: float | None) -> tuple[str, str]:
    """Resolve a severity band and record what it was based on.

    Returns (severity, basis) where basis is one of "vendor", "cvss" or "absent".

    Absence of evidence is not evidence of absence. When the vendor publishes
    neither a severity string nor a CVSS base score - which is the norm for
    Chromium passthrough advisories, where Microsoft defers to Google - the
    answer is "Unknown". It must never silently become "Low"; doing so
    presented browser use-after-free bugs to administrators as negligible.
    """
    lowered = (value or "").lower()
    has_vendor_text = any(word in lowered for word in SEVERITY_WORDS)
    has_score = base_score is not None

    if not has_vendor_text and not has_score:
        return "Unknown", "absent"

    basis = "vendor" if has_vendor_text else "cvss"

    if "critical" in lowered or (has_score and base_score >= 9):
        return "Critical", basis
    if "important" in lowered or "high" in lowered or (has_score and base_score >= 7):
        return "Important", basis
    if "moderate" in lowered or "medium" in lowered or (has_score and base_score >= 4):
        return "Moderate", basis
    return "Low", basis


def normalize_severity(value: str, base_score: float | None) -> str:
    """Backwards-compatible wrapper. Prefer resolve_severity for new callers."""
    return resolve_severity(value, base_score)[0]


def exploitation_assessment(value: str) -> str:
    lowered = value.lower()
    if "exploitation detected" in lowered or "exploited:yes" in lowered:
        return "detected"
    if "exploitation more likely" in lowered:
        return "more-likely"
    if "exploitation less likely" in lowered:
        return "less-likely"
    if "exploitation unlikely" in lowered:
        return "unlikely"
    return "unknown"


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
        raw_score = cvss.get("BaseScore")
        # Preserve a missing score as None. Coercing it to 0 made every
        # unscored advisory look benign to every downstream consumer.
        score = float(raw_score) if raw_score not in (None, "") else None
        temporal_score = cvss.get("TemporalScore")
        vector = str(cvss.get("Vector") or "")
        severity_text = threat_description(vuln, "3") or threat_description(vuln, "Severity")
        severity, severity_basis = resolve_severity(severity_text, score)
        exploit_text = " ".join(text_value(v) for v in as_list(vuln.get("Notes"))) + " " + threat_description(vuln, "1")
        combined = " ".join([title, *[item["name"] for item in products], exploit_text])
        overlay = inference.get(cve, {})
        # Judgement tags come from the model overlay alone. Product tags are derived
        # separately from structured data and never merged into the risk path.
        tags = sorted(set(as_list(overlay.get("tags"))))
        product_tags = derive_product_tags(products, title)
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
            "severity": severity,
            "severity_basis": severity_basis,
            "customer_action_required": customer_action_required,
            "cvss": {
                "base_score": score,
                "temporal_score": float(temporal_score) if temporal_score is not None else None,
                "vector": vector or None,
                "version": "4.0" if vector.startswith("CVSS:4.0") else "3.1" if vector.startswith("CVSS:3.1") else "3.0" if vector.startswith("CVSS:3.0") else "unknown",
            },
            "products": products,
            "tags": tags,
            "product_tags": product_tags,
            "attack": vector_fields(vector),
            "threat": {
                "kev": cve in kev,
                "exploitation_detected": "exploitation detected" in exploit_text.lower(),
                "exploitation_assessment": exploitation_assessment(exploit_text),
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
