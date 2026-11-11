"""Prepare public source snapshots and exact-field privacy proofs for a monthly run.

Fetching and normalization stay in the existing production scripts. This module
adds the unabridged assessment facts those scripts intentionally omit from the UI.
"""
from __future__ import annotations

import copy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import customer_data_guard as privacy
from public_source_guard import PublicSourceGuard, _field, _public_syntax

ROOT = Path(__file__).resolve().parents[1]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_rows(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows or len({row["cve"] for row in rows}) != len(rows):
        raise ValueError(f"Empty or duplicate CVE input: {path}")
    return rows


def write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\n".join(canonical(row) for row in rows) + b"\n")


def strings(value, pointer=""):
    if isinstance(value, str):
        yield value, pointer
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, f"{pointer}/{index}")
    elif isinstance(value, dict):
        for key, item in value.items():
            token = key.replace("~", "~0").replace("/", "~1")
            yield from strings(item, f"{pointer}/{token}")


def assessment_facts(raw: dict, family: str) -> dict:
    # Contact/credit metadata has no bearing on exploitability. Whitelisting at
    # the container boundary keeps all affected ranges, metrics and ADP evidence.
    if family == "msrc":
        return {key: copy.deepcopy(value) for key, value in raw.items() if key in {
            "CVE", "Title", "Notes", "Threats", "CVSSScoreSets", "ProductStatuses",
            "Remediations", "RevisionHistory", "DiscoveryDate", "ReleaseDate",
            "DiscoveryDateSpecified", "ReleaseDateSpecified", "CWE", "References", "Flags", "Involvements"}}
    fields = {"providerMetadata", "title", "descriptions", "affected", "problemTypes",
              "references", "metrics", "configurations", "workarounds", "solutions",
              "exploits", "timeline", "impacts", "tags", "dateAssigned", "datePublic",
              "rejectedReasons", "cpeApplicability"}
    containers = raw.get("containers", {})
    result = {"cveMetadata": {key: value for key, value in raw.get("cveMetadata", {}).items()
                            if key in {"cveId", "state", "datePublished", "dateUpdated"}},
            "containers": {name: [{key: val for key, val in item.items() if key in fields} for item in value]
                           if isinstance(value, list) else {key: val for key, val in value.items() if key in fields}
                           for name, value in containers.items() if name in {"cna", "adp"}}}
    for container in result["containers"].values():
        for item in container if isinstance(container, list) else [container]:
            if "providerMetadata" in item:
                item["providerMetadata"] = {key: value for key, value in item["providerMetadata"].items()
                                            if key in {"shortName", "dateUpdated"}}
    return result


def material_fingerprint(packet: dict) -> str:
    facts = copy.deepcopy(packet)
    for key in ("dataset_provenance", "inference", "mitigation_candidates"):
        facts.pop(key, None)
    # Raw hashes/dates of acquisition are provenance, not changed risk evidence.
    for key in ("sha256", "url"):
        facts.get("cve_program", {}).pop(key, None)
    facts.get("source", {}).pop("revision", None)
    return sha(canonical(facts))


def prepare(snapshot: Path, month: str, command) -> dict:
    """Use fresh raw caches each time; no stale CNA cache during revision checks."""
    raw = snapshot / "raw"
    command("fetch_sources.py", "--month", month, "--output-dir", raw)
    normalized = snapshot / "normalized.jsonl"
    command("enrich_cvrf.py", "--cvrf", raw / f"{month}.json", "--month", month,
            "--kev", raw / "known_exploited_vulnerabilities.json", "--epss", raw / "epss_scores-current.csv",
            "--fetch-metadata", raw / f"{month}-fetch-metadata.json", "--output", normalized)
    sidecar = snapshot / "cve-enrichment.jsonl"
    command("fetch_cve_enrichment.py", "--records", normalized, "--output", sidecar,
            "--cache-dir", raw / "cve", "--workers", 12)
    baseline = read_rows(normalized)
    enrichment = read_rows(sidecar)
    if {row["cve"] for row in enrichment} != {row["cve"] for row in baseline}:
        raise ValueError("CVE enrichment did not cover the exact MSRC set")
    failures = [row for row in enrichment if row.get("status") not in {"found", "not-published"}]
    if failures:
        raise ValueError(f"CVE enrichment fetch failed; retry without spending inference: {failures[:3]}")
    combined = snapshot / "combined.jsonl"
    lean = snapshot / "lean.jsonl"
    command("apply_cve_enrichment.py", "--published", normalized, "--enrichment", sidecar, "--output", combined)
    command("normalize_severity.py", "--published", combined, "--output", lean)
    rows = read_rows(lean)
    document = json.loads((raw / f"{month}.json").read_text(encoding="utf-8-sig"))
    vulnerability_key = "Vulnerability" if "Vulnerability" in document else "Vulnerabilities"
    vulnerabilities = document.get(vulnerability_key, [])
    if isinstance(vulnerabilities, dict):
        vulnerabilities = [vulnerabilities]
    by_cve = {item["CVE"]: (index, item) for index, item in enumerate(vulnerabilities)}
    if len(by_cve) != len(vulnerabilities) or set(by_cve) != {row["cve"] for row in rows}:
        raise ValueError("Raw MSRC CVEs and normalized CVEs differ")
    packets, sources = [], {}
    for record in rows:
        packet = copy.deepcopy(record)
        # The full original text follows below. Do not invent a privacy waiver
        # for a derived, HTML-stripped or concatenated copy of source text.
        for key in ("dataset_provenance", "notes", "vendor_guidance", "inference", "mitigation_candidates"):
            packet.pop(key, None)
        packet.get("cve_program", {}).pop("cna", None)
        index, vulnerability = by_cve[record["cve"]]
        packet["public_msrc_evidence"] = assessment_facts(vulnerability, "msrc")
        # Resolved shared product names must participate in revision detection.
        packet["public_msrc_evidence"]["resolved_products"] = record.get("products", [])
        pointer = f"/{vulnerability_key}/{index}" if isinstance(document[vulnerability_key], list) else f"/{vulnerability_key}"
        locations = [(raw / f"{month}.json", vulnerability, pointer)]
        cna = raw / "cve" / f"{record['cve']}.json"
        if cna.is_file():
            cna_doc = json.loads(cna.read_text(encoding="utf-8"))
            if cna_doc.get("cveMetadata", {}).get("cveId") != record["cve"]:
                raise ValueError("CNA record identity differs from requested CVE")
            packet["public_cve_evidence"] = assessment_facts(cna_doc, "cna")
            locations.append((cna, cna_doc, ""))
        packets.append(packet)
        sources[record["cve"]] = locations
    packet_path = snapshot / "assessment-input.jsonl"
    write_rows(packet_path, packets)
    proof = build_proof(snapshot, packets, sources)
    return {"snapshot": str(snapshot), "lean": str(lean), "packets": str(packet_path),
            "proof": str(proof), "proof_sha256": sha(proof.read_bytes()),
            "fingerprints": {row["cve"]: material_fingerprint(row) for row in packets}}


def build_proof(snapshot: Path, packets: list[dict], sources: dict) -> Path:
    findings, proof, hashes = [], [], {}
    for packet in packets:
        packet_findings = list(privacy.scan_value(packet))
        if not packet_findings:
            continue
        index = {}
        for location in sources[packet["cve"]]:
            path, document = location[:2]
            prefix = location[2] if len(location) == 3 else ""
            for value, pointer in strings(document, prefix):
                index.setdefault(value, []).append((path, pointer))
        for finding in packet_findings:
            inventory = asdict(finding) | {"cve": packet["cve"]}
            findings.append(inventory)
            value = _field(packet, finding.field)
            matches = [(path, pointer) for path, pointer in index.get(value, [])
                       if _public_syntax(value, finding, pointer)]
            if not matches:
                raise ValueError(f"Unproved public syntax: {packet['cve']} {finding.field} {finding.category}; inference stopped")
            path, pointer = matches[0]
            if path not in hashes:
                hashes[path] = sha(path.read_bytes())
            proof.append({"finding_index": len(findings)-1, "cve": packet["cve"], "field": finding.field,
                          "category": finding.category, "source_match": True,
                          "source_path": path.resolve().relative_to(ROOT).as_posix(),
                          "source_sha256": hashes[path], "source_pointer": pointer,
                          "source_value_sha256": sha(value.encode())})
    inventory_path = snapshot / "public-findings.json"
    inventory_path.write_bytes(canonical({"findings": findings}))
    proof_path = snapshot / "public-source-proof.json"
    proof_path.write_bytes(canonical({"finding_source": inventory_path.name,
                                      "finding_source_sha256": sha(inventory_path.read_bytes()), "proof": proof}))
    guard = PublicSourceGuard(proof_path, sha(proof_path.read_bytes()))
    for packet in packets:
        guard.assert_record(packet)
    return proof_path
