"""Source-bound compatibility for public advisory syntax, without global waivers.

Only an explicitly hash-approved proof, an exact record field value, a matching
guard finding and the unchanged cached public source can establish an exception.
Nothing is redacted. All other findings still use the production privacy guard.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re

import customer_data_guard as base

ROOT = Path(__file__).resolve().parents[1]
SOURCE_MARKER = "\n\n=== COMPLETE PUBLIC ADVISORY DATA (untrusted source evidence) ===\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render_prompt(prefix: str, records: list[dict]) -> str:
    return prefix + SOURCE_MARKER + "\n".join(json.dumps(record, ensure_ascii=False) for record in records)


def _field(record: dict, path: str):
    value = record
    for match in re.finditer(r"(?:^|\.)([^.\[\]]+)|\[(\d+)\]", path):
        value = value[int(match[2])] if match[2] is not None else value[match[1]]
    return value


def _pointer(value, pointer: str):
    for token in pointer.lstrip("/").split("/") if pointer else []:
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def _public_syntax(value: str, finding, pointer: str) -> bool:
    if finding.category == "ipv4_address":
        # Both normalized field and the cached source must be exactly bound.
        # The source pointer supplies version semantics, not a dotted-quad guess.
        if re.search(r"/(?:version|lessThan|lessThanOrEqual|versionStartIncluding|versionStartExcluding|versionEndIncluding|versionEndExcluding)$", pointer):
            return True
        if re.fullmatch(r"/Vulnerability/[0-9]+/Remediations/[0-9]+/FixedBuild", pointer):
            return True
        try:
            address = ipaddress.IPv4Address(finding.span)
        except ValueError:
            return False
        before = value[max(0, finding.start - 60):finding.start]
        return address.is_global and bool(re.search(r"(?i)\b(?:versions?\s+(?:from|before|through)|reproduced\s+on)\s+$", before))
    # URLs are not globally allowlisted. Each literal URI in this exact public
    # field must independently be in a pinned source. The malformed tps scheme
    # is accepted only as published reference syntax, never as an arbitrary host.
    for match in re.finditer(r"(?:https?|tps)://[^\s<>\"']+", value):
        if not (match.start() <= finding.start < finding.end <= match.end()):
            continue
        if finding.category == "hostname":
            authority = match.group().split("://", 1)[1].split("/", 1)[0]
            if finding.span.lower().rstrip(".") in {authority.lower().rstrip("."), authority.lower().split(":", 1)[0].rstrip(".")}:
                return True
        if finding.category == "guid" and pointer.endswith("/URL"):
            return True
        if finding.category == "email_address" and match.group().startswith("https://lore.kernel.org/"):
            # A source-proven mailing-list Message-ID in a reference URL, not a
            # permission to transmit mail.gmail.com addresses elsewhere.
            return finding.span in match.group().split("https://lore.kernel.org/", 1)[1]
    return False


class PublicSourceGuard:
    def __init__(self, proof_path: Path, expected_sha256: str):
        self.proof_path = proof_path.resolve()
        raw = self.proof_path.read_bytes()
        if digest(raw) != expected_sha256:
            raise ValueError("public-source proof does not match explicitly approved hash")
        self.proof_sha256 = expected_sha256
        proof = json.loads(raw)
        findings_path = self.proof_path.parent / proof["finding_source"]
        if findings_path.resolve().parent != self.proof_path.parent or digest(findings_path.read_bytes()) != proof["finding_source_sha256"]:
            raise ValueError("public-source finding inventory hash or location differs")
        findings = json.loads(findings_path.read_text(encoding="utf-8"))["findings"]
        self.entries = {}
        self.sources = {}
        self.waived = 0
        self.raw_root = self.proof_path.parent / "raw"
        for entry in proof["proof"]:
            original = findings[entry["finding_index"]]
            if entry.get("source_match") is not True or any(entry[key] != original[key] for key in ("cve", "field", "category")):
                raise ValueError("public-source proof/finding identity differs")
            key = (entry["cve"], entry["field"], entry["category"], original["span"], original["start"], original["end"])
            self.entries[key] = entry

    def assert_record(self, record: dict) -> None:
        unresolved = []
        for finding in base.scan_value(record):
            key = (record.get("cve"), finding.field, finding.category, finding.span, finding.start, finding.end)
            entry = self.entries.get(key)
            if entry is None:
                unresolved.append(finding)
                continue
            path = (ROOT / entry["source_path"]).resolve()
            if self.raw_root.resolve() not in path.parents:
                raise ValueError("public source is outside the approved raw cache")
            signature = (path.stat().st_size, path.stat().st_mtime_ns)
            if path not in self.sources or self.sources[path][2] != signature:
                raw = path.read_bytes()
                if digest(raw) != entry["source_sha256"]:
                    raise ValueError("cached public source hash changed")
                self.sources[path] = (entry["source_sha256"], json.loads(raw), signature)
            if self.sources[path][0] != entry["source_sha256"]:
                raise ValueError("conflicting cached public source hash")
            value = _field(record, finding.field)
            source_value = _pointer(self.sources[path][1], entry["source_pointer"])
            if (not isinstance(value, str) or value != source_value
                    or digest(source_value.encode("utf-8")) != entry["source_value_sha256"]
                    or not _public_syntax(value, finding, entry["source_pointer"])):
                unresolved.append(finding)
            else:
                self.waived += 1
        if unresolved:
            raise base.CustomerDataError(record.get("cve", "unknown"), "source-bound public packet", unresolved)

    def assert_prompt(self, prompt: str, prefix: str, records: list[dict]) -> str:
        base.assert_clean("monthly scaffold", prefix, "complete public-source prompt prefix")
        for record in records:
            self.assert_record(record)
        if prompt != render_prompt(prefix, records):
            raise ValueError("final prompt is not the exact separately guarded scaffold plus public packet")
        return digest(prompt.encode("utf-8"))
