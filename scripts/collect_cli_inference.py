#!/usr/bin/env python3
"""Collect an assessor CLI inference run into a merge-ready overlay JSONL.

The CLI-path counterpart to scripts/collect_full_inference.py, which is
Luna-specific and must not be run for another provider. Same guarantees, different
provenance source:

  Luna    the overlay carried its own invocation hashes, written by the Codex step
  CLI     run_cli_inference.py writes raw model assessments with no provenance,
          so provenance is attached here from the run manifest and recomputed
          locally from the response files on disk

What this script does NOT do is fill in any field the model was asked to author.
`cvss_basis` in particular is echoed by the model and checked against the baseline
by merge_inference.validate_cvss_basis; supplying it here would make that gate
tautological. A non-conformant batch is reported and excluded, never repaired.

`--run-dir` is repeatable, because a full month is normally split across several
concurrent processes. Each shard is verified against the records it actually ran on,
and the output is only written when the shards together cover every baseline CVE
exactly once.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import merge_inference as validation  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def response_assessments(response_path: Path) -> list | None:
    """Re-derive the assessments from the captured CLI envelope.

    assessments-NNN.json is a convenience artefact. The envelope is the evidence,
    so the two are compared rather than the convenience artefact being trusted.
    """
    envelope = json.loads(response_path.read_text(encoding="utf-8"))
    payload = envelope.get("structured_output")
    if payload is None:
        raw = (envelope.get("result") or "").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1].removeprefix("json").strip()
        payload = json.loads(raw)
    return payload.get("assessments") if isinstance(payload, dict) else None


def verify_run_source(run_dir: Path, manifest: dict, fallback: Path) -> None:
    """Confirm the shard's input file is still byte-identical to what the run saw."""
    records_path = Path(manifest.get("source_records") or fallback)
    if not records_path.is_file():
        candidate = ROOT / records_path
        if not candidate.is_file():
            raise SystemExit(f"{run_dir}: source records {records_path} are gone; cannot verify the run against them")
        records_path = candidate
    if sha256_bytes(records_path.read_text(encoding="utf-8").encode("utf-8")) != manifest["source_records_sha256"]:
        raise SystemExit(
            f"{run_dir}: {records_path} does not match the records this run was launched against. "
            "Either the wrong month was passed, or the source changed mid-run; reconcile before collecting."
        )


def validate_overlay(overlay: dict, baseline: dict, tags_allowed: set, controls_allowed: set) -> None:
    cve = overlay["cve"]
    validation.validate_cvss_basis(overlay, baseline)
    validation.validate_framework_assessment(overlay, baseline)
    unknown = set(overlay.get("tags") or []) - tags_allowed
    if unknown:
        raise ValueError(f"{cve}: unknown tags {sorted(unknown)}")
    candidate_ids = [item["id"] for item in overlay.get("mitigation_candidates") or []]
    if len(set(candidate_ids)) != len(candidate_ids):
        raise ValueError(f"{cve}: duplicate mitigation candidates")
    for candidate in overlay.get("mitigation_candidates") or []:
        validation.validate_candidate(candidate, controls_allowed, cve)
    validation.validate_path_compatibility(overlay, baseline)


def provenance(manifest: dict, call: dict, label: str, response_hash: str) -> dict:
    return {
        "model_configured": manifest["model_configured"],
        # Asserted only where the CLI reported it. Never guessed: the serving model
        # can differ from the configured one.
        "model_served": call.get("model_served"),
        "provider": call.get("provider"),
        "arm": manifest["arm"],
        "taxonomy_version": "1.0",
        "generated_at": call["finished_at"],
        "invocation": {
            "batch": label,
            "prompt_sha256": call["prompt_sha256"],
            "system_prompt_sha256": call["system_prompt_sha256"],
            "response_sha256": response_hash,
            "schema_enforced": call["schema_enforced"],
        },
        "pipeline_validation": {
            "type": "automated-source-and-schema",
            "source_sha256": manifest["source_records_sha256"],
            "validated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def collect_batch(run_dir: Path, manifest: dict, call: dict, label: str,
                  baseline: dict, seen: set, tags_allowed: set, controls_allowed: set) -> list:
    response_path = run_dir / f"response-{call['batch']:03d}.json"
    assessments_path = run_dir / f"assessments-{call['batch']:03d}.json"
    if not response_path.is_file():
        raise ValueError("captured model response is missing")
    if not assessments_path.is_file():
        raise ValueError("assessments artefact is missing")

    response_hash = sha256_bytes(response_path.read_bytes())
    if response_hash != call["response_sha256"]:
        raise ValueError("response file does not match the hash recorded at call time")

    authored = response_assessments(response_path)
    if not isinstance(authored, list):
        raise ValueError("no assessments array in the captured response")
    if json.loads(assessments_path.read_text(encoding="utf-8")) != authored:
        raise ValueError("assessments artefact differs from the captured model response")

    expected = set(call["cves"])
    returned = [item.get("cve") for item in authored]
    if len(returned) != len(expected) or set(returned) != expected:
        raise ValueError(f"CVE set does not match the batch input: {sorted(expected.symmetric_difference(set(returned)))}")

    for overlay in authored:
        cve = overlay["cve"]
        if cve not in baseline:
            raise ValueError(f"{cve}: absent from baseline")
        if cve in seen:
            raise ValueError(f"{cve}: duplicate across batches")
        validate_overlay(overlay, baseline[cve], tags_allowed, controls_allowed)

    # Nothing is admitted until every record in the batch has passed, so a batch
    # cannot be half-collected.
    for overlay in authored:
        seen.add(overlay["cve"])
        overlay["inference"] = provenance(manifest, call, label, response_hash)
    return authored


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", required=True, type=Path, action="append",
                        help="Repeatable: one per shard when the month was split across processes")
    parser.add_argument("--baseline", required=True, type=Path,
                        help="The enriched month the run was launched against")
    parser.add_argument("--output", type=Path, help="Overlay JSONL for merge_inference --inference")
    parser.add_argument("--taxonomy", type=Path, default=ROOT / "data" / "tag-taxonomy.json")
    parser.add_argument("--mitigations", type=Path, default=ROOT / "data" / "mitigation-catalog.json")
    args = parser.parse_args()

    baseline = {record["cve"]: record for record in validation.read_jsonl(args.baseline)}
    tags_allowed = validation.allowed_tags(args.taxonomy)
    controls_allowed = validation.allowed_mitigations(args.mitigations)

    collected: list = []
    seen: set = set()
    errors: list = []
    skipped: list = []

    for run_dir in args.run_dir:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        verify_run_source(run_dir, manifest, args.baseline)
        for call in manifest["calls"]:
            label = f"{run_dir.name}/batch-{call['batch']:03d}"
            if not call.get("conformant"):
                # Recorded as a gap, never repaired. Measure 1 lives in the run manifest.
                skipped.append({"batch": label, "reason": call.get("conformance_failure", "non-conformant")})
                continue
            try:
                collected.extend(collect_batch(run_dir, manifest, call, label, baseline,
                                               seen, tags_allowed, controls_allowed))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                errors.append({"batch": label, "error": str(error)})

    missing = sorted(set(baseline) - seen)
    report = {
        "expected": len(baseline),
        "validated": len(collected),
        "missing_cves": len(missing),
        "skipped_batches": skipped,
        "errors": errors,
    }
    print(json.dumps(report, indent=2))

    if args.output:
        if errors or skipped or missing:
            raise SystemExit("Refusing to write an incomplete inference release")
        collected.sort(key=lambda item: item["cve"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            "\n".join(json.dumps(item, separators=(",", ":")) for item in collected) + "\n",
            encoding="utf-8",
        )
        print(f"Collected {len(collected)} model-authored assessments into {args.output}")


if __name__ == "__main__":
    main()
