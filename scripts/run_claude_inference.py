#!/usr/bin/env python3
"""Run assessor inference through the Claude CLI. Provider-neutral by construction.

Structurally identical to scripts/run_luna_inference.py: a local CLI subprocess,
a captured response, locally computed hashes. Swapping providers means swapping the
command template, not rewriting the pipeline. No risk judgements are computed here -
this records what the model said and whether it conformed.

Two arms, so the scaffolding's contribution is attributable:

  scaffolded  full enrichment contract as the system prompt, JSON schema enforced
  minimal     bare instruction, no contract, no schema. The ablation baseline

Measure 1 (schema conformance) is recorded, never repaired. A response that comes
back unparseable or schema-invalid is a conformance failure; silently fixing it
would convert the exact capability under test into apparent success.

Environment note: the Claude CLI lives in the cloud container, not on the device
bridge, so this script runs there against staged records.

Trap, learned 2026-09-10: --exclude-dynamic-system-prompt-sections silently breaks
--json-schema (structured_output comes back null). Do not add it.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import merge_inference as validation  # noqa: E402

MINIMAL_SYSTEM_PROMPT = (
    "You assess public vulnerability advisories. Return your assessment."
)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def obj(properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def enum(values) -> dict:
    return {"type": "string", "enum": list(values)}


def build_schema(cves: list[str], tags: set[str], controls: set[str]) -> dict:
    """Identical shape to the Luna adapter's schema, so arms stay comparable."""
    string = {"type": "string"}
    factor_keys = sorted(validation.REQUIRED_FACTORS)
    effect = obj({
        "likelihood_steps": {"type": "integer", "enum": [0, 1, 2]},
        "consequence_steps": {"type": "integer", "enum": [0, 1, 2]},
        "path_block": {"type": "boolean"},
    })
    candidate = obj({
        "id": enum(sorted(controls)),
        "relevance": enum(["relevant", "not-relevant", "unknown"]),
        "confidence": enum(["high", "medium", "low"]),
        "effect": effect,
        "evidence": string,
    })
    communication = obj({
        "summary": string, "why_this_action": string,
        "control_limitations": string,
        "reassessment_triggers": {"type": "array", "items": string},
    })
    assessment = obj({
        "risk_model_version": enum([validation.RISK_MODEL_VERSION]),
        "baseline_model": enum(sorted(validation.BASELINE_MODELS)),
        "baseline_likelihood": enum(validation.LIKELIHOODS),
        "baseline_action": enum(validation.ACTIONS),
        "confidence": enum(["high", "medium", "low"]),
        "factors": obj({key: string for key in factor_keys}),
        "risk_communication": communication,
    })
    # Direction is asserted BEFORE controls are assessed, and is required, so the
    # model cannot credit an ingress control against an outbound attack path
    # without first committing to a direction the validator can check.
    attack_path = obj({
        "direction": enum(validation.ATTACK_DIRECTIONS),
        "evidence": string,
    })
    overlay = obj({
        "cve": enum(cves),
        "attack_path": attack_path,
        "tags": {"type": "array", "items": enum(sorted(tags))},
        "mitigation_candidates": {"type": "array", "items": candidate},
        "framework_assessment": assessment,
    })
    return obj({"assessments": {"type": "array", "items": overlay}})


def batches(records: list[dict], size: int):
    for index in range(0, len(records), size):
        yield index // size, records[index:index + size]


def invoke(command: list[str], prompt: str, timeout: int) -> tuple[int, str, str]:
    """The prompt goes on stdin, never argv.

    A 15-record packet is roughly 120KB, which overruns ARG_MAX and fails with
    OSError [Errno 7] "Argument list too long" before the CLI is even reached.
    The system prompt is written to a file for the same reason.
    """
    proc = subprocess.run(
        command, input=prompt, encoding="utf-8", errors="replace",
        capture_output=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", required=True, type=Path, help="JSONL of source records to assess")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--arm", choices=["scaffolded", "minimal"], required=True)
    parser.add_argument("--model", default="haiku")
    parser.add_argument("--cli", default="claude")
    parser.add_argument("--batch-size", type=int, default=15, help="Matches the Luna run, so batching is not confounded with harness changes")
    parser.add_argument("--contract", type=Path, default=Path("prompts/enrichment-system.md"))
    parser.add_argument("--guidance", type=Path, default=Path("prompts/assessor-evidence-guidance.md"))
    parser.add_argument("--taxonomy", type=Path, default=Path("data/tag-taxonomy.json"))
    parser.add_argument("--catalogue", type=Path, default=Path("data/mitigation-catalog.json"))
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    records = [json.loads(line) for line in args.records.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.limit:
        records = records[:args.limit]

    tags = validation.allowed_tags(args.taxonomy)
    controls = {item["id"] for item in json.loads(args.catalogue.read_text(encoding="utf-8"))}

    scaffolded = args.arm == "scaffolded"
    system_prompt = (
        args.contract.read_text(encoding="utf-8") + "\n\n" + args.guidance.read_text(encoding="utf-8")
        if scaffolded else MINIMAL_SYSTEM_PROMPT
    )

    args.run_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    results, conformance_failures = [], []

    for index, packet in batches(records, args.batch_size):
        cves = [record["cve"] for record in packet]
        schema = build_schema(cves, tags, controls)
        schema_path = args.run_dir / f"schema-{index:03d}.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")

        prompt = (
            "PUBLIC ADVISORY DATA:\n" + "\n".join(json.dumps(record) for record in packet)
            if scaffolded else
            "Assess each of these public vulnerability advisories:\n"
            + "\n".join(json.dumps(record) for record in packet)
        )
        (args.run_dir / f"prompt-{index:03d}.txt").write_text(prompt, encoding="utf-8")

        system_prompt_path = args.run_dir / "system-prompt.txt"
        if not system_prompt_path.exists():
            system_prompt_path.write_text(system_prompt, encoding="utf-8")
        command = [
            args.cli, "-p", "--model", args.model, "--output-format", "json",
            "--system-prompt-file", str(system_prompt_path),
        ]
        if scaffolded:
            # Schema enforcement is part of the scaffolding under test, so the
            # ablation arm deliberately runs without it.
            command += ["--json-schema", json.dumps(schema)]

        call_started = datetime.now(timezone.utc).isoformat()
        try:
            code, stdout, stderr = invoke(command, prompt, args.timeout)
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -1, "", f"timeout after {args.timeout}s"
        call_finished = datetime.now(timezone.utc).isoformat()

        (args.run_dir / f"response-{index:03d}.json").write_text(stdout, encoding="utf-8")
        if stderr:
            (args.run_dir / f"stderr-{index:03d}.txt").write_text(stderr, encoding="utf-8")

        record_entry = {
            "batch": index, "cves": cves, "arm": args.arm,
            "model_configured": args.model,
            "started_at": call_started, "finished_at": call_finished,
            "returncode": code,
            "prompt_sha256": sha256(prompt),
            "system_prompt_sha256": sha256(system_prompt),
            "response_sha256": sha256(stdout),
            "schema_enforced": scaffolded,
        }

        assessments, failure = None, None
        try:
            envelope = json.loads(stdout)
            usage = envelope.get("modelUsage") or {}
            if usage:
                served, detail = next(iter(usage.items()))
                # The CLI reports the model that actually served the call, so this
                # is assertable rather than guessed.
                record_entry["model_served"] = served
                record_entry["canonical_model"] = detail.get("canonicalModel")
                record_entry["provider"] = detail.get("provider")
                record_entry["cost_usd"] = detail.get("costUSD")
            record_entry["session_id"] = envelope.get("session_id")
            record_entry["is_error"] = envelope.get("is_error")

            payload = envelope.get("structured_output")
            if payload is None:
                raw = envelope.get("result") or ""
                stripped = raw.strip()
                if stripped.startswith("```"):
                    stripped = stripped.split("```")[1].removeprefix("json").strip()
                payload = json.loads(stripped)
                record_entry["recovered_from_text"] = True
            assessments = payload.get("assessments") if isinstance(payload, dict) else None
            if not isinstance(assessments, list):
                failure = "no assessments array in response"
        except Exception as error:  # noqa: BLE001 - any parse path failing is measure 1
            failure = f"{type(error).__name__}: {error}"

        if assessments is not None and failure is None:
            returned = {item.get("cve") for item in assessments if isinstance(item, dict)}
            if returned != set(cves):
                failure = f"CVE set mismatch: missing {sorted(set(cves) - returned)}, extra {sorted(returned - set(cves))}"

        record_entry["conformant"] = failure is None
        if failure:
            # Recorded, never repaired. Repairing it would hide the exact gap the
            # scaffolding is supposed to close.
            record_entry["conformance_failure"] = failure
            conformance_failures.append({"batch": index, "reason": failure})
        else:
            (args.run_dir / f"assessments-{index:03d}.json").write_text(
                json.dumps(assessments, indent=2), encoding="utf-8")

        results.append(record_entry)
        print(json.dumps({"batch": index, "conformant": record_entry["conformant"],
                          "failure": failure, "cves": len(cves)}), flush=True)

    conformant = sum(1 for item in results if item["conformant"])
    manifest = {
        "arm": args.arm,
        "model_configured": args.model,
        "records": len(records),
        "batch_size": args.batch_size,
        "batches": len(results),
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "source_records_sha256": sha256(args.records.read_text(encoding="utf-8")),
        "system_prompt_sha256": sha256(system_prompt),
        "schema_enforced": scaffolded,
        "measure_1_schema_conformance": {
            "conformant_batches": conformant,
            "total_batches": len(results),
            "rate": round(conformant / len(results), 4) if results else None,
            "failures": conformance_failures,
        },
        "calls": results,
    }
    (args.run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": manifest["measure_1_schema_conformance"]}, indent=2))


if __name__ == "__main__":
    main()
