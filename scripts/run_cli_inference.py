#!/usr/bin/env python3
"""Run assessor inference through the assessor CLI. Provider-neutral by construction.

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

Environment note: the assessor CLI lives in the cloud container, not on the device
bridge, so this script runs there against staged records.

Trap, learned 2026-09-10: --exclude-dynamic-system-prompt-sections silently breaks
--json-schema (structured_output comes back null). Do not add it.

Customer-data guard: this is the process boundary. CLAUDE.md says no customer
data in inference, and scripts/customer_data_guard.py enforces it here, in three
places - every record as it is loaded, every batch prompt, and the system prompt
- each time immediately before the text could leave. A violation stops the run;
it is never redacted, because a silent redaction would conceal that customer
data reached the pipeline at all, which is the fact the consultant needs.

Sandbox: every model invocation from this file is sandboxed - an empty MCP config
plus --strict-mcp-config, --allowedTools __none__ and a named denylist. On
2026-09-10 this adapter passed none of them, so assessor invocations ran as full
agents with the session's MCP servers attached and wrote eleven documents into
the user's live hosted project while being asked to assess advisories. The
definition is imported from scripts/score_tags.py rather than copied: a second
copy is how the two callers drifted apart in the first place, and the copy that
was supposed to land here never did.
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
import customer_data_guard as guard  # noqa: E402
import merge_inference as validation  # noqa: E402
# ONE definition of the CLI sandbox, imported by both callers - this adapter and
# scripts/score_tags.py, where it lives. Do not re-declare SANDBOX_ARGS here or
# anywhere else: the 2026-09-10 incident is precisely what happens when the
# sandbox is "in the codebase" but not in the command this file builds. If the
# denylist is widened, both callers must get it from the same edit.
from score_tags import SANDBOX_ARGS  # noqa: E402

MINIMAL_SYSTEM_PROMPT = (
    "You assess public vulnerability advisories. Return your assessment."
)

# --strict-mcp-config tells the CLI to use only the MCP configuration it is given
# instead of inheriting the session's. It therefore needs a configuration to be
# given: on its own it is a modifier with nothing to modify. score_tags.py writes
# an empty one beside the run and passes it with --mcp-config; this does the same,
# so the two invocations are detached from MCP in identical fashion.
EMPTY_MCP_CONFIG = '{"mcpServers":{}}'


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
    # The model echoes the CVSS basis; the collector must never fill it in. This is
    # the source-fidelity gate, and a gate the pipeline satisfies on the model's
    # behalf cannot fail. The enrichment contract has always required this field -
    # it was missing here, and additionalProperties:false meant a conformant model
    # could not emit it, which is why no run on this path ever reached merge_inference.
    cvss_basis = obj({
        "base_score": {"type": ["number", "null"]},
        "vector": {"type": ["string", "null"]},
        "attack_vector": {"type": ["string", "null"]},
        "privileges_required": {"type": ["string", "null"]},
        "user_interaction": {"type": ["string", "null"]},
    })
    overlay = obj({
        "cve": enum(cves),
        "cvss_basis": cvss_basis,
        "attack_path": attack_path,
        "tags": {"type": "array", "items": enum(sorted(tags))},
        "mitigation_candidates": {"type": "array", "items": candidate},
        "framework_assessment": assessment,
    })
    return obj({"assessments": {"type": "array", "items": overlay}})


def batches(records: list[dict], size: int):
    for index in range(0, len(records), size):
        yield index // size, records[index:index + size]


def write_sandbox_mcp_config(run_dir: Path) -> Path:
    """Write the empty MCP config this run's invocations are pinned to."""
    path = run_dir / "empty-mcp.json"
    path.write_text(EMPTY_MCP_CONFIG, encoding="utf-8")
    return path


def build_command(cli: str, model: str, system_prompt_path: Path,
                  mcp_config_path: Path, schema: dict | None) -> list[str]:
    """Build the CLI invocation. Every model call in this file goes through here.

    One builder, not a base command that each arm then amends, because the sandbox
    has to be unconditional and a conditional is where it would be lost.

    THE SANDBOX APPLIES TO BOTH ARMS. The `minimal` ablation deliberately drops the
    enrichment contract and the JSON schema, because those are the scaffolding whose
    contribution the ablation is measuring. The sandbox is not scaffolding - it is a
    safety control on what the model can reach while it runs, and it is no more part
    of the experiment than the customer-data guard is. Dropping it "for symmetry"
    would re-run the 2026-09-10 incident deliberately, on the arm nobody reads the
    output of. If a later reader is tempted to move `*SANDBOX_ARGS` into the
    schema-conditional below: that is the bug, not the asymmetry.
    """
    command = [
        cli, "-p", "--model", model, "--output-format", "json",
        "--system-prompt-file", str(system_prompt_path),
        "--mcp-config", str(mcp_config_path),
        *SANDBOX_ARGS,
    ]
    if schema is not None:
        command += ["--json-schema", json.dumps(schema)]
    return command


def invoke(command: list[str], prompt: str, timeout: int, guard_label: str) -> tuple[int, str, str]:
    """The prompt goes on stdin, never argv.

    A 15-record packet is roughly 120KB, which overruns ARG_MAX and fails with
    OSError [Errno 7] "Argument list too long" before the CLI is even reached.
    The system prompt is written to a file for the same reason.

    The last thing checked before subprocess.run is the exact string that will be
    written to the child's stdin. Guarding here rather than only at the caller
    means no future caller can construct a prompt that bypasses the gate.
    """
    guard.assert_clean(guard_label, prompt, "prompt about to be written to the model CLI's stdin")
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
    # Default is the name of the CLI executable on disk, not a provider credit;
    # override it to point at a different assessor binary.
    parser.add_argument("--cli", default="claude")
    parser.add_argument("--batch-size", type=int, default=15, help="Matches the Luna run, so batching is not confounded with harness changes")
    parser.add_argument("--contract", type=Path, default=Path("prompts/enrichment-system.md"))
    parser.add_argument("--guidance", type=Path, default=Path("prompts/assessor-evidence-guidance.md"))
    parser.add_argument("--taxonomy", type=Path, default=Path("data/tag-taxonomy.json"))
    parser.add_argument("--catalogue", type=Path, default=Path("data/mitigation-catalog.json"))
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--limit", type=int)
    guard.add_allow_domain_argument(parser)
    args = parser.parse_args()
    guard.allow_domains(args.guard_allow_domain)

    records = [json.loads(line) for line in args.records.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.limit:
        records = records[:args.limit]

    # Checked once, up front, so a violation is reported against the record that
    # carries it rather than against the batch that happens to contain it - and
    # so the run stops before the first call rather than partway through a month.
    for record in records:
        guard.assert_clean(record.get("cve", f"{args.records}:<record without a cve>"),
                           record, f"source record from {args.records}")

    tags = validation.allowed_tags(args.taxonomy)
    controls = {item["id"] for item in json.loads(args.catalogue.read_text(encoding="utf-8"))}

    scaffolded = args.arm == "scaffolded"
    system_prompt = (
        args.contract.read_text(encoding="utf-8") + "\n\n" + args.guidance.read_text(encoding="utf-8")
        if scaffolded else MINIMAL_SYSTEM_PROMPT
    )
    # The contract and guidance files are repo content, but they are assembled
    # into a prompt that leaves the process, so they are gated like any other.
    guard.assert_clean(f"{args.contract} + {args.guidance}", system_prompt,
                       "system prompt about to be handed to the model CLI")

    args.run_dir.mkdir(parents=True, exist_ok=True)
    mcp_config_path = write_sandbox_mcp_config(args.run_dir)
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
        guard.assert_clean(f"batch {index} ({cves[0]}..{cves[-1]})", prompt,
                           "assembled batch prompt")
        (args.run_dir / f"prompt-{index:03d}.txt").write_text(prompt, encoding="utf-8")

        system_prompt_path = args.run_dir / "system-prompt.txt"
        if not system_prompt_path.exists():
            system_prompt_path.write_text(system_prompt, encoding="utf-8")
        # Schema enforcement is part of the scaffolding under test, so the ablation
        # arm passes no schema. The sandbox is not - see build_command.
        command = build_command(args.cli, args.model, system_prompt_path,
                                mcp_config_path, schema if scaffolded else None)

        call_started = datetime.now(timezone.utc).isoformat()
        try:
            code, stdout, stderr = invoke(command, prompt, args.timeout,
                                          f"batch {index} ({cves[0]}..{cves[-1]})")
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
            # Recorded per call, not only per run, so an audit of a single batch can
            # tell whether that batch was sandboxed without trusting the summary.
            "sandboxed": True,
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
        # Path as well as hash, so a collector spanning several shards can verify
        # each shard against what it actually ran on without being told.
        "source_records": str(args.records),
        "source_records_sha256": sha256(args.records.read_text(encoding="utf-8")),
        "system_prompt_sha256": sha256(system_prompt),
        "schema_enforced": scaffolded,
        # The exact restrictions this run applied, both arms, written down so the
        # claim is checkable after the fact rather than taken from the runbook.
        "sandbox": {
            "args": list(SANDBOX_ARGS),
            "mcp_config": str(mcp_config_path),
            "mcp_config_content": EMPTY_MCP_CONFIG,
            "applies_to_both_arms": True,
        },
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
