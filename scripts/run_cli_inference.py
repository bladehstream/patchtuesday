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
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import customer_data_guard as guard  # noqa: E402
import merge_inference as validation  # noqa: E402
import claude_stream as transport  # noqa: E402
from public_source_guard import PublicSourceGuard, render_prompt  # noqa: E402
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
ROOT = Path(__file__).resolve().parents[1]
ADAPTER_VERSION = "monthly-2026.11.1"
GUIDANCE_VERSION = "monthly-2026.11.2"


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
        "tag_evidence": {"type": "array", "items": obj({"tag": enum(sorted(tags)), "evidence": string})},
        "review_requirement": obj({"required": {"type": "boolean"}, "reasons": {"type": "array", "items": string}}),
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
        "mitigation_candidates": {"type": "array", "items": candidate,
                                  "minItems": len(controls), "maxItems": len(controls)},
        "framework_assessment": assessment,
    })
    return obj({"assessments": {"type": "array", "items": overlay,
                                "minItems": len(cves), "maxItems": len(cves)}})


def batches(records: list[dict], size: int):
    for index in range(0, len(records), size):
        yield index // size, records[index:index + size]


def write_sandbox_mcp_config(run_dir: Path) -> Path:
    """Write the empty MCP config this run's invocations are pinned to."""
    path = run_dir / "empty-mcp.json"
    path.write_text(EMPTY_MCP_CONFIG, encoding="utf-8", newline="\n")
    return path


def build_command(cli: str, model: str, system_prompt_path: Path,
                  mcp_config_path: Path, schema: dict | None, *, effort: str = "medium",
                  session_id: str | None = None) -> list[str]:
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
        cli, "-p", "--model", model, "--effort", effort,
        "--session-id", session_id or str(uuid.uuid4()),
        "--output-format", "stream-json", "--verbose", "--include-partial-messages",
        "--no-chrome", "--permission-mode", "dontAsk", "--permission-prompts", "none",
        "--restricted", "--safe-mode", "--disable-slash-commands", "--tools", "",
        "--mcp-config", str(mcp_config_path),
        *SANDBOX_ARGS,
    ]
    if schema is not None:
        command += ["--json-schema", json.dumps(schema)]
    return command


def invoke(command: list[str], prompt: str, timeout: int, guard_label: str, *,
           raw_path: Path, stderr_path: Path, source_bound_prompt_sha256: str | None = None) -> tuple[int, bytes, str, str | None]:
    """The prompt goes on stdin, never argv.

    A 15-record packet is roughly 120KB, which overruns ARG_MAX and fails with
    OSError [Errno 7] "Argument list too long" before the CLI is even reached.
    The system prompt is written to a file for the same reason.

    The last thing checked before subprocess.run is the exact string that will be
    written to the child's stdin. Guarding here rather than only at the caller
    means no future caller can construct a prompt that bypasses the gate.
    """
    if source_bound_prompt_sha256 is None:
        guard.assert_clean(guard_label, prompt, "prompt about to be written to the model CLI's stdin")
    elif sha256(prompt) != source_bound_prompt_sha256:
        raise ValueError("source-bound prompt changed immediately before provider stdin")
    # The raw NDJSON file advances during inference, rather than retaining a
    # multi-minute response solely in a completion-only Python buffer. The fresh
    # cwd plus safe-mode prevents inherited project/plugin instructions; the
    # entire applicable scaffold is already embedded on stdin.
    cwd = Path(tempfile.mkdtemp(prefix="vap-monthly-"))
    cleanup_error = None
    try:
        with raw_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            try:
                proc = subprocess.run(command, input=prompt, encoding="utf-8", stdout=stdout,
                                      stderr=stderr, cwd=cwd, timeout=timeout)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                code = -1
    finally:
        try:
            # Remove only this empty owned directory. AppContainer can deny
            # even that operation; a cleanup error must not lose raw results.
            cwd.rmdir()
        except OSError as error:
            cleanup_error = f"{type(error).__name__}: {error}"
    return code, raw_path.read_bytes(), stderr_path.read_text(encoding="utf-8", errors="replace"), cleanup_error


def skeleton() -> dict:
    """Production vocabulary, not the incompatible historical-study schema."""
    return {"assessments": [{"cve": "<assigned-cve>", "cvss_basis": {
        "base_score": None, "vector": None, "attack_vector": None,
        "privileges_required": None, "user_interaction": None},
        "attack_path": {"direction": "unknown", "evidence": "<source and entry/processing distinction>"},
        "tags": ["<judgment-tag>"], "mitigation_candidates": [{"id": "<catalogue-id>",
        "relevance": "unknown", "confidence": "low", "effect": {"likelihood_steps": 0,
        "consequence_steps": 0, "path_block": False}, "evidence": "<mechanism, source, condition and residual>"}],
        "framework_assessment": {"risk_model_version": validation.RISK_MODEL_VERSION,
        "baseline_model": "<production-archetype>", "baseline_likelihood": "<production-band>",
        "baseline_action": "<production-action>", "confidence": "<confidence>",
        "factors": {key: "<source-grounded factor>" for key in sorted(validation.REQUIRED_FACTORS)},
        "risk_communication": {"summary": "<summary>", "why_this_action": "<reason>",
        "control_limitations": "<limits>", "reassessment_triggers": ["<trigger>"]},
        "tag_evidence": [{"tag": "<judgment-tag>", "evidence": "<source fragment>"}],
        "review_requirement": {"required": True, "reasons": ["<material source gap>"]}}}]}


def scaffold(method: Path, taxonomy: Path, catalogue: Path, models: Path) -> tuple[str, dict]:
    parts = {"method": method.read_text(encoding="utf-8"),
             "models": models.read_text(encoding="utf-8"),
             "taxonomy": taxonomy.read_text(encoding="utf-8"),
             "catalogue": catalogue.read_text(encoding="utf-8")}
    text = "\n\n".join("=== " + name.upper() + " ===\n" + value for name, value in parts.items())
    text += "\n\n=== PRODUCTION RESPONSE SKELETON ===\n" + json.dumps(skeleton(), ensure_ascii=False)
    return text, {name: sha256(value) for name, value in parts.items()}


def validate_monthly_overlay(overlay: dict, baseline: dict, tags: set, controls: set) -> None:
    validation.validate_cvss_basis(overlay, baseline)
    validation.validate_framework_assessment(overlay, baseline)
    emitted = overlay.get("tags") or []
    if len(emitted) != len(set(emitted)) or not set(emitted).issubset(tags):
        raise ValueError(f"{baseline['cve']}: duplicate or unknown tags")
    candidates = overlay.get("mitigation_candidates") or []
    ids = [item.get("id") for item in candidates]
    if len(ids) != len(controls) or set(ids) != controls:
        raise ValueError(f"{baseline['cve']}: assess every catalogue control exactly once")
    for candidate in candidates:
        validation.validate_candidate(candidate, controls, baseline["cve"])
    validation.validate_path_compatibility(overlay, baseline)
    framework = overlay["framework_assessment"]
    evidence = framework["tag_evidence"]
    evidence_tags = [item["tag"] for item in evidence]
    if set(evidence_tags) != set(emitted) or len(evidence_tags) != len(emitted) or any(not item["evidence"].strip() for item in evidence):
        raise ValueError(f"{baseline['cve']}: each judgment tag requires its own source evidence")
    review = framework["review_requirement"]
    if review["required"] != bool(review["reasons"]):
        raise ValueError(f"{baseline['cve']}: structured review flag/reasons differ")
    direction = (overlay.get("attack_path") or {}).get("direction")
    if direction not in validation.ATTACK_DIRECTIONS:
        raise ValueError(f"{baseline['cve']}: invalid attack direction")
    if direction == "unknown":
        if not review["required"]:
            raise ValueError(f"{baseline['cve']}: unknown direction requires an explicit review flag")
        if any(any((c.get("effect") or {}).get(key) for key in ("likelihood_steps", "consequence_steps", "path_block")) for c in candidates):
            raise ValueError(f"{baseline['cve']}: unknown direction permits no mitigation credit")


def terminal_envelope(raw: bytes) -> dict:
    """The unchanged result object; malformed streams are rejected separately."""
    results = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict) and value.get("type") == "result":
            results.append(value)
    return results[-1] if len(results) == 1 else {}


def analyze_transport(raw: bytes, code: int, schema_requested: bool, model: str) -> dict:
    expected = model if model.startswith("claude-") else None
    analysis = transport.analyze_stream(raw, code, code == -1, schema_requested, expected_model=expected)
    served = analysis["receipt"]["model_served"]
    if model in {"haiku", "sonnet", "opus"} and (not served or not served.startswith(f"claude-{model}-")):
        analysis["errors"].append(f"served canonical identity {served!r} does not match configured {model}")
    return analysis


def checkpoint(args, records, system_prompt, scaffold_hashes, public_guard, mcp_config_path,
               started, results, failures, *, final=False) -> dict:
    conformant = sum(1 for item in results if item["conformant"])
    manifest = {
        "arm": args.arm, "adapter_version": ADAPTER_VERSION, "guidance_version": GUIDANCE_VERSION,
        "effort_configured": args.effort,
        "scaffold_hashes": scaffold_hashes,
        "public_source_guard": {"proof": str(args.public_source_proof.resolve()), "proof_sha256": public_guard.proof_sha256,
                                "scoped_match_checks": public_guard.waived, "redaction": False} if public_guard else None,
        "model_configured": args.model, "records": len(records), "batch_size": args.batch_size,
        "batches": len(results), "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat() if final else None,
        "checkpointed_at": datetime.now(timezone.utc).isoformat(),
        "source_records": str(args.records.resolve()),
        "source_records_sha256": hashlib.sha256(args.records.read_bytes()).hexdigest(),
        "system_prompt_sha256": sha256(system_prompt), "schema_enforced": args.arm == "scaffolded",
        "sandbox": {"args": list(SANDBOX_ARGS), "mcp_config": str(mcp_config_path.resolve()),
                    "mcp_config_content": EMPTY_MCP_CONFIG, "applies_to_both_arms": True,
                    "isolated_cwd": True, "tools": [], "safe_mode": True},
        "measure_1_schema_conformance": {"conformant_batches": conformant, "total_batches": len(results),
            "rate": round(conformant / len(results), 4) if results else None, "failures": failures},
        "calls": results,
    }
    (args.run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", required=True, type=Path, help="JSONL of source records to assess")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--arm", choices=["scaffolded", "minimal"], required=True)
    parser.add_argument("--model", default="claude-haiku-5-5")
    parser.add_argument("--effort", choices=["low", "medium", "high"], default="medium")
    # Default is the name of the CLI executable on disk, not a provider credit;
    # override it to point at a different assessor binary.
    parser.add_argument("--cli", default="claude")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--contract", type=Path, default=ROOT / "prompts/monthly-assessor.md")
    parser.add_argument("--models", type=Path, default=ROOT / "models/baseline-risk-models.md")
    parser.add_argument("--taxonomy", type=Path, default=ROOT / "data/tag-taxonomy.json")
    parser.add_argument("--catalogue", type=Path, default=ROOT / "data/mitigation-catalog.json")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--public-source-proof", type=Path)
    parser.add_argument("--public-source-proof-sha256")
    guard.add_allow_domain_argument(parser)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    if args.run_dir.exists():
        parser.error("--run-dir must be new; preserve previous attempts")
    guard.allow_domains(args.guard_allow_domain)
    if bool(args.public_source_proof) != bool(args.public_source_proof_sha256):
        parser.error("public-source proof requires its explicit approved SHA256")
    public_guard = PublicSourceGuard(args.public_source_proof, args.public_source_proof_sha256) if args.public_source_proof else None

    records = [json.loads(line) for line in args.records.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.limit:
        records = records[:args.limit]

    # Checked once, up front, so a violation is reported against the record that
    # carries it rather than against the batch that happens to contain it - and
    # so the run stops before the first call rather than partway through a month.
    for record in records:
        if public_guard:
            public_guard.assert_record(record)
        else:
            guard.assert_clean(record.get("cve", f"{args.records}:<record without a cve>"),
                               record, f"source record from {args.records}")

    taxonomy = json.loads(args.taxonomy.read_text(encoding="utf-8"))
    tags = {tag for name in ("workload", "delivery", "impact") for tag in taxonomy["namespaces"][name]}
    controls = {item["id"] for item in json.loads(args.catalogue.read_text(encoding="utf-8"))}

    scaffolded = args.arm == "scaffolded"
    if scaffolded:
        # Fail before a provider call if the local canonical validator is absent.
        from jsonschema import Draft202012Validator
    system_prompt, scaffold_hashes = scaffold(args.contract, args.taxonomy, args.catalogue, args.models) if scaffolded else (MINIMAL_SYSTEM_PROMPT, {})
    # The contract and guidance files are repo content, but they are assembled
    # into a prompt that leaves the process, so they are gated like any other.
    guard.assert_clean(str(args.contract), system_prompt,
                       "system prompt about to be handed to the model CLI")

    args.run_dir.mkdir(parents=True, exist_ok=True)
    mcp_config_path = write_sandbox_mcp_config(args.run_dir)
    started = datetime.now(timezone.utc).isoformat()
    results, conformance_failures = [], []
    checkpoint(args, records, system_prompt, scaffold_hashes, public_guard, mcp_config_path,
               started, results, conformance_failures)

    for index, packet in batches(records, args.batch_size):
        cves = [record["cve"] for record in packet]
        schema = build_schema(cves, tags, controls)
        schema_path = args.run_dir / f"schema-{index:03d}.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8", newline="\n")

        prefix = system_prompt + "\n\n=== CANONICAL PRODUCTION JSON SCHEMA ===\n" + json.dumps(schema) if scaffolded else MINIMAL_SYSTEM_PROMPT
        prompt = render_prompt(prefix, packet)
        source_bound_hash = public_guard.assert_prompt(prompt, prefix, packet) if public_guard else None
        if not public_guard:
            guard.assert_clean(f"batch {index} ({cves[0]}..{cves[-1]})", prompt, "assembled batch prompt")
        (args.run_dir / f"prompt-{index:03d}.txt").write_text(prompt, encoding="utf-8", newline="\n")

        system_prompt_path = args.run_dir / "system-prompt.txt"
        if not system_prompt_path.exists():
            system_prompt_path.write_text(system_prompt, encoding="utf-8", newline="\n")
        # Schema enforcement is part of the scaffolding under test, so the ablation
        # arm passes no schema. The sandbox is not - see build_command.
        command = build_command(args.cli, args.model, system_prompt_path,
                                mcp_config_path.resolve(), schema if scaffolded else None,
                                effort=args.effort)

        call_started = datetime.now(timezone.utc).isoformat()
        code, raw, stderr, cleanup_error = invoke(command, prompt, args.timeout,
                                  f"batch {index} ({cves[0]}..{cves[-1]})",
                                  raw_path=args.run_dir / f"stream-{index:03d}.ndjson",
                                  stderr_path=args.run_dir / f"stderr-{index:03d}.txt",
                                  source_bound_prompt_sha256=source_bound_hash)
        call_finished = datetime.now(timezone.utc).isoformat()
        analyzed = analyze_transport(raw, code, scaffolded, args.model)
        envelope = terminal_envelope(raw)
        stdout = json.dumps(envelope, ensure_ascii=False, indent=2)
        (args.run_dir / f"response-{index:03d}.json").write_text(stdout, encoding="utf-8", newline="\n")

        record_entry = {
            "batch": index, "cves": cves, "arm": args.arm,
            "model_configured": args.model,
            "started_at": call_started, "finished_at": call_finished,
            "returncode": code,
            "prompt_sha256": sha256(prompt),
            "system_prompt_sha256": sha256(system_prompt),
            "response_sha256": sha256(stdout),
            "stream_sha256": hashlib.sha256(raw).hexdigest(),
            "schema_sha256": sha256(json.dumps(schema)),
            "effort_configured": args.effort,
            "guidance_version": GUIDANCE_VERSION,
            "source_bound_prompt_sha256": source_bound_hash,
            "command_safe": command,
            "transport_receipt": analyzed["receipt"],
            "temporary_cwd_cleanup_error": cleanup_error,
            "schema_enforced": scaffolded,
            # Recorded per call, not only per run, so an audit of a single batch can
            # tell whether that batch was sandboxed without trusting the summary.
            "sandboxed": True,
        }

        assessments, failure = None, "; ".join(analyzed["errors"]) or None
        try:
            usage = envelope.get("modelUsage") or {}
            record_entry["model_served"] = analyzed["receipt"]["model_served"]
            record_entry["canonical_model"] = analyzed["receipt"]["model_served"]
            providers = {item.get("provider") for item in usage.values() if isinstance(item, dict) and item.get("provider")}
            record_entry["provider"] = next(iter(providers)) if len(providers) == 1 else None
            record_entry["cost_usd"] = analyzed["receipt"]["total_cost_usd"]
            record_entry["session_id"] = envelope.get("session_id")
            record_entry["is_error"] = envelope.get("is_error")

            payload = analyzed["response"]
            assessments = payload.get("assessments") if isinstance(payload, dict) else None
            if failure is None and not isinstance(assessments, list):
                failure = "no assessments array in response"
            if failure is None and scaffolded:
                Draft202012Validator(schema).validate(payload)
                by_cve = {record["cve"]: record for record in packet}
                if len(assessments) != len(cves) or {item["cve"] for item in assessments} != set(cves):
                    raise ValueError("each assigned CVE must appear exactly once")
                for assessment in assessments:
                    validate_monthly_overlay(assessment, by_cve[assessment["cve"]], tags, controls)
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
                json.dumps(assessments, indent=2), encoding="utf-8", newline="\n")

        results.append(record_entry)
        (args.run_dir / f"receipt-{index:03d}.json").write_text(json.dumps(record_entry, indent=2) + "\n", encoding="utf-8", newline="\n")
        checkpoint(args, records, system_prompt, scaffold_hashes, public_guard, mcp_config_path,
                   started, results, conformance_failures)
        print(json.dumps({"batch": index, "conformant": record_entry["conformant"],
                          "failure": failure, "cves": len(cves)}), flush=True)

    manifest = checkpoint(args, records, system_prompt, scaffold_hashes, public_guard, mcp_config_path,
                          started, results, conformance_failures, final=True)
    print(json.dumps({"summary": manifest["measure_1_schema_conformance"]}, indent=2))


if __name__ == "__main__":
    main()
