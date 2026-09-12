#!/usr/bin/env python3
"""Self-test for collect_claude_inference.py. Plain python, no test framework.

    python3 scripts/collect_claude_self_test.py

Every gate in the collector gets a fixture it rejects, plus fixtures it accepts. A
gate that has never been seen to fail is not evidence of anything - and a mutation
that happens to match the original value is not a failing fixture either, which is
why each negative case changes a field to a value the fixture never held.

Fixtures are built from real published records, so the framework validators run
against real data rather than a shape invented to satisfy them.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "scripts" / "collect_claude_inference.py"
PUBLISHED = ROOT / "data" / "2026-Sep.jsonl"
SAMPLE = 6


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sample_records() -> list:
    rows = []
    with PUBLISHED.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record.get("inference", {}).get("framework_assessment"):
                rows.append(record)
            if len(rows) >= SAMPLE:
                break
    if len(rows) < SAMPLE:
        raise SystemExit(f"Need {SAMPLE} assessed records in {PUBLISHED}")
    return rows


def split(record: dict) -> tuple[dict, dict]:
    """Reconstruct the pre-inference baseline and the overlay the model would author."""
    source = {k: v for k, v in record.items() if k not in ("inference", "mitigation_candidates", "priority", "review")}
    overlay = {
        "cve": record["cve"],
        "cvss_basis": {
            "base_score": source.get("cvss", {}).get("base_score"),
            "vector": source.get("cvss", {}).get("vector"),
            "attack_vector": source.get("attack", {}).get("vector"),
            "privileges_required": source.get("attack", {}).get("privileges_required"),
            "user_interaction": source.get("attack", {}).get("user_interaction"),
        },
        "attack_path": {"direction": "inbound", "evidence": "self-test fixture"},
        "tags": sorted(set(record.get("tags") or [])),
        "mitigation_candidates": record.get("mitigation_candidates") or [],
        "framework_assessment": record["inference"]["framework_assessment"],
    }
    return source, overlay


def build_run(work: Path, name: str, pairs: list) -> tuple[Path, Path]:
    """Write a records file and a run directory as run_claude_inference.py would."""
    sources = [source for source, _ in pairs]
    overlays = [overlay for _, overlay in pairs]
    records_path = work / f"{name}-records.jsonl"
    records_path.write_text("\n".join(json.dumps(item, separators=(",", ":")) for item in sources) + "\n", encoding="utf-8")

    run = work / name
    run.mkdir()
    envelope = {
        "structured_output": {"assessments": overlays},
        "modelUsage": {"claude-haiku-self-test": {"canonicalModel": "haiku", "provider": "anthropic", "costUSD": 0.0}},
        "session_id": "self-test", "is_error": False,
    }
    response = json.dumps(envelope)
    (run / "response-000.json").write_text(response, encoding="utf-8")
    (run / "assessments-000.json").write_text(json.dumps(overlays, indent=2), encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({
        "arm": "scaffolded", "model_configured": "haiku", "records": len(sources),
        "batch_size": 15, "batches": 1, "schema_enforced": True,
        "source_records": str(records_path),
        "source_records_sha256": sha256(records_path.read_text(encoding="utf-8")),
        "system_prompt_sha256": "self-test",
        "calls": [{
            "batch": 0, "cves": [item["cve"] for item in overlays], "arm": "scaffolded",
            "model_configured": "haiku", "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:01:00+00:00", "returncode": 0,
            "prompt_sha256": "self-test", "system_prompt_sha256": "self-test",
            "response_sha256": sha256(response), "schema_enforced": True,
            "model_served": "claude-haiku-self-test", "provider": "anthropic", "conformant": True,
        }],
    }, indent=2), encoding="utf-8")
    return records_path, run


def rewrite_response(run: Path, mutate) -> None:
    path = run / "response-000.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    mutate(envelope["structured_output"]["assessments"])
    response = json.dumps(envelope)
    path.write_text(response, encoding="utf-8")
    (run / "assessments-000.json").write_text(json.dumps(envelope["structured_output"]["assessments"], indent=2), encoding="utf-8")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["calls"][0]["response_sha256"] = sha256(response)
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    failures: list = []
    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)
        pairs = [split(record) for record in sample_records()]
        baseline = work / "baseline.jsonl"
        baseline.write_text("\n".join(json.dumps(source, separators=(",", ":")) for source, _ in pairs) + "\n", encoding="utf-8")

        _, whole = build_run(work, "whole-month", pairs)
        _, shard_a = build_run(work, "shard-a", pairs[:3])
        _, shard_b = build_run(work, "shard-b", pairs[3:])

        def case(name: str, runs: list, expect: str | None) -> None:
            command = [sys.executable, str(COLLECTOR), "--baseline", str(baseline), "--output", str(work / f"out-{name}.jsonl")]
            for run in runs:
                command += ["--run-dir", str(run)]
            result = subprocess.run(command, capture_output=True, text=True)
            combined = result.stdout + result.stderr
            if expect is None:
                if result.returncode != 0:
                    failures.append(f"{name}: expected success, got\n{combined}")
            elif result.returncode == 0:
                failures.append(f"{name}: gate did not fire")
            elif expect not in combined:
                failures.append(f"{name}: rejected for the wrong reason\n{combined}")

        def variant(name: str, template: Path, mutate) -> Path:
            copy = work / name
            shutil.copytree(template, copy)
            mutate(copy)
            return copy

        case("accepts-a-whole-month-run", [whole], None)
        case("accepts-shards-that-together-cover-the-month", [shard_a, shard_b], None)
        case("one-shard-alone-is-incomplete", [shard_a], "incomplete inference release")
        case("the-same-shard-twice-is-a-duplicate", [shard_a, shard_a], "duplicate across batches")

        def tamper(copy: Path) -> None:
            path = copy / "assessments-000.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload[0]["attack_path"]["evidence"] = "edited after the call was captured"
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        case("artefact-edited-after-the-call",
             [variant("tampered", whole, tamper)], "differs from the captured model response")

        case("model-echoed-a-wrong-cvss-basis",
             [variant("wrong-basis", whole,
                      lambda copy: rewrite_response(copy, lambda items: items[0]["cvss_basis"].__setitem__("base_score", -1.0)))],
             "cvss_basis does not match")

        case("batch-returned-fewer-cves",
             [variant("short-batch", whole,
                      lambda copy: rewrite_response(copy, lambda items: items.pop()))],
             "CVE set does not match")

        def mark_failed(copy: Path) -> None:
            manifest = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
            manifest["calls"][0].update({"conformant": False, "conformance_failure": "no assessments array in response"})
            (copy / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        case("non-conformant-batch-not-repaired",
             [variant("non-conformant", whole, mark_failed)], "incomplete inference release")

        def drift_source(copy: Path) -> None:
            manifest = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
            source = Path(manifest["source_records"])
            # Written as a sibling rather than in place, so the shared fixture stays
            # intact and the cases above this one are not order-dependent.
            drifted = copy / "drifted-records.jsonl"
            drifted.write_text("\n".join(source.read_text(encoding="utf-8").splitlines()[:-1]) + "\n", encoding="utf-8")
            manifest["source_records"] = str(drifted)
            (copy / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        case("source-records-changed-under-the-run",
             [variant("drifted", whole, drift_source)], "does not match the records")

    total = 9
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{total - len(failures)}/{total} collector gates behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
