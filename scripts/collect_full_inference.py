#!/usr/bin/env python3
"""Collect every model-authored batch, validating source fidelity and exact coverage."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import merge_inference as validation

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.run_dir/"manifest.json").read_text(encoding="utf-8"))
    baseline_path = ROOT/"data/2026-Sep.jsonl"
    if hashlib.sha256(baseline_path.read_bytes()).hexdigest() != manifest["source_sha256"]:
        raise ValueError("Source snapshot changed during inference; reconcile before collecting")
    baseline = {r["cve"]:r for r in validation.read_jsonl(baseline_path)}
    tags = validation.allowed_tags(ROOT/"data/tag-taxonomy.json")
    controls = validation.allowed_mitigations(ROOT/"data/mitigation-catalog.json")
    seen = set()
    collected = []
    errors = []
    missing_batches = []
    for assignment in manifest["assignments"]:
        folder = args.run_dir / ("shard-" + str(assignment["shard"]))
        for packet_path in sorted(folder.glob("input-*.jsonl")):
            output_path = packet_path.with_name(packet_path.name.replace("input-", "output-"))
            if not output_path.exists():
                missing_batches.append(str(output_path.relative_to(args.run_dir)))
                continue
            try:
                receipt_path = output_path.with_name(output_path.name.replace("output-", "receipt-").replace(".jsonl", ".json"))
                if not receipt_path.exists():
                    raise ValueError("Missing real-model-call receipt; generated templates are not accepted")
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                if receipt.get("status") != "validated-model-response" or receipt.get("output_sha256") != hashlib.sha256(output_path.read_bytes()).hexdigest():
                    raise ValueError("Model-call receipt does not match batch output")
                records = validation.read_jsonl(output_path)
                response_path = packet_path.with_name(packet_path.name.replace("input-", "response-").replace(".jsonl", ".json"))
                if not response_path.exists(): raise ValueError("Original model response is missing")
                response_hash = hashlib.sha256(response_path.read_bytes()).hexdigest()
                input_hash = hashlib.sha256(packet_path.read_bytes()).hexdigest()
                model_records = {r["cve"]:r for r in json.loads(response_path.read_text(encoding="utf-8"))["assessments"]}
                expected = {r["cve"] for r in validation.read_jsonl(packet_path)}
                if {r.get("cve") for r in records} != expected or len(records) != len(expected):
                    raise ValueError("CVE set does not exactly match its input batch")
                for overlay in records:
                    cve = overlay["cve"]
                    if cve in seen: raise ValueError(f"Duplicate {cve}")
                    validation.validate_cvss_basis(overlay, baseline[cve])
                    validation.validate_framework_assessment(overlay, baseline[cve])
                    if set(overlay.get("tags",[])) - tags: raise ValueError(f"{cve}: unknown tags")
                    ids = [c["id"] for c in overlay.get("mitigation_candidates",[])]
                    if len(set(ids)) != len(ids): raise ValueError(f"{cve}: duplicate mitigations")
                    for candidate in overlay.get("mitigation_candidates",[]):
                        validation.validate_candidate(candidate, controls, cve)
                    validation.validate_path_compatibility(overlay, baseline[cve])
                    provenance = overlay.get("inference",{})
                    invocation = provenance.get("invocation", {})
                    if invocation.get("response_sha256") != response_hash or invocation.get("input_sha256") != input_hash:
                        raise ValueError(f"{cve}: model response/input provenance mismatch")
                    authored = model_records[cve]["framework_assessment"]
                    if overlay["framework_assessment"]["factors"] != authored["factors"] or overlay["framework_assessment"]["risk_communication"] != authored["risk_communication"]:
                        raise ValueError(f"{cve}: substantive reasoning differs from original model response")
                    if "luna" not in provenance.get("model","").lower() or not provenance.get("generated_at"):
                        raise ValueError(f"{cve}: missing Luna generation provenance")
                    datetime.fromisoformat(provenance["generated_at"].replace("Z","+00:00"))
                for overlay in records:
                    seen.add(overlay["cve"])
                    overlay["inference"]["pipeline_validation"] = {
                        "type":"automated-source-and-schema",
                        "source_sha256":manifest["source_sha256"],
                        "batch":str(output_path.relative_to(args.run_dir)),
                        "validated_at":datetime.now(timezone.utc).isoformat()
                    }
                    collected.append(overlay)
            except (ValueError, KeyError, TypeError) as exc:
                errors.append({"batch":str(output_path.relative_to(args.run_dir)),"error":str(exc)})
    report={"expected":len(baseline),"validated":len(collected),"missing_cves":len(set(baseline)-seen),"missing_batches":missing_batches,"errors":errors}
    print(json.dumps(report,indent=2))
    if args.output:
        if errors or missing_batches or seen != set(baseline):
            raise ValueError("Refusing to write an incomplete inference release")
        args.output.parent.mkdir(parents=True,exist_ok=True)
        collected.sort(key=lambda r:r["cve"])
        args.output.write_text("\n".join(json.dumps(r,separators=(",",":")) for r in collected)+"\n",encoding="utf-8")
        print(f"Collected all {len(collected)} model-authored assessments into {args.output}")

if __name__ == "__main__":
    main()
