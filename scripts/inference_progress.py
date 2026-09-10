#!/usr/bin/env python3
"""Summarize actual model-call coverage and surface review candidates."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import merge_inference as validation

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--run-dir",type=Path,required=True)
    args=parser.parse_args()
    records=[]
    packets={}
    for p in args.run_dir.glob("shard-*/input-*.jsonl"):
        for line in p.read_text(encoding="utf-8").splitlines():
            r=json.loads(line); packets[r["cve"]]=r
    for p in args.run_dir.glob("shard-*/output-*.jsonl"):
        receipt=p.with_name(p.name.replace("output-","receipt-").replace(".jsonl",".json"))
        if receipt.exists():
            records.extend(json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip())
    flags=[]
    for r in records:
        source=packets[r["cve"]]
        assessment=r["framework_assessment"]
        if source.get("customer_action_required") is not False:
            public_band=validation.public_threat_likelihood(source)
            if validation.LIKELIHOODS.index(assessment["baseline_likelihood"]) > public_band:
                flags.append({"cve":r["cve"],"issue":"model likelihood exceeds structured threat evidence; check additional rationale","model_likelihood":assessment["baseline_likelihood"],"source_likelihood":validation.LIKELIHOODS[public_band],"evidence":assessment["factors"]["threat_evidence"]})
            if assessment["baseline_model"]=="critical-preauth-network-rce" and validation.LIKELIHOODS.index(assessment["baseline_likelihood"]) < 2:
                flags.append({"cve":r["cve"],"issue":"preauth RCE archetype selected without elevated threat evidence","action":assessment["baseline_action"],"reason":assessment["risk_communication"]["why_this_action"]})
        notes=" ".join(n.get("text","") for n in source.get("notes",[])).lower()
        positive=[c for c in r.get("mitigation_candidates",[]) if c["relevance"]=="relevant" and c["confidence"] in {"high","medium"} and (c["effect"]["likelihood_steps"] or c["effect"]["consequence_steps"])]
        for c in positive:
            if c["id"]=="remove_external_exposure" and "in-network attacker" in notes:
                flags.append({"cve":r["cve"],"issue":"perimeter credit on explicit internal attacker","control":c})
            if c["id"]=="office_protected_view" and any(term in notes for term in ["rtf","preview pane","reading pane"]):
                flags.append({"cve":r["cve"],"issue":"Protected View credit requires verification of parser prevention","control":c})
            if c["id"] in {"edr_detection_response","attack_surface_reduction"}:
                flags.append({"cve":r["cve"],"issue":"quantified generic response/ASR control","control":c})
            if c["effect"]["consequence_steps"] or c["effect"]["path_block"]:
                flags.append({"cve":r["cve"],"issue":"strong effect requires direct vendor evidence","control":c})
    sums=Counter()
    for p in args.run_dir.glob("shard-*/events-*.jsonl"):
        for line in p.read_text(encoding="utf-8",errors="replace").splitlines():
            try: event=json.loads(line)
            except json.JSONDecodeError: continue
            if event.get("type")=="turn.completed":
                sums.update(event.get("usage",{})); sums["model_calls"]+=1
    print(json.dumps({"expected":len(packets),"validated":len(records),"unique_cves":len({r["cve"] for r in records}),"unique_explanations":len({r["framework_assessment"]["risk_communication"]["why_this_action"] for r in records}),"actions":dict(Counter(r["framework_assessment"]["baseline_action"] for r in records)),"usage":dict(sums),"review_flags":flags},indent=2))
if __name__=="__main__":
    main()
