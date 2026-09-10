#!/usr/bin/env python3
"""Apply explicit authored QA amendments after verifying the complete model run."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import merge_inference as validation

ROOT=Path(__file__).resolve().parents[1]
def merge(target,updates):
    for key,value in updates.items():
        if isinstance(value,dict) and isinstance(target.get(key),dict): merge(target[key],value)
        else: target[key]=value

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--corrections",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    records=validation.read_jsonl(args.input)
    source={r["cve"]:r for r in validation.read_jsonl(ROOT/"data/2026-Sep.jsonl")}
    if len(records)!=len(source) or {r["cve"] for r in records}!=set(source):
        raise ValueError("QA amendments require a complete authentic inference release")
    document=json.loads(args.corrections.read_text(encoding="utf-8"))
    corrections=document["corrections"]
    if set(corrections)-set(source): raise ValueError("Unknown correction CVE")
    allowed=validation.allowed_mitigations(ROOT/"data/mitigation-catalog.json")
    for record in records:
        cve=record["cve"]
        if cve in corrections:
            correction=corrections[cve]
            original=json.dumps(record["framework_assessment"],sort_keys=True).encode()
            merge(record["framework_assessment"],correction.get("assessment_updates",{}))
            for candidate in record.get("mitigation_candidates",[]):
                update=correction.get("mitigation_updates",{}).get(candidate["id"])
                if update: merge(candidate,update)
            record["inference"]["verification"]={"reviewer":document["reviewer"],"reviewed_at":datetime.now(timezone.utc).isoformat(),"reason":correction["reason"],"original_assessment_sha256":hashlib.sha256(original).hexdigest(),"corrections_file_sha256":hashlib.sha256(args.corrections.read_bytes()).hexdigest()}
            record["framework_assessment"].setdefault("policy_adjustments",[]).append("Source review: "+correction["reason"])
        validation.validate_cvss_basis(record,source[cve])
        validation.validate_framework_assessment(record,source[cve])
        for candidate in record.get("mitigation_candidates",[]): validation.validate_candidate(candidate,allowed,cve)
        validation.validate_path_compatibility(record,source[cve])
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text("\n".join(json.dumps(r,separators=(",",":")) for r in records)+"\n",encoding="utf-8")
    print(f"Applied {len(corrections)} explicit QA amendments to {len(records)} genuine model assessments")
if __name__=="__main__":
    main()
