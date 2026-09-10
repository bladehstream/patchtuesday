#!/usr/bin/env python3
"""Prepare complete source packets; no model judgments are made here."""
import argparse
import hashlib
import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source = ROOT / "data/2026-Sep.jsonl"
    rows = sorted([json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()], key=lambda r:r["cve"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    assignments = []
    for shard in range(3):
        assigned = rows[shard::3]
        folder = args.output_dir / f"shard-{shard+1}"
        folder.mkdir(exist_ok=True)
        packets = []
        for r in assigned:
            packet = {k:r[k] for k in ("cve","title","severity","customer_action_required","cvss","attack","threat","tags","source")}
            packet["products"] = sorted({p["name"] for p in r["products"]})
            packet["notes"] = [{"title":n.get("title"),"type":n.get("type"),"text":html.unescape(re.sub("<[^>]+>", " ", n.get("value","")))} for n in r.get("vendor_guidance",{}).get("notes",[])]
            packet["remediations"] = list({json.dumps({k:v for k,v in m.items() if k != "product_ids"},sort_keys=True):{k:v for k,v in m.items() if k != "product_ids"} for m in r.get("vendor_guidance",{}).get("remediations",[])}.values())
            packets.append(packet)
        for offset in range(0,len(packets),15):
            batch = packets[offset:offset+15]
            path = folder / f"input-{offset//15+1:03}.jsonl"
            path.write_text("\n".join(json.dumps(r,separators=(",",":")) for r in batch)+"\n",encoding="utf-8")
        assignments.append({"shard":shard+1,"count":len(assigned),"cves":[r["cve"] for r in assigned]})
    manifest={"source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"record_count":len(rows),"assignments":assignments}
    (args.output_dir/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"records":len(rows),"shards":[a["count"] for a in assignments],"output":str(args.output_dir)}))
if __name__ == "__main__":
    main()
