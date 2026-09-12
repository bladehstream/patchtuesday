#!/usr/bin/env python3
"""Prepare complete source packets; no model judgments are made here.

Every packet is checked by scripts/customer_data_guard.py before it is written.
A packet that carries a hostname, address, tenant identifier, inventory or
topology is refused here rather than at send time, because a shard file on disk
is already halfway to a provider: a later step reads it without re-deriving it.
Nothing is redacted - the run stops and names the record and the span.
"""
import argparse
import hashlib
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import customer_data_guard as guard  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--month", required=True, help="Month being assessed, e.g. 2026-Oct")
    parser.add_argument("--source", type=Path,
                        help="Enriched baseline to shard. Defaults to data/<month>.jsonl, but a\nmonth that has not been published yet has no file there — pass the enrich output.")
    guard.add_allow_domain_argument(parser)
    args = parser.parse_args()
    guard.allow_domains(args.guard_allow_domain)
    source = (args.source if args.source else ROOT / f"data/{args.month}.jsonl").resolve()
    if not source.is_file():
        raise SystemExit(f"Enriched baseline not found: {source}")
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
            # The gate, before the packet is written and therefore before any
            # downstream step can send it. Raises CustomerDataError naming the
            # CVE, the field path and the matched span.
            try:
                guard.assert_clean(packet["cve"], packet, f"inference packet for shard {shard+1}")
            except guard.CustomerDataError as violation:
                raise SystemExit(str(violation)) from violation
            packets.append(packet)
        for offset in range(0,len(packets),15):
            batch = packets[offset:offset+15]
            path = folder / f"input-{offset//15+1:03}.jsonl"
            path.write_text("\n".join(json.dumps(r,separators=(",",":")) for r in batch)+"\n",encoding="utf-8")
        assignments.append({"shard":shard+1,"count":len(assigned),"cves":[r["cve"] for r in assigned]})
    manifest={"month":args.month,"source_file":source.relative_to(ROOT).as_posix() if source.is_relative_to(ROOT) else str(source),"source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"record_count":len(rows),"assignments":assignments}
    (args.output_dir/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"records":len(rows),"shards":[a["count"] for a in assignments],"output":str(args.output_dir)}))
if __name__ == "__main__":
    main()
