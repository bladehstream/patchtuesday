"""Draw a reproducible random sample and emit source-only packets for independent review."""
import hashlib, html, json, random, re, secrets
from datetime import datetime, timezone
from pathlib import Path

root=Path(__file__).resolve().parents[1]
out=root/"work"/"independent-20-review"
out.mkdir(parents=True,exist_ok=True)
manifest_path=out/"sample.json"
data_path=root/"data"/"2026-Sep.jsonl"
records={r["cve"]:r for r in (json.loads(line) for line in data_path.read_text(encoding="utf-8").splitlines() if line.strip())}
if manifest_path.exists():
    manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
else:
    seed=secrets.randbits(32)
    ids=random.Random(seed).sample(sorted(records),20)
    manifest={"created_at":datetime.now(timezone.utc).isoformat(),"seed":seed,"method":"Python random.Random(seed).sample(sorted(CVE identifiers), 20), without replacement; one draw, no substitutions","population":len(records),"population_sha256":hashlib.sha256(data_path.read_bytes()).hexdigest(),"cves":ids}
    manifest_path.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
raw=json.loads((root/"raw"/"2026-Sep.json").read_text(encoding="utf-8"))
raw_by_id={v["CVE"]:v for v in raw["Vulnerability"]}
packets=[]
for cve in manifest["cves"]:
    record=records[cve]
    original=raw_by_id[cve]
    packet={key:record[key] for key in ["cve","title","severity","customer_action_required","cvss","attack","threat","products","vendor_guidance","source"]}
    packet["raw_msrc_cvss"]=original.get("CVSSScoreSets")
    packet["raw_msrc_threats"]=original.get("Threats")
    packets.append(packet)
(out/"source-only.json").write_text(json.dumps(packets,indent=2)+"\n",encoding="utf-8")
print(json.dumps(manifest,indent=2))
for r in packets:
    notes=[{"title":n["title"],"text":html.unescape(re.sub("<[^>]+>"," ",n["value"]))} for n in r["vendor_guidance"].get("notes",[]) if n.get("type") in [2,4,6]]
    print(json.dumps({**{k:r[k] for k in ["cve","title","severity","customer_action_required","cvss","attack","threat"]},"products":[p["name"] for p in r["products"]],"notes":notes,"remediation_types":sorted({m["type"] for m in r["vendor_guidance"].get("remediations",[])})},separators=(",",":")))
