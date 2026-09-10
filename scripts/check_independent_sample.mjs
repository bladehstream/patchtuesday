import assert from "node:assert/strict";
import fs from "node:fs";
import { publicProfile } from "../engine.js";

const read = file => fs.readFileSync(new URL("../" + file, import.meta.url), "utf8");
const parse = text => text.trim().split(/\r?\n/).map(JSON.parse);
const sample = JSON.parse(read("work/independent-20-review/sample.json"));
const ids = new Set(sample.cves);
assert.equal(ids.size, 20);
const data = new Map(parse(read("data/2026-Sep.jsonl")).map(r => [r.cve, r]));
const raw = JSON.parse(read("work/independent-20-review/fresh-sources/2026-Sep.json"));
const rawRecords = new Map(raw.Vulnerability.map(r => [r.CVE, r]));
const kev = new Set(JSON.parse(read("work/independent-20-review/fresh-sources/known_exploited_vulnerabilities.json")).vulnerabilities.map(r => r.cveID));
const epss = new Map(read("work/independent-20-review/fresh-sources/epss_scores-current.csv").split(/\r?\n/).filter(line => line.startsWith("CVE-")).map(line => { const [cve, score] = line.split(","); return [cve, Number(score)]; }));
const catalog = JSON.parse(read("data/mitigation-catalog.json"));
const missingSeverity = [];
let subsets = 0, singles = 0;
const priorities = ["No customer action", "Normal scheduled", "Expedited", "Emergency"];
const likelihoods = ["Low evidence", "Plausible", "Elevated", "Active"];
for (const cve of ids) {
  const r = data.get(cve), v = rawRecords.get(cve);
  const scores = v.CVSSScoreSets || [];
  assert.ok(r.cvss.vector ? scores.some(s => s.Vector === r.cvss.vector && s.BaseScore === r.cvss.base_score) : scores.length === 0, cve);
  const severity = [...new Set((v.Threats || []).filter(t => t.Type === 3).map(t => t.Description?.Value).filter(Boolean))];
  if (!severity.length) missingSeverity.push(cve);
  else assert.ok(severity.includes(r.severity), cve);
  const text = (v.Threats || []).filter(t => t.Type === 1).map(t => t.Description?.Value || "").join(" ");
  const expected = /Exploited:Yes|Exploitation detected/i.test(text) ? "detected" : /Exploitation More Likely/i.test(text) ? "more-likely" : /Exploitation Less Likely/i.test(text) ? "less-likely" : /Exploitation Unlikely/i.test(text) ? "unlikely" : "unknown";
  assert.equal(r.threat.exploitation_assessment, expected, cve);
  assert.equal(r.threat.kev, kev.has(cve), cve);
  assert.equal(r.threat.epss, epss.get(cve), cve);
  const base = publicProfile(r);
  const controlIds = r.mitigation_candidates.map(c => c.id);
  for (let mask = 0; mask < 2 ** controlIds.length; mask++) {
    const selection = new Set(controlIds.filter((_, index) => mask & (1 << index)));
    const p = publicProfile(r, selection);
    assert.deepEqual(p.baseline, base.baseline);
    assert.ok(priorities.indexOf(p.residual.action) <= priorities.indexOf(base.baseline.action));
    assert.ok(likelihoods.indexOf(p.residual.likelihood) <= likelihoods.indexOf(base.baseline.likelihood));
    if (r.customer_action_required !== false) assert.ok(priorities.indexOf(p.residual.action) >= 1);
    subsets++;
  }
  for (const c of catalog) {
    const p = publicProfile(r, new Set([c.id]));
    if (!controlIds.includes(c.id)) {
      assert.equal(p.residual.action, base.residual.action);
      assert.equal(p.residual.likelihood, base.residual.likelihood);
    }
    singles++;
  }
}
assert.deepEqual(missingSeverity.sort(), ["CVE-2026-84335", "CVE-2026-84358"]);
console.log(JSON.stringify({sample:ids.size,raw_cvss_match:20,microsoft_exploitation_match:20,kev_match:20,epss_match:20,missing_source_severity:missingSeverity,candidate_subsets:subsets,catalogue_single_selections:singles,interpretation:"Scenario checks verify software behavior, not the substantive correctness of mitigation relevance."},null,2));
