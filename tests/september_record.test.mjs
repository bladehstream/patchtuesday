import assert from "node:assert/strict";
import fs from "node:fs";
import { parseJsonl, predictProfile, reviewStatus } from "../engine.js";

const records = parseJsonl(fs.readFileSync(new URL("../data/2026-Sep.jsonl", import.meta.url), "utf8"));

// The published record count is asserted against the build manifest, never a
// literal. A frozen literal here contradicts the standing instruction to
// recheck the live MSRC manifest before a run, and broke the moment the
// 2026-09-10 refresh added CVE-2026-85046 (1186 records, not 1185).
const manifest = JSON.parse(fs.readFileSync(new URL("../data/months.json", import.meta.url), "utf8"));
const september = manifest.find(item => item.month === "2026-Sep");
assert.ok(september, "months.json must describe the 2026-Sep dataset");
assert.ok(Number.isInteger(september.record_count), "months.json must carry a record_count for 2026-Sep");
assert.equal(records.length, september.record_count, "Published record count must match the build manifest");
assert.equal(records.filter(item => item.inference?.review_status === "reviewed" && item.inference?.framework_assessment).length, records.length, "Every September CVE must have an inference assessment");
const record = records.find(item => item.cve === "CVE-2026-69829");
assert.ok(record, "CVE-2026-69829 must remain in the curated September dataset");
assert.equal(record.threat.exploitation_assessment, "unlikely");
assert.equal(record.cvss.base_score, 9.8);
assert.equal(record.attack.vector, "network");
assert.equal(record.attack.privileges_required, "none");
assert.equal(record.attack.user_interaction, "none");
const baseline = predictProfile(record, new Set()).baseline;
assert.equal(baseline.likelihood, "Plausible", "Current EPSS evidence may raise likelihood above Microsoft's Unlikely rating");
assert.equal(baseline.action, "Out-of-cycle");
assert.ok(record.mitigation_candidates.some(item => item.id === "segmentation_acl"));
assert.ok(!record.mitigation_candidates.some(item => item.id === "email_web_filtering"));

const dns = records.find(item => item.cve === "CVE-2026-69730");
assert.ok(dns, "CVE-2026-69730 must remain in the September dataset");
const dnsBaseline = predictProfile(dns, new Set());
assert.equal(dnsBaseline.baseline.likelihood, "Elevated");
assert.equal(dnsBaseline.baseline.action, "Immediate");
const dnsMitigated = predictProfile(dns, new Set(dns.mitigation_candidates.map(item => item.id)));
assert.equal(dnsMitigated.residual.action, "Out-of-cycle");
// Regression: a missing vendor severity and a missing CVSS score must never
// resolve to Low. 23 Chromium passthrough records were published as Low on
// this basis, 56% of the entire Low bucket.
const unevidencedLow = records.filter(item => item.severity === "Low" && item.cvss?.base_score === null && item.severity_basis !== "vendor");
assert.equal(unevidencedLow.length, 0, `No record may be rated Low without vendor severity or a CVSS score. Offenders: ${unevidencedLow.slice(0, 5).map(item => item.cve).join(", ")}`);

// Every Unknown-severity record must carry a review flag, and its scheduled
// action must be a declared placeholder rather than a fall-through.
const unknowns = records.filter(item => item.severity === "Unknown");
for (const item of unknowns) {
  if (item.customer_action_required === false) continue;
  const status = reviewStatus(item);
  assert.ok(status.required, `${item.cve} has Unknown severity and must be flagged for review`);
  assert.ok(status.reasons.some(reason => reason.code === "missing-vendor-severity"), `${item.cve} must carry the missing-vendor-severity review reason`);
}
console.log(`September CVE regression test passed (${records.length} records, ${unknowns.length} Unknown severity)`);
