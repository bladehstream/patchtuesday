import assert from "node:assert/strict";
import fs from "node:fs";
import { parseJsonl, predictProfile, reviewStatus, frameworkIsUsable, missingImpactJudgement } from "../engine.js";
import fsSync from "node:fs";

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
// Layer separation: nothing the risk path reads may be produced by matching
// advisory prose. Product tags are derived from structured vendor strings and are
// cosmetic; judgement tags are model-asserted and gate mitigation credit and
// archetypes. The two must not mix.
//
// Narrowed 2026-09-12. Seven workload tags are now asserted deterministically from
// the component half of the MSRC title, which is a lookup on a delimited vendor
// field and not prose matching - the taxonomy declares them in
// derivation.derived_from_title_component. They are therefore legitimately present
// in product_tags. Everything else in the judgement namespaces still is not, so
// this gate can still fail: a model-only workload tag, or any delivery or impact
// tag, leaking into the derived set is caught exactly as before.
const taxonomy = JSON.parse(fsSync.readFileSync(new URL("../data/tag-taxonomy.json", import.meta.url), "utf8"));
const deterministicWorkloads = new Set(taxonomy.derivation.derived_from_title_component || []);
// The declaration cannot be used to smuggle a risk-path tag into the derived set.
// Delivery and impact are what gate mitigation credit and archetype selection, so
// nothing in either may ever be declared deterministic, whatever the title says.
const riskPathOnly = new Set(["delivery", "impact"].flatMap(ns => taxonomy.namespaces[ns]));
for (const tag of deterministicWorkloads) {
  assert.ok(!riskPathOnly.has(tag),
    `${tag} is declared deterministic but is a delivery or impact tag; those gate mitigation credit and must stay model-asserted`);
}
const judgement = new Set(["workload", "delivery", "impact"]
  .flatMap(ns => taxonomy.namespaces[ns])
  .filter(tag => !deterministicWorkloads.has(tag)));
const derived = new Set(["vendor", "platform", "deployment", "release"].flatMap(ns => taxonomy.namespaces[ns]));
for (const item of records) {
  assert.ok(Array.isArray(item.product_tags), `${item.cve} must carry derived product_tags`);
  const strayJudgement = item.product_tags.filter(tag => judgement.has(tag));
  assert.equal(strayJudgement.length, 0, `${item.cve}: derived product_tags leaked judgement tags ${strayJudgement}`);
  const strayDerived = item.tags.filter(tag => derived.has(tag));
  assert.equal(strayDerived.length, 0, `${item.cve}: risk-path tags contain derived product tags ${strayDerived}`);
}

// An assessment that exists but fails validation must be flagged, never allowed to
// pass silently as an assessed record while deterministic policy quietly stands in.
const broken = { ...records[0], inference: { ...records[0].inference, framework_assessment: { ...records[0].inference.framework_assessment, baseline_action: "Not-A-Real-Action" } } };
assert.equal(frameworkIsUsable(broken.inference.framework_assessment), false, "a bad baseline_action must not validate");
const brokenStatus = reviewStatus(broken);
assert.ok(brokenStatus.required, "an unusable assessment must require review");
assert.ok(brokenStatus.reasons.some(reason => reason.code === "unusable-assessment"), "an unusable assessment must carry the unusable-assessment reason");

// The gate must reject something. A synthetic pre-auth network record at CVSS 9.8
// with no impact tag is exactly the shape that silently loses the
// critical-preauth-network-rce floor, so it must flag.
const untagged = {
  ...records[0],
  cvss: { base_score: 9.8, temporal_score: null, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", version: "3.1" },
  attack: { vector: "network", privileges_required: "none", user_interaction: "none" },
  tags: [],
  customer_action_required: true,
};
assert.ok(missingImpactJudgement(untagged), "an untagged pre-auth network 9.8 must be detected");
assert.ok(reviewStatus(untagged).reasons.some(reason => reason.code === "missing-impact-judgement"), "detection must raise a review reason");

// And it must NOT fire once the assessor has actually asserted an impact.
assert.equal(missingImpactJudgement({ ...untagged, tags: ["remote-code-execution"] }), false, "an asserted impact tag must clear the flag");
assert.equal(missingImpactJudgement({ ...untagged, cvss: { ...untagged.cvss, base_score: 6.5 } }), false, "the flag is scoped to high severity");
assert.equal(missingImpactJudgement({ ...untagged, attack: { ...untagged.attack, privileges_required: "high" } }), false, "the flag is scoped to pre-authentication access");

const liveUntagged = records.filter(missingImpactJudgement);
for (const item of liveUntagged) {
  assert.ok(reviewStatus(item).required, `${item.cve} has no impact judgement and must require review`);
}

console.log(`  ${liveUntagged.length} records flagged for missing impact judgement: ${liveUntagged.map(item => item.cve).join(", ")}`);
console.log(`September CVE regression test passed (${records.length} records, ${unknowns.length} Unknown severity)`);
