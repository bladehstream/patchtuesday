import assert from "node:assert/strict";
import fs from "node:fs";
import { parseJsonl, predictProfile } from "../engine.js";

const records = parseJsonl(fs.readFileSync(new URL("../data/2026-Sep.jsonl", import.meta.url), "utf8"));
assert.equal(records.length, 1185, "The September page must publish the complete CVRF record set");
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
console.log("September CVE regression test passed");
