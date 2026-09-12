import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ssvc, reviewStatus, baselineProfile, predictProfile } from "../engine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "data", "months.json"), "utf8"));
const published = manifest.find(item => !String(item.month).endsWith("-demo"));
const records = fs.readFileSync(path.join(root, "data", published.file), "utf8").trim().split(/\r?\n/).map(JSON.parse);

const base = { cve: "CVE-2026-00001", severity: "Important", customer_action_required: true, cvss: { base_score: 7.8 }, attack: { vector: "network", privileges_required: "none", user_interaction: "none" }, threat: {}, inference: { framework_assessment: { risk_model_version: "2026.09.1", baseline_model: "standard-remediation", baseline_likelihood: "Plausible", baseline_action: "Scheduled", confidence: "high", factors: {}, risk_communication: {} } } };
const withSsvc = options => ({ ...base, cve_program: { status: "found", ssvc: options } });

assert.equal(ssvc(withSsvc({ exploitation: "none" })).exploitation, "none");
assert.equal(ssvc({ ...base, cve_program: { status: "found", ssvc: null } }), null);
assert.equal(ssvc({ ...base, cve_program: { status: "not-published", ssvc: null } }), null);
assert.equal(ssvc(base), null, "a record with no enrichment block has no SSVC");

// A public proof of concept that no other signal reflects is the whole point.
{
  const status = reviewStatus(withSsvc({ exploitation: "poc", automatable: "no", technical_impact: "total" }));
  const reason = status.reasons.find(item => item.code === "public-exploit-evidence");
  assert.ok(reason, "a poc with no KEV and no vendor detection must be flagged");
  assert.ok(!reason.informational, "public exploit evidence is a hold, not context");
  assert.match(reason.evidence, /Exploitation: poc/);
}

// Already known: KEV and the vendor both say so, so there is nothing new to surface.
{
  const known = { ...withSsvc({ exploitation: "active" }), threat: { kev: true } };
  assert.equal(reviewStatus(known).reasons.some(item => item.code === "public-exploit-evidence"), false, "SSVC must not re-flag what KEV already carries");
}

// The default value is a null signal and must never fire.
{
  const quiet = reviewStatus(withSsvc({ exploitation: "none", automatable: "no", technical_impact: "total" }));
  assert.equal(quiet.reasons.some(item => item.code === "public-exploit-evidence"), false);
  assert.equal(quiet.required, false, "an ordinary record must not be held by SSVC alone");
}

// Automatable is context, not a hold: 116 records carry it.
{
  const status = reviewStatus(withSsvc({ exploitation: "none", automatable: "yes" }));
  const reason = status.reasons.find(item => item.code === "automatable");
  assert.ok(reason);
  assert.equal(reason.informational, true);
  assert.equal(status.required, false);
}

// Technical Impact is only surfaced where no vendor severity exists.
{
  const unrated = reviewStatus({ ...withSsvc({ exploitation: "none", technical_impact: "total" }), severity: "Unknown" });
  assert.ok(unrated.reasons.some(item => item.code === "ssvc-technical-impact"));
  const rated = reviewStatus(withSsvc({ exploitation: "none", technical_impact: "total" }));
  assert.equal(rated.reasons.some(item => item.code === "ssvc-technical-impact"), false, "where the vendor rated it, Technical Impact restates the severity");
}

// Absence is recorded as absence.
{
  const status = reviewStatus({ ...base, cve_program: { status: "found", ssvc: null, ssvc_absent_reason: "no CISA-ADP SSVC assessment" } });
  const reason = status.reasons.find(item => item.code === "ssvc-absent");
  assert.ok(reason, "a record with no SSVC must say so rather than read as quiet");
  assert.equal(reason.informational, true);
}

// THE TRAP. "none" is an evidentiary status, not a prediction, and SSVC is CISA's
// judgement rather than the vendor's. If any code path lets it reach the risk model,
// likelihood is suppressed by one step across the 1055 records carrying "none".
//
// Asserted as a property over every published record rather than over a hand-built
// fixture: a fixture only catches a leak its own values happen to expose, and the first
// version of this test passed against a mutation that forced likelihood to zero on
// "none" because its baseline was already zero. Stripping the block from real records
// and requiring an identical profile catches any path, on any value.
{
  for (const record of records) {
    const { cve_program, ...stripped } = record;
    if (!cve_program) continue;
    assert.deepEqual(baselineProfile(record), baselineProfile(stripped), `${record.cve}: SSVC reached the deterministic baseline`);
    assert.deepEqual(predictProfile(record).baseline, predictProfile(stripped).baseline, `${record.cve}: SSVC reached the predicted profile`);
  }
}

// The property test above is necessary but not sufficient, and it is worth saying why.
// baselineProfile takes Math.max of the evidence likelihood and the framework's saved
// likelihood, so on a record carrying a usable assessment the deterministic floor is
// masked and a leak into it is unobservable. Three separate mutations that wired SSVC
// into the risk path passed the property test for exactly that reason.
//
// The floor is only in force where no usable assessment exists - which is a real state,
// not a contrived one. This fixture exposes that path, so a leak becomes observable.
{
  const unassessed = { ...base, threat: {}, inference: { model: "none" } };
  const quiet = { ...unassessed, cve_program: { status: "found", ssvc: { exploitation: "none", automatable: "no", technical_impact: "partial" } } };
  const loud = { ...unassessed, cve_program: { status: "found", ssvc: { exploitation: "active", automatable: "yes", technical_impact: "total" } } };
  const reference = baselineProfile(unassessed);
  assert.deepEqual(baselineProfile(quiet), reference, "SSVC \"none\" must not lower the deterministic floor; 96 records have no vendor assessment either, and their floor would drop from Plausible to Low evidence");
  assert.deepEqual(baselineProfile(loud), reference, "SSVC \"active\" must not raise the deterministic floor; KEV does that, because a KEV listing is a fact and SSVC is an assessment");
}

// Against the published month.
const enriched = records.filter(record => record.cve_program);
if (enriched.length) {
  const withDecision = enriched.filter(record => ssvc(record));
  assert.ok(withDecision.length / records.length > 0.8, `SSVC coverage collapsed to ${(withDecision.length / records.length * 100).toFixed(1)}%; the enrichment is stale or the fetch failed`);
  const flagged = records.filter(record => reviewStatus(record).reasons.some(item => item.code === "public-exploit-evidence"));
  for (const record of flagged) {
    assert.equal(record.threat?.kev || false, false, `${record.cve} is in KEV and must not also raise public-exploit-evidence`);
  }
  console.log(`SSVC checks passed: ${withDecision.length} of ${records.length} records carry a decision, ${flagged.length} raise public exploit evidence.`);
} else {
  console.log("SSVC checks passed against fixtures; the published month carries no enrichment block yet.");
}
