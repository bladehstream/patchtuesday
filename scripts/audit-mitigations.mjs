import assert from "node:assert/strict";
import fs from "node:fs";
import { ACTIONS, LIKELIHOOD, parseJsonl, predictProfile } from "../engine.js";
import { RISK_MODEL } from "../risk-model.js";

const records = parseJsonl(fs.readFileSync(new URL("../data/2026-Sep.jsonl", import.meta.url), "utf8"));
const catalog = JSON.parse(fs.readFileSync(new URL("../data/mitigation-catalog.json", import.meta.url), "utf8"));
const reviewed = records.filter(record => record.inference?.framework_assessment);
const priorSamples = new Set(["CVE-2026-81963", "CVE-2026-85880", "CVE-2026-69730", "CVE-2026-69829"]);

function random(seed) {
  let value = seed >>> 0;
  return () => {
    value += 0x6d2b79f5;
    let result = value;
    result = Math.imul(result ^ result >>> 15, result | 1);
    result ^= result + Math.imul(result ^ result >>> 7, result | 61);
    return ((result ^ result >>> 14) >>> 0) / 4294967296;
  };
}

function shuffled(values, seed) {
  const output = [...values];
  const next = random(seed);
  for (let index = output.length - 1; index > 0; index -= 1) {
    const other = Math.floor(next() * (index + 1));
    [output[index], output[other]] = [output[other], output[index]];
  }
  return output;
}

function eligible(candidate) {
  return candidate.relevance === "relevant" && candidate.confidence !== "low";
}

function sameProfile(left, right) {
  return left.likelihood === right.likelihood && left.action === right.action;
}

function auditRecord(record) {
  const baseline = predictProfile(record, new Set());
  const candidateIds = new Set(record.mitigation_candidates.map(candidate => candidate.id));
  const unrelated = catalog.find(control => !candidateIds.has(control.id));
  assert.ok(unrelated, `${record.cve}: expected an unrelated catalogue control`);
  const unrelatedProfile = predictProfile(record, new Set([unrelated.id]));
  assert.equal(unrelatedProfile.applied.length, 0, `${record.cve}: unrelated control was applied`);
  assert.ok(sameProfile(unrelatedProfile.residual, baseline.residual), `${record.cve}: unrelated control changed risk`);

  const selected = new Set(record.mitigation_candidates.map(candidate => candidate.id));
  const profile = predictProfile(record, selected);
  const expected = record.mitigation_candidates.filter(eligible).map(candidate => candidate.id).sort();
  assert.deepEqual(profile.applied.map(candidate => candidate.id).sort(), expected, `${record.cve}: eligible mitigation mismatch`);
  assert.ok(LIKELIHOOD.indexOf(profile.residual.likelihood) <= LIKELIHOOD.indexOf(profile.baseline.likelihood), `${record.cve}: mitigation raised likelihood`);
  assert.ok(ACTIONS.indexOf(profile.residual.action) <= ACTIONS.indexOf(profile.baseline.action), `${record.cve}: mitigation raised action`);
  const model = RISK_MODEL.baselineModels[profile.baseline.model];
  const exactPathBlock = profile.applied.some(candidate => candidate.confidence === "high" && candidate.effect?.path_block);
  const floor = exactPathBlock ? model.floorWithPathBlock : model.floorWithoutPathBlock;
  assert.ok(ACTIONS.indexOf(profile.residual.action) >= floor, `${record.cve}: mitigation broke the ${profile.baseline.model} floor`);

  for (const candidate of profile.applied) {
    if (["remove_external_exposure", "segmentation_acl", "exploit_specific_ips", "waf_virtual_patch"].includes(candidate.id)) {
      assert.ok(["network", "adjacent"].includes(record.attack.vector), `${record.cve}: network control credited to ${record.attack.vector}`);
    }
    if (["email_web_filtering", "office_protected_view"].includes(candidate.id)) {
      assert.ok(record.tags.includes("user-content"), `${record.cve}: content control lacks a user-content exploit path`);
    }
    if (["edr_detection_response", "immutable_backups"].includes(candidate.id)) {
      assert.equal(candidate.effect?.likelihood_steps || 0, 0, `${record.cve}: response/recovery control reduced exploit likelihood`);
    }
  }
  return profile;
}

for (const record of reviewed) auditRecord(record);

const samples = shuffled(reviewed.filter(record => !priorSamples.has(record.cve)), 0x20260910).slice(0, 20);
assert.equal(samples.length, 20, "Expected twenty new random spot checks");
console.log("Random mitigation spot checks (seed 0x20260910):");
for (const record of samples) {
  const profile = auditRecord(record);
  const applied = profile.applied.map(candidate => candidate.id).join(", ") || "none";
  console.log(`${record.cve}\t${profile.baseline.action}/${profile.baseline.likelihood}\t→ ${profile.residual.action}/${profile.residual.likelihood}\t${applied}`);
}
console.log(`Mitigation audit passed: ${reviewed.length} reviewed records checked; ${samples.length} random records reported.`);

const overlays = fs.readFileSync(new URL("../inference/2026-Sep-luna.jsonl", import.meta.url), "utf8").trim().split(/\r?\n/).map(JSON.parse);
assert.equal(overlays.length, reviewed.length, "Every Luna output must have a published reviewed record");
const denied = {
  "CVE-2026-81963": ["edr_detection_response", "attack_surface_reduction"],
  "CVE-2026-85880": ["edr_detection_response", "attack_surface_reduction"],
  "CVE-2026-65669": catalog.map(m => m.id),
  "CVE-2026-69769": ["remove_external_exposure"],
  "CVE-2026-69829": ["remove_external_exposure"],
  "CVE-2026-69845": ["remove_external_exposure"],
  "CVE-2026-77493": ["office_protected_view"],
  "CVE-2026-78510": ["office_protected_view"],
};
let combinations = 0;
for (const overlay of overlays) {
  const record = records.find(r => r.cve === overlay.cve);
  assert.deepEqual(record.inference.framework_assessment, overlay.framework_assessment);
  assert.deepEqual(record.mitigation_candidates, overlay.mitigation_candidates);
  assert.deepEqual(overlay.cvss_basis, {
    base_score: record.cvss.base_score, vector: record.cvss.vector,
    attack_vector: record.attack.vector, privileges_required: record.attack.privileges_required,
    user_interaction: record.attack.user_interaction,
  });
  assert.ok(record.inference.verification || record.inference.pipeline_validation, record.cve + ": missing validation provenance");
  const ids = record.mitigation_candidates.filter(c => eligible(c) && ((c.effect?.likelihood_steps || 0) > 0 || (c.effect?.consequence_steps || 0) > 0)).map(c => c.id);
  for (let mask = 0; mask < 2 ** ids.length; mask += 1) {
    const selection = new Set(ids.filter((_, i) => mask & (1 << i)));
    const result = predictProfile(record, selection);
    const base = predictProfile(record);
    assert.equal(result.baseline.action, base.baseline.action);
    assert.equal(result.baseline.likelihood, base.baseline.likelihood);
    if (record.customer_action_required !== false) {
      assert.ok(ACTIONS.indexOf(result.residual.action) >= 1, record.cve + ": ordinary controls erased patch obligation");
      const maxCredit = result.applied.some(c => c.confidence === "high" && c.effect?.path_block) ? 2 : 1;
      assert.ok(LIKELIHOOD.indexOf(base.baseline.likelihood) - LIKELIHOOD.indexOf(result.residual.likelihood) <= maxCredit, record.cve + ": overlapping controls stacked");
    }
    combinations += 1;
  }
  for (const id of denied[record.cve] || []) {
    const result = predictProfile(record, new Set([id]));
    assert.equal(result.applied.length, 0, record.cve + ": unsupported " + id);
    assert.ok(sameProfile(result.baseline, result.residual));
  }
}
let catalogueScenarios = 0;
for (const record of records) {
  for (const control of catalog) {
    const result = predictProfile(record, new Set([control.id]));
    if (!record.mitigation_candidates.some(c => c.id === control.id && eligible(c))) {
      assert.equal(result.applied.length, 0);
      assert.ok(sameProfile(result.baseline, result.residual), record.cve + ": unrelated catalogue control changed result");
    }
    catalogueScenarios += 1;
  }
}
const oldAssessment = records.find(r => r.cve === "CVE-2026-69829");
for (const threat of [
  { ...oldAssessment.threat, exploitation_assessment: "more-likely" },
  { ...oldAssessment.threat, epss: 0.25 },
]) {
  const result = predictProfile({ ...oldAssessment, threat }, new Set(["segmentation_acl"]));
  assert.equal(result.baseline.likelihood, "Elevated", "New public evidence must override stale inference");
  assert.equal(result.baseline.action, "Immediate");
  assert.equal(result.residual.action, "Out-of-cycle");
}
const localRecord = records.find(r => r.cve === "CVE-2026-81963");
const invalid = { id: "segmentation_acl", relevance: "relevant", confidence: "high", effect: { likelihood_steps: 1, consequence_steps: 1 } };
assert.equal(predictProfile({ ...localRecord, mitigation_candidates: [invalid] }, new Set([invalid.id])).applied.length, 0);
assert.equal(predictProfile({ ...localRecord, mitigation_candidates: [{ ...invalid, id: "edr_detection_response" }] }, new Set(["edr_detection_response"])).applied.length, 0);
console.log("Complete review checks passed: " + combinations + " control combinations and " + catalogueScenarios + " catalogue scenarios across " + records.length + " records.");
