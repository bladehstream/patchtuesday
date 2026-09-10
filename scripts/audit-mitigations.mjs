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
