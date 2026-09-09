import assert from "node:assert/strict";
import { formatEpss, parseJsonl, predictProfile } from "../engine.js";

const active = parseJsonl(JSON.stringify({
  month: "2026-Sep", cve: "CVE-TEST-1", severity: "Critical", tags: ["server"],
  attack: { vector: "network", privileges_required: "none", user_interaction: "none" },
  threat: { kev: true, epss: 0.9 },
  mitigation_candidates: [{ id: "vendor_workaround", relevance: "relevant", confidence: "high", effect: { likelihood_steps: 2, consequence_steps: 1, path_block: true } }]
}))[0];

const activeProfile = predictProfile(active, new Set(["vendor_workaround"]));
assert.equal(activeProfile.baseline.action, "Immediate");
assert.equal(activeProfile.residual.action, "Out-of-cycle", "Known exploitation keeps an out-of-cycle floor");

const local = { ...active, cve: "CVE-TEST-2", severity: "Important", attack: { vector: "local", privileges_required: "low", user_interaction: "none" }, threat: { kev: false, exploitation_assessment: "less-likely", epss: 0.001 }, mitigation_candidates: [{ id: "segmentation_acl", relevance: "not-relevant", confidence: "high", effect: { likelihood_steps: 1 } }] };
const localProfile = predictProfile(local, new Set(["segmentation_acl"]));
assert.equal(localProfile.baseline.action, localProfile.residual.action, "An irrelevant mitigation receives no credit");

const noAction = { ...active, cve: "CVE-TEST-3", customer_action_required: false };
const noActionProfile = predictProfile(noAction, new Set());
assert.equal(noActionProfile.residual.action, "Defer and review", "Microsoft no-action records do not create patch work");

assert.equal(formatEpss(null), "Not yet scored");
assert.equal(formatEpss(0.00623), "0.62%");
assert.equal(formatEpss(0), "0.00%");

console.log("engine tests passed");
