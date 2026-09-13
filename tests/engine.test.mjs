import assert from "node:assert/strict";
import { archetypeMismatch, formatEpss, formatMicrosoftAssessment, matchesSmartSearch, parseJsonl, predictProfile, reviewStatus } from "../engine.js";

// Severity is a vendor-plural object; the risk path reads `normalized_band`. A
// bare string resolves to unknown by design, so fixtures state the band.
const MSRC = { critical: "Critical", high: "Important", medium: "Moderate", low: "Low" };
function band(value) {
  if (value === "unknown") return { assessments: [], primary: null, normalized_band: "unknown", normalized_basis: "absent" };
  return {
    assessments: [{ source: "microsoft", role: "publisher", scale: "msrc", value: MSRC[value], basis: "vendor" }],
    primary: "microsoft",
    normalized_band: value,
    normalized_basis: "scale-mapping:msrc:1.0",
  };
}

const active = parseJsonl(JSON.stringify({
  month: "2026-Sep", cve: "CVE-TEST-1", severity: band("critical"), tags: ["server"],
  attack: { vector: "network", privileges_required: "none", user_interaction: "none" },
  threat: { kev: true, epss: 0.9 },
  mitigation_candidates: [{ id: "vendor_workaround", relevance: "relevant", confidence: "high", effect: { likelihood_steps: 2, consequence_steps: 1, path_block: true } }]
}))[0];

const activeProfile = predictProfile(active, new Set(["vendor_workaround"]));
assert.equal(activeProfile.baseline.action, "Immediate");
assert.equal(activeProfile.residual.action, "Out-of-cycle", "Known exploitation keeps an out-of-cycle floor");

const local = { ...active, cve: "CVE-TEST-2", severity: band("high"), attack: { vector: "local", privileges_required: "low", user_interaction: "none" }, threat: { kev: false, exploitation_assessment: "less-likely", epss: 0.001 }, mitigation_candidates: [{ id: "segmentation_acl", relevance: "not-relevant", confidence: "high", effect: { likelihood_steps: 1 } }] };
const localProfile = predictProfile(local, new Set(["segmentation_acl"]));
assert.equal(localProfile.baseline.action, localProfile.residual.action, "An irrelevant mitigation receives no credit");

const unknown = { ...local, mitigation_candidates: [{ id: "segmentation_acl", relevance: "unknown", confidence: "high", effect: { likelihood_steps: 1, consequence_steps: 1 } }] };
const unknownProfile = predictProfile(unknown, new Set(["segmentation_acl"]));
assert.equal(unknownProfile.applied.length, 0, "An unknown exploit-path relationship receives no credit");
assert.equal(unknownProfile.baseline.action, unknownProfile.residual.action, "Unknown relevance must not alter the predicted profile");

const noAction = { ...active, cve: "CVE-TEST-3", customer_action_required: false };
const noActionProfile = predictProfile(noAction, new Set());
assert.equal(noActionProfile.residual.action, "Defer and review", "Microsoft no-action records do not create patch work");

assert.equal(formatEpss(null), "Not yet scored");
assert.equal(formatEpss(0.00623), "0.62%");
assert.equal(formatEpss(0.00996), "0.996%", "Display must not round sub-1% evidence across a policy threshold");
assert.equal(formatEpss(0.0996), "9.96%", "Display must not imply the 10% threshold was reached");
assert.equal(formatEpss(0), "0.00%");
assert.equal(formatMicrosoftAssessment("unlikely"), "Unlikely");
assert.equal(formatMicrosoftAssessment("unknown"), "Not published");

const unlikelyCritical = {
  ...active,
  cve: "CVE-TEST-4",
  threat: { kev: false, exploitation_detected: false, exploitation_assessment: "unlikely", epss: null },
};
const unlikelyProfile = predictProfile(unlikelyCritical, new Set());
assert.equal(unlikelyProfile.baseline.likelihood, "Low evidence");
assert.equal(unlikelyProfile.baseline.action, "Out-of-cycle");

const moreLikely = {
  ...unlikelyCritical,
  cve: "CVE-TEST-5",
  threat: { kev: false, exploitation_detected: false, exploitation_assessment: "more-likely", epss: null },
};
assert.equal(predictProfile(moreLikely, new Set()).baseline.likelihood, "Elevated");

const frameworkReviewed = {
  ...moreLikely,
  severity: band("high"),
  inference: {
    framework_assessment: {
      risk_model_version: "2026.09.1",
      baseline_model: "elevated-high-severity",
      baseline_likelihood: "Elevated",
      baseline_action: "Immediate",
      risk_communication: { why_this_action: "Combined threat and workload evidence warrants immediate triage." },
    },
  },
};
const frameworkProfile = predictProfile(frameworkReviewed, new Set());
assert.equal(frameworkProfile.baseline.action, "Immediate", "A validated framework assessment may refine the fallback archetype");
assert.equal(frameworkProfile.baseline.model, "elevated-high-severity");
assert.equal(frameworkProfile.baseline.model_version, "2026.09.1");

const ordinaryNetworkIssue = {
  ...moreLikely,
  severity: band("medium"),
  attack: { vector: "network", privileges_required: "none", user_interaction: "required" },
  threat: { exploitation_assessment: "unlikely", kev: false, exploitation_detected: false, epss: 0.001 },
  tags: ["information-disclosure"],
};
assert.equal(
  predictProfile(ordinaryNetworkIssue, new Set()).baseline.action,
  "Scheduled",
  "Network reachability alone must not trigger an out-of-cycle deterministic floor",
);

const searchable = {
  ...unlikelyCritical,
  cve: "CVE-2026-69829",
  title: "Windows Shell Remote Code Execution Vulnerability",
  tags: ["windows", "server-2016", "windows-shell"],
  products: [{ name: "Windows Server 2016", product_id: "10816" }],
  cvss: { base_score: 9.8 },
  mitigation_candidates: [{ id: "segmentation_acl", evidence: "Restrict in-network access" }],
};
assert.equal(matchesSmartSearch(searchable, "69829"), true);
assert.equal(matchesSmartSearch(searchable, '"windows shell" tag:server-2016'), true);
assert.equal(matchesSmartSearch(searchable, "cvss:>=9 microsoft:unlikely vector:network"), true);
assert.equal(matchesSmartSearch(searchable, "kev:true"), false);
assert.equal(matchesSmartSearch(searchable, "-tag:windows-shell"), false);

// ---------------------------------------------------------------------------
// The saved archetype is a claim about the record's inputs, not a judgement.
// `selectBaselineModel` is deterministic, so a saved label that disagrees is
// describing some other record. Direction decides what happens next: understating
// raises the remediation floor, overstating leaves the date alone and says the
// stated reasoning is wrong.
// ---------------------------------------------------------------------------
function assessed(model, action, likelihood = "Low evidence") {
  return {
    inference: {
      review_status: "reviewed",
      framework_assessment: {
        risk_model_version: "2026.09.1",
        baseline_model: model,
        baseline_action: action,
        baseline_likelihood: likelihood,
        confidence: "high",
        factors: { applicability: "a", threat_evidence: "a", exploitability: "a", technical_impact: "a", workload_context: "a", remediation_context: "a", uncertainty: "a" },
        risk_communication: { summary: "s", why_this_action: "w", control_limitations: "c", reassessment_triggers: ["t"] },
      },
    },
  };
}

const archetypeBase = {
  cve: "CVE-TEST-ARCH",
  customer_action_required: true,
  cvss: { base_score: 7.8, vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" },
  attack: { vector: "local", privileges_required: "low", user_interaction: "none" },
  threat: { exploitation_assessment: "unlikely", kev: false, exploitation_detected: false, epss: 0.001 },
  tags: ["elevation-of-privilege"],
  mitigation_candidates: [],
};

const agreeing = { ...archetypeBase, severity: band("high"), ...assessed("standard-remediation", "Scheduled") };
assert.equal(archetypeMismatch(agreeing), null, "an archetype the record's facts select is not a mismatch");
assert.ok(!reviewStatus(agreeing).reasons.some(r => r.code === "archetype-contradicts-severity"), "an agreeing archetype must not be flagged");

// Understating: a critical band called routine remediation. This is the direction
// that gets an administrator hurt, and the two 2026-Sep records in it -
// CVE-2026-69799 and CVE-2026-69864 - were published as Normal scheduled.
const understating = { ...archetypeBase, severity: band("critical"), ...assessed("standard-remediation", "Scheduled") };
const understated = archetypeMismatch(understating);
assert.equal(understated?.determined, "critical-technical");
assert.equal(understated?.understates, true);
assert.equal(predictProfile(understating, new Set()).baseline.action, "Out-of-cycle", "a critical band must raise the remediation floor above the saved Scheduled");
assert.ok(reviewStatus(understating).reasons.some(r => r.code === "archetype-contradicts-severity"), "an understating archetype must be flagged");
assert.equal(reviewStatus(understating).required, true);

// Overstating: `critical-technical` claimed where no vendor rated it critical.
// Errs towards patching sooner, so the date stands; the rationale is still false
// and the reader is told so rather than the action being lowered underneath them.
const overstating = { ...archetypeBase, severity: band("high"), ...assessed("critical-technical", "Out-of-cycle") };
const overstated = archetypeMismatch(overstating);
assert.equal(overstated?.determined, "standard-remediation");
assert.equal(overstated?.understates, false);
assert.equal(predictProfile(overstating, new Set()).baseline.action, "Out-of-cycle", "an overstating archetype must not lower the published action");
assert.ok(reviewStatus(overstating).reasons.some(r => r.code === "archetype-contradicts-severity"), "an overstating archetype must still be flagged");
// The action is unchanged either way, so only the written reason distinguishes a
// floor that was applied from one that was not. Without this, dropping the
// direction guard is an equivalent mutation on the number and a false sentence in
// the explanation: the reader would be told a higher floor applied when none did.
assert.ok(
  !predictProfile(overstating, new Set()).reasons.some(reason => /higher remediation floor applies/.test(reason)),
  "an overstating archetype must not claim a remediation floor was applied",
);
assert.ok(
  predictProfile(understating, new Set()).reasons.some(reason => /higher remediation floor applies/.test(reason)),
  "an understating archetype must say why the floor rose",
);

// A superseded assessment is already set aside, so it must not be double-reported
// as an archetype mismatch on top of that.
const superseded = {
  ...archetypeBase,
  severity: { assessments: [{ source: "Chrome", role: "assigning-cna", scale: "chromium", value: "Critical", basis: "vendor" }], primary: "Chrome", normalized_band: "critical", normalized_basis: "scale-mapping:chromium:1.0" },
  ...assessed("standard-remediation", "Scheduled"),
};
assert.equal(archetypeMismatch(superseded), null, "a superseded assessment is set aside, not reported twice");
assert.ok(reviewStatus(superseded).reasons.some(r => r.code === "superseded-assessment"));

console.log("engine tests passed");
