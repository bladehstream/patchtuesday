import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assessmentSuperseded, issuingCna, cveProgramUrl, reviewStatus } from "../engine.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "data", "months.json"), "utf8"));
// These assertions describe September's Chrome records and superseded assessments,
// not the release that happens to be first in the month selector.
const published = manifest.find(item => item.month === "2026-Sep");
assert.ok(published, "the manifest must contain the historical September release");
const records = fs.readFileSync(path.join(root, "data", published.file), "utf8").trim().split(/\r?\n/).map(JSON.parse);

// CVRF note Type 8 is the assigning CNA. Microsoft declines to rate a CVE it did not
// assign, so severity, CVSS and the Exploitability Index are all absent by policy.
const note = (type, title) => ({ type, title, value: "x" });
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

const base = { cve: "CVE-2026-84353", severity: band("unknown"), customer_action_required: true };

assert.equal(issuingCna({ vendor_guidance: { notes: [note(8, "Chrome")] } }), "Chrome");
assert.equal(issuingCna({ vendor_guidance: { notes: [note(8, "Microsoft")] } }), "Microsoft");
assert.equal(issuingCna({ vendor_guidance: { notes: [note(4, "Chrome"), note(2, "Description")] } }), null, "only a Type 8 note names the CNA");
assert.equal(issuingCna({ vendor_guidance: { notes: [note(8, "   ")] } }), null, "a blank title is not a CNA");
assert.equal(issuingCna({}), null);

assert.equal(cveProgramUrl("CVE-2026-84353"), "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/84xxx/CVE-2026-84353.json");
assert.equal(cveProgramUrl("CVE-2026-1234"), "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/CVE-2026-1234.json");
assert.equal(cveProgramUrl("CVE-2026-999"), "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/0xxx/CVE-2026-999.json", "a sub-thousand serial buckets to 0xxx");
assert.equal(cveProgramUrl("not-a-cve"), null);
assert.equal(cveProgramUrl(undefined), null);

// An unrated third-party CVE must say whose rating to go and read, or the review flag
// is a dead end: it tells the reviewer to establish the severity and gives no source.
{
  const status = reviewStatus({ ...base, vendor_guidance: { notes: [note(8, "Chrome")] } });
  const reason = status.reasons.find(item => item.code === "missing-vendor-severity");
  assert.ok(reason, "an Unknown severity must still be flagged");
  assert.match(reason.message, /Chrome assigned it/, "the message must name the assigning CNA");
  assert.match(reason.evidence, /cvelistV5/, "the evidence must point at the CVE Program record");
}

// A Microsoft-assigned CVE must not be told to go read someone else's rating.
{
  const status = reviewStatus({ ...base, vendor_guidance: { notes: [note(8, "Microsoft")] } });
  const reason = status.reasons.find(item => item.code === "missing-vendor-severity");
  assert.ok(reason);
  assert.doesNotMatch(reason.message, /assigned it/, "no third-party framing for a Microsoft CVE");
  assert.equal(status.reasons.some(item => item.code === "third-party-cna"), false);
}

// Rated by Microsoft but assigned elsewhere: two different scales, worth naming.
{
  const complete = { ...base, severity: band("high"), cvss: { base_score: 7.8 }, attack: { vector: "local", privileges_required: "low", user_interaction: "none" }, inference: { framework_assessment: null, model: "none" } };
  const status = reviewStatus({ ...complete, inference: undefined, vendor_guidance: { notes: [note(8, "GitHub_M")] } });
  const surfaced = status.reasons.find(item => item.code === "third-party-cna");
  assert.ok(surfaced, "a third-party assignment must be surfaced even when Microsoft rated it");
  assert.equal(surfaced.informational, true, "a rated CVE with a third-party CNA is context, not a hold");
  assert.equal(status.reasons.filter(item => !item.informational).length, 1, "the only hold should be the missing assessment, not the CNA note");
  assert.equal(reviewStatus({ ...complete, vendor_guidance: { notes: [note(8, "GitHub_M")] }, inference: { framework_assessment: { risk_model_version: "2026.09.1", baseline_model: "standard-remediation", baseline_likelihood: "Plausible", baseline_action: "Scheduled", confidence: "high", factors: {}, risk_communication: {} } } }).required, false, "informational context alone must not force review");
  assert.equal(status.reasons.some(item => item.code === "missing-vendor-severity"), false, "a rated CVE is not missing a severity");
}

// And must not fire for the ordinary case, or it fires on 973 of 1,185 records.
{
  const status = reviewStatus({ ...base, severity: band("high"), vendor_guidance: { notes: [note(8, "Microsoft")] } });
  assert.equal(status.reasons.some(item => item.code === "third-party-cna"), false);
}

// Against the September release: every Chrome-CNA record is unrated by Microsoft and
// every one of them is flagged. If this ever reads zero, the detector has gone blind.
const chrome = records.filter(record => issuingCna(record) === "Chrome");
assert.ok(chrome.length > 0, "the published month must contain Chrome-CNA records");
// Microsoft still rates none of them. The band they now carry is Google's own
// tier, read from the CVE Program record and attributed to Chrome, so the guard
// moves from "no band at all" to "no band from the publisher" - which is what it
// was always actually asserting.
assert.equal(
  chrome.filter(record => (record.severity?.assessments || []).some(item => item.role === "publisher")).length,
  0,
  "Microsoft does not rate Chrome-assigned CVEs; a publisher assessment here means the severity path invented one",
);
assert.equal(
  chrome.filter(record => record.severity?.primary !== "Chrome").length,
  0,
  "a Chrome-assigned record's severity must be attributed to Chrome, not to the publisher",
);
assert.ok(
  chrome.some(record => record.severity?.normalized_band === "critical"),
  "Google rates one September Chromium record Critical; if none is critical the tier is not being read",
);
// They stay flagged, but for the accurate reason. missing-vendor-severity is now
// false of them - Google published a band - and asserting it would be asserting
// something untrue. What holds them is that the saved model assessment reasoned
// from "no vendor severity exists", which Google's tier has superseded.
for (const record of chrome) {
  const status = reviewStatus(record);
  assert.ok(status.required, `${record.cve} must still be flagged`);
  assert.ok(
    status.reasons.some(item => item.code === "superseded-assessment"),
    `${record.cve} must carry superseded-assessment: its assessment predates Google's band`,
  );
  assert.equal(
    status.reasons.some(item => item.code === "missing-vendor-severity"),
    false,
    `${record.cve} is rated by Google, so missing-vendor-severity would be false`,
  );
}

const thirdParty = records.filter(record => { const cna = issuingCna(record); return cna && cna !== "Microsoft"; });
assert.ok(thirdParty.length >= chrome.length, "third-party CNAs are not only Chrome");

// A current monthly assessment already considered the CNA band/disagreement.
// Retain that evidence flag, but supersede only when the assessed facts change.
{
  const severity = { ...band("high"), normalized_band: "critical", normalized_basis: "scale-mapping:chromium:1.0",
    assessments: [...band("high").assessments,
      { source: "Chrome", role: "assigning-cna", scale: "chromium", value: "Critical", basis: "vendor" }],
    divergence: { kind: "scale" },
  };
  const severity_basis = structuredClone({ primary: severity.primary, normalized_band: severity.normalized_band,
    normalized_basis: severity.normalized_basis, assessments: severity.assessments });
  const fresh = { ...base, severity, inference: { severity_basis, model: "claude-haiku-5-5", framework_assessment: {
    risk_model_version: "2026.09.1", baseline_model: "critical-technical", baseline_likelihood: "Plausible",
    baseline_action: "Out-of-cycle", confidence: "medium", factors: {}, risk_communication: {},
  } } };
  assert.equal(assessmentSuperseded(fresh), false, "a fresh known disagreement does not supersede the assessment");
  assert.ok(reviewStatus(fresh).reasons.some(item => item.code === "severity-divergence"));
  assert.ok(!reviewStatus(fresh).reasons.some(item => item.code === "superseded-assessment"));
  assert.equal(assessmentSuperseded({ ...fresh, severity: { ...severity, assessments: [...severity.assessments].reverse() } }), false,
    "reordering the same source facts does not change their basis");
  const changed = structuredClone(fresh);
  changed.severity.assessments[0].value = "Moderate";
  assert.equal(assessmentSuperseded(changed), true, "a source assessment change matters even within the same winning band");
  assert.ok(reviewStatus(changed).reasons.some(item => item.code === "superseded-assessment"));
  const cnaOnly = { ...severity, primary: "Chrome", assessments: severity.assessments.slice(1) };
  assert.equal(assessmentSuperseded({ ...fresh, severity: cnaOnly,
    inference: { ...fresh.inference, severity_basis: structuredClone(cnaOnly) } }), false, "a fresh CNA-only basis stays usable");
  assert.equal(assessmentSuperseded({ ...fresh, inference: {} }), true, "legacy divergence still supersedes");
}

console.log(`September third-party CNA checks passed: ${chrome.length} Chrome-assigned and ${thirdParty.length} third-party records across ${new Set(records.map(issuingCna).filter(Boolean)).size} CNAs.`);
