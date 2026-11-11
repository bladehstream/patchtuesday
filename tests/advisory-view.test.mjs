import assert from "node:assert/strict";
import fs from "node:fs";
import { performance } from "node:perf_hooks";
import { nextAdvisorySort, sortAdvisories, sourcePlainText, microsoftSourceContent, microsoftSourceHtml } from "../advisory-view.js";

function record(cve, options = {}) {
  return {
    cve, customer_action_required: true,
    severity: { normalized_band: "high", primary: "microsoft", assessments: [{ source: "microsoft", role: "publisher", scale: "msrc", value: "Important", basis: "vendor" }] },
    attack: { vector: "network", privileges_required: "none", user_interaction: "none" },
    tags: ["information-disclosure"], threat: { exploitation_assessment: "less-likely", epss: null }, cvss: { base_score: 7 },
    mitigation_candidates: [], ...options,
  };
}
const ids = rows => rows.map(row => row.cve);
const sort = (rows, key, direction, selected) => ids(sortAdvisories(rows, { key, direction }, selected));
assert.deepEqual(nextAdvisorySort(null, "cve"), { key: "cve", direction: "asc" });
for (const key of ["threat", "baseline", "predicted"]) {
  assert.deepEqual(nextAdvisorySort(null, key), { key, direction: "desc" });
  assert.deepEqual(nextAdvisorySort({ key, direction: "desc" }, key), { key, direction: "asc" });
}
assert.equal(nextAdvisorySort(null, "invalid"), null);

const natural = [record("CVE-2026-100"), record("CVE-2025-2000"), record("CVE-2026-9")];
assert.deepEqual(sort(natural, "cve", "asc"), ["CVE-2025-2000", "CVE-2026-9", "CVE-2026-100"]);
assert.deepEqual(sort(natural, "cve", "desc"), ["CVE-2026-100", "CVE-2026-9", "CVE-2025-2000"]);
assert.equal(sortAdvisories(natural, null), natural, "No sort preserves the original default order");
assert.deepEqual(ids(natural), ["CVE-2026-100", "CVE-2025-2000", "CVE-2026-9"], "Sorting must not mutate source order");

const threat = [
  record("CVE-2026-1", { threat: { exploitation_assessment: "more-likely", epss: 0.02 }, cvss: { base_score: 4 } }),
  record("CVE-2026-2", { threat: { kev: true, epss: 0.01 }, cvss: { base_score: 3 } }),
  record("CVE-2026-3", { threat: { exploitation_assessment: "less-likely", epss: 0.03 }, cvss: { base_score: 9.8 } }),
];
assert.deepEqual(sort(threat, "threat", "desc"), ["CVE-2026-2", "CVE-2026-1", "CVE-2026-3"], "Active exploitation outranks technical score alone");
assert.deepEqual(sort(threat, "threat", "asc"), ["CVE-2026-3", "CVE-2026-1", "CVE-2026-2"]);
assert.deepEqual(sort([threat[0], record("CVE-2026-4", { customer_action_required: false, threat: { exploitation_detected: true } })], "threat", "desc"), ["CVE-2026-4", "CVE-2026-1"], "Confirmed exploitation still leads Threat when the vendor requires no customer action");
const scores = [
  record("CVE-2026-1", { threat: { exploitation_assessment: "less-likely", epss: null } }),
  record("CVE-2026-2", { threat: { exploitation_assessment: "less-likely", epss: 0 }, cvss: { base_score: null } }),
  record("CVE-2026-3", { threat: { exploitation_assessment: "less-likely", epss: 0 }, cvss: { base_score: 0 } }),
  record("CVE-2026-4", { threat: { exploitation_assessment: "less-likely", epss: 0 }, cvss: { base_score: 9.8 } }),
];
assert.deepEqual(sort(scores, "threat", "asc"), ["CVE-2026-3", "CVE-2026-4", "CVE-2026-2", "CVE-2026-1"]);
assert.deepEqual(sort(scores, "threat", "desc"), ["CVE-2026-4", "CVE-2026-3", "CVE-2026-2", "CVE-2026-1"], "Missing EPSS/CVSS stay last in both directions; zero is valid");

const routine = record("CVE-2026-9");
const urgent = record("CVE-2026-10", { threat: { exploitation_assessment: "more-likely" } });
const emergency = record("CVE-2026-11", { threat: { kev: true } });
for (const key of ["baseline", "predicted"]) {
  assert.deepEqual(sort([urgent, routine, emergency], key, "asc"), [routine.cve, urgent.cve, emergency.cve]);
  assert.deepEqual(sort([urgent, routine, emergency], key, "desc"), [emergency.cve, urgent.cve, routine.cve]);
  assert.deepEqual(sort([record("CVE-2026-10"), record("CVE-2026-9")], key, "desc"), ["CVE-2026-9", "CVE-2026-10"], "Risk ties use deterministic natural CVE order");
}
const mitigated = record("CVE-2026-1", { threat: { exploitation_assessment: "more-likely" }, mitigation_candidates: [{
  id: "segmentation_acl", relevance: "relevant", confidence: "high", effect: { likelihood_steps: 1, consequence_steps: 0, path_block: false },
}] });
assert.deepEqual(sort([urgent, mitigated], "predicted", "desc"), [mitigated.cve, urgent.cve]);
assert.deepEqual(sort([urgent, mitigated], "predicted", "desc", new Set(["segmentation_acl"])), [urgent.cve, mitigated.cve], "Predicted sorting responds to current mitigation scope");
assert.deepEqual(sort([urgent, mitigated], "baseline", "desc", new Set(["segmentation_acl"])), [mitigated.cve, urgent.cve], "Mitigations do not change baseline sorting");

const source = record("CVE-2026-95885", { source: { url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-95885" }, vendor_guidance: { notes: [
  { title: "Description", type: 2, value: "<p>A use after free &amp; other issue.</p>\\n" },
  { title: "Executive Summary", type: 2, value: "<p>Public executive summary.</p>" },
  { title: "FAQ", type: 4, value: "<p><strong>Is user interaction required?</strong></p>\\n<p>Yes, open a file.</p>\\n<p>Preview alone is insufficient.</p>\\n" },
] } });
assert.equal(microsoftSourceContent(source).summaries[0].label, "Microsoft executive summary");
const sourceHtml = microsoftSourceHtml(source);
assert.ok(sourceHtml.includes("A use after free &amp; other issue."));
assert.ok(sourceHtml.includes("<h4>Is user interaction required?</h4>"));
assert.ok(sourceHtml.includes("Yes, open a file.\n\nPreview alone is insufficient."));
assert.ok(!sourceHtml.includes("\\n") && !sourceHtml.includes("&lt;p&gt;"), "MSRC markup becomes readable paragraphs");
assert.ok(sourceHtml.includes("Microsoft Security Response Center"));
const absent = microsoftSourceHtml(record("CVE-2026-2", { inference: { summary: "AI narrative must not become vendor content" }, vendor_guidance: { cna: { description: "CNA text" } } }));
assert.ok(absent.includes("No Microsoft executive summary or description"));
assert.ok(absent.includes("No Microsoft FAQ"));
assert.ok(!absent.includes("AI narrative") && !absent.includes("CNA text"));
const longAnswer = "Full answer continues. ".repeat(200) + "END OF COMPLETE ANSWER";
const longHtml = microsoftSourceHtml(record("CVE-2026-3", { vendor_guidance: { notes: [{ title: "FAQ", value: `<p>Question?</p><p>${longAnswer}</p>` }] } }));
assert.ok(longHtml.includes('<details class="source-faq-details">') && longHtml.includes("END OF COMPLETE ANSWER"), "Long FAQ disclosure retains the complete answer");
assert.equal(sourcePlainText("<p>Safe &#38; &#x2014; text</p>"), "Safe & — text");
const hostileHtml = microsoftSourceHtml(record("CVE-2026-4", { source: { url: "javascript:alert(1)" }, vendor_guidance: { notes: [{ title: "FAQ", value: '<script>alert(1)</script><p>&lt;img src=x onerror=alert(1)&gt; &quot;quoted&quot;</p><img src=x onerror=alert(2)>' }] } }));
assert.ok(!hostileHtml.includes("<script") && !hostileHtml.includes("<img") && !hostileHtml.includes("javascript:"));
assert.ok(hostileHtml.includes("&lt;img src=x onerror=alert(1)&gt; &quot;quoted&quot;"), "Encoded source markup remains inert text");

const app = fs.readFileSync(new URL("../app.js", import.meta.url), "utf8");
const page = fs.readFileSync(new URL("../index.html", import.meta.url), "utf8");
assert.ok(app.includes("sortAdvisories(filteredRecords(), state.advisorySort, state.selectedMitigations)"), "Every filtered/live render uses current mitigation values");
assert.ok(app.includes("if (!records.some(record => record.cve === state.selectedCve))"), "Reordering retains selected CVE while it remains visible");
assert.ok(app.indexOf("${microsoftSourceHtml(record)}") < app.indexOf("${reviewSectionHtml(record.review)}"), "Vendor information precedes potentially lengthy review notices");
assert.ok(app.includes('aria-label="Assessment summary"'), "Model assessment is labelled separately from MSRC text");
for (const key of ["cve", "threat", "baseline", "predicted"]) assert.ok(page.includes(`data-advisory-sort="${key}"`));
assert.ok(app.includes('setAttribute("aria-sort"') && app.includes('setAttribute("aria-label"'), "Headers expose state and next action to assistive technology");

const november = fs.readFileSync(new URL("../data/2026-Nov.jsonl", import.meta.url), "utf8").trim().split(/\r?\n/).map(JSON.parse);
const started = performance.now();
for (const key of ["cve", "threat", "baseline", "predicted"]) for (const direction of ["asc", "desc"]) assert.equal(sortAdvisories(november, { key, direction }).length, november.length);
assert.ok(performance.now() - started < 5000, "All eight full-month sorts remain comfortably interactive");
const actual = november.find(row => row.cve === "CVE-2026-95885");
assert.equal(microsoftSourceContent(actual).faqs.length, 2);
assert.ok(!microsoftSourceHtml(actual).includes("\\n"), "Actual November FAQ notes render as paragraphs");
console.log(`Advisory sorting and Microsoft source tests passed (${november.length} real records)`);
