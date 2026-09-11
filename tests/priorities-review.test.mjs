import assert from "node:assert/strict";
import fs from "node:fs";
import { formatPriority, formatPriorityText, publicProfile, reviewStatus, matchesSmartSearch, predictProfile, updateSummary } from "../engine.js";

const records = fs.readFileSync(new URL("../data/2026-Sep.jsonl", import.meta.url), "utf8").trim().split(/\r?\n/).map(JSON.parse);
const get = cve => records.find(record => record.cve === cve);
assert.equal(formatPriority("Immediate"), "Emergency");
assert.equal(formatPriority("Out-of-cycle"), "Expedited");
assert.equal(formatPriority("Scheduled"), "Normal scheduled");
assert.equal(formatPriority("Defer and review"), "No customer action");
assert.equal(formatPriorityText("Scheduled Tasks service needs scheduled patching."), "Scheduled Tasks service needs Normal scheduled patching.");
assert.equal(formatPriorityText("Normal scheduled remediation."), "Normal scheduled remediation.");
assert.equal(publicProfile(get("CVE-2026-69730")).baseline.action, "Emergency");
assert.equal(matchesSmartSearch(get("CVE-2026-69730"), "action:emergency"), true);
assert.equal(matchesSmartSearch(get("CVE-2026-69730"), "action:immediate"), true);
assert.equal(matchesSmartSearch(get("CVE-2026-69829"), "action:expedited"), true);
assert.equal(publicProfile(get("CVE-2026-70352")).baseline.action, "No customer action");
assert.equal(reviewStatus(get("CVE-2026-70352")).required, false, "Already mitigated hosted services do not need an unavailable-patch flag");
assert.equal(reviewStatus(get("CVE-2026-69388")).reasons.some(reason => reason.code === "guidance-discrepancy"), true);
// CVE-2026-78510 has 10 of 13 products patched with real KBs; only the three Mac
// LTSC builds are pending. The old `update-availability` reason was a regex over
// the model's prose and flagged the whole record for every reader, which is the
// behaviour a user objected to on 2026-09-11. It must NOT flag globally now.
assert.equal(reviewStatus(get("CVE-2026-78510")).reasons.some(reason => reason.code === "update-availability"), false,
  "the prose-driven update-availability reason is gone");
assert.equal(reviewStatus(get("CVE-2026-78510")).required, false,
  "a record with 10 of 13 products patched must not be flagged for everyone");
{
  const status = updateSummary(get("CVE-2026-78510"));
  assert.equal(status.available, 10, "10 of 13 Word products have an update");
  assert.equal(status.missing, 3);
  assert.ok(status.missingNames.every(name => name.includes("Mac")), "the pending builds are the Mac ones");
  // But it MUST surface for someone who actually runs the affected product.
  assert.equal(updateSummary(get("CVE-2026-78510"), new Set(["office"])).flag, true,
    "selecting Office surfaces the pending Mac builds");
  assert.equal(updateSummary(get("CVE-2026-78510"), new Set(["server-2012"])).flag, false,
    "a Windows-only estate is not warned about Mac builds");
}
assert.equal(reviewStatus(get("CVE-2026-69730")).required, false, "Routine customer exposure uncertainty alone is not a review flag");
assert.equal(reviewStatus(get("CVE-2026-65669")).required, false, "Attacker privileges and an authorized victim workflow are distinct, not conflicting prerequisites");
assert.equal(reviewStatus(get("CVE-2026-77493")).required, false, "An automatic preview path does not by itself contradict UI:N");
assert.equal(matchesSmartSearch(get("CVE-2026-69388"), "review:required"), true);
assert.equal(matchesSmartSearch(get("CVE-2026-69730"), "review:false"), true);
const dns = get("CVE-2026-69730");
const before = predictProfile(dns);
reviewStatus(dns);
assert.deepEqual(predictProfile(dns), before, "Review status must not modify risk judgments");
const sparse = { ...dns, cvss: { base_score: null }, attack: { vector: "unknown" } };
assert.equal(reviewStatus(sparse).reasons.some(reason => reason.code === "incomplete-prerequisites"), true);
console.log("Priority terminology and review-marker tests passed");
