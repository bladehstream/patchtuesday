// Update availability must come from the vendor's structured remediation list.
// Regression for two records a user flagged on 2026-09-11: both were marked
// "further review required" because the model's prose mentioned a late Mac LTSC
// build, even though 8 of 11 (and 1 of 4) products had updates available.
import assert from "node:assert/strict";
import fs from "node:fs";
import { parseJsonl, updateStatus, updateSummary, reviewStatus } from "../engine.js";

const records = parseJsonl(fs.readFileSync(new URL("../data/2026-Sep.jsonl", import.meta.url), "utf8"));
const byCve = new Map(records.map(r => [r.cve, r]));

const office = byCve.get("CVE-2026-69632");
assert.ok(office, "CVE-2026-69632 must be present");
const u = updateSummary(office);
assert.equal(u.total, 11);
assert.equal(u.available, 8, "8 of 11 Office products have an update");
assert.ok(u.missingNames.some(n => n.includes("Mac")), "the pending products are the Mac LTSC builds");
assert.equal(u.flag, false, "a partially-patched record must not flag globally");
assert.ok(!reviewStatus(office).reasons.some(r => r.code === "update-availability"),
  "the prose-driven update-availability reason must be gone");

const android = byCve.get("CVE-2026-78439");
if (android) {
  assert.equal(updateSummary(android).flag, false, "one available update is enough to clear the global flag");
}

// A record with no fix anywhere SHOULD still flag - the gate must be able to fire.
// Restricted to records that actually need customer action: most no-fix records
// are cloud services Microsoft patches itself, where silence is correct.
const noFix = records.find(r => {
  const s = updateSummary(r);
  return s.total > 0 && s.available === 0 && r.customer_action_required !== false;
});
assert.ok(noFix, "the dataset must contain an actionable record with no vendor fix");
assert.equal(updateSummary(noFix).flag, true);
assert.ok(reviewStatus(noFix).reasons.some(r => r.code === "no-update-available"),
  `${noFix.cve} has no listed fix and needs customer action, so it must flag`);

// And a cloud-service record with no fix must NOT flag: nothing for the admin to do.
const vendorFixed = records.find(r => {
  const s = updateSummary(r);
  return s.total > 0 && s.available === 0 && r.customer_action_required === false;
});
if (vendorFixed) {
  assert.equal(reviewStatus(vendorFixed).required, false,
    `${vendorFixed.cve} is vendor-remediated, so it must not ask the reader to review anything`);
}

// Scoping: an unfixed product only matters when the record is in the selection.
const scoped = updateSummary(office, new Set(["office"]));
assert.equal(scoped.flag, true, "selecting Office surfaces the pending Mac builds");
const elsewhere = updateSummary(office, new Set(["server-2012"]));
assert.equal(elsewhere.flag, false, "a Windows-only estate is not warned about Mac builds");

// Every row must carry a usable answer to 'is there an update'.
for (const row of updateStatus(office)) {
  assert.equal(typeof row.available, "boolean");
  assert.ok(row.name);
}
console.log(`update status tests passed (${u.available}/${u.total} on CVE-2026-69632, flag=${u.flag})`);
