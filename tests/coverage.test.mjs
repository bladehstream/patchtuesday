import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { validateCoverage } from "../scripts/validate-coverage.mjs";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "patchtuesday-coverage-"));
try {
  const month = { month: "2026-Sep", file: "month.jsonl", record_count: 2 };
  fs.writeFileSync(path.join(directory, "months.json"), JSON.stringify([month]));
  const record = {
    cve: "CVE-TEST-1",
    inference: {
      model: "gpt-5.6-luna", generated_at: "2026-09-10T00:00:00Z", review_status: "reviewed",
      framework_assessment: {
        baseline_action: "Scheduled", baseline_likelihood: "Plausible",
        factors: Object.fromEntries(["applicability", "threat_evidence", "exploitability", "technical_impact", "workload_context", "remediation_context", "uncertainty"].map(key => [key, "Test evidence"])),
        risk_communication: { summary: "Test summary", why_this_action: "Test reason" },
      },
    },
  };
  const write = rows => fs.writeFileSync(path.join(directory, "month.jsonl"), rows.map(JSON.stringify).join("\n") + "\n");
  write([record, { cve: "CVE-TEST-2", inference: { model: "none" } }]);
  assert.throws(() => validateCoverage(directory), /incomplete inference/);
  write([record, record]);
  assert.throws(() => validateCoverage(directory), /duplicate CVEs/);
  write([record, { ...record, cve: "CVE-TEST-2" }]);
  assert.deepEqual(validateCoverage(directory), [{ month: "2026-Sep", records: 2, inferred: 2 }]);
  write([record]);
  assert.throws(() => validateCoverage(directory), /count mismatch/);
  console.log("Publication coverage gate tests passed");
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
