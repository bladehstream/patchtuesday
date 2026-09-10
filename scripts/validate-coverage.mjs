import fs from "node:fs";
import path from "node:path";

export function validateCoverage(dataDirectory) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dataDirectory, "months.json"), "utf8"));
  const reports = [];
  for (const month of manifest) {
    if (month.month.endsWith("-demo")) continue;
    const records = fs.readFileSync(path.join(dataDirectory, month.file), "utf8").trim().split(/\r?\n/).map(JSON.parse);
    const ids = new Set(records.map(record => record.cve));
    if (ids.size !== records.length || records.length !== month.record_count) throw new Error(`${month.month}: duplicate CVEs or manifest count mismatch`);
    const missing = records.filter(record => {
      const inference = record.inference;
      const assessment = inference?.framework_assessment;
      return inference?.review_status !== "reviewed" || !inference.model || inference.model === "none" || !inference.generated_at
        || !assessment?.baseline_action || !assessment?.baseline_likelihood
        || !["applicability", "threat_evidence", "exploitability", "technical_impact", "workload_context", "remediation_context", "uncertainty"].every(key => typeof assessment.factors?.[key] === "string" && assessment.factors[key].trim())
        || !assessment.risk_communication?.summary || !assessment.risk_communication?.why_this_action;
    });
    if (missing.length) throw new Error(`${month.month}: incomplete inference (${records.length - missing.length}/${records.length}); missing ${missing.slice(0, 5).map(record => record.cve).join(", ")}`);
    reports.push({ month: month.month, records: records.length, inferred: records.length });
  }
  return reports;
}
