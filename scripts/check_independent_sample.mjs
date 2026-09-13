/**
 * Re-verify a random sample of published records against the raw vendor feed.
 *
 *   node scripts/check_independent_sample.mjs [--month 2026-Sep] [--sources raw]
 *
 * This is the only check in the repository that compares what we publish against
 * what the vendor actually said. Everything in `npm test` reads the published
 * JSONL and checks it against itself or against derived expectations, which
 * cannot catch a parser that mis-reads the source the same way twice. That is the
 * shape of the six Phase 0 coercions, which published 23 Chromium RCE-class
 * advisories as Low while every test passed.
 *
 * It is NOT part of `npm test` and cannot be: it reads `raw/` and `work/`, both
 * gitignored, so a clean clone has nothing to run it against. Run it locally
 * after `fetch_sources.py` and before publishing a month. See the monthly runbook.
 *
 * Scope. It checks the deterministic parse only - the CVSS pair, the exploitation
 * assessment derived from the vendor's threat prose, KEV membership, the severity
 * bands each party published, and the EPSS likelihood band. It says nothing about
 * whether a mitigation is substantively right, and it duplicates no part of
 * `scripts/audit-mitigations.mjs`, which already exercises every control
 * combination over every record inside `npm test`.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RISK_MODEL } from "../risk-model.js";

const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const at = argv.indexOf(`--${name}`);
  return at === -1 ? fallback : argv[at + 1];
};
const month = arg("month", "2026-Sep");
const sourcesDir = arg("sources", "raw");
const root = fileURLToPath(new URL("../", import.meta.url));

const required = {
  sample: path.join(root, "work", "independent-20-review", "sample.json"),
  published: path.join(root, "data", `${month}.jsonl`),
  cvrf: path.join(root, sourcesDir, `${month}.json`),
  kev: path.join(root, sourcesDir, "known_exploited_vulnerabilities.json"),
  epss: path.join(root, sourcesDir, "epss_scores-current.csv"),
};
const absent = Object.entries(required).filter(([, file]) => !fs.existsSync(file));
if (absent.length) {
  console.error(`Cannot run: ${absent.map(([name]) => name).join(", ")} not found.`);
  for (const [name, file] of absent) console.error(`  ${name}: ${file}`);
  console.error(`\nBoth raw/ and work/ are gitignored, so this never runs in CI.`);
  console.error(`Fetch the sources first:  python scripts/fetch_sources.py --month ${month}`);
  console.error(`Draw the sample:          python scripts/prepare_independent_sample.py`);
  process.exit(2);
}

const read = file => fs.readFileSync(file, "utf8");
const sample = JSON.parse(read(required.sample));
const ids = new Set(sample.cves);
const data = new Map(read(required.published).trim().split(/\r?\n/).map(JSON.parse).map(r => [r.cve, r]));
const rawRecords = new Map(JSON.parse(read(required.cvrf)).Vulnerability.map(r => [r.CVE, r]));
const kev = new Set(JSON.parse(read(required.kev)).vulnerabilities.map(r => r.cveID));
const epss = new Map(
  read(required.epss).split(/\r?\n/).filter(line => line.startsWith("CVE-"))
    .map(line => { const [cve, score] = line.split(","); return [cve, Number(score)]; }),
);

// EPSS is a live daily probability, so equality against any fetch is guaranteed to
// rot - it did, when an automated refresh moved 5 of these 20 after the sources
// were captured. What has to hold is the thing a patch date depends on: that both
// values fall in the same band of the risk model. A score that wanders inside a
// band changes nothing an administrator would do.
const epssBand = score => {
  if (score === null || score === undefined) return "absent";
  if (score >= RISK_MODEL.epss.elevatedScore) return "elevated";
  if (score >= RISK_MODEL.epss.plausibleScore) return "plausible";
  return "low";
};

// Every 2026-Sep score sits in the `low` band on both sides, so the band
// comparison below cannot fail on this month's data alone - it would compare
// "low" against "low" twenty times and report a pass that proves nothing. The
// band function is therefore gated directly, against the thresholds the risk
// model actually uses, so the comparison is known to discriminate before it is
// trusted to agree.
assert.equal(epssBand(null), "absent");
assert.equal(epssBand(0), "low");
assert.equal(epssBand(RISK_MODEL.epss.plausibleScore - 0.0001), "low");
assert.equal(epssBand(RISK_MODEL.epss.plausibleScore), "plausible");
assert.equal(epssBand(RISK_MODEL.epss.elevatedScore - 0.0001), "plausible");
assert.equal(epssBand(RISK_MODEL.epss.elevatedScore), "elevated");
assert.notEqual(epssBand(0.005), epssBand(0.05), "the band function must separate scores either side of a threshold");

// Same problem on the CVSS pair. 922 of the month's 1,185 records carry more than
// one score set, but within a record the vector is unique, so on real data
// matching the vector alone gives the same answer as matching the pair - dropping
// the score half is an equivalent mutation and the check looks stronger than it is
// proven to be. What the pair guards against is a parser that takes the vector
// from one score set and the score from another, so that is gated on a fixture.
const pairMatches = (sets, vector, score) => sets.some(s => s.Vector === vector && s.BaseScore === score);
const twoSets = [
  { Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8 },
  { Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", BaseScore: 7.8 },
];
assert.ok(pairMatches(twoSets, twoSets[1].Vector, 7.8), "a genuine pair must match");
assert.ok(!pairMatches(twoSets, twoSets[1].Vector, 9.8), "a vector from one score set with a score from another must not match");
assert.ok(!pairMatches(twoSets, "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 7.8), "a vector the vendor never published must not match");

const counts = { cvss: 0, severity: 0, exploitation: 0, kev: 0, epss: 0 };
const noVendorSeverity = [];
const epssDrift = [];
const epssAbsent = [];

for (const cve of ids) {
  const r = data.get(cve);
  const v = rawRecords.get(cve);
  assert.ok(r, `${cve}: in the sample but not in ${month}.jsonl`);
  assert.ok(v, `${cve}: in the sample but not in the raw CVRF`);

  const scores = v.CVSSScoreSets || [];
  assert.ok(
    r.cvss.vector ? pairMatches(scores, r.cvss.vector, r.cvss.base_score) : scores.length === 0,
    `${cve}: published CVSS is not a matched pair from the vendor's own score sets`,
  );
  counts.cvss++;

  // The raw string lives on the publisher assessment since the vendor-plural
  // migration. Asserted by shape, not by a September literal, so the tool still
  // works next month: MSRC publishing nothing means no publisher-role assessment,
  // and MSRC publishing something means the two must agree.
  const published = [...new Set((v.Threats || []).filter(t => t.Type === 3).map(t => t.Description?.Value).filter(Boolean))];
  const publisher = (r.severity?.assessments || []).find(a => a.role === "publisher");
  if (!published.length) {
    assert.ok(!publisher, `${cve}: MSRC published no severity, but the record carries a publisher assessment`);
    noVendorSeverity.push(cve);
  } else {
    assert.ok(publisher, `${cve}: MSRC published ${published.join("/")} but the record carries no publisher assessment`);
    assert.ok(published.includes(publisher.value), `${cve}: publisher assessment says ${publisher.value}, MSRC published ${published.join("/")}`);
    counts.severity++;
  }

  const text = (v.Threats || []).filter(t => t.Type === 1).map(t => t.Description?.Value || "").join(" ");
  const expected = /Exploited:Yes|Exploitation detected/i.test(text) ? "detected"
    : /Exploitation More Likely/i.test(text) ? "more-likely"
    : /Exploitation Less Likely/i.test(text) ? "less-likely"
    : /Exploitation Unlikely/i.test(text) ? "unlikely"
    : "unknown";
  assert.equal(r.threat.exploitation_assessment, expected, `${cve}: exploitation assessment does not match the vendor's threat prose`);
  counts.exploitation++;

  assert.equal(r.threat.kev, kev.has(cve), `${cve}: KEV membership disagrees with the catalogue`);
  counts.kev++;

  // A CVE absent from the daily CSV is not a mismatch. The bulk file lags a Patch
  // Tuesday by days, and refresh_epss.py falls back to the per-CVE API for exactly
  // that gap, so the published score can legitimately have no counterpart here.
  // Reported, not asserted; asserting it would make the tool fail on every fresh
  // month, which is the only time it is worth running.
  const live = epss.get(cve);
  if (live === undefined) {
    epssAbsent.push(cve);
  } else {
    assert.equal(
      epssBand(r.threat.epss), epssBand(live),
      `${cve}: published EPSS ${r.threat.epss} and source EPSS ${live} fall in different risk-model bands`,
    );
    if (r.threat.epss !== live) epssDrift.push({ cve, published: r.threat.epss, source: live });
    counts.epss++;
  }
}

console.log(JSON.stringify({
  month,
  sources: sourcesDir,
  sample: ids.size,
  seed: sample.seed,
  drawn_at: sample.created_at,
  cvss_pair_match: counts.cvss,
  publisher_severity_match: counts.severity,
  no_vendor_severity: noVendorSeverity,
  exploitation_assessment_match: counts.exploitation,
  kev_match: counts.kev,
  epss_band_match: counts.epss,
  epss_absent_from_source: epssAbsent,
  epss_drift_within_band: epssDrift,
  interpretation: "Deterministic parse only. Says nothing about whether a mitigation or a priority is substantively right.",
}, null, 2));
