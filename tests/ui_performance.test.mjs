import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";
import { launchPage, startStaticServer, waitFor } from "./support/cdp-browser.mjs";

const root = process.env.PATCH_TUESDAY_TEST_ROOT
  ? path.resolve(process.env.PATCH_TUESDAY_TEST_ROOT)
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { monthTotals, parseJsonl, predictProfile } = await import(pathToFileURL(path.join(root, "engine.js")).href);
const manifest = JSON.parse(fs.readFileSync(path.join(root, "data", "months.json"), "utf8"));
const published = manifest.find(item => !String(item.month).endsWith("-demo"));
assert.ok(published, "months.json must contain a non-demo release");
assert.ok(Number.isInteger(published.record_count) && published.record_count > 0, "the non-demo manifest entry must provide a positive record_count");

const records = parseJsonl(fs.readFileSync(path.join(root, "data", published.file), "utf8"));
const catalog = JSON.parse(fs.readFileSync(path.join(root, "data", "mitigation-catalog.json"), "utf8"));
assert.equal(records.length, published.record_count, `${published.month}: manifest record_count must match its JSONL`);
assert.ok(records.every(record => record.month === published.month), `${published.month}: a complete release may not mix months`);

const baselineProfiles = records.map(record => predictProfile(record));
const baselineTotals = monthTotals(records);
const actionSummary = Object.fromEntries(Object.entries(baselineTotals.counts).sort());
const likelihoodSummary = Object.fromEntries(["Low evidence", "Plausible", "Elevated", "Active"].map(likelihood => [likelihood,
  baselineProfiles.filter(profile => profile.baseline.likelihood === likelihood).length,
]));
const control = catalog.find(item => records.some(record => {
  const profile = predictProfile(record, new Set([item.id]));
  return profile.baseline.action !== profile.residual.action || profile.baseline.likelihood !== profile.residual.likelihood;
}));
assert.ok(control, `${published.month}: at least one catalogue control must have a measurable complete-month effect`);
const selectedProfiles = records.map(record => predictProfile(record, new Set([control.id])));
const changedProfiles = selectedProfiles.filter(profile => profile.baseline.action !== profile.residual.action || profile.baseline.likelihood !== profile.residual.likelihood).length;
assert.ok(changedProfiles > 0, `${control.id}: expected a selected-control calculation effect`);

function completeMonthCalculation() {
  const started = performance.now();
  let selectedChanges = 0;
  let clearedBaselines = 0;
  for (const item of catalog) {
    const selected = new Set([item.id]);
    for (const record of records) {
      const withControl = predictProfile(record, selected);
      const cleared = predictProfile(record, new Set());
      if (withControl.baseline.action !== withControl.residual.action || withControl.baseline.likelihood !== withControl.residual.likelihood) selectedChanges += 1;
      if (cleared.baseline.action === cleared.residual.action && cleared.baseline.likelihood === cleared.residual.likelihood) clearedBaselines += 1;
    }
  }
  return { elapsed_ms: Math.round((performance.now() - started) * 100) / 100, selectedChanges, clearedBaselines };
}

completeMonthCalculation(); // Warm cache/JIT without treating its timing as a result.
const calculationRuns = Array.from({ length: 3 }, completeMonthCalculation);
const calculationReference = calculationRuns[0];
for (const run of calculationRuns) {
  assert.equal(run.selectedChanges, calculationReference.selectedChanges, "catalogue control selection calculations must be reproducible");
  assert.equal(run.clearedBaselines, catalog.length * records.length, "clearing every catalogue control must restore every baseline profile");
}

const totalsFromDom = selector => `(() => {
  const ids = ["total", "immediate", "out-cycle", "scheduled", "no-action", "review"];
  return Object.fromEntries(ids.map(id => [id, Number(document.querySelector(${JSON.stringify(selector)}.replace("COUNT", id)).textContent)]));
})()`;
const expectedTotals = totals => ({
  total: totals.total,
  immediate: totals.counts.Immediate,
  "out-cycle": totals.counts["Out-of-cycle"],
  scheduled: totals.counts.Scheduled,
  "no-action": totals.counts["Defer and review"],
  review: totals.reviewCount,
});
const frames = "new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))";
function toggleExpression(selector, checked) {
  return `(async () => {
    const input = document.querySelector(${JSON.stringify(selector)});
    if (!input) throw new Error(${JSON.stringify(`Missing mitigation control: ${selector}`)});
    const started = performance.now();
    if (input.checked !== ${checked}) input.click();
    await ${frames};
    return { elapsed_ms: Math.round((performance.now() - started) * 100) / 100, checked: input.checked,
      overview_checked: document.querySelector(${JSON.stringify(`#ov-mitigation-filters input[value="${control.id}"]`)}).checked,
      advisory_checked: document.querySelector(${JSON.stringify(`#mitigation-filters input[value="${control.id}"]`)}).checked };
  })()`;
}

const server = await startStaticServer(root);
let page;
try {
  page = await launchPage(server.url);
  await waitFor(async () => page.evaluate(`Boolean(document.querySelector('#ov-mitigation-filters input[value="${control.id}"]'))
    && document.querySelectorAll('#results-body tr').length === ${published.record_count}
    && document.querySelector('#dataset-meta').textContent === ${JSON.stringify(`${published.month} · ${published.record_count} records`)}`));

  assert.deepEqual(await page.evaluate(totalsFromDom("#ov-COUNT-count")), expectedTotals(baselineTotals), "Overview must render the complete manifest-selected release");
  assert.equal(await page.evaluate("document.querySelectorAll('#results-body tr').length"), published.record_count,
    "Advisories must render the complete manifest-selected release before filtering");

  const overviewSelected = await page.evaluate(toggleExpression(`#ov-mitigation-filters input[value="${control.id}"]`, true));
  assert.deepEqual({ ...overviewSelected, elapsed_ms: typeof overviewSelected.elapsed_ms }, { elapsed_ms: "number", checked: true, overview_checked: true, advisory_checked: true },
    "Overview selection must propagate through the shared mitigation state after animation frames");
  assert.deepEqual(await page.evaluate(totalsFromDom("#ov-COUNT-count")), expectedTotals(monthTotals(records, new Set([control.id]))),
    "Overview totals must use the selected-control calculation");
  const overviewCleared = await page.evaluate(toggleExpression(`#ov-mitigation-filters input[value="${control.id}"]`, false));
  assert.equal(overviewCleared.checked, false, "Overview control must clear after animation frames");
  assert.deepEqual(await page.evaluate(totalsFromDom("#ov-COUNT-count")), expectedTotals(baselineTotals), "Overview clear must restore baseline totals");

  await page.evaluate(`(async () => { document.querySelector('#tab-advisories').click(); await ${frames}; })()`);
  const advisorySelected = await page.evaluate(toggleExpression(`#mitigation-filters input[value="${control.id}"]`, true));
  assert.equal(advisorySelected.checked, true, "Advisories control must select after animation frames");
  assert.equal(await page.evaluate("document.querySelectorAll('#results-body .change-note').length"), changedProfiles,
    "Advisories must render every calculated mitigation change");
  const advisoryCleared = await page.evaluate(toggleExpression(`#mitigation-filters input[value="${control.id}"]`, false));
  assert.equal(advisoryCleared.checked, false, "Advisories control must clear after animation frames");
  assert.equal(await page.evaluate("document.querySelectorAll('#results-body .change-note').length"), 0,
    "Advisories clear must restore every baseline profile");

  console.log(`UI baseline: month=${published.month} records=${published.record_count} baseline_actions=${JSON.stringify(actionSummary)} baseline_likelihoods=${JSON.stringify(likelihoodSummary)}`);
  console.log(`UI calculation baseline: controls=${catalog.length} records_per_control=${records.length} select_clear_runs_ms=${calculationRuns.map(run => run.elapsed_ms).join(",")} selected_changes=${calculationReference.selectedChanges} cleared_baselines=${calculationReference.clearedBaselines} control=${control.id} changed_profiles=${changedProfiles} selected_actions=${JSON.stringify(Object.fromEntries(Object.entries(monthTotals(records, new Set([control.id])).counts).sort()))}`);
  console.log(`UI real render: browser=${page.browser} overview_select_ms=${overviewSelected.elapsed_ms} overview_clear_ms=${overviewCleared.elapsed_ms} advisories_select_ms=${advisorySelected.elapsed_ms} advisories_clear_ms=${advisoryCleared.elapsed_ms}`);
} finally {
  if (page) await page.close();
  await server.close();
}

console.log("UI calculation-and-render baseline passed");
