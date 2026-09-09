import { ACTIONS, exportJsonl, parseJsonl, predictProfile } from "./engine.js";

const state = { records: [], catalog: [], selectedProducts: new Set(), selectedMitigations: new Set(), selectedCve: null };
const $ = id => document.getElementById(id);

async function loadCatalog() {
  const response = await fetch("./data/mitigation-catalog.json");
  if (!response.ok) throw new Error("Could not load the mitigation catalogue.");
  state.catalog = await response.json();
  renderMitigations();
}

async function loadPublishedMonths() {
  const response = await fetch("./data/months.json", { cache: "no-store" });
  if (!response.ok) return;
  const months = await response.json();
  const select = $("published-month");
  for (const item of months) {
    const option = document.createElement("option");
    option.value = item.file;
    option.textContent = item.label || item.month;
    option.dataset.month = item.month;
    select.append(option);
  }
  const preferred = months.find(item => !item.month.endsWith("-demo")) || months[0];
  if (preferred) {
    select.value = preferred.file;
    $("load-published").disabled = false;
    const dataset = await fetch(`./data/${preferred.file}`, { cache: "no-store" });
    if (dataset.ok) await loadText(await dataset.text(), preferred.label || preferred.month);
  }
}

function checkedValues(containerId) {
  return new Set([...$(containerId).querySelectorAll("input:checked")].map(input => input.value));
}

function renderMitigations() {
  const container = $("mitigation-filters");
  container.classList.remove("muted-copy");
  container.innerHTML = state.catalog.map(item => `
    <label title="${escapeHtml(item.credit_rule)}">
      <input type="checkbox" value="${escapeHtml(item.id)}" />
      <span>${escapeHtml(item.name)}<span class="secondary-line">${escapeHtml(item.category)}</span></span>
    </label>`).join("");
  container.onchange = () => {
    state.selectedMitigations = checkedValues("mitigation-filters");
    render();
  };
}

function productTags() {
  return [...new Set(state.records.flatMap(record => record.tags).filter(tag => /^(windows|server|office|sharepoint|dns|dhcp|identity|hyper-v|print|endpoint)/.test(tag)))].sort();
}

function renderProductFilters() {
  const tags = productTags();
  const container = $("product-filters");
  container.classList.toggle("muted-copy", tags.length === 0);
  container.innerHTML = tags.length ? tags.map(tag => `
    <label><input type="checkbox" value="${escapeHtml(tag)}" /><span>${escapeHtml(tag)}</span></label>`).join("") : "No product tags in this dataset.";
  container.onchange = () => {
    state.selectedProducts = checkedValues("product-filters");
    render();
  };
}

function filteredRecords() {
  const severity = checkedValues("severity-filters");
  const vectors = checkedValues("vector-filters");
  return state.records.filter(record => {
    if (!severity.has(record.severity)) return false;
    if (!vectors.has(record.attack.vector)) return false;
    if (state.selectedProducts.size && !record.tags.some(tag => state.selectedProducts.has(tag))) return false;
    if ($("filter-exploited").checked && !(record.threat.kev || record.threat.exploitation_detected)) return false;
    if ($("filter-likely").checked && record.threat.exploitation_assessment !== "more-likely") return false;
    return true;
  });
}

function decisionClass(action) { return action.toLowerCase().replaceAll(" ", "-"); }

function render() {
  const records = filteredRecords();
  const body = $("results-body");
  body.innerHTML = records.map(record => {
    const profile = predictProfile(record, state.selectedMitigations);
    const changed = profile.baseline.action !== profile.residual.action || profile.baseline.likelihood !== profile.residual.likelihood;
    return `<tr data-cve="${escapeHtml(record.cve)}" tabindex="0" aria-selected="${state.selectedCve === record.cve}">
      <td><span class="cve-id">${escapeHtml(record.cve)}</span></td>
      <td class="title-cell">${escapeHtml(record.title)}<span class="secondary-line">${escapeHtml(record.severity)} · ${escapeHtml(record.attack.vector)}</span></td>
      <td><div class="tag-list">${record.tags.slice(0, 8).map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}</div></td>
      <td>${record.threat.kev ? "KEV" : record.threat.exploitation_detected ? "Detected" : escapeHtml(record.threat.exploitation_assessment || "No current evidence")}<span class="secondary-line">EPSS ${formatPercent(record.threat.epss)}</span></td>
      <td><span class="decision ${decisionClass(profile.baseline.action)}">${escapeHtml(profile.baseline.action)}</span><span class="secondary-line">${escapeHtml(profile.baseline.likelihood)}</span></td>
      <td><span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(profile.residual.action)}</span><span class="secondary-line">${escapeHtml(profile.residual.likelihood)}</span>${changed ? `<span class="change-note">Adjusted by verified relevant controls</span>` : ""}</td>
    </tr>`;
  }).join("");

  const profiles = records.map(record => predictProfile(record, state.selectedMitigations));
  $("visible-count").textContent = records.length;
  $("immediate-count").textContent = profiles.filter(p => p.residual.action === "Immediate").length;
  $("out-cycle-count").textContent = profiles.filter(p => p.residual.action === "Out-of-cycle").length;
  $("scheduled-count").textContent = profiles.filter(p => p.residual.action === "Scheduled").length;
  $("empty-state").hidden = records.length > 0;
  $("empty-state").textContent = state.records.length ? "No vulnerabilities match the selected criteria." : "No records loaded.";
  $("status").textContent = state.records.length ? `${records.length} of ${state.records.length} records match. ${state.selectedMitigations.size} verified mitigation selections are active.` : "Import an enriched monthly JSONL file or load the synthetic demo.";
  $("export-jsonl").disabled = state.records.length === 0;

  for (const row of body.querySelectorAll("tr")) {
    const select = () => { state.selectedCve = row.dataset.cve; render(); renderDetail(); };
    row.addEventListener("click", select);
    row.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); } });
  }
  if (state.selectedCve) renderDetail();
}

function renderDetail() {
  const record = state.records.find(item => item.cve === state.selectedCve);
  if (!record) return;
  const profile = predictProfile(record, state.selectedMitigations);
  const relevant = record.mitigation_candidates.filter(item => item.relevance !== "not-relevant");
  $("detail-panel").innerHTML = `
    <h2>${escapeHtml(record.cve)}</h2>
    <p class="detail-meta">${escapeHtml(record.severity)} · ${escapeHtml(record.attack.vector)} · ${escapeHtml(record.month)}</p>
    <p>${escapeHtml(record.title)}</p>
    <h3>Predicted profile</h3>
    <p><span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(profile.residual.action)}</span></p>
    <ul class="reason-list">${profile.reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
    <h3>Relevant mitigation inference</h3>
    ${relevant.length ? relevant.map(item => `<div class="mitigation-row"><div class="mitigation-name">${escapeHtml(catalogName(item.id))}</div><div class="confidence">${escapeHtml(item.confidence)} confidence · ${item.effect?.likelihood_steps || 0} likelihood step credit</div><div>${escapeHtml(item.evidence || "No evidence fragment recorded")}</div></div>`).join("") : `<p class="detail-meta">No mitigations were inferred as relevant.</p>`}
    <h3>Inference record</h3>
    <p class="detail-meta">${escapeHtml(record.inference.model || "unknown model")} · taxonomy ${escapeHtml(record.inference.taxonomy_version || "unknown")}</p>
    ${record.source.url ? `<h3>Source</h3><a class="source-link" href="${escapeHtml(record.source.url)}" target="_blank" rel="noreferrer">${escapeHtml(record.source.url)}</a>` : ""}`;
}

function catalogName(id) { return state.catalog.find(item => item.id === id)?.name || id; }
function formatPercent(value) { return Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : "n.a."; }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]); }

async function loadText(text, label) {
  try {
    state.records = parseJsonl(text);
    state.selectedProducts.clear();
    state.selectedCve = state.records[0]?.cve || null;
    renderProductFilters();
    const month = state.records[0]?.month || "unknown";
    $("dataset-meta").textContent = `${month} · ${state.records.length} enriched records · ${label}`;
    render();
  } catch (error) {
    $("status").textContent = error.message;
  }
}

$("jsonl-file").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (file) await loadText(await file.text(), file.name);
});
$("load-demo").addEventListener("click", async () => {
  const response = await fetch("./data/demo-2026-Sep.jsonl");
  await loadText(await response.text(), "synthetic demonstration data");
});
$("published-month").addEventListener("change", event => { $("load-published").disabled = !event.target.value; });
$("load-published").addEventListener("click", async () => {
  const select = $("published-month");
  if (!select.value) return;
  const response = await fetch(`./data/${select.value}`, { cache: "no-store" });
  if (!response.ok) { $("status").textContent = `Could not load ${select.value}.`; return; }
  await loadText(await response.text(), select.options[select.selectedIndex].textContent);
});
$("export-jsonl").addEventListener("click", () => {
  const assessed = state.records.map(record => ({ ...record, assessment: { assessed_at: new Date().toISOString(), selected_mitigations: [...state.selectedMitigations], profile: predictProfile(record, state.selectedMitigations) } }));
  const blob = new Blob([exportJsonl(assessed)], { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${state.records[0]?.month || "patch-tuesday"}-assessment.jsonl`;
  link.click();
  URL.revokeObjectURL(url);
});
$("clear-filters").addEventListener("click", () => {
  document.querySelectorAll("#product-filters input, #mitigation-filters input, #filter-exploited, #filter-likely").forEach(input => { input.checked = false; });
  document.querySelectorAll("#severity-filters input, #vector-filters input").forEach(input => { input.checked = true; });
  state.selectedProducts.clear();
  state.selectedMitigations.clear();
  render();
});
for (const id of ["severity-filters", "vector-filters", "filter-exploited", "filter-likely"]) $(id).addEventListener("change", render);

loadCatalog().catch(error => { $("status").textContent = error.message; });
loadPublishedMonths().catch(() => {});
