import { ACTIONS, exportJsonl, formatEpss, formatMicrosoftAssessment, isCriticalPreAuthNetworkRce, matchesSmartSearch, parseJsonl, predictProfile } from "./engine.js?v=2026.09.1.2";

const state = { records: [], recordByCve: new Map(), catalog: [], selectedProducts: new Set(), selectedMitigations: new Set(), selectedCve: null, searchQuery: "" };
const $ = id => document.getElementById(id);

async function loadCatalog() {
  const response = await fetch("./data/mitigation-catalog.json");
  if (!response.ok) throw new Error("Could not load the mitigation catalogue.");
  state.catalog = await response.json();
  renderMitigations();
}

function publishedDataUrl(select) {
  const version = select.selectedOptions[0]?.dataset.version;
  const suffix = version ? `?v=${encodeURIComponent(version)}` : "";
  return `./data/${select.value}${suffix}`;
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
    option.dataset.version = item.published_at || "";
    select.append(option);
  }
  const preferred = months.find(item => !item.month.endsWith("-demo")) || months[0];
  if (preferred) {
    select.value = preferred.file;
    $("load-published").disabled = false;
    const dataset = await fetch(publishedDataUrl(select), { cache: "no-store" });
    if (dataset.ok) await loadText(await dataset.text());
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
  updateMitigationSummary();
  container.onchange = () => {
    state.selectedMitigations = checkedValues("mitigation-filters");
    updateMitigationSummary();
    render();
  };
}

function updateMitigationSummary() {
  const summary = $("mitigation-summary");
  if (!summary) return;
  const selected = [...state.selectedMitigations];
  if (!selected.length) {
    summary.textContent = "No mitigations selected";
  } else if (selected.length === 1) {
    summary.textContent = catalogName(selected[0]);
  } else {
    summary.textContent = `${selected.length} mitigations selected`;
  }
}

function productTags() {
  const excluded = new Set(["microsoft", "remote-code-execution", "elevation-of-privilege", "security-feature-bypass", "information-disclosure", "denial-of-service", "spoofing", "user-content"]);
  return [...new Set(state.records.flatMap(record => record.tags).filter(tag => !excluded.has(tag)))].sort();
}

function renderProductFilters() {
  const tags = productTags();
  const container = $("product-filters");
  container.classList.toggle("muted-copy", tags.length === 0);
  container.innerHTML = tags.length ? tags.map(tag => `
    <label><input type="checkbox" value="${escapeHtml(tag)}" /><span>${escapeHtml(tag)}</span></label>`).join("") : "No product tags in this dataset.";
  updateProductSummary();
  container.onchange = () => {
    state.selectedProducts = checkedValues("product-filters");
    updateProductSummary();
    render();
  };
}

function updateProductSummary() {
  const summary = $("product-summary");
  if (!summary) return;
  const selected = [...state.selectedProducts];
  if (!selected.length) {
    summary.textContent = "All products and workloads";
  } else if (selected.length === 1) {
    summary.textContent = selected[0];
  } else {
    summary.textContent = `${selected.length} products and workloads selected`;
  }
}

function filteredRecords() {
  const severity = checkedValues("severity-filters");
  const vectors = checkedValues("vector-filters");
  return state.records.filter(record => {
    if (!matchesSmartSearch(record, state.searchQuery, state.selectedMitigations)) return false;
    if (!severity.has(record.severity)) return false;
    if (!vectors.has(record.attack.vector)) return false;
    if (state.selectedProducts.size && !record.tags.some(tag => state.selectedProducts.has(tag))) return false;
    if ($("filter-exploited").checked && !(record.threat.kev || record.threat.exploitation_detected)) return false;
    if ($("filter-likely").checked && record.threat.exploitation_assessment !== "more-likely") return false;
    return true;
  });
}

function decisionClass(action) { return action.toLowerCase().replaceAll(" ", "-"); }

function epssDisplay(threat) {
  const score = formatEpss(threat.epss);
  if (threat.epss_status === "pending") return `${score}${threat.epss_date ? ` · feed ${threat.epss_date}` : ""}`;
  if (threat.epss_status === "stale") return `${score} · previous published value`;
  if (threat.epss_percentile !== null && threat.epss_percentile !== undefined) return `${score} · ${(Number(threat.epss_percentile) * 100).toFixed(1)}th percentile`;
  return score;
}

function render() {
  const records = filteredRecords();
  const body = $("results-body");
  if (!records.some(record => record.cve === state.selectedCve)) state.selectedCve = records[0]?.cve || null;
  body.innerHTML = records.map(record => {
    const profile = predictProfile(record, state.selectedMitigations);
    const changed = profile.baseline.action !== profile.residual.action || profile.baseline.likelihood !== profile.residual.likelihood;
    return `<tr data-cve="${escapeHtml(record.cve)}" tabindex="0" aria-selected="${state.selectedCve === record.cve}">
      <td><span class="cve-id">${escapeHtml(record.cve)}</span></td>
      <td class="title-cell">${escapeHtml(record.title)}<span class="secondary-line">${escapeHtml(record.severity)} · ${escapeHtml(record.attack.vector)}</span></td>
      <td><div class="tag-list">${record.tags.slice(0, 8).map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}</div></td>
      <td><span class="threat-line">Microsoft: ${formatMicrosoftAssessment(record.threat.exploitation_assessment)}</span><span class="secondary-line">CVSS ${record.cvss.base_score ?? "Not published"}${record.cvss.temporal_score !== null && record.cvss.temporal_score !== undefined ? ` · temporal ${record.cvss.temporal_score}` : ""}</span><span class="secondary-line">EPSS ${epssDisplay(record.threat)}</span>${record.threat.kev ? `<span class="kev-line">CISA KEV listed</span>` : ""}</td>
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
  const scoredEpss = records.filter(record => record.threat.epss !== null && record.threat.epss !== undefined && Number.isFinite(Number(record.threat.epss))).length;
  const epssStatus = records.length ? `EPSS is available for ${scoredEpss} of ${records.length}; newly published CVEs remain marked not yet scored.` : "";
  const searchStatus = state.searchQuery ? ` Search: "${state.searchQuery}".` : "";
  $("status").textContent = state.records.length ? `${records.length} of ${state.records.length} records match.${searchStatus} ${state.selectedMitigations.size} verified mitigation selections are active. ${epssStatus}` : "Import an enriched monthly JSONL file or load the synthetic demo.";
  $("export-jsonl").disabled = state.records.length === 0;

  const selectRow = row => {
    const selected = body.querySelector('tr[aria-selected="true"]');
    if (selected && selected !== row) selected.setAttribute("aria-selected", "false");
    row.setAttribute("aria-selected", "true");
    state.selectedCve = row.dataset.cve;
    renderDetail();
  };
  body.onclick = event => {
    const row = event.target.closest("tr[data-cve]");
    if (row && body.contains(row)) selectRow(row);
  };
  body.onkeydown = event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const row = event.target.closest("tr[data-cve]");
    if (!row || !body.contains(row)) return;
    event.preventDefault();
    selectRow(row);
  };
  if (state.selectedCve) renderDetail();
}

function riskInterpretation(record, profile) {
  const reviewed = record.inference?.framework_assessment?.risk_communication;
  if (reviewed?.summary) return reviewed.summary;
  if (record.customer_action_required === false) return "Microsoft states that this service has already been mitigated and no customer action is required.";
  if (record.threat.kev || record.threat.exploitation_detected) return "Immediate action is driven by confirmed exploitation. CVSS describes technical impact, but observed exploitation determines present urgency.";
  if (isCriticalPreAuthNetworkRce(record) && profile.baseline.likelihood === "Elevated") return "Immediate action is driven by the combination of Critical impact, unauthenticated network reachability, no user interaction, remote code execution, and elevated Microsoft exploitation likelihood.";
  if (record.severity === "Critical") return "Out-of-cycle action is driven by Critical technical impact even though current exploitation evidence is lower.";
  return "The action combines current exploitation evidence with technical severity and exploit prerequisites. Selected controls adjust the result only when the reviewed overlay links them to this exploit path.";
}

function renderDetail() {
  const record = state.recordByCve.get(state.selectedCve);
  if (!record) {
    $("detail-panel").innerHTML = `<p class="detail-placeholder">Select a vulnerability to inspect its evidence, applicable mitigations, and decision path.</p>`;
    return;
  }
  const profile = predictProfile(record, state.selectedMitigations);
  const relevant = record.mitigation_candidates.filter(item => item.relevance === "relevant");
  const framework = record.inference?.framework_assessment;
  $("detail-panel").innerHTML = `
    <h2>${escapeHtml(record.cve)}</h2>
    <p class="detail-meta">${escapeHtml(record.severity)} · ${escapeHtml(record.attack.vector)} · ${escapeHtml(record.month)}</p>
    <p>${escapeHtml(record.title)}</p>
    <h3>Risk assessment</h3>
    <dl class="risk-breakdown">
      <dt>Threat likelihood</dt><dd>${escapeHtml(profile.baseline.likelihood)}</dd>
      <dt>Baseline model</dt><dd>${escapeHtml(profile.baseline.model || "deterministic fallback")}</dd>
      <dt>Microsoft</dt><dd>${formatMicrosoftAssessment(record.threat.exploitation_assessment)}</dd>
      <dt>CVSS</dt><dd>${record.cvss.base_score ?? "Not published"}${record.cvss.temporal_score !== null && record.cvss.temporal_score !== undefined ? ` · temporal ${record.cvss.temporal_score}` : ""}</dd>
      <dt>Exploit path</dt><dd>${escapeHtml(record.attack.vector)} · privileges ${escapeHtml(record.attack.privileges_required)} · interaction ${escapeHtml(record.attack.user_interaction)}</dd>
      <dt>Baseline action</dt><dd><span class="decision ${decisionClass(profile.baseline.action)}">${escapeHtml(profile.baseline.action)}</span></dd>
      <dt>With controls</dt><dd><span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(profile.residual.action)}</span></dd>
    </dl>
    <p class="risk-interpretation">${escapeHtml(riskInterpretation(record, profile))}</p>
    <ul class="reason-list">${profile.reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
    ${framework ? `<div class="framework-review">
      <h3>Framework review</h3>
      <p><strong>Why this action:</strong> ${escapeHtml(framework.risk_communication.why_this_action)}</p>
      <p><strong>Control limitations:</strong> ${escapeHtml(framework.risk_communication.control_limitations)}</p>
      <p><strong>Reassess when:</strong> ${framework.risk_communication.reassessment_triggers.map(item => escapeHtml(item)).join("; ")}</p>
      <p class="detail-meta">Model ${escapeHtml(framework.risk_model_version)} · ${escapeHtml(framework.confidence)} confidence</p>
    </div>` : ""}
    <h3>Relevant mitigation inference</h3>
    ${relevant.length ? relevant.map(item => `<div class="mitigation-row"><div class="mitigation-name">${escapeHtml(catalogName(item.id))}</div><div class="confidence">${item.confidence === "low" ? "No assessment credit · low confidence" : `${escapeHtml(item.confidence)} confidence · ${item.effect?.likelihood_steps || 0} likelihood step credit · ${item.effect?.consequence_steps || 0} consequence step credit`}</div><div>${escapeHtml(item.evidence || "No evidence fragment recorded")}</div></div>`).join("") : `<p class="detail-meta">No mitigations were inferred as relevant.</p>`}
    <h3>Inference record</h3>
    <p class="detail-meta">${escapeHtml(record.inference.model || "unknown model")} · ${escapeHtml(record.inference.review_status || "unreviewed")} · taxonomy ${escapeHtml(record.inference.taxonomy_version || "unknown")}</p>
    ${record.source.url ? `<h3>Source</h3><a class="source-link" href="${escapeHtml(record.source.url)}" target="_blank" rel="noreferrer">${escapeHtml(record.source.url)}</a>` : ""}`;
}

function catalogName(id) { return state.catalog.find(item => item.id === id)?.name || id; }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]); }

async function loadText(text) {
  try {
    state.records = parseJsonl(text);
    state.recordByCve = new Map(state.records.map(record => [record.cve, record]));
    state.selectedProducts.clear();
    state.selectedCve = state.records[0]?.cve || null;
    renderProductFilters();
    const month = state.records[0]?.month || "unknown";
    $("dataset-meta").textContent = `${month} · ${state.records.length} records`;
    render();
  } catch (error) {
    $("status").textContent = error.message;
  }
}

$("jsonl-file").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (file) await loadText(await file.text());
});
$("load-demo").addEventListener("click", async () => {
  const response = await fetch("./data/demo-2026-Sep.jsonl");
  await loadText(await response.text());
});
$("published-month").addEventListener("change", event => { $("load-published").disabled = !event.target.value; });
$("load-published").addEventListener("click", async () => {
  const select = $("published-month");
  if (!select.value) return;
  const response = await fetch(publishedDataUrl(select), { cache: "no-store" });
  if (!response.ok) { $("status").textContent = `Could not load ${select.value}.`; return; }
  await loadText(await response.text());
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
  updateProductSummary();
  state.selectedMitigations.clear();
  updateMitigationSummary();
  state.searchQuery = "";
  $("smart-search").value = "";
  render();
});
document.addEventListener("click", event => {
  for (const id of ["product-select", "mitigation-select"]) {
    const select = $(id);
    if (select?.open && !select.contains(event.target)) select.open = false;
  }
});
for (const id of ["severity-filters", "vector-filters", "filter-exploited", "filter-likely"]) $(id).addEventListener("change", render);
$("smart-search-form").addEventListener("submit", event => event.preventDefault());
$("smart-search").addEventListener("input", event => {
  state.searchQuery = event.target.value.trim();
  render();
});
document.addEventListener("keydown", event => {
  if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName)) {
    event.preventDefault();
    $("smart-search").focus();
  }
  if (event.key === "Escape" && document.activeElement === $("smart-search")) {
    $("smart-search").value = "";
    state.searchQuery = "";
    render();
  }
});

loadCatalog().catch(error => { $("status").textContent = error.message; });
loadPublishedMonths().catch(() => {});
