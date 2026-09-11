import { ACTIONS, exportJsonl, formatEpss, formatMicrosoftAssessment, formatPriority, formatPriorityText, publicProfile, reviewStatus, isCriticalPreAuthNetworkRce, matchesSmartSearch, parseJsonl, predictProfile } from "./engine.js?v=2026.09.priorities";

const state = { records: [], recordByCve: new Map(), catalog: [], productFilters: null, selectedProducts: new Set(), productMatchMode: "or", selectedMitigations: new Set(), selectedCve: null, searchQuery: "" };
const $ = id => document.getElementById(id);

async function loadCatalog() {
  const response = await fetch("./data/mitigation-catalog.json");
  if (!response.ok) throw new Error("Could not load the mitigation catalogue.");
  state.catalog = await response.json();
  renderMitigations();
}

function severityHtml(record) {
  const label = escapeHtml(record.severity);
  return record.severity === "Unknown" ? `<span class="severity-unknown" title="The vendor published no severity rating and no CVSS score.">${label}</span>` : label;
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

async function loadProductFilters() {
  // The selector is a curated list, not whatever tags happen to appear in the
  // data. An auto-populated list grew to 26 checkboxes and buried the handful an
  // administrator actually uses. Adding a taxonomy tag no longer adds a checkbox.
  const response = await fetch("./data/product-filters.json");
  if (!response.ok) throw new Error("Could not load the product filter list.");
  state.productFilters = await response.json();
  state.productMatchMode = state.productFilters.match_mode_default || "or";
}

function filterOptionTag(value) {
  for (const group of state.productFilters?.groups || []) {
    const option = group.options.find(item => item.tag === value);
    if (option) return { ...option, source: group.source };
  }
  return null;
}

function recordFilterTags(record, source) {
  return source === "tags" ? (record.tags || []) : (record.product_tags || []);
}

function renderProductFilters() {
  const container = $("product-filters");
  const groups = state.productFilters?.groups || [];
  if (!groups.length) {
    container.classList.add("muted-copy");
    container.textContent = "Product filter list unavailable.";
    return;
  }
  container.classList.remove("muted-copy");

  // Counts come from the loaded month, so an option that matches nothing this
  // month is visibly empty rather than silently misleading.
  const counts = new Map();
  for (const group of groups) {
    for (const option of group.options) {
      counts.set(option.tag, state.records.filter(record =>
        recordFilterTags(record, group.source).includes(option.tag)).length);
    }
  }

  container.innerHTML = groups.map(group => `
    <div class="filter-group">
      <p class="filter-group-label">${escapeHtml(group.label)}<span class="filter-group-hint" title="${escapeHtml(group.hint || "")}">?</span></p>
      <div class="choice-list">
        ${group.options.map(option => {
          const count = counts.get(option.tag) || 0;
          return `<label${count ? "" : ' class="empty-option"'}>
            <input type="checkbox" value="${escapeHtml(option.tag)}"${state.selectedProducts.has(option.tag) ? " checked" : ""} />
            <span>${escapeHtml(option.label)}</span><span class="option-count">${count}</span>
          </label>`;
        }).join("")}
      </div>
    </div>`).join("");

  updateProductSummary();
  container.onchange = () => {
    state.selectedProducts = checkedValues("product-filters");
    updateProductSummary();
    render();
  };
}

function renderMatchModeToggle() {
  const toggle = $("product-match-mode");
  if (!toggle) return;
  toggle.checked = state.productMatchMode === "and";
  toggle.onchange = () => {
    state.productMatchMode = toggle.checked ? "and" : "or";
    updateProductSummary();
    render();
  };
}

function matchesProductFilters(record) {
  // Nothing selected means nothing is excluded, so records outside the curated
  // list stay visible by default and are only hidden once a filter is applied.
  if (!state.selectedProducts.size) return true;
  const selected = [...state.selectedProducts];
  const hit = tag => {
    const option = filterOptionTag(tag);
    return option ? recordFilterTags(record, option.source).includes(tag) : false;
  };
  return state.productMatchMode === "and" ? selected.every(hit) : selected.some(hit);
}

function updateProductSummary() {
  const summary = $("product-summary");
  if (!summary) return;
  const selected = [...state.selectedProducts];
  if (!selected.length) {
    summary.textContent = "All products and workloads";
    return;
  }
  const labels = selected.map(tag => filterOptionTag(tag)?.label || tag);
  if (labels.length === 1) {
    summary.textContent = labels[0];
  } else {
    const joiner = state.productMatchMode === "and" ? " AND " : " OR ";
    summary.textContent = labels.length <= 3
      ? labels.join(joiner)
      : `${labels.length} selected (${state.productMatchMode.toUpperCase()})`;
  }
}

function filteredRecords() {
  const severity = checkedValues("severity-filters");
  const vectors = checkedValues("vector-filters");
  return state.records.filter(record => {
    if (!matchesSmartSearch(record, state.searchQuery, state.selectedMitigations)) return false;
    if (!severity.has(record.severity)) return false;
    if (!vectors.has(record.attack.vector)) return false;
    if (!matchesProductFilters(record)) return false;
    if ($("filter-exploited").checked && !(record.threat.kev || record.threat.exploitation_detected)) return false;
    if ($("filter-likely").checked && record.threat.exploitation_assessment !== "more-likely") return false;
    if ($("filter-review").checked && !record.review.required) return false;
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
      <td><span class="cve-id">${escapeHtml(record.cve)}</span>${record.review.required ? `<span class="review-badge" title="${escapeHtml(record.review.reasons.map(reason => reason.message).join(" "))}">Review required</span>` : ""}</td>
      <td class="title-cell">${escapeHtml(record.title)}<span class="secondary-line">${severityHtml(record)} · ${escapeHtml(record.attack.vector)}</span></td>
      <td><div class="tag-list">${[...(record.product_tags || []), ...record.tags].slice(0, 8).map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join("")}</div></td>
      <td><span class="threat-line">Microsoft: ${formatMicrosoftAssessment(record.threat.exploitation_assessment)}</span><span class="secondary-line">CVSS ${record.cvss.base_score ?? "Not published"}${record.cvss.temporal_score !== null && record.cvss.temporal_score !== undefined ? ` · temporal ${record.cvss.temporal_score}` : ""}</span><span class="secondary-line">EPSS ${epssDisplay(record.threat)}</span>${record.threat.kev ? `<span class="kev-line">CISA KEV listed</span>` : ""}</td>
      <td><span class="decision ${decisionClass(profile.baseline.action)}">${escapeHtml(formatPriority(profile.baseline.action))}</span><span class="secondary-line">${escapeHtml(profile.baseline.likelihood)}</span></td>
      <td><span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(formatPriority(profile.residual.action))}</span><span class="secondary-line">${escapeHtml(profile.residual.likelihood)}</span>${changed ? `<span class="change-note">Adjusted by verified relevant controls</span>` : ""}</td>
    </tr>`;
  }).join("");

  const profiles = records.map(record => predictProfile(record, state.selectedMitigations));
  $("visible-count").textContent = records.length;
  $("immediate-count").textContent = profiles.filter(p => p.residual.action === "Immediate").length;
  $("out-cycle-count").textContent = profiles.filter(p => p.residual.action === "Out-of-cycle").length;
  $("scheduled-count").textContent = profiles.filter(p => p.residual.action === "Scheduled").length;
  $("no-action-count").textContent = profiles.filter(p => p.residual.action === "Defer and review").length;
  $("review-count").textContent = records.filter(record => record.review.required).length;
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
  if (record.severity === "Unknown") return "The vendor published no severity rating and no CVSS score, so no severity-driven judgement is possible. This record is flagged for review; the scheduled action is a placeholder, not a finding of low risk.";
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
    <p class="detail-meta">${severityHtml(record)} · ${escapeHtml(record.attack.vector)} · ${escapeHtml(record.month)}</p>
    <p>${escapeHtml(record.title)}</p>
    ${record.review.required ? `<section class="review-notice" aria-label="Further review required">
      <h3>Further review required</h3>
      <ul>${record.review.reasons.map(reason => `<li>${escapeHtml(reason.message)}${reason.evidence ? `<span class="secondary-line">${escapeHtml(formatPriorityText(reason.evidence))}</span>` : ""}</li>`).join("")}</ul>
      <p>Review these points alongside the shown patch priority.</p>
    </section>` : ""}
    <h3>Risk assessment</h3>
    <dl class="risk-breakdown">
      <dt>Threat likelihood</dt><dd>${escapeHtml(profile.baseline.likelihood)}</dd>
      <dt>Baseline model</dt><dd>${escapeHtml(profile.baseline.model || "deterministic fallback")}</dd>
      <dt>Microsoft</dt><dd>${formatMicrosoftAssessment(record.threat.exploitation_assessment)}</dd>
      <dt>CVSS</dt><dd>${record.cvss.base_score ?? "Not published"}${record.cvss.temporal_score !== null && record.cvss.temporal_score !== undefined ? ` · temporal ${record.cvss.temporal_score}` : ""}</dd>
      <dt>Exploit path</dt><dd>${escapeHtml(record.attack.vector)} · privileges ${escapeHtml(record.attack.privileges_required)} · interaction ${escapeHtml(record.attack.user_interaction)}</dd>
      <dt>Baseline priority</dt><dd><span class="decision ${decisionClass(profile.baseline.action)}">${escapeHtml(formatPriority(profile.baseline.action))}</span></dd>
      <dt>With controls</dt><dd><span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(formatPriority(profile.residual.action))}</span></dd>
    </dl>
    <p class="risk-interpretation">${escapeHtml(formatPriorityText(riskInterpretation(record, profile)))}</p>
    <ul class="reason-list">${profile.reasons.map(reason => `<li>${escapeHtml(formatPriorityText(reason))}</li>`).join("")}</ul>
    ${framework ? `<div class="framework-review">
      <h3>Framework review</h3>
      <p><strong>Why this priority:</strong> ${escapeHtml(formatPriorityText(framework.risk_communication.why_this_action))}</p>
      <p><strong>Control limitations:</strong> ${escapeHtml(formatPriorityText(framework.risk_communication.control_limitations))}</p>
      <p><strong>Reassess when:</strong> ${framework.risk_communication.reassessment_triggers.map(item => escapeHtml(formatPriorityText(item))).join("; ")}</p>
      <p class="detail-meta">Model ${escapeHtml(framework.risk_model_version)} · ${escapeHtml(framework.confidence)} confidence</p>
    </div>` : ""}
    <h3>Relevant mitigation inference</h3>
    ${relevant.length ? relevant.map(item => `<div class="mitigation-row"><div class="mitigation-name">${escapeHtml(catalogName(item.id))}</div><div class="confidence">${item.confidence === "low" ? "No assessment credit · low confidence" : `${escapeHtml(item.confidence)} confidence · ${item.effect?.likelihood_steps || 0} likelihood step credit · ${item.effect?.consequence_steps || 0} consequence step credit`}</div><div>${escapeHtml(item.evidence || "No evidence fragment recorded")}</div></div>`).join("") : `<p class="detail-meta">No mitigations were inferred as relevant.</p>`}
    <h3>Inference record</h3>
    <p class="detail-meta">${escapeHtml(record.inference.model || "unknown model")} · ${record.inference.review_status === "reviewed" ? "model assessed" : "not assessed"}${record.inference.verification ? " · additional Codex review" : ""}</p>
    ${record.source.url ? `<h3>Source</h3><a class="source-link" href="${escapeHtml(record.source.url)}" target="_blank" rel="noreferrer">${escapeHtml(record.source.url)}</a>` : ""}`;
}

function catalogName(id) { return state.catalog.find(item => item.id === id)?.name || id; }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[char]); }

async function loadText(text) {
  try {
    state.records = parseJsonl(text);
    for (const record of state.records) {
      record.review = reviewStatus(record);
      record.priority = formatPriority(predictProfile(record).baseline.action);
    }
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
  const assessed = state.records.map(record => ({ ...record, review: reviewStatus(record), assessment: { assessed_at: new Date().toISOString(), selected_mitigations: [...state.selectedMitigations], profile: publicProfile(record, state.selectedMitigations), review: reviewStatus(record) } }));
  const blob = new Blob([exportJsonl(assessed)], { type: "application/x-ndjson" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${state.records[0]?.month || "patch-tuesday"}-assessment.jsonl`;
  link.click();
  URL.revokeObjectURL(url);
});
$("clear-filters").addEventListener("click", () => {
  document.querySelectorAll("#product-filters input, #mitigation-filters input, #filter-exploited, #filter-likely, #filter-review").forEach(input => { input.checked = false; });
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
for (const id of ["severity-filters", "vector-filters", "filter-exploited", "filter-likely", "filter-review"]) $(id).addEventListener("change", render);
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

loadProductFilters()
  .then(() => { renderMatchModeToggle(); renderProductFilters(); })
  .catch(error => { $("status").textContent = error.message; });
loadCatalog().catch(error => { $("status").textContent = error.message; });
loadPublishedMonths().catch(() => {});
