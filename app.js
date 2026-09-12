import { ACTIONS, updateSummary, exportJsonl, formatEpss, formatMicrosoftAssessment, formatPriority, formatPriorityText, monthTotals, overviewBoard, publicProfile, recordFilterTags, reviewStatus, isCriticalPreAuthNetworkRce, matchesSmartSearch, parseJsonl, predictProfile, worstFirst } from "./engine.js?v=2026.09.overview";

const state = { records: [], recordByCve: new Map(), catalog: [], productFilters: null, selectedProducts: new Set(), productMatchMode: "or", selectedMitigations: new Set(), selectedCve: null, searchQuery: "", view: "overview" };
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

// The same catalogue is offered on both views. One selection set backs both
// widgets, so a control verified on the overview is still verified when the
// administrator moves to the advisory list and vice versa.
const MITIGATION_WIDGETS = [
  { list: "mitigation-filters", summary: "mitigation-summary" },
  { list: "ov-mitigation-filters", summary: "ov-mitigation-summary" },
];

function renderMitigations() {
  for (const widget of MITIGATION_WIDGETS) {
    const container = $(widget.list);
    if (!container) continue;
    container.classList.remove("muted-copy");
    container.innerHTML = state.catalog.map(item => `
      <label title="${escapeHtml(item.credit_rule)}">
        <input type="checkbox" value="${escapeHtml(item.id)}"${state.selectedMitigations.has(item.id) ? " checked" : ""} />
        <span>${escapeHtml(item.name)}<span class="secondary-line">${escapeHtml(item.category)}</span></span>
      </label>`).join("");
    container.onchange = () => {
      state.selectedMitigations = checkedValues(widget.list);
      syncMitigationWidgets();
      render();
    };
  }
  updateMitigationSummary();
}

// Push the shared selection back into whichever widget did not originate the
// change, so the two can never show different answers for the same state.
function syncMitigationWidgets() {
  for (const widget of MITIGATION_WIDGETS) {
    const container = $(widget.list);
    if (!container) continue;
    for (const input of container.querySelectorAll("input[type=checkbox]")) {
      input.checked = state.selectedMitigations.has(input.value);
    }
  }
  updateMitigationSummary();
}

function updateMitigationSummary() {
  const selected = [...state.selectedMitigations];
  const text = !selected.length
    ? "No mitigations selected"
    : selected.length === 1 ? catalogName(selected[0]) : `${selected.length} mitigations selected`;
  for (const widget of MITIGATION_WIDGETS) {
    const summary = $(widget.summary);
    if (summary) summary.textContent = text;
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

// Colour is never the only carrier of meaning: every tile states its level in
// words as well, and the empty and unverified states say what they are rather
// than relying on being a different shade of grey.
const TILE_STATE_LABELS = Object.freeze({
  emergency: "Emergency",
  expedited: "Expedited",
  scheduled: "Normal scheduled",
  "no-action": "No customer action",
  unverified: "Unverified",
  empty: "None this month",
});

const UNVERIFIED_EXPLANATION = "No vendor severity was published for any advisory at this level, so the action shown is a placeholder pending review rather than a finding of low risk.";

function tileHtml(tile) {
  const label = TILE_STATE_LABELS[tile.state] || tile.state;
  const countLine = tile.total === 0
    ? "No advisories"
    : `<strong>${tile.worstCount}</strong> of ${tile.total} advisor${tile.total === 1 ? "y" : "ies"}`;
  // The unverified state has to say what it is. The tile carries the short form
  // so every tile stays the same height; the full sentence is on the tooltip and
  // repeated in the review notice on the record itself.
  const note = tile.unverified ? `<span class="tile-note">No vendor severity at this level</span>` : "";
  const review = tile.reviewCount
    ? `<span class="tile-review">${tile.reviewCount} need${tile.reviewCount === 1 ? "s" : ""} review</span>`
    : "";
  const aria = `${tile.label}: ${label}, ${tile.total === 0 ? "no advisories" : `${tile.worstCount} of ${tile.total} advisories`}${tile.reviewCount ? `, ${tile.reviewCount} needing review` : ""}`;
  return `<button class="tile tile--${escapeHtml(tile.state)}" type="button" data-tag="${escapeHtml(tile.tag)}"
      aria-label="${escapeHtml(aria)}"${tile.unverified ? ` title="${escapeHtml(UNVERIFIED_EXPLANATION)}"` : ""}>
    <span class="tile-head">
      <span class="tile-label">${escapeHtml(tile.label)}</span>
      <span class="tile-pill">${escapeHtml(label)}</span>
    </span>
    <span class="tile-count">${countLine}</span>
    <span class="tile-foot">${note}${review}</span>
  </button>`;
}

// The overview list repeats what the advisory detail pane shows, because a
// reader who has come to the board for the month's worst records should not have
// to open each one to learn what it is, what the evidence is, or whether there
// is a fix to apply.
function worstCardHtml({ record, profile }) {
  const framework = record.inference?.framework_assessment;
  const communication = framework?.risk_communication;
  const updates = updateSummary(record);
  const fact = (term, value) => `<span class="fact"><span class="fact-term">${term}</span><span class="fact-value">${value}</span></span>`;
  const updateText = updates.total === 0
    ? "None listed"
    : `${updates.available} of ${updates.total} products`;
  return `<li><button class="worst-card worst-card--${decisionClass(profile.residual.action)}" type="button" data-cve="${escapeHtml(record.cve)}">
    <span class="worst-head">
      <span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(formatPriority(profile.residual.action))}</span>
      <span class="worst-cve">${escapeHtml(record.cve)}</span>
      ${record.review?.required ? `<span class="worst-flag">Review required</span>` : ""}
      ${record.threat.kev ? `<span class="worst-flag worst-flag--kev">CISA KEV</span>` : ""}
    </span>
    <span class="worst-title">${escapeHtml(record.title)}</span>
    ${communication?.summary ? `<span class="worst-summary">${escapeHtml(formatPriorityText(communication.summary))}</span>` : ""}
    <span class="worst-facts">
      ${fact("Severity", severityHtml(record))}
      ${fact("CVSS", escapeHtml(String(record.cvss.base_score ?? "Not published")))}
      ${fact("EPSS", escapeHtml(epssDisplay(record.threat)))}
      ${fact("Microsoft", escapeHtml(formatMicrosoftAssessment(record.threat.exploitation_assessment)))}
      ${fact("Likelihood", escapeHtml(profile.residual.likelihood))}
      ${fact("Exploit path", escapeHtml(`${record.attack.vector} · privileges ${record.attack.privileges_required} · interaction ${record.attack.user_interaction}`))}
      ${fact("Updates", escapeHtml(updateText))}
    </span>
    ${communication?.why_this_action ? `<span class="worst-why"><span class="fact-term">Why this action</span>${escapeHtml(formatPriorityText(communication.why_this_action))}</span>` : ""}
  </button></li>`;
}

function renderOverview() {
  const board = $("overview-board");
  if (!board) return;
  if (!state.records.length) {
    board.innerHTML = `<p class="muted-copy">Load a month to populate the overview.</p>`;
    $("worst-first-list").innerHTML = "";
    return;
  }

  const groups = overviewBoard(state.records, state.productFilters, state.selectedMitigations);
  board.innerHTML = groups.map(group => `
    <section class="board-group" aria-label="${escapeHtml(group.label)}">
      <h2 class="board-group-label">${escapeHtml(group.label)}<span class="filter-group-hint" title="${escapeHtml(group.hint)}">?</span></h2>
      <div class="tile-grid">${group.tiles.map(tileHtml).join("")}</div>
    </section>`).join("");

  board.onclick = event => {
    const tile = event.target.closest("button[data-tag]");
    if (tile && board.contains(tile)) showProduct(tile.dataset.tag);
  };

  const totals = monthTotals(state.records, state.selectedMitigations);
  $("ov-total-count").textContent = totals.total;
  $("ov-immediate-count").textContent = totals.counts.Immediate;
  $("ov-out-cycle-count").textContent = totals.counts["Out-of-cycle"];
  $("ov-scheduled-count").textContent = totals.counts.Scheduled;
  $("ov-no-action-count").textContent = totals.counts["Defer and review"];
  $("ov-review-count").textContent = totals.reviewCount;

  const worst = worstFirst(state.records, state.selectedMitigations);
  const emergencyCount = worst.filter(item => item.profile.residual.action === "Immediate").length;
  // Say what the list is showing, so a reader can tell "these are all of them"
  // from "these are the first ten of many".
  $("worst-first-scope").textContent = worst.length
    ? emergencyCount >= worst.length
      ? `All ${worst.length} Emergency advisor${worst.length === 1 ? "y" : "ies"}. Expedited records are on the Advisories tab.`
      : `${emergencyCount ? `All ${emergencyCount} Emergency advisor${emergencyCount === 1 ? "y" : "ies"}, then the ` : "The "}highest ${worst.length - emergencyCount} Expedited. Selecting one opens it on the Advisories tab.`
    : "";
  const list = $("worst-first-list");
  list.innerHTML = worst.length
    ? worst.map(worstCardHtml).join("")
    : `<li class="muted-copy">No advisory this month rises above Normal scheduled.</li>`;
  list.onclick = event => {
    const item = event.target.closest("button[data-cve]");
    if (!item || !list.contains(item)) return;
    // The list is month-wide, so the record picked here need not survive the
    // advisory list's own filters. Clear them rather than open a detail pane for
    // a row the table does not contain and the next render would drop.
    state.selectedCve = item.dataset.cve;
    state.selectedProducts.clear();
    for (const input of document.querySelectorAll("#product-filters input")) input.checked = false;
    updateProductSummary();
    setView("advisories");
    render();
    renderDetail();
  };
}

// A tile click answers "show me these". Replacing the selection rather than
// adding to it means what you land on is what you clicked, regardless of what
// was already ticked or which match mode is set.
function showProduct(tag) {
  state.selectedProducts = new Set([tag]);
  for (const input of document.querySelectorAll("#product-filters input")) {
    input.checked = input.value === tag;
  }
  updateProductSummary();
  setView("advisories");
  render();
}

const VIEWS = ["overview", "advisories"];

function setView(view, { updateHash = true } = {}) {
  state.view = VIEWS.includes(view) ? view : "overview";
  for (const name of VIEWS) {
    $(`view-${name}`).hidden = name !== state.view;
    const tab = $(`tab-${name}`);
    tab.setAttribute("aria-selected", String(name === state.view));
  }
  // Search applies to the advisory list only. Leaving it visible on a board it
  // deliberately does not filter would read as a broken control.
  $("smart-search-form").hidden = state.view !== "advisories";
  if (state.view === "overview") renderOverview();
  if (updateHash) {
    const suffix = state.view === "advisories" && state.selectedProducts.size === 1
      ? `?product=${encodeURIComponent([...state.selectedProducts][0])}`
      : "";
    const next = `#${state.view}${suffix}`;
    // pushState, not replaceState: Back has to move between the views rather
    // than leave the site. The guard above keeps a repeated setView for the same
    // view from stacking duplicate entries.
    if (location.hash !== next) history.pushState(null, "", next);
  }
}

function applyHash() {
  const raw = location.hash.replace(/^#/, "");
  const [view, query] = raw.split("?");
  const product = new URLSearchParams(query || "").get("product");
  if (product && filterOptionTag(product)) {
    state.selectedProducts = new Set([product]);
    for (const input of document.querySelectorAll("#product-filters input")) {
      input.checked = input.value === product;
    }
    updateProductSummary();
  }
  setView(VIEWS.includes(view) ? view : "overview", { updateHash: false });
  render();
}

function render() {
  // The board is whole-month work across every tile. Building it while the
  // advisory list is on screen put that cost on every search keystroke, so it is
  // built when the overview is visible and refreshed by setView on the way in.
  if (state.view === "overview") renderOverview();
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
    <h3>1 &middot; What is affected</h3>
    ${(() => {
      const u = updateSummary(record, state.selectedProducts);
      const rows = u.rows.slice().sort((a, b) => Number(a.available) - Number(b.available));
      return `<p class="update-summary">
          <strong>${u.available} of ${u.total}</strong> affected products have an update.
        </p>
        <ul class="product-list">${rows.map(row => `<li class="${row.available ? "is-available" : "is-pending"}">
            <span class="product-name">${escapeHtml(row.name)}</span>
            <span class="product-status">${row.available
              ? `Update available${row.url ? ` &middot; <a href="${escapeHtml(row.url)}" target="_blank" rel="noreferrer">${escapeHtml(row.kb && /^\d+$/.test(row.kb) ? "KB" + row.kb : row.kb || "release notes")}</a>` : row.kb ? ` &middot; ${escapeHtml(row.kb)}` : ""}`
              : "Not yet released"}</span>
          </li>`).join("")}</ul>`;
    })()}

    <h3>2 &middot; Mitigations</h3>
    ${relevant.length
      ? `<ul class="product-list mitigation-list">${relevant.map(item => `<li>
           <span class="product-name">${escapeHtml(catalogName(item.id))}</span>
           <span class="product-status">${item.confidence === "low"
             ? "no credit &middot; low confidence"
             : `likelihood &minus;${item.effect?.likelihood_steps || 0}, consequence &minus;${item.effect?.consequence_steps || 0}${item.effect?.path_block ? " &middot; blocks the path" : ""}`}</span>
           <span class="product-basis">${escapeHtml(item.evidence || "no evidence recorded")}</span>
         </li>`).join("")}</ul>`
      : `<p class="detail-meta">None. Patching is the only remediation the vendor documents.</p>`}

    <h3>3 &middot; Priority</h3>
    <dl class="risk-breakdown">
      <dt>Baseline</dt><dd><span class="decision ${decisionClass(profile.baseline.action)}">${escapeHtml(formatPriority(profile.baseline.action))}</span> &middot; ${escapeHtml(profile.baseline.likelihood)}</dd>
      <dt>With your controls</dt><dd><span class="decision ${decisionClass(profile.residual.action)}">${escapeHtml(formatPriority(profile.residual.action))}</span> &middot; ${escapeHtml(profile.residual.likelihood)}</dd>
      <dt>Exploit path</dt><dd>${escapeHtml(record.attack.vector)} &middot; privileges ${escapeHtml(record.attack.privileges_required)} &middot; interaction ${escapeHtml(record.attack.user_interaction)}</dd>
      <dt>Evidence</dt><dd>Microsoft: ${formatMicrosoftAssessment(record.threat.exploitation_assessment)} &middot; CVSS ${record.cvss.base_score ?? "not published"} &middot; EPSS ${epssDisplay(record.threat)}${record.threat.kev ? " &middot; CISA KEV" : ""}</dd>
    </dl>
    ${framework ? `<details class="framework-review">
      <summary>Assessment detail &middot; ${escapeHtml(framework.confidence)} confidence &middot; model ${escapeHtml(framework.risk_model_version)}</summary>
      <p>${escapeHtml(formatPriorityText(framework.risk_communication.why_this_action))}</p>
      ${framework.risk_communication.control_limitations ? `<p><strong>Limits:</strong> ${escapeHtml(formatPriorityText(framework.risk_communication.control_limitations))}</p>` : ""}
      ${framework.risk_communication.reassessment_triggers?.length ? `<p><strong>Reassess if:</strong> ${framework.risk_communication.reassessment_triggers.map(i => escapeHtml(formatPriorityText(i))).join("; ")}</p>` : ""}
      <ul class="reason-list">${profile.reasons.map(r => `<li>${escapeHtml(formatPriorityText(r))}</li>`).join("")}</ul>
    </details>` : ""}
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
    // loadText clears selectedProducts, so a stale ?product= in the hash would be
    // re-applied on the next refresh after the filter had already been dropped.
    setView(state.view);
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
  syncMitigationWidgets();
  state.searchQuery = "";
  $("smart-search").value = "";
  render();
});
document.addEventListener("click", event => {
  for (const id of ["product-select", "mitigation-select", "ov-mitigation-select"]) {
    const select = $(id);
    if (select?.open && !select.contains(event.target)) select.open = false;
  }
});
for (const name of VIEWS) $(`tab-${name}`).addEventListener("click", () => setView(name));
window.addEventListener("hashchange", applyHash);
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

// The overview is the landing view, so the filter list has to be in place before
// the first render: the board is built from it, and a tile carrying a product
// from the hash needs the option to exist before it can be selected.
loadProductFilters()
  .then(() => { renderMatchModeToggle(); renderProductFilters(); })
  .catch(error => { $("status").textContent = error.message; })
  .finally(() => loadPublishedMonths().catch(() => {}).then(applyHash));
loadCatalog().catch(error => { $("status").textContent = error.message; });
