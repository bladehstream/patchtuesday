import { RISK_MODEL, isCriticalPreAuthNetworkRce, selectBaselineModel } from "./risk-model.js?v=2026.09.1";

export const ACTIONS = RISK_MODEL.actionLabels;
export const LIKELIHOOD = RISK_MODEL.likelihoodLabels;
export { isCriticalPreAuthNetworkRce };

export const PRIORITY_LABELS = Object.freeze({
  "Immediate": "Emergency",
  "Out-of-cycle": "Expedited",
  "Scheduled": "Normal scheduled",
  "Defer and review": "No customer action",
});

export function formatPriority(action) {
  return PRIORITY_LABELS[action] || action;
}

export function formatPriorityText(value) {
  return String(value ?? "")
    .replace(/\bdefer and review\b/gi, "No customer action")
    .replace(/\bout[- ]of[- ]cycle\b/gi, "Expedited")
    .replace(/\bimmediate\b/gi, "Emergency")
    .replace(/\b(?<!normal )scheduled\b(?=\s+(?:remediation|patching|patch|action|handling|cadence|updating|updates?|rather|because|while|given|pending|despite)|\s*[.;,]|$)/gi, "Normal scheduled");
}

export function publicProfile(record, selectedMitigations = new Set()) {
  const profile = predictProfile(record, selectedMitigations);
  return {
    ...profile,
    baseline: { ...profile.baseline, action: formatPriority(profile.baseline.action) },
    residual: { ...profile.residual, action: formatPriority(profile.residual.action) },
    reasons: profile.reasons.map(formatPriorityText),
  };
}

const IMPACT_TAGS = new Set([
  "remote-code-execution", "elevation-of-privilege", "security-feature-bypass",
  "information-disclosure", "denial-of-service", "spoofing",
]);

// A high-severity, pre-authentication, network-reachable record with no impact tag
// at all means the assessor asserted no judgement about what the vulnerability
// does. Since impact tags gate the critical-preauth-network-rce archetype and its
// higher remediation floor, an untagged record of this shape silently loses that
// floor the moment exploitation evidence rises. Flag it rather than let a missing
// judgement read as an assessed one.
export function missingImpactJudgement(record) {
  const baseScore = record.cvss?.base_score;
  const attack = record.attack || {};
  return typeof baseScore === "number"
    && baseScore >= 9
    && attack.vector === "network"
    && attack.privileges_required === "none"
    && attack.user_interaction === "none"
    && !(record.tags || []).some(tag => IMPACT_TAGS.has(tag));
}

export function frameworkIsUsable(framework) {
  return Boolean(framework)
    && framework.risk_model_version === RISK_MODEL.version
    && RISK_MODEL.framework.allowedLikelihoods.includes(framework.baseline_likelihood)
    && RISK_MODEL.framework.allowedActions.includes(framework.baseline_action)
    && Boolean(RISK_MODEL.baselineModels[framework.baseline_model]);
}

// CVRF remediation types as MSRC uses them:
//   2 = the fix itself (Security Update / Monthly Rollup)
//   3 = the KB number in `subtype`, or "Release Notes" for Click-to-Run products
//   6 = the KB article link
// "Remediation" in CVRF means the patch, NOT a workaround. Reading it as
// "mitigation" is what produced prose like "release-note remediation references
// are supplied", which an administrator reasonably read as "there is something to
// do other than patch". There is not.
export function updateStatus(record) {
  const remediations = record.vendor_guidance?.remediations || [];
  const kbByProduct = new Map();
  for (const item of remediations) {
    const type = String(item.type);
    if (type !== "3" && type !== "6") continue;
    const kb = type === "3" ? (item.subtype || "") : (item.description || "");
    for (const id of item.product_ids || []) {
      if (kb && !kbByProduct.has(id)) kbByProduct.set(id, { kb, url: item.url || "" });
    }
  }
  const fixedIds = new Set();
  const fixKind = new Map();
  for (const item of remediations) {
    if (String(item.type) !== "2") continue;
    for (const id of item.product_ids || []) {
      fixedIds.add(id);
      if (!fixKind.has(id)) fixKind.set(id, item.subtype || "Security Update");
    }
  }
  return (record.products || []).map(product => {
    const ref = kbByProduct.get(product.product_id) || {};
    return {
      product_id: product.product_id, name: product.name,
      available: fixedIds.has(product.product_id),
      kind: fixKind.get(product.product_id) || null,
      kb: ref.kb || null, url: ref.url || null,
    };
  });
}

export function updateSummary(record, selectedProducts = new Set()) {
  const rows = updateStatus(record);
  const total = rows.length;
  const available = rows.filter(row => row.available).length;
  const recordInScope = !selectedProducts.size
    || [...(record.product_tags || []), ...(record.tags || [])].some(tag => selectedProducts.has(tag));
  const missingNames = rows.filter(row => !row.available).map(row => row.name);
  return {
    total, available, missing: total - available, rows, missingNames,
    // Scope the flag to what the administrator runs. A late Mac LTSC build is not
    // a reason to flag the record for a Windows-only estate, and an unfixed
    // product only matters if the record is in scope at all.
    flag: selectedProducts.size
      ? recordInScope && missingNames.length > 0
      : total > 0 && available === 0,
  };
}

// CVRF note Type 8 carries the assigning CNA. Microsoft republishes third-party-CNA
// CVEs across Chromium/Edge, Azure Linux packages, GitHub-assigned tooling,
// VulnCheck-assigned dependencies and more - 212 of September's 1,185 records, from
// 16 distinct CNAs. For a CVE it did not assign, Microsoft may decline to rate it at
// all: severityId 0, no CVSS, no Exploitability Index, no KB. That is policy, not a
// data gap, and it is universal for Chrome-CNA records.
//
// A CVE with no vendor severity is a declared UNKNOWN, not a declared LOW. The
// severity path already resolves it to Unknown; this names who did assign it, so a
// reviewer knows whose rating to go and read.
export function issuingCna(record) {
  const notes = record.vendor_guidance?.notes || [];
  const note = notes.find(item => item?.type === 8 && String(item.title || "").trim());
  return note ? String(note.title).trim() : null;
}

// Where the real rating lives for a third-party-CNA CVE. Static JSON, no key, and the
// bucket is the CVE's number rounded down to thousands.
export function cveProgramUrl(cve) {
  const match = /^CVE-(\d{4})-(\d+)$/.exec(String(cve || ""));
  if (!match) return null;
  const [, year, serial] = match;
  const bucket = `${serial.slice(0, -3) || "0"}xxx`;
  return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/CVE-${year}-${serial}.json`;
}

export function reviewStatus(record) {
  const reasons = [];
  const add = (code, message, evidence = "") => reasons.push({ code, message, evidence });
  // Context a reviewer should see, but not on its own a reason to hold the record. 189
  // of September's 1,185 records carry a third-party CNA; making every one of them
  // "review required" would bury the 23 that genuinely have no rating at all.
  const note = (code, message, evidence = "") => reasons.push({ code, message, evidence, informational: true });
  if (record.customer_action_required === false) return { required: false, reasons };
  const cna = issuingCna(record);
  const thirdParty = Boolean(cna) && cna !== "Microsoft";
  if (record.severity === "Unknown") {
    add(
      "missing-vendor-severity",
      thirdParty
        ? `Microsoft declined to rate this CVE because ${cna} assigned it, so there is no severity, CVSS or Exploitability Index here. Read the assigning CNA's own rating before deciding.`
        : "The vendor published no severity rating and no CVSS score. Establish the real severity before deciding.",
      thirdParty
        ? `Issuing CNA: ${cna}. Rating: ${cveProgramUrl(record.cve) || "CVE Program record"}`
        : "No vendor severity and no CVSS score on the source record.",
    );
  } else if (thirdParty) {
    // Rated by Microsoft despite a third-party assignment - worth knowing, because the
    // two scales are not the same claim, but not on its own a reason to review.
    note(
      "third-party-cna",
      `${cna} assigned this CVE; the rating shown is Microsoft's, not ${cna}'s. Check the two agree before citing either.`,
      `Issuing CNA: ${cna}. Rating: ${cveProgramUrl(record.cve) || "CVE Program record"}`,
    );
  }
  if (missingImpactJudgement(record)) {
    add(
      "missing-impact-judgement",
      "No impact tag was asserted for a high-severity, pre-authentication, network-reachable vulnerability. Establish what it actually does before relying on the remediation floor.",
      `base_score=${record.cvss?.base_score} vector=${record.attack?.vector} privileges_required=${record.attack?.privileges_required} user_interaction=${record.attack?.user_interaction}`,
    );
  }
  const framework = record.inference?.framework_assessment;
  if (!framework || record.inference?.model === "none") {
    add("missing-assessment", "Obtain an inference assessment for this CVE.");
  } else if (!frameworkIsUsable(framework)) {
    // The saved assessment exists but does not validate, so baselineProfile fell
    // back to deterministic policy. That fallback is a placeholder, not a
    // judgement, and must never pass silently as an assessed record.
    add(
      "unusable-assessment",
      "The saved assessment failed validation, so no model judgement is in force. Re-run inference for this CVE.",
      `risk_model_version=${framework.risk_model_version ?? "absent"} baseline_model=${framework.baseline_model ?? "absent"}`,
    );
  } else {
    const uncertainty = framework.factors?.uncertainty || "";
    if (framework.confidence === "low") add("low-confidence", "Check the assessment's low-confidence conclusion.", uncertainty);
    const conflict = /\b(?:conflicts?|conflicting|contradict\w*|inconsisten\w*|discrepanc\w*|tension)\b/i;
    const interpretationOnly = /simplistic|simple .{0,25}interpretation|EPSS signal conflicts|Critical severity.*CVSS|between Critical severity and|privileges-required value conflicts with the FAQ.s authorized-user SQL Copilot workflow|CVSS says no user interaction while the FAQ describes file opening or preview rendering/i;
    if (conflict.test(uncertainty) && !interpretationOnly.test(uncertainty)) {
      add("guidance-discrepancy", "Check the reported discrepancy in exploit, impact or product guidance.", uncertainty);
    }
    // Update availability comes from the vendor's structured remediation list,
    // not from pattern-matching the model's prose. The old regex fired on any
    // narrative mentioning a late build, which flagged every Office CVE for every
    // reader because the Mac LTSC update was behind.
    const updates = updateSummary(record);
    if (updates.total > 0 && updates.available === 0) {
      add("no-update-available", "No vendor fix is listed for any affected product.",
          `0 of ${updates.total} affected products have a listed update`);
    }
    const base = baselineProfile(record);
    if (base.likelihood > LIKELIHOOD.indexOf(framework.baseline_likelihood)) {
      add("changed-threat-evidence", "Recheck the explanation against the newer threat evidence.");
    }
    if (base.action === 3 && base.likelihood < 2) {
      add("workload-priority", "Confirm the workload role and exposure supporting Emergency priority.", framework.factors?.workload_context || "");
    }
  }
  if (record.cvss?.base_score == null || ["vector", "privileges_required", "user_interaction"].some(key => !record.attack?.[key] || record.attack[key] === "unknown")) {
    add("incomplete-prerequisites", "Confirm the missing CVSS or exploit-prerequisite details.");
  }
  if (record.threat?.epss_status === "stale") add("stale-threat-data", "Refresh the stale threat data before relying on the assessment.");
  return { required: reasons.some(reason => !reason.informational), reasons };
}

export function baselineProfile(record) {
  const threat = record.threat || {};
  const microsoftLikelihood = RISK_MODEL.microsoftLikelihood[threat.exploitation_assessment] ?? RISK_MODEL.microsoftLikelihood.unknown;
  let likelihood = microsoftLikelihood;
  const reasons = [`Microsoft exploitation assessment: ${formatMicrosoftAssessment(threat.exploitation_assessment)}`];

  if (record.customer_action_required === false) {
    const [modelId, model] = selectBaselineModel(record, 0);
    return { likelihood: 0, action: model.action, model: modelId, modelVersion: RISK_MODEL.version, reasons: [model.reason] };
  }

  if (threat.kev || threat.exploitation_detected) {
    likelihood = 3;
    reasons.push(threat.kev ? "CISA KEV" : "Microsoft exploitation detected");
  }

  if ((threat.epss || 0) >= RISK_MODEL.epss.elevatedScore) {
    likelihood = Math.max(likelihood, 2);
    reasons.push("EPSS provides elevated exploitation evidence");
  } else if ((threat.epss || 0) >= RISK_MODEL.epss.plausibleScore) {
    likelihood = Math.max(likelihood, 1);
    reasons.push("EPSS provides additional exploitation evidence");
  }

  const evidenceLikelihood = likelihood;
  const [fallbackModelId, fallbackModel] = selectBaselineModel(record, likelihood);
  let modelId = fallbackModelId;
  let model = fallbackModel;
  let action = model.action;
  const framework = record.inference?.framework_assessment;
  if (frameworkIsUsable(framework)) {
    likelihood = Math.max(likelihood, LIKELIHOOD.indexOf(framework.baseline_likelihood));
    action = ACTIONS.indexOf(framework.baseline_action);
    modelId = framework.baseline_model;
    model = RISK_MODEL.baselineModels[modelId];
    reasons.push(`Framework assessment: ${framework.risk_communication?.why_this_action || model.reason}`);
    if (Array.isArray(framework.policy_adjustments)) reasons.push(...framework.policy_adjustments.filter(reason => typeof reason === "string"));
    if (evidenceLikelihood > LIKELIHOOD.indexOf(framework.baseline_likelihood)) {
      action = Math.max(action, fallbackModel.action);
      modelId = fallbackModelId;
      model = fallbackModel;
      reasons.push("Current source evidence exceeds the saved inference; its likelihood and remediation floor take precedence. Review the saved explanation.");
    }
  } else {
    reasons.push(model.reason);
  }

  if (threat.kev || threat.exploitation_detected) {
    likelihood = 3;
    action = 3;
    modelId = "active-exploitation";
    model = RISK_MODEL.baselineModels[modelId];
  }

  if (isCriticalPreAuthNetworkRce(record)) {
    action = Math.max(action, 2);
    if (likelihood >= 2 && modelId !== "active-exploitation") modelId = "critical-preauth-network-rce";
  }
  action = Math.max(action, 1);

  return { likelihood, action, model: modelId, modelVersion: RISK_MODEL.version, reasons };
}

export function predictProfile(record, selectedMitigations = new Set()) {
  const base = baselineProfile(record);
  if (record.customer_action_required === false) {
    return {
      baseline: { likelihood: LIKELIHOOD[base.likelihood], action: ACTIONS[base.action], model: base.model, model_version: base.modelVersion },
      residual: { likelihood: LIKELIHOOD[base.likelihood], action: ACTIONS[base.action], model: base.model, model_version: base.modelVersion },
      applied: [],
      ignored: [],
      reasons: base.reasons,
    };
  }
  const candidates = record.mitigation_candidates || [];
  let likelihoodCredit = 0;
  let consequenceCredit = 0;
  const applied = [];
  const ignored = [];
  const seen = new Set();

  for (const candidate of candidates) {
    if (!selectedMitigations.has(candidate.id)) continue;
    if (seen.has(candidate.id)) continue;
    seen.add(candidate.id);
    if (candidate.relevance !== "relevant" || !["medium", "high"].includes(candidate.confidence)) {
      ignored.push(`${candidate.id}: inference did not establish exploit-path relevance`);
      continue;
    }
    const effect = candidate.effect || {};
    const likelihoodSteps = effect.likelihood_steps || 0;
    const consequenceSteps = effect.consequence_steps || 0;
    const networkControls = ["remove_external_exposure", "segmentation_acl", "exploit_specific_ips", "waf_virtual_patch", "isolation_airgap"];
    const incompatible = ![0, 1, 2].includes(likelihoodSteps) || ![0, 1, 2].includes(consequenceSteps)
      || (likelihoodSteps > 0 && networkControls.includes(candidate.id) && !["network", "adjacent"].includes(record.attack?.vector))
      || (likelihoodSteps > 0 && ["edr_detection_response", "immutable_backups"].includes(candidate.id))
      || (likelihoodSteps > 0 && ["email_web_filtering", "office_protected_view"].includes(candidate.id) && !record.tags?.includes("user-content"))
      || (likelihoodSteps > 0 && ["strong_authentication", "least_privilege_pam"].includes(candidate.id) && !["low", "high"].includes(record.attack?.privileges_required))
      || (effect.path_block && !(candidate.confidence === "high" && ["vendor_workaround", "service_disabled_vendor_guidance"].includes(candidate.id)))
      || (likelihoodSteps === 2 && !effect.path_block);
    if (incompatible) {
      ignored.push(`${candidate.id}: effect is incompatible with source prerequisites or mitigation guardrails`);
      continue;
    }
    likelihoodCredit += Math.max(0, Number(candidate.effect?.likelihood_steps || 0));
    consequenceCredit += Math.max(0, Number(candidate.effect?.consequence_steps || 0));
    applied.push(candidate);
  }

  const specialPathBlock = applied.some(item => item.effect?.path_block === true && item.confidence === "high");
  const model = RISK_MODEL.baselineModels[base.model];
  const maxLikelihoodCredit = specialPathBlock ? RISK_MODEL.mitigation.exactPathBlockLikelihoodCreditCap : RISK_MODEL.mitigation.ordinaryLikelihoodCreditCap;
  likelihoodCredit = Math.min(likelihoodCredit, maxLikelihoodCredit);
  consequenceCredit = Math.min(consequenceCredit, RISK_MODEL.mitigation.consequenceCreditCap);

  const residualLikelihood = Math.max(0, base.likelihood - likelihoodCredit);
  let residualAction = base.action;
  if (likelihoodCredit >= 1 || consequenceCredit >= 1) residualAction -= 1;
  if (likelihoodCredit >= 2 && consequenceCredit >= 1) residualAction -= 1;
  const actionFloor = Math.max(1, specialPathBlock ? model.floorWithPathBlock : model.floorWithoutPathBlock);
  residualAction = Math.max(actionFloor, residualAction);

  const reasons = [...base.reasons];
  if (applied.length) reasons.push(`${applied.length} verified exploit-relevant mitigation${applied.length === 1 ? "" : "s"} applied`);
  if (actionFloor === 2 && residualAction === 2) reasons.push(`${model.reason}; the model enforces an out-of-cycle remediation floor`);

  return {
    baseline: { likelihood: LIKELIHOOD[base.likelihood], action: ACTIONS[base.action], model: base.model, model_version: base.modelVersion },
    residual: { likelihood: LIKELIHOOD[residualLikelihood], action: ACTIONS[residualAction], model: base.model, model_version: base.modelVersion },
    applied,
    ignored,
    reasons,
  };
}

export function normalizeRecord(record) {
  return {
    schema_version: record.schema_version || "1.0",
    month: record.month || "unknown",
    cve: record.cve || "UNKNOWN",
    title: record.title || "Untitled vulnerability",
    severity: record.severity || "Unknown",
    severity_basis: record.severity_basis || (record.severity ? "vendor" : "absent"),
    customer_action_required: record.customer_action_required ?? null,
    cvss: record.cvss || { base_score: null, temporal_score: null, vector: null, version: "unknown" },
    products: Array.isArray(record.products) ? record.products : [],
    tags: Array.isArray(record.tags) ? record.tags : [],
    product_tags: Array.isArray(record.product_tags) ? record.product_tags : [],
    attack: record.attack || { vector: "unknown", privileges_required: "unknown", user_interaction: "unknown" },
    threat: record.threat || {},
    mitigation_candidates: Array.isArray(record.mitigation_candidates) ? record.mitigation_candidates : [],
    // Carries the vendor's structured remediation list, which updateStatus reads.
    // Omitting it here silently emptied the affected-products table: parseJsonl
    // dropped the field, so every record looked as though no fix existed.
    vendor_guidance: record.vendor_guidance || {},
    source: record.source || {},
    dataset_provenance: record.dataset_provenance || {},
    inference: record.inference || {},
    review: record.review || null,
    priority: record.priority || null,
    assessment: record.assessment || null,
  };
}

export function parseJsonl(text) {
  return text.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map((line, index) => {
    try { return normalizeRecord(JSON.parse(line)); }
    catch (error) { throw new Error(`Invalid JSON on line ${index + 1}: ${error.message}`); }
  });
}

export function exportJsonl(records) {
  return records.map(record => JSON.stringify(record)).join("\n") + "\n";
}

export function formatEpss(value) {
  if (value === null || value === undefined || value === "") return "Not yet scored";
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "Not yet scored";
  const percent = numeric * 100;
  if (percent > 0 && percent < 0.01) return "<0.01%";
  for (const threshold of [1, 10]) {
    if (percent < threshold && Number(percent.toFixed(threshold === 1 ? 2 : 1)) >= threshold) {
      const precise = Number(percent.toFixed(3));
      return precise < threshold ? `${precise}%` : `<${threshold}%`;
    }
  }
  if (percent < 1) return `${percent.toFixed(2)}%`;
  return `${percent.toFixed(1)}%`;
}

export function formatMicrosoftAssessment(value) {
  return ({
    detected: "Detected",
    "more-likely": "More likely",
    "less-likely": "Less likely",
    unlikely: "Unlikely",
    unknown: "Not published",
  })[value] || "Not published";
}

function queryTokens(query) {
  const tokens = [];
  const pattern = /"([^"]+)"|(\S+)/g;
  let match;
  while ((match = pattern.exec(query)) !== null) tokens.push(match[1] || match[2]);
  return tokens;
}

function compareNumber(actual, expression) {
  if (actual === null || actual === undefined || !Number.isFinite(Number(actual))) return false;
  const match = String(expression).match(/^(>=|<=|>|<|=)?\s*([0-9.]+)(%)?$/);
  if (!match) return false;
  const operator = match[1] || "=";
  let expected = Number(match[2]);
  if (match[3]) expected /= 100;
  const value = Number(actual);
  return ({
    ">=": value >= expected,
    "<=": value <= expected,
    ">": value > expected,
    "<": value < expected,
    "=": value === expected,
  })[operator];
}

function allText(record) {
  return [
    record.cve,
    record.title,
    record.severity,
    record.attack?.vector,
    record.attack?.privileges_required,
    record.attack?.user_interaction,
    record.threat?.exploitation_assessment,
    ...(record.tags || []),
    ...(record.product_tags || []),
    ...(record.products || []).flatMap(product => [product.name, product.product_id]),
    ...(record.mitigation_candidates || []).flatMap(item => [item.id, item.evidence]),
    ...(record.vendor_guidance?.notes || []).flatMap(note => [note.title, note.value]),
  ].filter(Boolean).join(" ").toLowerCase();
}

function fieldMatches(record, field, value, selectedMitigations) {
  const query = value.toLowerCase();
  if (field === "cve") return record.cve.toLowerCase().includes(query);
  if (field === "tag") return [...(record.tags || []), ...(record.product_tags || [])].some(tag => tag.toLowerCase() === query || tag.toLowerCase().includes(query));
  if (field === "product") return (record.products || []).some(product => `${product.name} ${product.product_id}`.toLowerCase().includes(query));
  if (field === "severity") return record.severity.toLowerCase() === query;
  if (field === "vector") return record.attack?.vector?.toLowerCase() === query;
  if (field === "microsoft") return record.threat?.exploitation_assessment?.toLowerCase() === query.replaceAll(" ", "-");
  if (field === "mitigation") return (record.mitigation_candidates || []).some(item => `${item.id} ${item.evidence}`.toLowerCase().includes(query));
  if (field === "kev") return Boolean(record.threat?.kev) === ["true", "yes", "1"].includes(query);
  if (field === "cvss") return compareNumber(record.cvss?.base_score, query);
  if (field === "epss") return compareNumber(record.threat?.epss, query);
  if (field === "action") {
    const action = predictProfile(record, selectedMitigations).residual.action;
    return [action, formatPriority(action)].some(label => label.toLowerCase().replaceAll(" ", "-") === query.replaceAll(" ", "-"));
  }
  if (field === "review") return reviewStatus(record).required === ["required", "true", "yes", "1"].includes(query);
  if (field === "likelihood") return predictProfile(record, selectedMitigations).residual.likelihood.toLowerCase().replaceAll(" ", "-") === query.replaceAll(" ", "-");
  return null;
}

export function matchesSmartSearch(record, query, selectedMitigations = new Set()) {
  if (!String(query || "").trim()) return true;
  const haystack = allText(record);
  return queryTokens(query).every(rawToken => {
    const negative = rawToken.startsWith("-") && rawToken.length > 1;
    const token = negative ? rawToken.slice(1) : rawToken;
    const separator = token.indexOf(":");
    let matched;
    if (separator > 0) {
      const field = token.slice(0, separator).toLowerCase();
      const value = token.slice(separator + 1);
      const fieldResult = fieldMatches(record, field, value, selectedMitigations);
      matched = fieldResult === null ? haystack.includes(token.toLowerCase()) : fieldResult;
    } else {
      matched = haystack.includes(token.toLowerCase());
    }
    return negative ? !matched : matched;
  });
}

// ---------------------------------------------------------------------------
// Overview board
// ---------------------------------------------------------------------------

// One definition of what a filter option matches, shared by the checkbox filter
// and the overview tiles. Two copies drifted once already: the config says
// "product_tags+tags" but nothing here unions them, so the workload hint and the
// reach figures quoted in the handoff describe behaviour the code does not have.
// That discrepancy is reported, not silently corrected here - changing which
// records a workload tag reaches changes what the tool asserts about coverage.
export function recordFilterTags(record, source) {
  return source === "tags" ? (record.tags || []) : (record.product_tags || []);
}

// A tile is green only when nothing at its worst level is missing a vendor
// severity. Edge is the case that forces this: 23 Chromium passthrough records,
// every one of them severity Unknown and review-required, all resolving to
// Scheduled because unknown-severity's action is a placeholder. Its own reason
// string says so - "a placeholder pending review, not a finding of low risk" -
// and a green light would republish exactly the claim rule 1 exists to prevent.
//
// The boundary: Unverified replaces a colour that would understate, never one
// that would overstate. A tile whose worst level is Expedited or Emergency keeps
// that colour even if those records carry no vendor severity, because a
// KEV-listed Unknown-severity record is an emergency with a data gap, not an
// absence of urgency. Greying it would be the same coercion in the other
// direction.
const UNDERSTATING_ACTIONS = new Set(["Scheduled", "Defer and review"]);

export const TILE_STATES = Object.freeze({
  "Immediate": "emergency",
  "Out-of-cycle": "expedited",
  "Scheduled": "scheduled",
  "Defer and review": "no-action",
});

export function summariseTile(records, selectedMitigations = new Set()) {
  const counts = Object.fromEntries(ACTIONS.map(action => [action, 0]));
  let worstIndex = -1;
  // One profile per record. Every tile on the board runs this on every render,
  // and predictProfile walks the mitigation candidates each time it is called.
  const actions = records.map(record => predictProfile(record, selectedMitigations).residual.action);
  for (const action of actions) {
    counts[action] += 1;
    worstIndex = Math.max(worstIndex, ACTIONS.indexOf(action));
  }
  const worstAction = worstIndex < 0 ? null : ACTIONS[worstIndex];
  const unverified = worstAction !== null
    && UNDERSTATING_ACTIONS.has(worstAction)
    && records.every((record, index) => actions[index] !== worstAction || record.severity === "Unknown");
  // reviewStatus is the most expensive thing here - it rebuilds the per-product
  // update tables from the vendor remediation list. The loaders already compute
  // it once per record, so use that result when it is present.
  const reviewCount = records.filter(record =>
    (record.review ? record.review.required : reviewStatus(record).required)).length;
  return {
    total: records.length,
    counts,
    worstAction,
    worstCount: worstAction === null ? 0 : counts[worstAction],
    reviewCount,
    unverified,
    state: worstAction === null ? "empty" : unverified ? "unverified" : TILE_STATES[worstAction],
  };
}

// The board is deliberately independent of the severity, vector, search and
// product filters. Those narrow the view; an overview that changes when you
// untick "Local" is not an overview. Verified mitigations are the exception:
// they are facts asserted about the estate, and they move the answer.
export function overviewBoard(records, filterConfig, selectedMitigations = new Set()) {
  return (filterConfig?.groups || []).map(group => ({
    id: group.id,
    label: group.label,
    hint: group.hint || "",
    source: group.source,
    tiles: group.options
      // An option can opt out of the board while staying in the filter list.
      // "Microsoft" matches every record in the month, so as a tile it restates
      // the month summary directly above it in a permanently alarming colour.
      .filter(option => option.overview !== false)
      .map(option => ({
        tag: option.tag,
        label: option.label,
        ...summariseTile(
          records.filter(record => recordFilterTags(record, group.source).includes(option.tag)),
          selectedMitigations,
        ),
      })),
  }));
}

// The month totals the tiles decompose. Same scope rule as the board.
export function monthTotals(records, selectedMitigations = new Set()) {
  const summary = summariseTile(records, selectedMitigations);
  return { total: summary.total, counts: summary.counts, reviewCount: summary.reviewCount };
}

// The advisories that set the tone for the month. Every Emergency is shown
// without exception - truncating that list would be the one omission an
// administrator cannot afford - and Expedited records top it up to a readable
// minimum. Once Emergency alone reaches the minimum the Expedited records are
// dropped rather than appended, because at that point the month's problem is
// the emergencies and a longer list only buries them.
//
// Ordering within each band runs on exploitation evidence, then CVSS, then CVE,
// so the sequence is stable between renders and identical for two readers
// looking at the same month.
export function worstFirst(records, selectedMitigations = new Set(), { minimum = 10, maxTopUp = 10 } = {}) {
  const ranked = records
    .map(record => ({ record, profile: predictProfile(record, selectedMitigations) }))
    .filter(item => ACTIONS.indexOf(item.profile.residual.action) >= 2)
    .sort((a, b) => {
      const byAction = ACTIONS.indexOf(b.profile.residual.action) - ACTIONS.indexOf(a.profile.residual.action);
      if (byAction) return byAction;
      const byLikelihood = LIKELIHOOD.indexOf(b.profile.residual.likelihood) - LIKELIHOOD.indexOf(a.profile.residual.likelihood);
      if (byLikelihood) return byLikelihood;
      const byScore = (b.record.cvss?.base_score ?? 0) - (a.record.cvss?.base_score ?? 0);
      if (byScore) return byScore;
      return a.record.cve.localeCompare(b.record.cve);
    });
  const emergency = ranked.filter(item => item.profile.residual.action === "Immediate");
  if (emergency.length >= minimum) return emergency;
  const topUp = ranked.filter(item => item.profile.residual.action === "Out-of-cycle");
  return [...emergency, ...topUp.slice(0, Math.min(maxTopUp, minimum - emergency.length))];
}
