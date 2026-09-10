import { RISK_MODEL, isCriticalPreAuthNetworkRce, selectBaselineModel } from "./risk-model.js?v=2026.09.1";

export const ACTIONS = RISK_MODEL.actionLabels;
export const LIKELIHOOD = RISK_MODEL.likelihoodLabels;
export { isCriticalPreAuthNetworkRce };

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
  if (framework?.risk_model_version === RISK_MODEL.version
      && RISK_MODEL.framework.allowedLikelihoods.includes(framework.baseline_likelihood)
      && RISK_MODEL.framework.allowedActions.includes(framework.baseline_action)
      && RISK_MODEL.baselineModels[framework.baseline_model]) {
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
    severity: record.severity || "Low",
    customer_action_required: record.customer_action_required ?? null,
    cvss: record.cvss || { base_score: null, temporal_score: null, vector: null, version: "unknown" },
    products: Array.isArray(record.products) ? record.products : [],
    tags: Array.isArray(record.tags) ? record.tags : [],
    attack: record.attack || { vector: "unknown", privileges_required: "unknown", user_interaction: "unknown" },
    threat: record.threat || {},
    mitigation_candidates: Array.isArray(record.mitigation_candidates) ? record.mitigation_candidates : [],
    source: record.source || {},
    dataset_provenance: record.dataset_provenance || {},
    inference: record.inference || {},
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
    ...(record.products || []).flatMap(product => [product.name, product.product_id]),
    ...(record.mitigation_candidates || []).flatMap(item => [item.id, item.evidence]),
    ...(record.vendor_guidance?.notes || []).flatMap(note => [note.title, note.value]),
  ].filter(Boolean).join(" ").toLowerCase();
}

function fieldMatches(record, field, value, selectedMitigations) {
  const query = value.toLowerCase();
  if (field === "cve") return record.cve.toLowerCase().includes(query);
  if (field === "tag") return (record.tags || []).some(tag => tag.toLowerCase() === query || tag.toLowerCase().includes(query));
  if (field === "product") return (record.products || []).some(product => `${product.name} ${product.product_id}`.toLowerCase().includes(query));
  if (field === "severity") return record.severity.toLowerCase() === query;
  if (field === "vector") return record.attack?.vector?.toLowerCase() === query;
  if (field === "microsoft") return record.threat?.exploitation_assessment?.toLowerCase() === query.replaceAll(" ", "-");
  if (field === "mitigation") return (record.mitigation_candidates || []).some(item => `${item.id} ${item.evidence}`.toLowerCase().includes(query));
  if (field === "kev") return Boolean(record.threat?.kev) === ["true", "yes", "1"].includes(query);
  if (field === "cvss") return compareNumber(record.cvss?.base_score, query);
  if (field === "epss") return compareNumber(record.threat?.epss, query);
  if (field === "action") return predictProfile(record, selectedMitigations).residual.action.toLowerCase().replaceAll(" ", "-") === query.replaceAll(" ", "-");
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
