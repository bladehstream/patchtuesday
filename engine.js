export const ACTIONS = ["Defer and review", "Scheduled", "Out-of-cycle", "Immediate"];
export const LIKELIHOOD = ["Low evidence", "Plausible", "Elevated", "Active"];

const severityRank = { Critical: 4, Important: 3, Moderate: 2, Low: 1 };

export function baselineProfile(record) {
  const threat = record.threat || {};
  const vector = (record.attack || {}).vector || "unknown";
  const severity = severityRank[record.severity] || 1;
  const microsoftLikelihood = {
    detected: 3,
    "more-likely": 2,
    "less-likely": 1,
    unlikely: 0,
    unknown: 1,
  }[threat.exploitation_assessment] ?? 1;
  let likelihood = microsoftLikelihood;
  let action = 1;
  const reasons = [`Microsoft exploitation assessment: ${formatMicrosoftAssessment(threat.exploitation_assessment)}`];

  if (record.customer_action_required === false) {
    return { likelihood: 0, action: 0, reasons: ["Microsoft states that no customer action is required"] };
  }

  if (threat.kev || threat.exploitation_detected) {
    likelihood = 3;
    action = 3;
    reasons.push(threat.kev ? "CISA KEV" : "Microsoft exploitation detected");
  }

  if ((threat.epss || 0) >= 0.1) {
    likelihood = Math.max(likelihood, 2);
    reasons.push("EPSS provides elevated exploitation evidence");
  } else if ((threat.epss || 0) >= 0.01) {
    likelihood = Math.max(likelihood, 1);
    reasons.push("EPSS provides additional exploitation evidence");
  }

  if (action < 3 && severity === 4) {
    action = 2;
    reasons.push("Critical technical severity");
  } else if (action < 3 && likelihood >= 2 && severity >= 3) {
    action = 2;
    reasons.push("Elevated exploitation likelihood and high technical severity");
  } else if (severity <= 2) {
    action = 1;
    reasons.push("No current high-confidence exploitation evidence");
  } else if (action < 2) {
    reasons.push("Important severity requires scheduled remediation");
  }

  if (vector === "network" && (record.attack || {}).privileges_required === "none") {
    action = Math.max(action, 2);
    reasons.push("Network reachable without privileges");
  }

  return { likelihood, action, reasons };
}

export function predictProfile(record, selectedMitigations = new Set()) {
  const base = baselineProfile(record);
  if (record.customer_action_required === false) {
    return {
      baseline: { likelihood: LIKELIHOOD[base.likelihood], action: ACTIONS[base.action] },
      residual: { likelihood: LIKELIHOOD[base.likelihood], action: ACTIONS[base.action] },
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

  for (const candidate of candidates) {
    if (!selectedMitigations.has(candidate.id)) continue;
    if (candidate.relevance === "not-relevant" || candidate.confidence === "low") {
      ignored.push(`${candidate.id}: inference did not establish exploit-path relevance`);
      continue;
    }
    likelihoodCredit += Math.max(0, Number(candidate.effect?.likelihood_steps || 0));
    consequenceCredit += Math.max(0, Number(candidate.effect?.consequence_steps || 0));
    applied.push(candidate);
  }

  const active = Boolean(record.threat?.kev || record.threat?.exploitation_detected);
  const specialPathBlock = applied.some(item => item.effect?.path_block === true && item.confidence === "high");
  const maxLikelihoodCredit = specialPathBlock ? 2 : 1;
  likelihoodCredit = Math.min(likelihoodCredit, maxLikelihoodCredit);
  consequenceCredit = Math.min(consequenceCredit, 1);

  const residualLikelihood = Math.max(0, base.likelihood - likelihoodCredit);
  let residualAction = base.action;
  if (likelihoodCredit >= 1 || consequenceCredit >= 1) residualAction -= 1;
  if (likelihoodCredit >= 2 && consequenceCredit >= 1) residualAction -= 1;
  residualAction = Math.max(active ? 2 : 0, residualAction);

  const reasons = [...base.reasons];
  if (applied.length) reasons.push(`${applied.length} verified exploit-relevant mitigation${applied.length === 1 ? "" : "s"} applied`);
  if (active && residualAction === 2) reasons.push("Active exploitation enforces an out-of-cycle floor");

  return {
    baseline: { likelihood: LIKELIHOOD[base.likelihood], action: ACTIONS[base.action] },
    residual: { likelihood: LIKELIHOOD[residualLikelihood], action: ACTIONS[residualAction] },
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
