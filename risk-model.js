export const RISK_MODEL = Object.freeze({
  version: "2026.09.1",
  likelihoodLabels: ["Low evidence", "Plausible", "Elevated", "Active"],
  actionLabels: ["Defer and review", "Scheduled", "Out-of-cycle", "Immediate"],
  microsoftLikelihood: {
    detected: 3,
    "more-likely": 2,
    "less-likely": 1,
    unlikely: 0,
    unknown: 1,
  },
  epss: {
    elevatedScore: 0.10,
    plausibleScore: 0.01,
  },
  mitigation: {
    ordinaryLikelihoodCreditCap: 1,
    exactPathBlockLikelihoodCreditCap: 2,
    consequenceCreditCap: 1,
  },
  framework: {
    allowedLikelihoods: ["Low evidence", "Plausible", "Elevated", "Active"],
    allowedActions: ["Defer and review", "Scheduled", "Out-of-cycle", "Immediate"],
    requiredFactors: ["applicability", "threat_evidence", "exploitability", "technical_impact", "workload_context", "remediation_context", "uncertainty"],
  },
  baselineModels: {
    "no-customer-action": {
      action: 0,
      floorWithoutPathBlock: 0,
      floorWithPathBlock: 0,
      reason: "Microsoft states that no customer action is required",
    },
    "active-exploitation": {
      action: 3,
      floorWithoutPathBlock: 2,
      floorWithPathBlock: 2,
      reason: "Confirmed exploitation requires immediate triage and an out-of-cycle remediation floor",
    },
    "critical-preauth-network-rce": {
      action: 3,
      floorWithoutPathBlock: 2,
      floorWithPathBlock: 1,
      reason: "Critical pre-authentication network RCE with elevated exploitation evidence",
    },
    "critical-technical": {
      action: 2,
      floorWithoutPathBlock: 0,
      floorWithPathBlock: 0,
      reason: "Critical technical severity requires out-of-cycle remediation",
    },
    "elevated-high-severity": {
      action: 2,
      floorWithoutPathBlock: 0,
      floorWithPathBlock: 0,
      reason: "Elevated exploitation likelihood and high technical severity require out-of-cycle remediation",
    },
    "unknown-severity": {
      action: 1,
      floorWithoutPathBlock: 0,
      floorWithPathBlock: 0,
      requiresReview: true,
      confidence: "low",
      reason: "The vendor published neither a severity rating nor a CVSS score. Scheduled is a placeholder pending review, not a finding of low risk",
    },
    "standard-remediation": {
      action: 1,
      floorWithoutPathBlock: 0,
      floorWithPathBlock: 0,
      reason: "Current evidence supports normal scheduled remediation",
    },
  },
});

export function isCriticalPreAuthNetworkRce(record) {
  // A missing base score is not a zero. Treat it as unknown and let the
  // unknown-severity baseline handle the record instead of scoring it benign.
  const baseScore = record.cvss?.base_score;
  return typeof baseScore === "number" && baseScore >= 9
    && record.attack?.vector === "network"
    && record.attack?.privileges_required === "none"
    && record.attack?.user_interaction === "none"
    && (record.tags || []).includes("remote-code-execution");
}

export function selectBaselineModel(record, likelihoodIndex) {
  if (record.customer_action_required === false) return ["no-customer-action", RISK_MODEL.baselineModels["no-customer-action"]];
  if (record.threat?.kev || record.threat?.exploitation_detected) return ["active-exploitation", RISK_MODEL.baselineModels["active-exploitation"]];
  if (isCriticalPreAuthNetworkRce(record) && likelihoodIndex >= 2) return ["critical-preauth-network-rce", RISK_MODEL.baselineModels["critical-preauth-network-rce"]];
  if (record.severity === "Unknown") return ["unknown-severity", RISK_MODEL.baselineModels["unknown-severity"]];
  if (record.severity === "Critical") return ["critical-technical", RISK_MODEL.baselineModels["critical-technical"]];
  if (likelihoodIndex >= 2 && record.severity === "Important") return ["elevated-high-severity", RISK_MODEL.baselineModels["elevated-high-severity"]];
  return ["standard-remediation", RISK_MODEL.baselineModels["standard-remediation"]];
}
