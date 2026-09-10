# Baseline risk models

Model version `2026.09.1` defines a framework for the public-evidence baseline used before customer-specific exposure and controls are selected. The executable guardrails and fallback policy are in `risk-model.js`.

The archetypes are reference cases, not a numeric scoring algorithm. Luna must weigh the full record and may choose an adjacent action when the evidence supports it. Hard rules protect source facts and minimum actions; they do not replace analysis.

## Required separation

Every assessment communicates four different things:

1. Applicability: whether Microsoft requires customer action.
2. Threat likelihood: current exploitation evidence from Microsoft, CISA KEV and EPSS.
3. Technical severity: CVSS impact and exploit prerequisites.
4. Action: the remediation cadence produced by combining the first three.

CVSS is not exploitation likelihood. A lower-CVSS vulnerability can require Immediate action when exploitation is confirmed. A CVSS 9.8 vulnerability can also require Immediate action before exploitation is confirmed when it is a pre-authentication network RCE and Microsoft rates exploitation More Likely.

## Threat likelihood

Microsoft Exploitability Index is the primary prospective signal:

- Exploitation Detected: Active
- Exploitation More Likely: Elevated
- Exploitation Less Likely: Plausible
- Exploitation Unlikely: Low evidence
- Not published: Plausible pending other evidence

CISA KEV or Microsoft confirmed exploitation overrides the result to Active. EPSS of at least 10 percent raises the result to Elevated. EPSS of at least 1 percent raises it to at least Plausible. EPSS may raise but never lower Microsoft's assessment.

## Baseline archetypes

### No customer action

Use when Microsoft explicitly states that no customer action is required. Action is Defer and review because Microsoft has already mitigated the hosted service or the advisory is informational.

### Active exploitation

Use when Microsoft reports exploitation detected or CISA lists the CVE in KEV. Baseline action is Immediate regardless of CVSS. Verified controls may reduce operational sequencing to Out-of-Cycle but cannot make the vulnerability Scheduled while the vulnerable component remains present.

### Critical pre-authentication network RCE

Required conditions:

- CVSS base score at least 9.0
- Remote code execution
- Network attack vector
- No privileges required
- No user interaction
- Threat likelihood Elevated or Active

Baseline action is Immediate. Ordinary reachability controls may reduce the residual action to Out-of-Cycle. Only a high-confidence, vendor-documented workaround or service disablement that blocks the exact path may reduce it further.

### Critical technical severity

Use for other Critical vulnerabilities. Baseline action is Out-of-Cycle. Threat evidence, exploit prerequisites and customer exposure determine whether a higher action is warranted.

### Elevated high severity

Use for Important vulnerabilities with Elevated threat likelihood. Baseline action is Out-of-Cycle.

### Standard remediation

Use when none of the higher archetypes apply. Baseline action is Scheduled. Defer requires explicit non-applicability, Microsoft no-action guidance, or a separately governed exception.

## Mitigation credit

- Ordinary preventive controls can reduce likelihood by at most one band.
- Two-band likelihood credit requires a high-confidence exact path block from Microsoft guidance.
- Detection and response controls receive no exploit-likelihood credit.
- Backups receive no exploit-likelihood credit.
- Consequence credit is capped at one band.
- Network controls receive credit only for network or adjacent attack vectors.
- Content controls require an evidence-backed content delivery path.
- Authentication and privilege controls must agree with the CVSS privileges-required metric and Microsoft description.

## Luna output requirements

For every reviewed CVE, Luna must return:

- Exact `cvss_basis` copied from the normalized Microsoft record
- `risk_model_version` equal to `2026.09.1`
- `baseline_model` selected from the six archetypes above
- `baseline_likelihood` and `baseline_action` matching the executable model
- A `factors` assessment covering applicability, threat evidence, exploitability, technical impact, workload context, remediation context and uncertainty
- Evidence-grounded mitigation candidates
- `risk_communication` with `summary`, `why_this_action`, `control_limitations` and `reassessment_triggers`

The merge rejects a CVSS mismatch, an unknown model or rating, violation of a hard remediation floor, unsupported mitigation credit or missing factor and communication fields.

## Framework reasoning sequence

Luna should reason in this order without converting the factors into an invented arithmetic score:

1. Confirm applicability and whether Microsoft requires customer action.
2. Establish threat evidence from Microsoft exploitation status, KEV, public disclosure and EPSS, including conflicts and freshness.
3. Interpret the full CVSS vector: attack vector, complexity, privileges, user interaction, scope and confidentiality, integrity and availability impact.
4. Identify the affected workload and its plausible enterprise concentration, such as endpoint, shared infrastructure, identity control plane or hosted service.
5. Review available fixes, workarounds, service-disable guidance and operational constraints.
6. Select the closest baseline archetype, then adjust within the allowed action scale when the combined evidence warrants it.
7. Assess each mitigation against the specific exploit chain and state what it cannot address.
8. Communicate why the chosen action is appropriate, what evidence would change it and where uncertainty remains.
