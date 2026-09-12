# Assessor handoff

Start here. Guidance revision **2026.09.2**, recorded 2026-09-10.

## Read in order

1. prompts/enrichment-system.md — current overlay format and internal action identifiers.
2. prompts/assessor-evidence-guidance.md — revised evidence and reasoning requirements.
3. models/baseline-risk-models.md — qualitative reference cases and limits.
4. data/tag-taxonomy.json and data/mitigation-catalog.json — allowed tags and controls.
5. models/2026-Sep-independent-20-review.md and its JSON companion — independent findings and frozen sample.
6. models/2026-Sep-full-inference.md — prior run coverage and provenance.

The user wants a practical static tool for IT administrators: broad products/services, simple mitigation selectors, explainable priorities and review flags. No customer hostnames, IP addresses, tenant identifiers, inventories or topology should enter inference. Only public advisory material is needed.

## Current state and scope

The published September snapshot contains 1,185 actual Luna assessments. The independent spot check agreed with 17/20 patch priorities and all 20 likelihood bands, but found two unsupported severity defaults, one material mitigation mapping error, four missing review flags and a conservative PAM inconsistency. These new spot-check findings have **not** been implemented.

The refreshed MSRC feed retrieved at 2026-09-10T04:18:17Z contained 1,186 records, adding CVE-2026-85046. Recheck the live manifest/revisions before any fresh production run; do not freeze the expected total at 1,185. Existing tests still contain September-specific counts.

This handoff updates guidance only. It does not certify production readiness, rerun inference, change live ratings, implement the listed code fixes, or launch an assessor run.

## Known findings to address or retain as open issues

| Finding | Required behavior |
|---|---|
| CVE-2026-84335 / 84358 | Raw MSRC severity and CVSS are absent. The current parser turns missing score into zero and returns Low. Preserve Unknown and flag the baseline defect. |
| CVE-2026-18149, Undici | Upstream describes malicious-server responses attacking the HTTP client. Do not credit closing public ingress. Review outbound/retry paths and applicability of the upstream deadline/body-destruction workaround. |
| CVE-2026-69282 / 69615 / 69402 | Subscription Edition structured products versus Server 2016 FAQ references need explicit scope review. |
| CVE-2026-69282 / 69380 / 69510 | Independently challenge Normal scheduled given low-permission server RCE, all-mailbox access, or unauthenticated shared DHCP RCE. Expedited was the reviewer's preference; justify the outcome rather than copying a label. |
| CVE-2026-80843 | Avoid a categorical high-confidence PAM rejection based only on PR:H while accepting the same rationale elsewhere. Zero credit can remain conservative when the actual gate is unknown. |

Primary Undici reference: https://github.com/nodejs/undici/security/advisories/GHSA-pmjh-fq2x-6v4x

## Copyable starter task

> Review the files listed in ASSESSOR_HANDOFF.md, especially guidance revision 2026.09.2. Start with the frozen 20-CVE calibration sample in models/2026-Sep-independent-20-review.json. Read source evidence before the existing ratings. Produce an actual per-CVE assessment; do not build a keyword classifier or generic text generator and label it model inference. Use the exact model identifier and actual timestamps.
>
> Fetch public sources programmatically or use the frozen raw snapshot if available. Retain source revisions, original model responses, and a run manifest. Do not collect customer-specific asset information. Write trial outputs under work/assessor-trial/. Preserve the existing published dataset.
>
> Use the existing overlay fields and legacy action strings, plus the evidence extensions in prompts/assessor-evidence-guidance.md. Record attack direction, control prerequisites, residual paths and structured review reasons. Highlight missing source values instead of inheriting a fabricated Low rating.
>
> Compare your results with the independent review after making your own judgments. Separate factual failures, unsupported control credit, and defensible priority differences. Report known pipeline/adapter gaps explicitly. Do not publish a sample as a complete release. If subsequently authorized to replace production data, assess every CVE in the fresh source manifest and pass complete-coverage validation first.

An assessor CLI instance with this checkout can read these files directly. For a separate chat, supply the listed guidance, taxonomy, catalogue and selected source records; do not assume it can access ignored local files.

## Data and validation paths

- Published source/enrichment snapshot: data/2026-Sep.jsonl.
- Frozen raw CVRF, when present locally: raw/2026-Sep.json.
- Independent sample IDs and judgments: models/2026-Sep-independent-20-review.json.
- Local source-only sample: work/independent-20-review/source-only.json.
- Local fresh feeds: work/independent-20-review/fresh-sources/.
- raw/ and work/ are ignored and will not be present in a fresh clone. Fetch into a new trial directory if needed.

Generic validation for a deliberately limited trial:

```powershell
python scripts/merge_inference.py --baseline work/assessor-trial/baseline.jsonl --inference work/assessor-trial/assessments.jsonl --output work/assessor-trial/validated.jsonl
```

Use a baseline containing the intended source set. Do not use --include-unreviewed to conceal missing inference. For a full-release output, add --require-complete and compare the source set with the fresh MSRC release.

The generic merger accepts another provider's model name. Do **not** run scripts/run_luna_inference.py or scripts/collect_full_inference.py unchanged for another provider: they are Luna-specific, including model/provenance checks and response schema. Never label another provider's output as Luna to bypass those checks.

Source acquisition, when needed:

```powershell
python scripts/fetch_sources.py --month 2026-Sep --output-dir work/assessor-trial/raw
python scripts/enrich_cvrf.py --cvrf work/assessor-trial/raw/2026-Sep.json --month 2026-Sep --kev work/assessor-trial/raw/known_exploited_vulnerabilities.json --epss work/assessor-trial/raw/epss_scores-current.csv --fetch-metadata work/assessor-trial/raw/2026-Sep-fetch-metadata.json --output work/assessor-trial/baseline.jsonl
```

Caution: that existing normalizer still has the missing-severity defect described above. For a trial, record the defect and source truth in the evidence extension. Implement and test correct Unknown handling before publishing corrected source data; do not silently alter cvss_basis or immutable vendor facts merely to satisfy a validator.

## Implementation gaps versus updated guidance

1. Parser/UI: preserve Unknown severity; support its filtering/display and preserve explicit vendor severity independently of CVSS-derived severity.
2. Model adapters: request and validate attack_path, review_requirement, evidence_sources and per-control evidence fields. The current strict Luna schema excludes them.
3. Review rendering: consume structured review reasons; the current keyword detector misses scope ambiguity.
4. Validators: check route direction and evidence references, not only CVSS vector compatibility. A schema pass alone will not catch the Undici error.
5. Provider adapter: record actual CLI calls/receipts and exact CVE coverage without Luna-specific assumptions.
6. Freshness: diff source CVE sets and revisions, including newly added records. Current complete-coverage gates check the supplied snapshot, not the live remote release.
7. Calibration: use ranges and mandatory reasoning for judgment cases; reserve exact expectations for factual rules. Keep an unseen evaluation sample.

## Action identifiers and claims

| Display | Existing JSON action |
|---|---|
| Emergency | Immediate |
| Expedited | Out-of-cycle |
| Normal scheduled | Scheduled |
| No customer action | Defer and review |

Keep risk_model_version at 2026.09.1 until executable policy and compatibility are deliberately migrated. Use inference.guidance_version = 2026.09.2 for this guidance.

Do not equate model assessed, schema validated, and independently reviewed. Report each separately. Keep the source-first benchmark and earlier QA corrections as evidence, and reconsider snapshot-specific amendments if vendor facts change.
