# Patch Tuesday Triage

A dependency-free local prototype for filtering inference-enriched Microsoft CVRF data and applying verified enterprise mitigations to an explainable predicted risk profile.

## Run the interface

```powershell
python -m http.server 4173
```

Open `http://localhost:4173` and load the synthetic demonstration month or import a monthly JSONL file.

## Produce a monthly JSONL file

```powershell
python scripts/fetch_sources.py --month 2026-Sep --output-dir raw
python scripts/enrich_cvrf.py --cvrf raw/2026-Sep.json --month 2026-Sep --kev raw/known_exploited_vulnerabilities.json --epss raw/epss_scores-current.csv --fetch-metadata raw/2026-Sep-fetch-metadata.json --output work/2026-Sep-baseline.jsonl
python scripts/merge_inference.py --baseline work/2026-Sep-baseline.jsonl --inference inference/2026-Sep-luna.jsonl --include-unreviewed --output work/2026-Sep-curated.jsonl
```

The fetcher retrieves the complete MSRC CVRF release, CISA KEV catalogue and FIRST EPSS daily CSV directly from their public endpoints. It records URLs, retrieval time, sizes and SHA-256 hashes. The CVRF parser preserves Microsoft facts and adds deterministic baseline tags. The inference JSONL supplies a framework-based risk assessment, curated workload tags and mitigation candidates that follow `prompts/enrichment-system.md` and the reference cases in `models/baseline-risk-models.md`. The reference cases are anchors rather than a numeric scoring formula: the model weighs the complete evidence set and records its reasoning across applicability, threat evidence, exploitability, impact, workload, remediation and uncertainty. The merge step validates source fidelity and enforces only explicit safety floors such as confirmed exploitation and elevated critical pre-authentication network RCE.

## Publish an enriched month

Run inference locally, merge its output with the CVRF normalizer, then add the finished month to the static site:

```powershell
python scripts/publish_month.py work/2026-Sep-curated.jsonl --month 2026-Sep --label "September 2026"
npm run build
```

Deploy the generated `dist` directory to Cloudflare Pages. The build gives each monthly JSONL a content-addressed filename and rewrites the generated manifest, preventing an updated application from receiving an older dataset from an edge cache. The source dataset keeps its stable local filename. The site has no server functions, accounts, database, analytics, or remote API calls. Published JSONL files contain public advisory enrichment only. Environment filters and selected mitigations remain in browser memory unless the user explicitly exports an assessment.

Cloudflare Pages settings:

- Build command: `npm run build`
- Build output directory: `dist`
- Root directory: the project root

When Cloudflare Pages is connected to a private GitHub repository, a push to the configured production branch triggers the build automatically. Run fetching and inference locally, commit only the validated monthly JSONL and source changes, then push. The raw download and temporary working directories are ignored by Git.

## Refresh EPSS without rerunning inference

New CVEs are not always present in FIRST's daily EPSS population immediately. Refresh scores independently:

```powershell
python scripts/refresh_epss.py --data-dir data
npm run build
```

The refresher downloads FIRST's complete daily CSV and then batch-queries the official API for target CVEs still absent from that file. Missing values remain `pending`; existing values are never converted to zero. A scheduled GitHub workflow runs this check daily and commits only when published EPSS fields change. Cloudflare Pages then rebuilds from that commit.

## Risk assessment contract

- Reviewed records use the framework assessment produced by the local inference pass; unreviewed records use the deterministic fallback.
- Microsoft's Exploitability Index is mandatory evidence: Detected maps to Active, More Likely sets an Elevated floor, Less Likely supports Plausible, and Unlikely supports Low Evidence unless stronger evidence is present.
- CISA KEV or Microsoft-confirmed exploitation overrides the baseline likelihood to Active.
- EPSS contributes independent forecast evidence when a score is available.
- CVSS severity and the complete vector—including attack complexity, privileges, user interaction, scope and impacts—inform exploitability, consequence and patch cadence; they do not erase contradictory threat evidence.
- Only mitigations marked relevant by the monthly inference record receive credit.
- Low-confidence and not-relevant mitigations receive no credit.
- Ordinary controls can reduce predicted likelihood by at most one band.
- Two-band credit requires a high-confidence vendor workaround or exact service disablement.
- Known exploitation enforces an Out-of-Cycle minimum even when strong mitigations are selected.
- Generic EDR detection and backups receive no likelihood credit.

## Tests

```powershell
node tests/engine.test.mjs
node tests/september_record.test.mjs
node tests/ui_performance.test.mjs
node scripts/audit-mitigations.mjs
python tests/test_enrich_cvrf.py
python tests/test_merge_inference.py
python tests/test_refresh_epss.py
```

The demonstration JSONL contains synthetic records and must not be treated as Microsoft advisory data.
