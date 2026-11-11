# Monthly publication command

Run from a checkout containing the production monthly tools:

```powershell
.\run-month.ps1 2026-Dec
```

This fetches MSRC CVRF, CISA KEV, FIRST EPSS and complete CVE Program CNA/ADP evidence; assesses every CVE with tool-free Claude Haiku 5.5 at medium effort; validates original response receipts, source fidelity, CVSS, policy floors and all 17 controls; re-fetches sources and reassesses materially changed inputs; then tests/builds an isolated checkout of current `origin/main` and pushes only the month's JSONL and manifest. It verifies Cloudflare's default month and exact built asset SHA256. The existing Git-connected Pages project must already track that repository's `main`. No per-CVE approval is required. Automated validation does not claim independent human review.

One-time prerequisites: Python 3.11+, Node 22+, Git configured with a commit identity and non-interactive credentials for `origin`, Claude Code supporting Haiku 5.5/medium effort and signed in (`claude auth login`), and an installed Edge/Chrome/Chromium browser. Standard Windows Edge/Chrome locations are discovered automatically; otherwise set `PATCH_TUESDAY_BROWSER`. The launcher creates an ignored `work/monthly-venv` with pinned `requirements-monthly.txt` dependencies when needed. Authentication and a real browser startup are checked before the small tool-free model probe and monthly inference spending. It never signs into accounts automatically.

```powershell
.\run-month.ps1 2026-Dec --plan        # No fetching, model calls or publication
.\run-month.ps1 2026-Dec --no-publish  # Full assessment and release gates; no commit/push
```

Defaults are batches of 10 with six concurrent batches; `--batch-size` and `--concurrency` adjust those bounds. Repeat the same command after an interruption: valid unchanged captured assessments are revalidated and reused. Each batch gets one retry followed by single-CVE isolation; persistent invalid output, privacy findings, authentication/quota errors, continuously changing sources or moved upstream state stop the run. Raw rejected responses remain intact under `work/monthly/<month>/`, alongside the single `run-receipt.json` and actionable command logs. Nothing is pushed until all pre-publication gates pass. A post-push deployment timeout is explicitly recorded as unverified rather than reported as success; repeat the command after correcting the deployment issue.
