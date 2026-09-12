# Monthly runbook

What to do when Microsoft drops a new Patch Tuesday release. Substitute the month everywhere as MSRC spells it — `2026-Oct`, `2026-Nov` — hyphen and three-letter capitalised abbreviation included. Everything below is a command; nothing requires a decision unless the step says so.

Timing: MSRC publishes a month's CVRF on the second Tuesday, around 18:00 UTC. EPSS refreshes daily and KEV on CISA's own cadence, so both are re-fetched every run rather than pinned.

Expect roughly 2 hours end to end for a ~1,200-CVE month, almost all of it step 4.

---

## 0. Session setup

    mcp__remote-devices__device_request_delete_permission  →  C:\LLMWorkspace\Vulnerability Assessment Platform

Before any git command and before `npm run build`. See `CLAUDE.md` — without it the mount refuses `unlink`, git strands `.git/index.lock`, and `build-pages.mjs` fails on its opening `rmSync(dist)`.

Inference runs in the **cloud container**, not on the bridge — that is where the assessor CLI lives. Confirm it is on PATH there before starting step 4.

---

## 1. Fetch (≈2 min)

    python3 scripts/fetch_sources.py --month 2026-Oct --output-dir raw

Writes `raw/2026-Oct.json`, `raw/known_exploited_vulnerabilities.json`, `raw/epss_scores-current.csv` and `raw/2026-Oct-fetch-metadata.json` carrying a SHA-256 of each. Keep the metadata file — it is the provenance record for the release.

**Re-fetch before publishing, not only at the start.** MSRC revises a month after release: CVEs get added, severities corrected. If the second fetch's `sha256` differs, the run assessed a stale snapshot — restart from step 2 rather than publishing it.

---

## 2. Enrich (≈1 min)

    python3 scripts/enrich_cvrf.py \
      --cvrf raw/2026-Oct.json \
      --month 2026-Oct \
      --kev raw/known_exploited_vulnerabilities.json \
      --epss raw/epss_scores-current.csv \
      --fetch-metadata raw/2026-Oct-fetch-metadata.json \
      --output work/2026-Oct-baseline.jsonl

Deterministic parsing only: severity with its basis (`vendor` / `cvss` / `absent`), CVSS, KEV and EPSS joins, product tags from the structured product tree, and the `vendor_guidance` block the affected-products table reads.

Sanity check before going further. A month that looks wrong here is a parser problem, not a model problem:

    python3 -c "import json,collections; \
      rows=[json.loads(l) for l in open('work/2026-Oct-baseline.jsonl',encoding='utf-8')]; \
      print(len(rows), collections.Counter(r['severity'] for r in rows)); \
      print('no product filter:', sum(1 for r in rows if not set(r['product_tags'])-{'microsoft'}))"

`Unknown` severities are expected and correct. A count of *zero* across a large month is more suspicious than a handful — it is what the old fail-open coercions produced.

---

## 3. Split for concurrency (≈1 min)

`run_cli_inference.py` batches internally and runs its batches sequentially, so a whole month in one process takes hours. Split it and run the shards side by side:

    python3 -c "import json,pathlib; \
      rows=[l for l in open('work/2026-Oct-baseline.jsonl',encoding='utf-8') if l.strip()]; \
      [pathlib.Path(f'work/2026-Oct-shard-{i+1}.jsonl').write_text(''.join(rows[i::3]),encoding='utf-8') for i in range(3)]"

Three shards is what the September full run used. The split is by stride, so each shard sees a mixed severity and product distribution rather than one alphabetical block.

`scripts/prepare_full_inference.py` and `scripts/collect_full_inference.py` do this for the **Luna** path and have their own packet layout. Do not mix the two.

---

## 4. Inference (≈75 min for ~1,200 records, three shards concurrently)

    python3 scripts/run_cli_inference.py \
      --records work/2026-Oct-shard-1.jsonl \
      --run-dir work/2026-Oct-run/shard-1 \
      --arm scaffolded --model haiku

…and the same for shards 2 and 3.

Every invocation is sandboxed — an empty MCP config written to the run directory as `empty-mcp.json` and passed with `--mcp-config`, plus `--strict-mcp-config`, `--allowedTools __none__` and a named `--disallowedTools` denylist. Unsandboxed assessors previously wrote eleven documents into the live hosted project. The restrictions are defined once, in `scripts/score_tags.py`, and imported by `run_cli_inference.py`; each run records what it applied under `sandbox` in its `manifest.json` and `sandboxed: true` on every call, so the claim is checkable from the run artefacts rather than from this page. Verify before trusting it:

    python3 scripts/inference_sandbox_self_test.py

**The `minimal` ablation is sandboxed too.** It drops the contract and the schema because those are the scaffolding under test; the sandbox is a safety control, not scaffolding, and it applies to both arms. Do not "restore symmetry" by removing it.

Never add `--exclude-dynamic-system-prompt-sections` — it silently breaks `--json-schema` and returns `structured_output: null` while reporting success.

Malformed responses are recorded as conformance failures, never repaired. Each run prints its first-pass schema conformance at the end; that is measure 1.

---

## 5. Collect and merge (≈1 min)

    python3 scripts/collect_cli_inference.py \
      --baseline work/2026-Oct-baseline.jsonl \
      --run-dir work/2026-Oct-run/shard-1 \
      --run-dir work/2026-Oct-run/shard-2 \
      --run-dir work/2026-Oct-run/shard-3 \
      --output work/2026-Oct-inference.jsonl

    python3 scripts/merge_inference.py \
      --baseline work/2026-Oct-baseline.jsonl \
      --inference work/2026-Oct-inference.jsonl \
      --output work/2026-Oct-merged.jsonl \
      --require-complete

The collector re-derives every assessment from the captured CLI envelope, checks it against the convenience artefact, verifies each shard's input file is still byte-identical to what the run saw, and refuses to write output unless the shards together cover every baseline CVE exactly once. `--require-complete` then rejects the release if any CVE lacks an overlay.

`merge_inference.py` runs the **attack-direction gate** over every overlay, as the last of its per-record checks. Where a control was credited against a direction it cannot act in — an ingress control against an outbound attack path, the CVE-2026-18149 class of error — the credit is zeroed, the control is marked `direction_override: true`, and the contradiction is reported both in the command's output and on the record as `inference.direction_gate`. **It does not reject the record**: the rest of the assessment may be sound, and the record leaves the gate with less credit than the model claimed rather than none at all. Read the summary line it prints; a month with contradictions is not a month that failed.

An overlay that asserts no `attack_path.direction` at all **is** rejected, because there is then nothing to check any control against. `--allow-missing-direction` downgrades that to a recorded `unchecked` status on each record, and exists only for the 2026-Sep Luna overlay, which predates the direction contract. Unchecked is never a clean result: it means no mitigation credit on those records has been tested against a direction. Do not reach for the flag on a run through the CLI path — its schema requires `attack_path`, so an overlay from that path that needs the flag is a run that went wrong.

If the collector reports a handful of skipped batches, re-run **only those shards** into a fresh run directory and collect again. Do not hand-edit an `assessments-*.json` — the collector compares it against the captured response and will reject it.

Its own gates are exercised by:

    python3 scripts/collect_cli_self_test.py

---

## 6. Review

Tier 1, the deterministic checks, over the whole merged month:

    python3 scripts/review_month.py \
      --records work/2026-Oct-merged.jsonl \
      --output work/2026-Oct-tier1.json \
      --annotate work/2026-Oct-reviewed.jsonl

`review_month.py` drives every check in `tag_validators.py` plus citation verification from `span_verify.py`, writes a JSON report carrying per-check counts, rates and the offending CVEs — so months are comparable — and prints a short summary. `--annotate` is optional and writes a copy of the input with a `tier1_review` block on each flagged record. Keep the report beside the month; it is the Tier 1 record for the release.

Three things it deliberately does not do:

- **It does not gate.** There is no `--fail-under` and findings never change the exit status. Whether a month ships is this runbook's call and a human's, not a threshold hidden inside a review tool.
- **It does not assign or change anything.** `tier1_review` is a review flag: no tag, rating, priority or mitigation is touched, and the annotate mode asserts that before it writes. See the boundary note at the top of `tag_validators.py`.
- **It does not pass what it could not check.** A record lacking the data a check needs is reported as `unchecked`, with its reason and its CVE; a record with nothing for a check to act on is `not_applicable`. Neither is folded into the clean count, and a rate over an empty denominator is reported as null rather than as 0%.

Read the `unchecked` counts before the rates. A month whose tags are bare strings carries no per-tag evidence at all, so evidence presence, grounding and citation verification are all unchecked rather than clean — which is what `data/2026-Sep.jsonl`, assessed on 2026-09-10, still shows.

Their checks themselves are exercised offline, before you trust a month's findings:

    python3 scripts/tag_validators_self_test.py
    python3 scripts/span_verify_self_test.py
    python3 scripts/review_month_self_test.py

Tier 2, the adversarial scorer:

    python3 scripts/score_tags.py \
      --records work/2026-Oct-merged.jsonl \
      --assessments work/2026-Oct-run/shard-1 \
      --run-dir work/2026-Oct-review

---

## 7. Publish

    python3 scripts/publish_month.py work/2026-Oct-merged.jsonl \
      --month 2026-Oct --label "October 2026"

`publish_month.py` refuses partial inference and duplicate CVEs, then updates `data/months.json`. That manifest is what the site reads and what step 8 refreshes against, so nothing downstream needs telling about the new release separately.

---

## 8. Refresh EPSS across every published release

    python3 scripts/refresh_epss.py --data-dir data

Do this **after** `publish_month.py` and **before** `npm run build` — the build content-hashes the dataset, so a refresh afterwards leaves the site serving the pre-refresh hash.

Run it on release day and again on its own whenever scores are worth re-pulling. EPSS moves daily and a published score is a point-in-time snapshot, so the older months go stale too; this refreshes every published release, not only the new one.

The script reads `data/months.json` to decide what is published. It does not glob and carries no list of its own, so a new release is picked up the moment `publish_month.py` records it — including a second release in the same month. It prints a warning rather than guessing when the manifest and `data/` disagree (a `*.jsonl` no entry names, or an entry whose file is absent); treat a warning as a publish that did not finish.

A score it cannot find is recorded as `pending`, and an existing score it cannot re-confirm as `stale`. Neither is left looking current.

This ran unattended as `.github/workflows/refresh-epss.yml` until 2026-09-11, when the workflow was deleted. Three reasons, in order of weight:

- It committed and pushed to the repository on a daily cron. `CLAUDE.md` is explicit that **`git push` is Bob's**, and an unattended bot push is the same rewrite of published data with nobody reading it.
- It rewrote `data/*.jsonl` — assessed, reviewed, published records — and nothing rebuilt or reviewed the result. A commit no one looks at is not freshness.
- It carried its own copy of the test list, which had already drifted from `npm test`. Any list a workflow keeps beside the real one goes stale; moving to twice-monthly releases with non-Microsoft vendors only makes that faster.

---

## 9. Build

    npm run build

`build-pages.mjs` annotates each record with its priority and review status, content-hashes the dataset and rewrites the manifest to the versioned filename.

---

## 10. Verify before pushing

    npm test

`npm test` is node only, deliberately. The python checks are separate commands, run when the thing they cover is in play rather than on every front-end change:

    python3 tests/test_enrich_cvrf.py            # CVRF parsing, severity basis, product tags
    python3 tests/test_merge_inference.py        # overlay validation and framework gates
    python3 tests/test_refresh_epss.py           # EPSS application and dataset discovery
    python3 scripts/direction_gate_self_test.py  # mitigation credit vs attack direction
    python3 scripts/tag_validators_self_test.py  # Tier 1 tag checks
    python3 scripts/span_verify_self_test.py     # Tier 1 citation checks
    python3 scripts/review_month_self_test.py    # the Tier 1 driver (step 6)
    python3 scripts/assessor_sandbox_self_test.py   # the scorer has no tools, no MCP
    python3 scripts/inference_sandbox_self_test.py  # the adapter has no tools, no MCP — both arms
    python3 scripts/collect_cli_self_test.py  # collector gates (step 5)

`scripts/scorer_self_test.py` is the exception: it invokes the assessor CLI and costs money, so run it when the scorer or its prompt changes, not every cycle.

Then open the built site and check the new month:

- the month selector offers October and defaults sensibly
- a record with partial patch coverage shows pending products first, in amber
- a record with no vendor severity shows `Unknown` and carries a review flag
- the product filter reaches the new month's records — step 2's "no product filter" count should be near zero

Tests assert against `data/months.json`'s `record_count`. Never hardcode a month's expected CVE count in a test.

---

## 11. Push

`git push` is Bob's. The bridge VM has no network.

---

## Open — worth settling before the next cycle

1. **Tier 1 findings have no consumer.** `scripts/review_month.py` makes step 6 one command and `--annotate` flags the affected records, but nothing downstream reads `tier1_review`: it is neither surfaced in the built site nor handed to the Tier 2 scorer as a work queue. On September's data that is 152 flagged records nobody is assigned. Decide which of those two it should feed before the next cycle.
2. **September's published records are direction-UNCHECKED.** Closed for new months on 2026-09-11: `merge_inference.main()` now calls `enforce_direction`, and `check_direction` — the superseded raise-on-contradiction variant — is gone. What remains open is September itself. `inference/2026-Sep-luna.jsonl` carries no `attack_path` on any of its 1,185 overlays, so re-merging it needs `--allow-missing-direction` and every record comes out `unchecked`: 0 checked, 0 violations, 1,185 unchecked. That is the gate reaching the data and finding nothing to check, not the gate being quiet. 38 of those overlays credit an ingress-only control (`remove_external_exposure` ×37, `waf_virtual_patch` ×2), CVE-2026-18149 among them, and whether each is a contradiction cannot be settled without a direction the overlay never asserted. Decide whether September is re-assessed through the CLI path or published with the unchecked status visible; do not let it read as clean.
3. **Cadence.** This runbook assumes monthly. Adobe moved to twice-monthly on 2026-07-14, so ingesting Adobe (Phase 2) means the month stops being the unit. Worth deciding before Phase 2 starts, not during it. Step 8 no longer cares — it follows `months.json`, whatever shape the releases take — but steps 1–7 still name a month throughout.
4. **The KEV source** is a `develop` branch on a GitHub mirror (`cisagov/kev-data`), not a versioned endpoint. It can move without notice.
5. **No month has yet been published through the CLI path end to end.** September's published data came from the Luna run. Steps 1–10 are wired and their gates are tested against real records, but October will be the first live use.
6. ~~**`scripts/run_cli_inference.py` is not sandboxed.**~~ Closed 2026-09-11. The adapter now imports `SANDBOX_ARGS` from `scripts/score_tags.py` — one definition, two callers — writes an empty MCP config into the run directory, and passes both through `build_command`, which every invocation in the file goes through, on both arms. `scripts/inference_sandbox_self_test.py` asserts on the constructed command line and on the call site, and was confirmed to fail when the spread is removed from `build_command` and when `main()` stops calling it. The natural home for the constant is a neutral module both scripts import rather than the scorer; that move needs `score_tags.py`'s owner, and until then the rule is that there is exactly one definition and nobody copies it.

## Not covered here

Chrome, Firefox and Adobe ingestion (Phase 2, deferred). The vendor-plural severity schema (Phase 1.1), which changes what the tool asserts to an administrator and stops for human review by design.
