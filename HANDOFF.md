# Handoff

Written 2026-09-12. Read this first, then `CLAUDE.md`, then `REMEDIATION_PLAN.md`. `GOAL.md` is the autonomous brief for the harness loop and is still current. This file carries what those do not: the decisions taken on 2026-09-11/12, the state they left the repo in, and what is open.

## What this is

A contextual Patch Tuesday risk-triage tool. It ingests Microsoft MSRC CVRF, enriches it deterministically, has a sandboxed CLI assessor make the judgement calls with cited evidence, applies deterministic policy, and publishes a static site. The architecture rests on one separation, and most defects found so far have been one layer leaking into another:

- **Parsing** is deterministic and reads only structured vendor data. It never reaches a risk decision.
- **Judgement** is the model's, is evidence-cited, and is validated after the fact rather than trusted.
- **Policy** is deterministic by design so it is auditable.

The owner's standing position: hard risk decisions are made by a model, not by pattern matching on advisory prose. The harness is the deliverable; the model is deliberately weak test load.

## The rules that are not negotiable

1. **Absence of evidence is not evidence of absence.** A missing vendor severity or CVSS resolves to `Unknown` with a review flag. Never `Low`, never `0`, never a fall-through baseline. Six separate coercions once published 23 unrated RCE-class advisories as `Low`.
2. **A gate that cannot fail is not a gate.** Every validator needs a fixture it rejects, and you must have watched it fail. A mutation that happens to match the original value is a false pass — this has bitten the project twice.
3. **Halt, do not weaken.** If a criterion cannot be met, stop and report. Never relax it, disable a test, or narrow a check until it passes. If narrowing a test is genuinely correct, say so explicitly and explain where you drew the line.
4. **Malformed model responses are recorded, never repaired.** Repairing converts the gap under test into apparent success.
5. **Do not equate model-assessed, schema-validated, and independently reviewed.** Report each separately.
6. **No customer data in inference.** No hostnames, IPs, tenant identifiers, inventories or topology. Public advisory material only. `scripts/customer_data_guard.py` enforces this and refuses to send; it has no redact path and no disable switch.
7. **No pytest, no test framework.** It was added by mistake and deliberately reverted. Python tests are plain scripts invoked directly. `npm test` stays node-only.
8. **Republishing `data/*.jsonl` needs the owner's say-so**, except `scripts/refresh_product_tags.py`, which recomputes derived product tags only and touches no rating.
9. **Never mention Claude, Anthropic or AI assistance** in commit messages, pull request descriptions, code comments, docstrings, changelogs or documentation, and do not set a git identity naming a tool. The exception is a string the software needs to function — an executable name, a value captured verbatim from an API. Comment those as such.
10. **Do not hard-wrap prose.** One paragraph is one line; the renderer wraps it. Code and fenced blocks are exempt.
11. **`git push` is the owner's.**

## Decisions taken, do not relitigate

- **`Unknown` severity sorts last.** Explicit in `merge_inference.severity_order`; the unmapped fallback sits after it.
- **Workload tags that back a product filter are derived deterministically**, from the component half of the MSRC title. See below.
- **Attribution and tool references have been stripped** from the working tree. Git history has not been rewritten; that is pending the owner's decision and needs a force-push.
- **Twice-monthly publication was adopted on a premise that turned out to be half wrong.** See "Cadence" below. The decision is open again.

## State as of 2026-09-12

Everything below is on disk and pushed or staged for commit. `npm test`, `npm run build`, and all eleven python self-tests pass.

**Working end to end:** fetch, enrich, sandboxed inference, collect, merge, review, publish, build. `docs/MONTHLY-RUNBOOK.md` is the step-by-step. No month has yet been published through the CLI assessor path — September's published data came from the other provider's run, so the next month is the first live use.

**Fixed on 2026-09-11/12, with fixtures:**

- The inference adapter had never been sandboxed despite a harness log claiming it was. One `SANDBOX_ARGS` definition now, applied to both arms including the ablation, asserted against the constructed command line and the call site.
- `enforce_direction` was defined and never called. Now wired into the merge path, with a fixture that fails if the call site is removed.
- `cvss_basis` was required by the enrichment contract but absent from the JSON schema, with `additionalProperties: false` — so no conformant response could ever reach `merge_inference`. Added to the schema, echoed by the model, not filled in by the collector.
- No collector existed for the CLI path. `scripts/collect_cli_inference.py`, nine gates.
- `scripts/customer_data_guard.py`, zero false positives measured over all 1,185 records and all 81 assembled prompts.
- `scripts/review_month.py` gives Tier 1 a single entry point.
- Workload tag definitions rewritten as criteria with explicit boundary clauses, after a closed-enumeration form caused the scorer to read them as membership whitelists.
- Deterministic workload tags from the title component. Remote Desktop filter reach went 8 to 26 records, identity 23 to 34.
- Six orphaned pytest-style test files removed or rewritten. One of them, `tests/test_enrich_cvrf.py`, had its runner block in the middle of the file, so seven of its eight tests ran nowhere while it printed "tests passed".
- `.github/workflows/refresh-epss.yml` deleted. It committed and pushed on a daily cron, rewriting assessed records with nobody reading the result.

## Open work, in the order I would take it

**1. Nothing consumes Tier 1 findings.** `scripts/review_month.py` reports 190 findings across 180 of 1,185 September records and explicitly does not gate the release. `--annotate` writes an inert `tier1_review` block. Decide what acts on it. Note that three of the six checks — `evidence_present`, `evidence_grounded`, `citation_verification` — report `unchecked` on 1,029 records because September's tags are bare strings with no evidence field. They have no denominator until a month runs through the current schema.

**2. Cadence needs re-deciding.** Twice-monthly was adopted because Adobe moved to twice-monthly on 2026-07-14. That move is real, but **Acrobat is not on it** — Acrobat and Reader bulletins in 2026 were 03-10, 04-11 (a Saturday, out of band), 04-14, 06-09, 09-08. Quarterly. Meanwhile Chrome and Firefox both moved to two-week cycles in September 2026. `docs/vendor-ingestion-design.md` has the evidence and recommends separating ingestion cadence from publication cadence: poll daily into staging, publish on a cycle, and keep an out-of-band path for the 48-hour class (KEV listing, SSVC `Exploitation: active`, Adobe Priority 1, out-of-band advisory).

**3. Phase 1.1, the vendor-plural severity schema.** This is now a hard prerequisite rather than a nice-to-have: `resolve_severity()` is a Microsoft-scale function and will silently coerce any other vendor onto it. It changes what the tool asserts to an administrator, so it stops for human review by design — produce it and a worked example, then stop.

**4. Vendor ingestion**, once 1.1 lands. `docs/vendor-ingestion-design.md` is the design and names four shared assumptions that do not survive contact with a second vendor. Chrome, Firefox and Acrobat each have a section, a field-by-field mapping, and a list of checks needing fixtures.

**5. September is direction-unchecked.** None of the 1,185 published overlays carry `attack_path`; that field postdates the run that produced them. `merge_inference` halts on this by default. `--allow-missing-direction` marks each record `unchecked` and prints a banner. 38 overlays credit an ingress-only control, including the record that motivated the gate, and whether each contradicts cannot be settled without a direction the overlay never asserted.

**6. The workload filters never union their two sources, and the reach figures quoted above were measured as though they did.** `recordFilterTags` is `source === "tags" ? tags : product_tags`, so the workloads group's `product_tags+tags` reads `product_tags` alone. Nothing is broken and nothing silently misrates; the filter is narrower than its own configuration, hint text and the figures in this file describe. Actual reach against September: Active Directory 24 rather than 34, Remote Desktop 25 rather than 26, IIS 0 rather than 10. Deciding this is deliberate rather than a leftover changes what the tool asserts about coverage, so it stops here for a decision instead of being patched. Two things follow from it. The deterministic-tag decision recorded above is implemented as written, so if `product_tags` alone is the intent then the `source` string and the group hint are the parts that are wrong. And if the union is the intent, the `web-server` tag behind the option labelled **IIS** matches ten NGINX, Apache `httpd` and Erlang `inets` advisories and no IIS at all, so the label would have to change with it. `tests/overview.test.mjs` asserts the current behaviour explicitly, so a change to either breaks a test that says why rather than quietly moving every workload tile.

**7. Residual known gaps**, each documented where it lives: the customer-data guard will pass a bare single-label hostname in prose (inseparable from component names like `Win32K`); IIS has a deterministic tag rule and fixtures but zero matches in September, so treat that row as untested against real data; `scorer_self_test.py` needs a live model and `--run-dir` and is not part of any suite.

## Verification

Run all of these before claiming anything works.

```
npm test
npm run build
for f in scripts/*_self_test.py tests/*.py; do python3 "$f"; done   # skip scorer_self_test.py
python3 scripts/review_month.py --records data/2026-Sep.jsonl --output /tmp/tier1.json
```

`npm test` runs seven node suites plus `scripts/audit-mitigations.mjs`. Tests assert against `data/months.json`'s `record_count`; never hardcode a month's expected CVE count.

## Traps that have already cost a session each

- `--exclude-dynamic-system-prompt-sections` silently breaks `--json-schema`: `structured_output` comes back null while the call reports success. Never add it.
- A 15-record packet is roughly 120KB and overruns `ARG_MAX`. Prompts go to the CLI on stdin, not argv.
- The component that names a workload role is in the **title**, not the product tree. The product tree lists OS SKUs, so a Remote Desktop RCE and a graphics RCE have identical product trees.
- `.gitattributes` pins LF. If `git diff --stat` shows large symmetric insert and delete counts, check for carriage returns before assuming the change is real: `git diff --ignore-all-space --stat`.
- Datasets are written with compact JSON separators. Anything that rewrites one must match, or every line shows as changed.
- A number is not a finding until you know what it is made of. Three separate measurement errors in this project came from reporting an interesting aggregate before checking its composition: a tag-density figure that was counting discarded clerical tags, a "scorer failure" rate that was a brittle span checker, and an evidence-absence claim produced by a broken counting script.

## Note on CLAUDE.md

Its "two machines" section describes a remote bridge workflow: the repository on the owner's PC, reached by a cloud session, with a delete-permission request required before any git command. **None of that applies to a local session running on the owner's machine.** Ignore it, and consider rewriting that section for local use once you have confirmed with the owner which workflow he is standardising on.
