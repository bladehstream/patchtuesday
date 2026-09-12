# GOAL: make the harness carry a weak model

Self-contained brief for autonomous execution. A fresh session needs this file, `CLAUDE.md`, and `REMEDIATION_PLAN.md` — nothing from any prior conversation.

## Objective

**Make the scaffolding good enough that Haiku produces defensible vulnerability assessments.** The harness is the deliverable. The model is the test load, deliberately weak.

Done is defined in "Stop conditions" below. Until then, run the loop.

## FIRST CALL, before any git command

    mcp__remote-devices__device_request_delete_permission → C:\LLMWorkspace\Vulnerability Assessment Platform

Without it the mount refuses `unlink`, git strands `.git/index.lock`, and every later commit fails. This has already cost one session. See `CLAUDE.md`.

## The loop

    1. Run Haiku over the dev set, scaffolded arm
    2. Score: measures 1-2 automated, 3-5 via an adversarial scorer subagent
    3. Read the individual failures. Do not stop at the aggregate number
    4. Classify each: guidance gap, schema gap, or validator gap
    5. Fix the harness. Commit, naming the failure class
    6. Re-run dev. Repeat from 2
    7. At milestones: run holdout and full. If holdout lags dev, the guidance has
       been tuned to the dev records - generalise the fix, do not tune further

Run the minimal arm once at the start and once at the end. It is the only baseline that can attribute any improvement to the scaffolding rather than to Haiku.

## Commands

    # scaffolded arm, dev set
    python3 scripts/run_cli_inference.py \
      --records work/harness-dev/dev-records.jsonl \
      --run-dir work/harness-dev/runs/<iso8601>-scaffolded \
      --arm scaffolded --model haiku

    # ablation
    python3 scripts/run_cli_inference.py \
      --records work/harness-dev/dev-records.jsonl \
      --run-dir work/harness-dev/runs/<iso8601>-minimal \
      --arm minimal --model haiku

The assessor CLI lives in the **cloud container**, not on the device bridge. Stage the records up, run there, commit results back. `--exclude-dynamic-system-prompt-sections` silently breaks `--json-schema`; never add it.

## Measures

| # | Measure | How |
|---|---|---|
| 1 | Schema conformance, first pass before retry | Automated, in the run manifest |
| 2 | Validator catch rate — errors present vs errors caught | Automated |
| 3 | Evidence-groundedness — every claim traces to supplied advisory text | Adversarial scorer |
| 4 | Fabrication rate — claims contradicted by or absent from source | Adversarial scorer |
| 5 | Abstention correctness — `unknown` when evidence is insufficient | Adversarial scorer |

Undetected error is the only failure that matters. A harness works when a weak model's mistakes get caught, not when it stops making them.

## Stop conditions, pre-registered

Done when, **on the holdout**:

- Fabrication rate ≤ 5% of scored claims
- Validator catch rate ≥ 90%
- Schema conformance ≥ 95% first pass
- Scaffolded clearly beats the minimal ablation, margin stated and defended

Not done if any of those hold only on dev. Say so plainly rather than presenting dev numbers as the result.

## Rules

1. **Halt, do not weaken.** If a criterion cannot be met, stop and report. Never relax it, disable a test, or narrow a check until it passes.
2. **Fix the harness, never the sample.** A fix shaped like "handle CVE-X specially" is pattern matching in a new costume. If it would not catch the next instance of its kind, it is not a fix.
3. **Never inspect the holdout while tuning.** Milestones only.
4. **Malformed responses are recorded, never repaired.** Repairing converts the gap under test into apparent success.
5. **Every gate needs a fixture it rejects**, confirmed failing before the fix.
6. **Absence of evidence is not evidence of absence.** Missing vendor data resolves to `Unknown` with a review flag, never to a benign default.
7. Batch size stays 15. Vary it deliberately or not at all.
8. Three attempts per failing item, two per fetch, then halt and report.
9. One commit per harness change, naming the failure class it addresses.
10. All output under `work/harness-dev/`. **Nothing here replaces published data.**

## Requires a human — stop and ask

- Republishing `data/*.jsonl`
- Any change to `risk_model_version` or executable policy in `risk-model.js`
- Deleting anything
- `git push` — the bridge has no network
- Phase 1.1, the vendor-plural severity schema: produce it and a worked example, then stop. It changes what the tool asserts to an administrator
- Adjudicating a divergence the source does not settle

## Not in scope

Chrome, Firefox and Adobe ingestion (Phase 2, deferred). Luna and cross-provider comparison. Phase 3's four open decisions — presenting them is done; deciding them is not.

## State

- Dev set: `work/harness-dev/dev-set.json`, 63 records — 50 comparable plus 13 reference failures
- Holdout: `work/harness-dev/holdout-set.json`, 50 records
- Adapter: `scripts/run_cli_inference.py`
- Reference judgements: `work/harness-dev/reference-judgements/`, committed before any Haiku run so the ordering is auditable in `git log`
- Full plan and rationale: `REMEDIATION_PLAN.md`
