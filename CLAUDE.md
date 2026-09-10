# Working agreements for this project

`REMEDIATION_PLAN.md` is the backlog. `CLAUDE_ASSESSOR_HANDOFF.md` is the assessor
guidance it executes against.

## The two machines

**Bob's PC holds the repository**, `C:\LLMWorkspace\Vulnerability Assessment Platform`,
reached through the Cowork folder bridge as `$HOME/mnt/Vulnerability Assessment Platform`
(`mcp__remote-devices__device_bash` runs a shell there). The cloud container is a build
rig, not a repository of its own.

### FIRST CALL OF ANY SESSION

    mcp__remote-devices__device_request_delete_permission  →  C:\LLMWorkspace\Vulnerability Assessment Platform

Do this **before any git command**. Without it the mount refuses `unlink`, so git
strands `.git/index.lock` and every subsequent `git add` and `git commit` fails until
someone removes it by hand on Windows. `npm run build` also fails, because
`scripts/build-pages.mjs` starts with `rmSync(dist)`.

Learned the hard way on 2026-09-10: a `git checkout` run before the request stranded
the lock and blocked commits for the rest of the session.

### Commit identity

Claude commits under a repo-local identity, matching the convention in
`hermesprojects/drugwarsredux`. Set once per clone, never `--global`:

    git config user.name "Claude (Opus 5)"
    git config user.email "claude@anthropic.com"

Bob's own commits stay under his GitHub identity. Keeping them distinguishable in
`git log` is the point.

### How work lands

1. Edit in place over the bridge with `device_bash`. Do not stage files into the
   container to read or edit them.
2. `git add` / `git commit` over the bridge, in Bob's repo.
3. **`git push` is Bob's.** The bridge VM has no network.

## Line endings

`.gitattributes` pins everything to LF (`*.ps1` excepted). Before it existed the repo
accumulated 2,793 lines of CRLF churn with zero content change, which made every diff
unreadable. If `git diff --stat` shows large symmetric insert/delete counts, check for
carriage returns before assuming the change is real:

    git diff --ignore-all-space --stat

## The rules that matter

- **Absence of evidence is not evidence of absence.** A missing vendor severity or
  CVSS score resolves to `Unknown` and carries a review flag. It must never default to
  `Low`, `0`, or a fall-through baseline. Six separate coercions did exactly that and
  published 23 Chromium RCE-class advisories as `Low`.
- **A gate that cannot fail is not a gate.** Every validator needs a fixture it
  rejects. A schema pass alone does not catch a wrong-direction mitigation credit.
- **Do not equate model assessed, schema validated, and independently reviewed.**
  Report each separately; never let one imply another.
- **Never label one provider's output as another's** to satisfy a provenance check.
  `scripts/run_luna_inference.py` and `scripts/collect_full_inference.py` are
  Luna-specific — do not run them unchanged for another model.
- **No customer data in inference.** No hostnames, IPs, tenant identifiers,
  inventories or topology. Public advisory material only.

## Inference providers

The project is portable across inference providers. Claude Sonnet subagents are one
implementation, not an assumption.

- `scripts/run_luna_inference.py` and `scripts/collect_full_inference.py` are
  Luna-specific. Do not run them for another provider and never relabel output to
  pass their provenance checks.
- Luna inference ran through the **local Codex CLI** as a subprocess
  (`codex exec --sandbox read-only --output-schema -m gpt-5.6-luna`), authenticated
  by the CLI's own sign-in. This repo has never held a model API key. The only direct
  HTTP is `fetch_sources.py` pulling public MSRC/KEV/EPSS data.
- A subagent is the same shape as that subprocess: local invocation, captured
  response, locally computed hash. The existing provenance fields carry over as-is.
- What does **not** carry over is `--output-schema`. Codex constrained the response
  structurally before the script saw it. A subagent returns text, so validate
  strictly against the same schema, retry within bounds, and record a malformed
  response as a failure rather than repairing it.
- `model_configured` is assertable; `model_served` is not, because the serving model
  can differ from the configured one. Leave it null rather than guessing. Same rule
  as the source data: highlight what is missing, never inherit a fabricated value.

## Data pipeline

    fetch_sources.py → enrich_cvrf.py → merge_inference.py → publish_month.py → build-pages.mjs

`data/2026-Sep.jsonl` is written with compact JSON separators (`","` / `":"`), matching
`merge_inference.py`. Anything that rewrites the dataset must match, or every line
shows as changed.

Recheck the live MSRC manifest before any production run. Do not freeze an expected
record count in a test — assert against `data/months.json`'s `record_count`.
