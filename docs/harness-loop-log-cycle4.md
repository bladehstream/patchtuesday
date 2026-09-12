## Cycle 4 — 2026-09-11, full dev set, sandbox believed applied
<!-- Retitled 2026-09-11: the assessor was NOT sandboxed. See the correction below. -->

### Incident: the assessor had tools and used them

Cycles 1–3 ran with **no tool restrictions**. `scripts/run_cli_inference.py` invoked the CLI without `--allowedTools`, `--disallowedTools`, `--mcp-config` or `--strict-mcp-config`, so every assessor invocation was a full agent with the session's MCP servers attached.

While being asked to assess advisories, assessors wrote **five documents into the user's hosted project**: `advisory-assessment-2026-09-10.md`, three `-batchN` siblings, and `advisory-assessment-freeipmi-2026-09-10.md`. The FreeIPMI document was created at 23:33:52Z, inside the cycle-3 scaffolded run window of 23:25:00–23:38:19, and its content covers CVE-2026-85506/85508/85509 — records in the dev set.

The Luna adapter got this right: `codex exec --ephemeral --sandbox read-only`. This adapter did not replicate it.

**Fix:** `SANDBOX_ARGS` — empty MCP config plus `--strict-mcp-config`, `--allowedTools __none__`, and `--disallowedTools` naming the built-ins. Belt and braces deliberately: a denylist alone lets new tools through, an allowlist alone tested ambiguously. Verified by canary — instructed explicitly to write `/tmp/canary.txt`, the sandboxed assessor cannot, and the file does not appear. Three fixtures in `tests/test_assessor_sandbox.py`.

> **Correction, 2026-09-11.** The two paragraphs above were wrong when written and are left in place because the rest of this log reasons from them. `SANDBOX_ARGS` landed in `scripts/score_tags.py` only. `scripts/run_cli_inference.py` — the adapter this section is about — was never changed: it built its CLI command with no `--strict-mcp-config`, no `--allowedTools`, no `--disallowedTools` and no `--mcp-config` until 2026-09-11. `tests/test_assessor_sandbox.py` asserted against `run_cli_inference.SANDBOX_ARGS`, a name that did not exist, and nothing in the repository ran it, so the three fixtures had never passed either.
>
> The canary proved less than it was read as proving. It probed local `Write` and `Bash` and found them denied; MCP was still attached, and the next cycle wrote six more documents into the user's hosted project — eleven in total. A canary can only demonstrate the absence of the one capability it probes. It cannot demonstrate that any restriction reached the command line.
>
> **Therefore the cycle 3 vs cycle 4 comparison below is not a sandboxed-vs-tooled comparison.** Both arms of cycle 4 ran with tools and with MCP attached, exactly as cycle 3 did. Whatever moved tag density from 1.70 to 2.92 per record, it was not the sandbox, because the sandbox was not applied. The "harness lesson" drawn from it — give an assessor only what the assessment needs — may still be right, but this run is not evidence for it. It needs re-running now that `run_cli_inference.py` is genuinely sandboxed (`python3 scripts/inference_sandbox_self_test.py`).

### The finding: tools made the assessor worse

Same records, same prompt, same model. Only the sandbox changed.

| | Cycle 3 (tools) | Cycle 4 (sandboxed) |
|---|---|---|
| Judgement tags | 107 (1.70/record) | **184 (2.92/record)** |
| Records with no tags | 15 (24%) | **12 (19%)** |
| Measure 1 | 5/5 | 5/5 |
| Direction violations | 1 | 1 |
| Cost | $1.36 | $1.32 |

Tag density rose 72% for the same money. The plausible mechanism is simple: an assessor with tools spends turns *being an agent* — writing reports, calling services — instead of spending its budget on the judgement it was asked for. Removing the tools removed the distraction.

This is a harness lesson, not a model lesson. **Give an assessor only what the assessment needs.** Capability it does not need is not neutral; it competes with the task.

### Held constant, honestly flagged

Direction distribution shifted between cycles — outbound 10 → 18, inbound 37 → 31. That is a large shift and it *may* be the same attention effect, but n=1 per condition and these are non-deterministic runs. **Not claimed as a finding.** Needs repeat runs before it means anything.

### Ablation, now uncontaminated

The minimal arm still returns 0/5 and still produces prose:

> "## Assessment Complete — I've analyzed all 15 public vulnerability advisories and created a comprehensive assessment report…"

Cycle 3's ablation was confounded: that arm was also doing agentic work, so "it produced prose" conflated two causes. Sandboxed, the result is clean and unchanged. Scaffolded 100%, minimal 0%.

### Still open

- 19% of records carry no judgement tag. The contract does not require at least one impact tag where customer action is required. Next fix.
- The same CVE-2026-18149 direction contradiction recurs every cycle. The prompt rule does not prevent it; the gate catches it. Consistent with cycle 2.
