# Harness development loop — findings

One entry per cycle. What failed, what changed in the harness, whether it closed.

---

## Cycle 1 — 2026-09-10, dev batch 0, scaffolded, Haiku 4.5

Measure 1 (schema conformance): 1/1 batches, 15/15 CVEs. `--json-schema` held.

**Failure: attack direction ignored on CVE-2026-18149 (Undici).**

Haiku credited `remove_external_exposure` with a likelihood step, reasoning that
"removing public Node.js exposure reduces unsolicited attack reachability". The
flaw is a malicious *server* attacking an HTTP *client* — the traffic is outbound,
nothing connects in, and closing public ingress does nothing.

This is the same error the independent review caught in the previous assessor, and
`CLAUDE_ASSESSOR_HANDOFF.md` warns about it in writing. **No validator caught it.**
A CVSS-vector compatibility check structurally cannot: `AV:N` holds in both
directions.

Harness changes (none CVE-specific):

- `data/mitigation-catalog.json` — each control declares `applies_to_direction`.
- `scripts/merge_inference.py` — `check_direction()` rejects likelihood credit or
  `path_block` for a control that cannot act in the asserted direction.
- `prompts/enrichment-system.md` — rules 8a/8b require `attack_path.direction`
  with evidence, and state that direction is who initiates the connection, not the
  CVSS Attack Vector.
- `scripts/run_claude_inference.py` — `attack_path` is a required schema field.
- `tests/test_direction_validator.py` — 8 fixtures, the first reproducing the real
  failure.

---

## Cycle 2 — same batch, fixed scaffolding

Measure 1: 1/1 batches. Direction gate: **14/15 pass**.

**Haiku got the direction right and made the error anyway.** Its own
`attack_path.evidence` reads:

> "HTTP client (undici) connects outbound to attacker-controlled server; malicious
> response triggers orphaned RetryHandler and memory exhaustion."

Correct — and better reasoning than the previous assessor produced. Then, one field
later, it credited `remove_external_exposure` with a likelihood step against that
same outbound path.

### The lesson, which cuts against an assumption in this plan

Requiring the model to *state* its reasoning did not make it *apply* that
reasoning. The prompt rule alone failed. What caught the error was the
deterministic check reading the model's own assertion back against a data-declared
constraint.

So the scaffolding's value here was not guidance — it was **detection**. That is
consistent with the principle already recorded ("undetected error is the only
failure that matters"), but it is worth stating plainly, because "the scaffolding
guides the model to the right decision" is the weaker half of the claim. On this
evidence, mandatory structured assertions are valuable mainly because they give
validators something checkable to read.

Direction distribution over the batch: 8 inbound, 4 local, 3 outbound.

### Open design question for the next cycle

`check_direction` currently raises, which fails the whole merge for that record.
Rule 1 says halt rather than weaken — but rejecting an entire assessment over one
bad control credit is probably the wrong granularity. The conservative alternative
is to zero the offending credit and raise a review flag, so the assessment
survives with no unsupported discount. Needs deciding before the full run.
