## Cycle 3 — 2026-09-10, full dev set (63 records), both arms

| Arm | Measure 1 (schema conformance) | Cost |
|---|---|---|
| Scaffolded | **5/5 batches, 63/63 records** | $1.36 |
| Minimal (ablation) | **0/5 batches** | $1.10 |

### The ablation answer

The unscaffolded arm did not fail loudly. Every call returned `is_error: false, subtype: success`, and produced fluent, confident prose:

> "## Assessment Summary — I've completed a detailed assessment of all 15 public vulnerability advisories… **Risk Verdict: Low Overall** (with 2 exceptions)"

That batch contained the three FreeIPMI buffer overflows at CVSS 9.8 and the Undici case. "Low Overall" is wrong, and nothing about the output signals that it is wrong. It is also completely unusable by the pipeline — zero machine-readable assessments from 63 records.

So the scaffolding's contribution is not marginal. On measure 1 it is the entire difference between 100% and 0%. The ablation arm is retained as the standing baseline; this is the number any future claim about the harness has to beat.

### Scaffolded arm detail

- 63/63 records carried a valid `attack_path.direction`. Distribution: 37 inbound, 12 local, 10 outbound, 4 adjacent.
- Direction gate: **1 contradiction**, the same CVE-2026-18149 credit as cycle 2. Now zeroed and flagged rather than failing the record. 62 records passed clean.
- 107 judgement tags across 63 records (1.70 per record). The previous assessor managed 1,362 across 1,185 (1.15 per record), so Haiku tags **more** densely.
- But 15 of 63 records (24%) carry no judgement tag at all, against the previous assessor's 16.5%. Haiku is more generous where it engages and more likely to disengage entirely. The contract does not currently require at least one impact tag per record; that is the next targeted fix.

### Granularity decision, made

`check_direction` raised and failed the whole record. Replaced with `enforce_direction`, which zeroes the offending credit, marks the control `not-relevant` with `direction_override: true`, records what was claimed before zeroing, and returns the violation for review.

Rationale: an assessment's other work — direction, impact, factors, the remaining controls — may be sound, and discarding it buys nothing. Removing the unsupported discount leaves the record with *less* credit than the model claimed, which is the conservative direction. A missing or invalid direction still raises, because with no direction there is nothing to check any control against.

Six fixtures in `tests/test_direction_enforcement.py`.

### Next cycle

Require at least one impact tag per record where customer action is required, and re-measure the 24% disengagement rate.
