## Cycle 5 — 2026-09-11, complete dataset, two-tier tag review

**1,185 of 1,185 records assessed. 1,520 judgement tags adjudicated. 99.0% of scorer citations verified against the source.** Inference ~$25, scoring ~$39.

### Prerequisite: rule 5 was unsatisfiable

The contract required an evidence fragment for every judgement tag; the schema made `tags` a bare enum array with nowhere to put one. The instruction could not be obeyed and no citation could be checked. `tags` is now `[{tag, evidence}]`.

### Tier 1 — deterministic, no model calls

238 findings over 1,185 records:

| Finding | n |
|---|---:|
| workload-recall-miss | 112 |
| evidence-ungrounded | 72 |
| workload-uncorroborated | 37 |
| delivery-contradicts-cvss | 17 |

Boundary: these match terms in prose, which is what was removed from the *risk path*. Flagging a tag for review is not assigning one. Nothing in `scripts/tag_validators.py` writes a tag or touches a rating.

### Tier 2 — adversarial scorer

Validated before use on 8 planted cases, 8/8 separated, including a fabricated DHCP citation and the plausible "browser credential handling implies directory services".

| Namespace | n | supported | ambiguous | unsupported | contradicted |
|---|---:|---:|---:|---:|---:|
| impact | 1067 | 92.2% | 0.7% | 2.5% | 4.5% |
| workload | 173 | 80.9% | 4.0% | 15.0% | 0.0% |
| **delivery** | 265 | **51.7%** | 16.2% | **30.9%** | 1.1% |

Overall fabrication rate (unsupported + contradicted): **12.4%**.

### The headline problem: delivery tags

Barely half of delivery tags are supported by the record. `user-content` alone accounts for 72 rejections — the single largest defect found in this project.

This is not cosmetic. Delivery tags gate email/web filtering and Protected View mitigation credit, so an unsupported delivery tag becomes an **unearned risk discount on a live record**. It is the same class of failure as the original severity defect: a plausible value filling a gap the source never supported.

Impact tags at 92.2% are consistent with the earlier finding that vendors usually state impact outright.

### Workload recall did not improve

62%, against 60% before rule 5a was added. 112 records still name a role the assessor did not tag — Kerberos, SMB Server, Windows Shell, Services for NFS.

**Third instance of the same pattern.** The model was told a rule (5a), did not apply it, and a deterministic check caught it. Earlier: told not to emit release tags, emitted 52; told the direction rule, stated the direction correctly and then contradicted it. In this harness, prompt instruction is not a reliable lever for behaviour. Validation is. Design accordingly — do not spend further cycles rewording guidance and expecting recall to move.

### Span verification: fixed, and the first attempt was wrong

The first checker demanded one verbatim substring and discarded 36.7% of verdicts. That was the checker's fault. Real citations are composite — `Title: "..."; Description: "..."`, `"A" + "B"`, `X ... Y` — and the source carries HTML that never appears in a quotation.

`scripts/span_verify.py` now splits composite citations, strips HTML, and accepts a component when a contiguous run of its tokens appears in the record. Bag-of- words overlap was rejected as a design: a fabricated sentence assembled from the record's own vocabulary must still fail, and there is a fixture asserting exactly that. An empty span is compliant when the verdict is `source-ambiguous`, because the contract tells the scorer to return one. Short structured-field quotations (`"vector": "local"`) verify on their own.

Result: **99.0% of citations verify. The genuine scorer failure rate — support asserted with no quotable span — is 3 in 1,520, or 0.2%**, not 36.7%.

14 fixtures in `tests/test_span_verify.py`, all drawn from real citations in this run.

### Coverage

One batch of 15 returned only 5 CVEs and was recorded as a conformance failure rather than repaired. Those 15 were re-run separately at batch size 5, all conformant, and are included above. Final coverage 1,185/1,185.

### Next

1. **Delivery tags.** 48% unsupported-or-ambiguous, feeding mitigation credit. The obvious first move is to require that a delivery tag cite vendor text describing the delivery path, and reject it where the only support is the CVSS vector — `UI:R` says a user acts, not that the content arrived by email.
2. Workload recall needs a mechanism, not a rule. Consider supplying the component name explicitly as a separate extraction pass.
3. The 72 ungrounded citations are a cheap next target: they are already identified and each is a specific claim with no lexical contact with its source.
