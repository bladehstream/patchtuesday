## Cycle 6 — 2026-09-11, the delivery tag problem was a definitions problem

Cycle 5 reported delivery tags at 51.7% supported and called it the largest
quality defect in the project. About half of that was an undefined tag name.

### What was actually happening

The scorer read `user-content` in the web-application sense — content *authored
by* users, the upload/sanitisation meaning. The assessor used the patch-triage
sense — attacker content *delivered to* a user who must open it. Scorer reasoning,
verbatim:

> "The record clearly identifies the source of the exploited content as
> attacker-supplied ('an attacker must send'), not user-supplied. The user's role
> is to open the file, but opening an attacker-crafted file does not constitute
> processing 'user-content'."

Both readings are defensible from the tag name. Neither was written down. And the
assessor's reading is the one this system needs, because `user-content` gates
`email_web_filtering` and `office_protected_view` — controls that exist precisely
for a user opening a malicious attachment.

### Fix

Added a `definitions` block to `data/tag-taxonomy.json` covering the nine
judgement tags whose names are ambiguous, and supplied it to **both** sides: the
assessor prompt now points at it, and the scorer receives the authoritative
definition for the tag under review.

### Result — delivery tags, same records, same model

| Verdict | Before | After |
|---|---:|---:|
| supported | 51.3% | **64.5%** |
| source-ambiguous | 15.9% | 12.0% |
| unsupported | 31.7% | **18.9%** |
| contradicted | 1.1% | 4.6% |
| **rejection rate** | **32.8%** | **23.6%** |

`user-content` rejection halved: 46% → 23%.

### What this says about the method

Two hypotheses were tested and discarded before the real cause was found:

1. "Delivery tags fail because they cite the CVSS vector instead of vendor prose."
   Measured: citing prose correlated with *more* rejection, not less. Wrong.
2. "The assessor is fabricating FAQ quotations." Checked the source directly: the
   FAQ text was present and quoted accurately. Wrong, and it was my own counting
   script that was broken.

The cause was only found by reading what the scorer actually objected to. Three
measurement errors in this project so far have had the same shape — a number was
interesting, so it was reported before checking what it was made of.

**Residual 23.6% rejection is the real delivery defect**, and it is now a
tractable number rather than a definitional artefact.

### Next

Apply the same question to the other namespaces: `identity` was the worst
workload tag at 15 rejections, and "Windows identity infrastructure" is exactly
the kind of name two readers will interpret differently. The definitions block
already covers it; the workload tags have not been re-scored against it.
