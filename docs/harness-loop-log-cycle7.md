## Cycle 7 — 2026-09-11, defining the tags, and what it did not fix

All 1,520 judgement tags re-adjudicated against the definitions added in cycle 6,
then the impact tags again after defining those too.

### Result

| Namespace | supported before | after | change |
|---|---:|---:|---:|
| delivery | 51.7% | **68.9%** | +17.2 |
| impact | 92.2% | **97.1%** | +4.9 |
| workload | 80.9% | 81.0% | **+0.0** |

Overall fabrication rate across all judgement tags: **12.4% → ~6%**.

`remote-code-execution` rejections fell 19% → 2%; `user-content` 46% → 23%.

### The second naming collision

`remote-code-execution` was the worst remaining tag at 50 rejections — and 46 of
those 50 had "Remote Code Execution Vulnerability" **in the vendor's own title**.
The scorer was applying the strict industry meaning (exploitable over a network)
and rejecting the tag wherever the CVSS vector said `AV:L`.

There is a principled answer, not just a convenient one. Reachability is already
carried by `attack.vector`, which the risk model reads independently —
`isCriticalPreAuthNetworkRce` requires the tag *and* a network vector. So the
impact tag must denote the impact class alone. Encoding reachability in it as
well would make the tag redundant with the vector field and capable of
contradicting it. The definition now says so.

### The hypothesis that failed

`identity` was predicted to improve with a definition, on the reasoning that
"Windows identity infrastructure" is the kind of name two readers interpret
differently. **Workload tags did not move at all: 80.9% → 81.0%.** The definition
made no difference, so whatever is wrong with workload tags is not a naming
collision. Recorded as a wrong prediction rather than quietly dropped.

That leaves workload as the only namespace where the residual defect is real and
unexplained — 15% unsupported, with `identity` and `remote-desktop` the worst.

### Method note

Two of the three namespaces improved substantially because a tag name was
ambiguous and nobody had written down which meaning applied. Both collisions were
found the same way: by reading what the scorer actually objected to, rather than
by reasoning about what the number might mean. Three earlier measurement errors
in this project came from the opposite habit.

A caution against the obvious over-correction: defining a tag so that the
assessor is retrospectively right is only legitimate when there is an independent
reason the assessor's reading is the one the system needs. For `user-content` it
was that the tag gates email filtering and Protected View. For
`remote-code-execution` it was that reachability already lives in the vector
field. Absent such a reason, a disagreement should be resolved against the
assessor, not the scorer.

### Open

- Workload tags, 15% unsupported, cause unknown and not a definitions problem.
- 112 workload recall misses from Tier 1 — the check identifies them; nothing yet
  acts on them.
- 72 ungrounded citations, individually identified, untouched.
