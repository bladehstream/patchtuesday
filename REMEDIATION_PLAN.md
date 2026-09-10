# Remediation and vendor-expansion plan

Drafted 2026-09-10. Supersedes nothing; sits alongside `CLAUDE_ASSESSOR_HANDOFF.md`
(guidance revision 2026.09.2) and is the execution plan that handoff lacks.

Sequencing decisions taken by the owner on 2026-09-10:

- Live September snapshot: **hotfix now**, ahead of the methodology work.
- MSRC Chromium passthrough vs upstream Chrome advisory: **keep separate, cross-linked**.
- 20-CVE calibration sample: **treat as burned**; build a fresh unseen holdout.
- **Phase 2 (Chrome / Firefox / Adobe) deferred 2026-09-10.** Tidy the existing
  platform first. `docs/vendor-source-research.md` is retained and stays valid;
  nothing in Phase 0 or 1 depends on it.

## Status as of 2026-09-10

| Item | State |
|---|---|
| 0.0 Repo hygiene (line endings) | **Done** |
| 0.1 `Unknown` severity end to end | **Done** |
| 0.2 Chromium severity backfill | **Out of scope** — see below |
| 0.3 `unknown-severity` baseline model | **Done** |
| 0.4 Republish | **Data corrected; `dist/` rebuild pending** |
| 1.5 Freshness / hardcoded count | **Done** |
| Everything else in Phase 1 | Not started |
| Phase 2 | Deferred |

Every phase below states acceptance criteria. A phase is not done until its
criteria pass in CI. "Review it" is not an acceptance criterion.

---

## 0. Root cause — read this before anything else

The published dataset rates 23 records `Low` that carry no vendor severity and no
CVSS score. They are almost entirely Chromium passthroughs: use-after-free in V8,
missing authorization in FileSystem, confused deputy in CredentialProvider. That is
56% of the entire `Low` bucket (23 of 41), and 55 records in total have no base score.

This is **not** a single parser bug. It is a fail-open pattern repeated at six
independent points in the chain, each of which silently converts "we do not know"
into "benign":

| # | Location | Coercion |
|---|---|---|
| 1 | `scripts/enrich_cvrf.py` `best_cvss()` | `float(score.get("BaseScore") or 0)` |
| 2 | `scripts/enrich_cvrf.py` line ~199 | `float(cvss.get("BaseScore") or 0)` |
| 3 | `scripts/enrich_cvrf.py` `normalize_severity()` | bare `return "Low"` fall-through |
| 4 | `engine.js` line ~216 | `severity: record.severity \|\| "Low"` |
| 5 | `risk-model.js` `isCriticalPreAuthNetworkRce()` | `Number(record.cvss?.base_score \|\| 0) >= 9` |
| 6 | `risk-model.js` `selectBaselineModel()` | unmatched severity falls through to `standard-remediation` |

Fixing only #1–#3 leaves #4 re-defaulting to `Low` in the UI and #6 quietly
assigning `Scheduled`. **All six must be fixed together or the hotfix is cosmetic.**

The governing principle for every change below: *absence of evidence is not evidence
of absence.* Missing vendor data must propagate as `Unknown` and surface to the
administrator, never resolve to a benign default.

---

## Phase 0.0 — Repo hygiene (prerequisite)

Six files carried 2,793 lines of uncommitted diff with **zero content change** —
pure CRLF injection, with files holding mixed CRLF and LF terminators. Verified by
comparing HEAD against the working tree with carriage returns stripped: byte
identical.

This blocked everything downstream: no reviewable diff, no clean commit, and it
pollutes any git-history analysis. Fixed by rewriting the six files with LF endings
and adding `.gitattributes` (`* text=auto eol=lf`, with `*.ps1` kept CRLF).

## Phase 0 — Hotfix the live snapshot

Goal: no administrator sees a browser RCE labelled `Low`. Scope deliberately
minimal; no re-inference, no schema redesign, no new vendors.

### 0.1 Introduce `Unknown` as a first-class severity

- `normalize_severity()` returns `"Unknown"` when the vendor supplies neither a
  severity string nor a usable base score. Remove the bare `return "Low"`.
- `best_cvss()` and the call site return `None`, not `0`, for a missing `BaseScore`.
  `cvss.base_score` stays `null`; do not synthesise a number.
- `engine.js`: `record.severity || "Unknown"`.
- `risk-model.js`: `isCriticalPreAuthNetworkRce()` returns `false` on a null score
  (unchanged behaviour) but must not be the only gate — see 0.3.
- `app.js`: add `Unknown` to `#severity-filters`, checked by default, rendered with
  a distinct visual treatment (not the `Low` colour).

### 0.2 Chromium severity backfill — OUT OF SCOPE

Originally planned here: extract Google's own severity from the CNA description
parenthetical (`(Chromium security severity: High)`) in `cvelistV5` and use it to
resolve the 23 records to a real vendor rating.

**Dropped on 2026-09-10.** That is Chrome data ingestion, and the owner's standing
constraint is that no new vendor data is ingested until the assessment methodology
is fixed. Deferring it is the consistent reading of that rule, not an oversight.

Consequence, stated plainly: the 23 records now read **`Unknown`** rather than a
correct `High`/`Critical`. That is a truthful answer and a large improvement on
`Low` — an administrator is told the vendor published nothing and the record is
flagged for review, instead of being told the bug is negligible. It is not the
*best* available answer, and the backfill should be the first thing done when
Phase 2 is unparked.

Recorded so the trade-off is not silently forgotten.

### 0.3 Baseline model must handle `Unknown`

`selectBaselineModel()` currently falls through to `standard-remediation`
(`Scheduled`) for any severity it does not recognise. Add an explicit branch:

- `severity === "Unknown"` → new baseline model `unknown-severity`, action index 1
  (`Scheduled`) **but with a mandatory review flag** and
  `confidence: "low"`. The action may coincide with the old behaviour; the
  difference is that it is now a stated judgement carrying a review obligation
  rather than an accident of a fall-through.

### 0.4 Republish

Regenerate `data/2026-Sep.jsonl`, re-run `scripts/publish_month.py`, rebuild `dist/`.
Preserve the pre-hotfix snapshot under `models/` as evidence with a dated filename —
it is the artefact that documents the defect.

### Acceptance criteria — Phase 0

1. `python -m pytest tests/test_enrich_cvrf.py` passes with new cases: missing
   severity + missing score → `Unknown`; missing score + vendor text "Important"
   → `Important`; both present → unchanged.
2. Zero records in `data/2026-Sep.jsonl` have `severity == "Low"` while
   `cvss.base_score is null` **and** no vendor severity string was present.
3. A test asserts no `|| "Low"` or `or 0` severity/score coercion remains, by
   grepping `engine.js`, `risk-model.js`, `scripts/enrich_cvrf.py`.
4. Every record with `severity == "Unknown"` carries a review flag.
5. The count of `Unknown` records is reported in the build output and is non-zero
   for September (expected ≈ 23–32, exact figure to be recorded, not asserted).
6. UI renders `Unknown` distinctly and filters on it.

---

## Phase 1 — Assessment methodology

Ordered by how badly the current state misleads. Each item is independently shippable.

### 1.1 Vendor-plural severity model — the schema change that matters

`severity` is currently one string on one implied scale. Once Chrome, Firefox and
Adobe are in scope this is actively wrong, because **four vendors use overlapping
words that mean different things**:

| Vendor | Scale | Notable semantics |
|---|---|---|
| Microsoft | Critical / Important / Moderate / Low | MSRC's own scale |
| Google Chrome | Critical / High / Medium / Low | **Critical = sandbox escape**; High = RCE *inside* the sandbox |
| Mozilla | Critical / High / Moderate / Low | Critical = code execution on normal browsing |
| Adobe | Critical / Important / Moderate | Plus an **orthogonal Priority 1/2/3** |

A Chrome `High` and a Microsoft `Important` are not the same claim. Collapsing them
into one column and sorting by it is exactly the kind of false precision this tool
exists to avoid.

Proposed shape:

```json
"severity": {
  "vendor_scale": "chrome",
  "vendor_value": "High",
  "vendor_definition_url": "https://chromium.googlesource.com/...severity-guidelines.md",
  "normalized_band": "high",
  "normalized_basis": "vendor-scale-mapping",
  "cvss_derived_band": "high",
  "cvss_source": "CISA-ADP"
}
```

Two separate bands, never merged: what the vendor said, and what CVSS implies.
Where they disagree, **say so in the UI** — that disagreement is signal for an
administrator, not noise to be averaged away. Verified example: CVE-2026-84131 is
Mozilla `moderate` but CVSS 8.8 `HIGH`.

**Adobe Priority gets its own top-level field.** It is the single highest-signal
field for a patch-triage audience (P1 = "install within 72 hours", published because
exploitation is happening or likely) and it has no analogue in any other vendor's
data. Do not fold it into severity.

Migration: keep a flat `severity` string as a derived alias for one release so
`engine.js` search and existing tests keep working, then remove it.

### 1.2 CVSS provenance must be labelled

All three researched vendors **publish no CVSS of their own**. Verified: Google,
Mozilla and Adobe CNA records carry `metrics: null` or no metrics object. Every
CVSS vector you display for those CVEs comes from the **CISA-ADP (Vulnrichment)**
container and is machine-derived from description text. NVD does not independently
enrich Chrome CVEs at all.

Consequence: the UI must not present CVSS as vendor-authoritative for these
products. Add `cvss.source` ∈ `{vendor, cisa-adp, nvd, absent}` and render it.
Microsoft *does* supply its own CVSS, so this varies per record, not per vendor.

This is a real accuracy differentiator against every other patch-triage tool, and
it costs one field.

### 1.3 Replace the flat `review_status`

`review_status` is the string `"reviewed"` on all 1,185 records. The handoff
correctly insists that *model assessed*, *schema validated* and *independently
reviewed* are three different claims — but the data model collapses them into one.

Replace with:

```json
"assurance": {
  "model_assessed":        {"by": "<exact model id>", "at": "<iso8601>"},
  "schema_validated":      {"by": "merge_inference@<sha>", "at": "<iso8601>"},
  "independently_reviewed":{"by": "<reviewer>", "at": "<iso8601>", "outcome": "agreed|amended|rejected"},
  "review_required":       {"flagged": true, "reasons": ["scope-ambiguity", "missing-vendor-severity"]}
}
```

Absent keys mean the claim was not made. `review_required.reasons` is a controlled
vocabulary in `data/`, consumed by the renderer — replacing the current keyword
detector, which the handoff notes misses scope ambiguity.

### 1.4 Action identifiers become data, not prose

The display→JSON mapping (Emergency→`Immediate`, Expedited→`Out-of-cycle`, Normal
scheduled→`Scheduled`, No customer action→`Defer and review`) lives only in a
markdown table. Move it to `data/action-vocabulary.json`, consumed by `app.js`,
`engine.js`, `risk-model.js` and the validators.

Note the trap being locked in: `Defer and review` *reads* like a review flag but
means "no action required". Given 1.3 introduces a real review flag, these will be
confused. Rename the display label or the JSON key — deliberately, once, with a
migration — rather than leaving two things called "review" that mean opposites.

`risk_model_version` stays `2026.09.1` until executable policy migrates, per the
handoff. The vocabulary file carries its own version.

### 1.5 Freshness: stop asserting a frozen count

`tests/september_record.test.mjs:6` hard-asserts `records.length === 1185`. The
handoff instructs the next agent to recheck the live manifest — which breaks this
test. That is a trap left armed.

Replace with:
- assert `records.length === <count in the build manifest>`, not a literal;
- a separate CI job that diffs the local source CVE set against the live MSRC
  release and **fails loudly on drift**, reporting added/removed CVE IDs and
  revision changes. The known case: the 2026-09-10T04:18:17Z refresh added
  CVE-2026-85046 (1,186 vs 1,185).

### 1.6 Validators: check meaning, not just shape

Current validation is CVSS-vector compatibility plus schema. It cannot catch the
Undici error (crediting closed public ingress against a malicious-server attack on
an HTTP *client*). Add:

- **Route direction**: a control that blocks inbound traffic may not be credited
  against a vulnerability whose attack direction is outbound. Requires
  `attack_path.direction` ∈ `{inbound, outbound, local, adjacent}` as a required field.
- **Evidence references**: every credited mitigation must cite a source field that
  exists in the record. No free-floating claims.
- **Asset-leakage guard**: fail the build if any output field matches hostname,
  IPv4/IPv6, UNC path, GUID-shaped tenant ID or email patterns. The handoff states
  the no-customer-data rule twice but nothing enforces it. Given government
  clients, this is cheap and belongs in CI, not in a prompt.

### 1.7 Rebuild the calibration set

The current 20-CVE sample is described — IDs *and* findings — inside the handoff
every assessor reads, and that description is in git history. Treat as burned.

- Keep the existing 20 as a **regression fixture** (known-answer tests for factual
  rules: severity extraction, version comparison, route direction).
- Draw a **fresh holdout** of 25–30 CVEs stratified across vendor, severity band,
  attack direction and `Unknown`-severity presence. Store judgements in a
  reviewer-only path excluded from assessor-facing docs and from the repo the
  assessor reads.
- Calibration uses **ranges plus mandatory reasoning** for judgement cases and
  exact expectations only for factual rules, per handoff item 7.

### Acceptance criteria — Phase 1

1. Every published record validates against a JSON Schema checked into `data/`.
2. Vendor severity and CVSS-derived band are separately present; a test asserts at
   least one record where they disagree and that the UI renders both.
3. No record claims `independently_reviewed` without a reviewer identity and timestamp.
4. Action vocabulary exists as data; a test asserts no hardcoded action string
   remains in `app.js`/`engine.js`/`risk-model.js`.
5. Manifest-drift job runs against live MSRC and fails on an undeclared delta.
6. Route-direction validator rejects a synthetic Undici-shaped record that credits
   inbound blocking. This test must fail before the fix and pass after.
7. Asset-leakage guard rejects a synthetic record containing a hostname and an IP.
8. Fresh holdout exists, is not referenced in any assessor-facing document, and
   scoring is reproducible.

---

## Phase 2 — Chrome, Firefox and Adobe ingestion

**Gate: Phase 2 does not begin until Phase 1 acceptance criteria pass.** Ingesting
three new vendors into a methodology that fails open would multiply the defect
rather than fix it. This is the owner's stated sequencing and it is correct.

### 2.1 The architectural finding

Independent research on all three vendors converged on the same answer: **the CVE
Program `cvelistV5` corpus is the primary source for all three**, with each vendor's
own publication as a required supplement for the fields the CVE record omits.

That means one ingestion spine and three thin adapters, not three pipelines.

| | Chrome / Chromium | Firefox / ESR | Adobe Acrobat |
|---|---|---|---|
| CNA | `Chrome` (Google) | `mozilla` | `adobe` |
| Vendor publishes CVSS? | **No** | **No** | **Yes** (in bulletin + CNA) |
| CVSS actually from | CISA-ADP | CISA-ADP | Adobe PSIRT |
| Vendor severity from | CVE description parenthetical | MFSA YAML `impact` | APSB HTML |
| CSAF/VEX? | **No** (404) | **No** (404) | **No** (404 — verified 4 ways) |
| OSV.dev usable? | **No** (no browser ecosystem) | **No** (404s on current CVEs) | n/a |
| RSS? | Blogger GData JSON | **No** (404) | **No** (404) |
| Scraping required? | Optional enrichment only | **None** | **Yes — Priority is HTML-only** |
| Exploitation signal | Blog prose + KEV + ADP SSVC | ADP SSVC `Exploitation` | ADP SSVC + KEV + bulletin prose |
| Supplement repo | Chrome Releases feed | `mozilla/foundation-security-advisories` (MPL-2.0) | APSB bulletin HTML |

Practical consequences worth calling out:

- **Chrome severity is extractable from structured JSON.** No scraping needed for
  the field that matters. Scraping the release blog buys only bounty amounts,
  reporter credit and per-platform build numbers — make it non-blocking enrichment
  that can fail without failing the build.
- **Firefox needs no scraping at all**, but its CVE `affected` array has changed
  shape between 2024 and 2026 and encodes ESR lines as branch thresholds. A parser
  must handle both shapes, and must collect duplicate `"Firefox ESR"` product keys
  into a **list** — dict-keying silently drops an ESR line.
- **Adobe requires HTML scraping and there is no way around it.** Priority 1/2/3 is
  published only in the bulletin HTML, and it is the most decision-relevant field
  Adobe produces. Budget for a fragile parser with a loud CI assertion.

### 2.2 Enterprise release-channel handling — do not skip this

Each vendor ships parallel lines that enterprises actually deploy. Ignoring them
produces false positives across an entire fleet:

- **Chrome Extended Stable** (8-week cadence, separate channel). An Extended Stable
  machine always looks behind against the Stable feed.
- **Chrome fractional rollout**: "latest stable" is not one number at any moment.
  A machine on an older build may simply not have been served the update.
- **Chrome dual builds** (`152.0.7977.75/.76` Win/Mac from one announcement) —
  compare against the *lowest* announced build for the platform.
- **Firefox ESR is currently mid-transition**: ESR 140.15 and ESR 153.2 both shipped
  2026-09-01 with **non-identical CVE sets**; ESR 115.40 still ships for legacy OS.
  "ESR" is not one line. ESR 140 EOL is reported as 2026-09-29 — verify against
  Mozilla's calendar before displaying it, the third-party source for that date was
  independently shown to be stale.
- **Acrobat tracks**: Continuous (26.002.x) and Classic 2024 (24.001.x) are active;
  Classic 2020 reached EOL 2025-11-30 and no longer appears in bulletins. A
  20.005.x install is permanently unpatched — render that as an explicit
  "unsupported track" state, not as a version comparison.

The product selector must let an administrator declare their **channel/track**, not
just the product. Without it the tool is wrong for most managed estates.

### 2.3 Version comparison

Never use a semver library for any of these. Verified pitfalls:

- Chrome: 4-tuple integers; `.100 > .99`, `8010 > 7977` — lexicographic comparison fails.
- Firefox: `versionType: "rpm"`; `140.15` has two components, `115.40.0` has three.
- Adobe: CVE records *declare* `"versionType": "semver"` but `26.002.21900` is not
  semver (zero-padded `002`, 5-digit build).

Implement one integer-tuple comparator with per-vendor component-count tolerance,
and unit-test each vendor's real version strings.

### 2.4 Cross-linking, per the owner's decision

MSRC Chromium passthrough records (`Chromium: CVE-…`) stay as **Edge** records.
Upstream Chrome advisories become **separate** records. They are joined by CVE ID
and each carries `related_records: [{source, record_id, relationship}]`.

The UI must make the duality legible rather than showing the same CVE twice with no
explanation: one row per CVE per product-you-selected, with a visible note that the
same CVE affects the other product at a different fixed build. Edge and Chrome
version numbering diverges (`152.0.4191.62` vs `152.0.7977.82`) — the major matches
but the build does not, so **Edge applicability cannot be inferred from Chrome
version arithmetic**. MSRC's `sug/v2.0` endpoint is the only authoritative
Chromium-CVE→Edge-build mapping.

### 2.5 Cadence — the Patch Tuesday framing is now wrong

**Adobe moved to twice-monthly bulletins effective 2026-07-14** (2nd and 4th
Tuesday). The 2nd Tuesday still aligns with Microsoft; the 4th Tuesday has no
Microsoft counterpart. Chrome ships roughly every 4 weeks with out-of-band releases
within days of an in-the-wild exploit. Firefox ships every ~4 weeks with unscheduled
chemspill point releases.

A monthly, Patch-Tuesday-shaped build will be wrong about half the time for Adobe
and will miss Chrome's out-of-band security releases entirely — which are precisely
the ones that matter.

**Move to a daily build with an out-of-band trigger on KEV changes.** Present the
data as "current as of <timestamp>", not as a monthly snapshot. This is a product
framing change, not just a scheduling one, and it should be decided explicitly.

### 2.6 Licensing

- Firefox MFSA repo: **MPL-2.0** — redistributable. Avoid mozilla.org prose, which
  is CC BY-SA (viral share-alike). Do not ship Mozilla trademarks or the Firefox logo.
- Chrome: redistribute facts, not Google's prose. Source display text from the CVE
  record (CVE Program terms) rather than the blog. `robots.txt` allows `/feeds/`
  and disallows `/search/` — use the feed, never the search path.
- Adobe: no explicit reuse grant. Redistribute structured facts; link to the APSB
  rather than copying descriptive prose. `robots.txt` permits `/security/`.
- CVE records, NVD, CISA KEV and Vulnrichment: freely redistributable
  (CVE Program terms / US Government public domain).

Net: source display prose from CVE records wherever possible. That single choice
resolves the licensing question for all three vendors at once.

### Acceptance criteria — Phase 2

1. Each vendor adapter produces records passing the Phase 1 schema, including
   vendor-scoped severity and labelled CVSS provenance.
2. Version comparator unit-tested against real strings from all four vendors,
   including Chrome dual-build, Firefox two- vs three-component, Adobe zero-padded.
3. Firefox parser handles both 2024 and 2026 `affected` shapes; a test asserts
   duplicate `"Firefox ESR"` keys are preserved as a list.
4. Chrome ingestion succeeds with the blog enrichment disabled — proving the
   scraping layer is non-blocking.
5. Adobe parser asserts per bulletin: ≥1 CVE, priority ∈ {1,2,3}, ≥1 affected-version
   row. Build fails loudly on a parse yielding zero.
6. Channel/track selection exists in the UI for Chrome (Stable/Extended Stable),
   Firefox (Release/ESR line) and Acrobat (Continuous/Classic 2024/unsupported).
7. Cross-linked Edge↔Chrome records resolve to distinct fixed builds and the UI
   explains the relationship.
8. Asset-leakage guard passes on all new vendor outputs.

---

## Phase 3 — Open decisions requiring the owner

These are not blocked on research. They need a call.

1. **`Defer and review` rename.** Keeping it alongside a genuine review flag will
   confuse administrators. Rename which side?
2. **Monthly snapshot → daily current-state.** 2.5 argues the monthly framing is now
   incorrect. This changes the product's core metaphor and the URL structure.
3. **`Unknown` display policy.** Should `Unknown` sort above or below `Low`? Argument
   for above: an unrated V8 use-after-free deserves attention. Argument for below:
   it inflates the queue with genuinely minor Chromium bugs. Recommend: separate
   "needs a decision" lane, outside the severity sort entirely.
4. **Scope of re-inference.** Phase 0 fixes ratings mechanically. Phase 1.1–1.3
   changes the schema in ways that arguably invalidate the existing 1,185
   assessments. Re-run all, re-run only affected, or publish mixed-vintage with
   explicit `assurance` provenance?

   Partly answered 2026-09-10: re-inference is performed by Claude Sonnet subagents,
   so cost is not the constraint on this choice. The remaining question is
   epistemic, not economic - whether a mixed-vintage dataset is honest enough to
   publish given the `assurance` object now records which claim was made when.

---

## Unverified items carried forward

Flagged so they are not mistaken for established fact:

- CISA KEV JSON endpoint could not be fetched during research (egress 403 from two
  independent agents). URL is the long-standing canonical one; confirm before wiring.
- NVD published rate limits (5/30s anon, 50/30s keyed) could not be confirmed at
  source — the docs pages are JavaScript-rendered.
- CVE Program Terms of Use full text could not be read (JS-gated SPA). Confirm
  before launch.
- Firefox ESR EOL dates rest on `endoflife.date`, which was independently shown to
  be stale on version numbers. Medium confidence; re-check against Mozilla's calendar.
- `cvelistV5` release asset filenames not enumerable (JS-rendered releases page).
  Confirm baseline/delta zip names before wiring CI.
- Component extraction from CVE description prose is a heuristic (~90%), not a
  contract. Do not build filtering logic that assumes correctness.


---

## Autonomous execution contract

Recorded 2026-09-10, before this plan is handed over as a `/goal` for unattended
execution. The acceptance criteria above describe what correct looks like. This
section covers what to do when correct turns out to be unreachable, which is where
unattended runs actually cause damage.

### 1. Halt, do not weaken

If an acceptance criterion cannot be met, **stop and report**. Do not relax the
criterion, disable or skip a test to reach green, or narrow a check until it passes.

Every failure this project has already warned about is an instance of this rule
being broken under pressure: `--include-unreviewed` to conceal missing inference,
labelling one provider's output as another's to satisfy a provenance check, altering
`cvss_basis` to satisfy a validator. A blocked phase reported honestly is a good
outcome. A phase that passes because the bar moved is not.

### 2. Actions requiring a human

Proceed freely on everything except the following, which stop and ask:

- Republishing or overwriting `data/*.jsonl` beyond the corrections a phase declares.
- Any change to `risk_model_version` or to executable policy in `risk-model.js`.
- Deleting anything. Deletion is enabled in this folder for convenience with git;
  that is not licence to remove content.
- `git push`. The bridge has no network and pushing is Bob's, per `CLAUDE.md`.
- Changing what the tool asserts to an administrator - see the Phase 1.1 carve-out
  in section 10.

### 3. No cost ceiling; bounded failure instead

There is no token or wall-clock budget. Inference is performed by Claude Sonnet
subagents rather than a metered external API, so cost is not the limiting factor.

Unbounded is not unlimited. The real risk is a loop that retries forever, so:

- Three attempts at any single failing item, then halt and report it.
- No unbounded retry of a failing fetch. Two attempts, then report the source as
  unavailable and continue with what is reachable.
- Progress must be demonstrable per phase. A phase with no completed acceptance
  criterion after a full pass halts rather than continuing to churn.

### 4. Every gate needs a fixture it rejects

Generalised from Phase 1.6. For every validator, guard or assertion added: build a
case it **fails**, confirm it fails before the fix and passes after, and keep that
fixture. A gate that has never rejected anything is not known to be a gate.

This is the highest-value condition on this list, because the same agent writing a
check and confirming the check works is otherwise worth very little.

### 5. Pinned regression baseline

Before starting, snapshot every record's computed action and likelihood to
`work/goal-baseline/`. On completion, produce a diff report of every record whose
action or likelihood changed, each with a stated reason.

**Unexplained movement fails the phase.** This is the only mechanism that
distinguishes "fixed the defect" from "changed the answers".

### 6. Independence boundary

**Phase 1.7 is not autonomisable and must not be attempted unattended.** It calls
for a fresh *independent* calibration holdout. An agent that draws the sample, makes
the judgements and then scores itself against them has produced a circular result
wearing the label of an independent one - the exact confusion this plan exists to
remove.

What may be done unattended: build the stratification mechanism, draw the candidate
sample, and prepare the scoring harness. The judgements come from Bob or another
reviewer. Stop there and say so.

### 7. Definition of done for the goal

The goal is complete when **all** of the following hold:

1. Every Phase 0 and Phase 1 acceptance criterion passes, except 1.7, which is
   handed back per section 6.
2. `npm test` and `python -m pytest tests/` both pass.
3. `npm run build` succeeds.
4. The working tree is clean and every change is committed.
5. The regression diff report exists and contains no unexplained rating changes.
6. The Phase 3 open decisions are **still open**, listed, and unmade.

Point 6 is deliberate. Deciding them is not part of done; presenting them is.

### 8. Source snapshot is pinned

Pin `raw/2026-Sep.json` and the KEV/EPSS inputs at the start of the run and work
against that snapshot throughout. If the live MSRC manifest drifts mid-run - as it
did on 2026-09-10, adding CVE-2026-85046 - **report the drift, do not absorb it**.
A source set that changes underneath a run makes the regression baseline in section
5 meaningless.

Taken as the default because an unattended run cannot judge whether a mid-run change
is benign. Revisit if Bob prefers otherwise.

### 9. Commit granularity

One commit per plan item, subject line naming the item, so `git log` reads as the
plan's progress. Bob reviews after the fact; a single large commit is not
reviewable. Repo-local commit identity per `CLAUDE.md`.

### 10. Provider portability and honest provenance

The project is intended to be portable across inference providers. Claude Sonnet
subagents are **one implementation** of the provider interface, not an assumption
baked into it.

- `scripts/run_luna_inference.py` and `scripts/collect_full_inference.py` remain
  unused for any non-Luna provider. They carry Luna-specific model and provenance
  checks and a Luna-specific response schema. Never relabel output to pass them.
- A new provider adapter is defined by the fields it must produce, not by who
  produces them: prompt, response, model identifier, timestamps, per-CVE coverage.

**Corrected 2026-09-10.** An earlier revision of this section claimed the Luna path
recorded `response_sha256` and `input_sha256` because it made HTTP calls to a metered
API. That was wrong. `scripts/run_luna_inference.py` shells out to the **local Codex
CLI** (`codex exec --sandbox read-only --output-schema -m gpt-5.6-luna`) as a
subprocess and hashes the response file the CLI writes. Authentication belongs to the
CLI's own sign-in; this repository has never held a model API key.
`models/2026-Sep-full-inference.md` records it plainly: 81 calls of 15 advisory
records each, "through the authenticated local CLI".

The only direct HTTP this project performs is `scripts/fetch_sources.py`, fetching
public advisory data from MSRC, CISA KEV and EPSS - unauthenticated, and not model
inference.

This makes the provider adapter **easier**, not harder. A Codex CLI subprocess and a
Claude subagent are the same shape: local invocation, captured response file, locally
computed hash. The existing provenance fields carry over honestly; nothing needs
synthesising.

**The one capability that does not carry over is schema enforcement.** Codex was
invoked with `--output-schema`, so the response was structurally constrained before
it reached the script, which then hard-failed if the returned CVE set did not match
the requested set exactly. A subagent returns text. The adapter must therefore
validate strictly against the same JSON schema, retry within the bounded-failure
limits of section 3, and **record a malformed response as a failure rather than
repairing it**. This matters more with a smaller model, not less.

Further: the configured model identifier is assertable; the serving model is not.
This environment's own guidance is that the serving model can differ from the
configured one. Record `model_configured` and leave `model_served` null rather than
guessing. This is the plan's own rule - highlight missing source values instead of
inheriting a fabricated one - applied to our own provenance rather than to
Microsoft's.

### 11. Phase scope for unattended execution

| Item | Unattended? |
|---|---|
| 0.x (all) | Yes - already complete |
| 1.1 Vendor-plural severity schema | **No.** Produce the schema and a worked example against a handful of records, then stop. It changes what the tool asserts to an administrator |
| 1.2 CVSS provenance labelling | Yes for the mechanical half - adding and populating `cvss.source`. Presentation changes stop with 1.1 |
| 1.3 Assurance object | Yes |
| 1.4 Action vocabulary as data | Yes, except the `Defer and review` rename, which is Phase 3 decision 1 |
| 1.5 Freshness / manifest diff | Yes - already complete |
| 1.6 Validators | Yes |
| 1.7 Calibration holdout | **No** - see section 6 |
| Phase 2 | Deferred entirely |

---

## Environment blockers (2026-09-10)

Two operations could not be completed from this session because the sandbox
denies file deletion, and both need one command from the owner:

1. **Stale `.git/index.lock`.** A failed `git checkout` left a zero-byte
   `.git/index.lock` that cannot be removed from here. **Every `git add` and
   `git commit` will fail until it is deleted.** Nothing else is wrong with the
   repository; `git status` and `git diff` still work.

   ```powershell
   Remove-Item ".git\index.lock"
   ```

2. **`dist/` rebuild.** `scripts/build-pages.mjs` starts with `rmSync(dist)`,
   which needs unlink permission. Source and data are corrected; only the built
   output is stale.

   ```powershell
   npm run build
   ```
