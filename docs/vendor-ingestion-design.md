# Folding Chrome, Firefox and Acrobat in

Research dated 2026-09-11, verified against live sources. Supersedes the source-location work in `docs/vendor-source-research.md`, which remains valid for where the data lives. This document is about whether it can be made to fit, and what breaks if we pretend it does.

---

## The finding that changes the cadence decision

The twice-monthly cycle was adopted because Adobe moved to twice-monthly on 2026-07-14. That move is real and verified — second and fourth Tuesday, both are genuine security dates. **But Acrobat is not on it.** Acrobat and Reader security bulletins in 2026 fell on 03-10, 04-11 (a Saturday, out-of-band), 04-14, 06-09 and 09-08. Zero bulletins on 07-14, 07-28, 08-11 or 08-25 — despite seven Continuous product releases in that window. Acrobat's bulletin cadence is quarterly.

So a twice-monthly cycle produces an empty Adobe delta on roughly ten cycles in twelve, and it would have been wrong about the one Adobe event of 2026 that mattered: APSB26-43, Priority 1, published Saturday 2026-04-11 — *"Adobe is aware of CVE-2026-34621 being exploited in the wild"* — added to CISA KEV two days later. A second-and-fourth-Tuesday build would have carried it up to ten days late.

Meanwhile both browsers moved to a **two-week** cycle in September 2026, independently:

- Chrome: two-week milestones from Chrome 153 on 2026-09-08, with the stable and extended stable channels *refreshed weekly* on top. Eight distinct serving-set transitions were observed on win64 stable in eight days.
- Firefox: 4-week to 2-week from Firefox 155 on 2026-09-01, anchored to a merge train rather than a day of month — so alignment with any calendar cycle drifts (2026-09-29 is a fifth Tuesday; 2026-12-08 is followed by a five-week gap).

**Recommendation: separate ingestion cadence from publication cadence.** Poll daily, write to a staging dataset, publish on the cycle, and keep an out-of-band publish path for the 48-hour class — a KEV listing, SSVC `Exploitation: active`, an Adobe Priority 1, or an out-of-band vendor advisory. Cycle length then stops being load-bearing.

This matters in the client's own compliance terms. Essential Eight ML2 (ISM-1691) requires browser patches within two weeks of release; ML3 (ISM-1692) within 48 hours where the vendor rates it critical or a working exploit exists. A fortnightly ingest spends the entire ML2 budget on ingest latency before the client sees the record.

---

## Cross-cutting: four assumptions in the current pipeline that do not survive

**1. `resolve_severity()` is a Microsoft-scale function and will silently coerce.** Chrome `"High"` matches `"high" in lowered` and returns `("Important", "vendor")`. Chrome's scale is defined *relative to the renderer sandbox* — its `High` means code execution **inside** the sandbox, which is not Microsoft `Important`. Worse, a record with no vendor severity but a CISA-ADP CVSS returns `("Important", "cvss")`, presenting a machine-derived score as a vendor band. That is the seventh instance of the fail-open family already fixed in Phase 0 — it just fails open to `Important` rather than `Low`, which is differently wrong, not better. **Phase 1.1 (vendor-plural severity) is a prerequisite for any of these three vendors, not a follow-up.**

For Chrome, the honest `normalized_band` is `unknown`: there is no scalar that makes Chrome High and Microsoft Important the same claim. Adobe is the exception — it publishes its own CVSS in the CNA container, so `cvss.source` is `vendor`, not `cisa-adp`.

> `REMEDIATION_PLAN.md` §1.2 states that all three vendors publish no CVSS of their own.
> That is **false for Adobe** and has been corrected. §2.1's table was already right.

**2. `exploitation_detected` is a regex for one vendor's phrasing.** `enrich_cvrf.py` greps `"exploitation detected"`. Adobe writes *"is aware of CVE-… being exploited in the wild"*; Google writes *"Google is aware that an exploit for CVE-… exists in the wild"*. The regex returns **false for an actively exploited zero-day** from either. The fix is not a second regex — it is CISA KEV plus ADP SSVC as the structured signal, with the vendor prose demoted to assessor evidence.

One trap inside that: SSVC `Exploitation: none` means *no evidence found*. Mapping it to `unlikely` (likelihood 0) rather than `unknown` (likelihood 1) is a one-step likelihood suppression applied to every browser record.

**3. `updateStatus()` is CVRF-shaped and two-state.** Microsoft's `available: false` means "the vendor has shipped no fix for that SKU". None of the three vendors has an analogue. Mozilla and Google publish an advisory only once the build exists, so `false` can only ever mean "our parser failed". Adobe likewise. A third state — `unknown` — is required, and it must render as neither "update available" nor "not yet released".

The concrete lie to avoid: Chrome Extended Stable. Google publishes which Stable build fixes a CVE and does **not** publish which 152-branch back-port contains it. Extended win64 currently serves `152.0.7977.120` while Stable's last M152 build was `152.0.7977.85` — the extended branch's patch numbers run *ahead*, so cross-channel version arithmetic is invalid. An Extended Stable fleet shown "update available" has been lied to.

**4. `derive_product_tags()` seeds `tags = {"microsoft"}` unconditionally.** Every non- Microsoft record would be tagged Microsoft. The rule table needs to be per-vendor data.

---

## Chrome

**Source of record:** the CVE Program record (CNA `Chrome`) is authoritative and licensed for redistribution; the Chrome Releases blog is the *only* place the exploited-in-the-wild sentence exists at T+0 and arrives ~2h45m before the CVE record and ~27h before SSVC. So the blog is non-blocking for the build but load-bearing for the threat field — and a failed blog fetch must produce `exploitation_detected: null` plus a review flag, never `false`.

**Revision detection is better than MSRC's**, not worse: hash each CVE record, each ADP container and each blog body separately, so a change tells you *whose* fact moved. Note that `cveMetadata.dateUpdated` moves mostly on CISA enrichment, not Google revisions — key "the vendor revised this" on the CNA's own timestamp.

**The record's `affected` array, read literally, says nothing is affected:** `{"version":"152.0.7977.75","lessThan":"152.0.7977.75"}` with no `defaultStatus` is an empty range. "Everything below this is affected" is our inference and must be labelled `threshold_basis: "inferred-from-lessThan"`, not asserted as vendor fact.

**Abstention is the default, not the exception.** Chrome withholds bug detail until a majority of users have updated, and every description is the same template: a CWE phrase, a component, a precondition, an outcome. Mitigation reasoning is unassessable for essentially every Chrome CVE — and that is the vendor's disclosure policy working as designed, not a gap. It needs a different flag from "Microsoft usually publishes this and didn't".

**The record that proves the design:** CVE-2026-87491 is Chromium severity **Medium**, SSVC `active`, in KEV, and the seventh Chrome zero-day of 2026. Any design that lets Chrome severity drive the action buries it under 136 other Mediums. A `severity-conflicts-with- exploitation` review reason is the fixture.

**Licensing:** CVE Program content is explicitly redistributable with attribution — and that covers the `(Chromium security severity: X)` parenthetical, which is where the decision-relevant text lives. The blog carries no reuse grant: extract facts to booleans and dates with a citation URL, never store Google's sentences. The VersionHistory API has no published terms at all — flag for sign-off rather than assuming.

---

## Firefox

**The ESR problem is the whole problem.** On 2026-09-01 Mozilla shipped four advisories covering 33 distinct CVEs across Rapid Release, ESR 153.2, ESR 140.15 and ESR 115.40 — with only **5 CVEs common to all four**, and 3 present in ESR 140.15 that are not in Firefox 155. Those are back-ports. CVE-2026-16365, a high-impact privilege escalation, was fixed in Firefox 153 on 2026-07-21 and in ESR 140.15 on 2026-09-01: **an ESR fleet carried a publicly-disclosed high-impact flaw for 42 days after the Rapid Release fix shipped.**

That lag exists in no vendor feed and is the single most useful number this adapter can produce for a government fleet. It requires one record per CVE carrying a `channels[]` array — not one record per advisory (which duplicates every CVE up to seven times across Firefox and Thunderbird siblings) and not one record per channel.

**Rollups are the majority of the work.** Firefox 155's advisory has 29 CVEs, of which 4 are rollups covering **84 underlying bugs** — more than all 25 individually-tracked CVEs combined. Mozilla now splits the bug list by severity, so CVE-2026-84144 is rated `high` on the strength of 3 of its 34 bugs. The rating is a maximum over an undisclosed set.

The honest representation is one record with `record_kind: "rollup"`, carrying the census as structured evidence and *structurally barred* from impact, delivery and workload judgement. The critical detail: its priority must be driven by the vendor rating, stated as such. If rollups fall through to `Scheduled` because no impact tag was asserted, the Chromium-`Low` defect repeats at larger scale.

Two traps worth naming. The rollup title changed mid-2026 from *"Memory safety bugs fixed in…"* to *"Internally found bugs fixed in…"* — a title regex would have failed silently, so detect structurally and keep the regex only as a tripwire. And CVE-2026-84145's CNA title says **Thunderbird** while the same CVE is a Firefox advisory: last writer wins on the shared title field, so take the product from `affected[].product`, never the title.

**`Unknown` will dominate attack vector, not severity.** Mozilla rates every CVE but publishes no CVSS, so `attack.*` is `unknown` on ~100% of Firefox records, firing `incomplete-prerequisites` on all of them. A permanent structural absence needs its own non-escalating disposition, or the review queue becomes 100% Firefox noise and the Microsoft signal is buried.

**Unresolved and material:** ESR 140's end of support. endoflife.date says 2026-09-29; Mozilla's own "at least 12 weeks overlap" policy from ESR 153's 2026-07-21 release implies 2026-10-13. One is wrong, and it is the date a government fleet becomes permanently unpatched. Needs a Mozilla-primary source before it goes in the tool.

**Licensing:** the advisories repo is MPL-2.0; ship derived facts, not the YAML. Use the YAML `description` rather than the mozilla.org page text — same words, but MPL rather than CC BY-SA, which is materially cleaner for a commercial deliverable.

---

## Acrobat

**This one is scraping, and the terms are the decision.** Adobe publishes no CSAF and no usable feed. Priority, the severity word, the track column, per-platform fixed versions, the exploitation sentence and the revision log exist **only** in HTML. `helpx.adobe.com`'s sitemap is stale to 2022 and carries no 2026 bulletins.

Adobe's General Terms of Use (effective 2025-10-03) §6.18 prohibits data scraping, §6.6 access by means other than the provided interface, and §17 use of content *"to directly or indirectly create, train, test, or otherwise improve any machine learning algorithms or artificial intelligence system"*. §17 is aimed squarely at a pipeline that feeds advisory text to an LLM assessor. `robots.txt` does **not** disallow `/security/`, which cuts the other way.

The exposure is contractual and reputational rather than copyright — under *IceTV* and *Telstra v Phone Directories* the facts themselves attract no copyright in Australia — but that is a different risk, not a smaller one, and it is not cured by "we only redistribute facts". Recommended: write to Adobe PSIRT for written permission (they have an interest in patch uptake; a written yes is what a government assurance reviewer will want to see); meanwhile constrain to one request per bulletin per day with an identifying User-Agent; **never send Adobe prose to the model**, enforced by a guard test rather than a convention; and build the degraded mode now, so a legal "no" costs a feature rather than the vendor.

**Track sprawl is real and cannot be inferred.** Bulletins are keyed by (Product, Track, Platform); fixed versions differ by platform (APSB26-43: Win 24.001.30362 / Mac 24.001.30360); product display names drift between bulletins (`Acrobat DC` → `Adobe Acrobat`); and **track cannot be derived from the version string** — `26.001.21789` and `26.002.21869` are both Continuous, and Adobe's own Admin Guide rule about the leading digit is stale. The earlier suggestion to infer track from the version and flag the inference should be dropped rather than flagged: it is unsound.

**Priority is a second axis and belongs in the parser, not the risk model.** It is a verbatim vendor publication and deterministic to extract, so it parses like severity. But it is the output of *Adobe's* risk model over Adobe's telemetry, so letting `priority == 1` set `baseline_action = Immediate` would launder Adobe's judgement as ours and create an action floor the customer's own mitigations cannot move. Render it beside the computed action, offer it to the assessor as citable evidence but forbid citing it *alone*, and make the one deterministic hook a review flag: Priority 1 with a computed action below Out-of-cycle is a `vendor-priority-disagreement`, not an override.

Severity and CVSS genuinely diverge — within one bulletin, CVE-2026-80159 is Adobe **Critical** at CVSS **4.0**. That is a real day-one demonstration of why the vendor-plural severity object is needed.

**Two things that will bite:** `available: false` on a supported track can only mean the parser failed, because Adobe publishes the bulletin *with* the fix — so it must fail the build, not render as "no fix exists". And **latest is not patched**: Continuous `26.002.21900` shipped 2026-09-07 and was listed as affected by APSB26-141 the next day, so comparison must be against the bulletin's fixed version and never against "the newest release".

**One live warning from the research itself:** an LLM-mediated fetch returned APSB26-63's revision block as APSB26-141's — fluent, plausible, and wrong. The HTML parser must be `lxml`/`selectolax` against explicit selectors with an asserted header tuple; the model stays strictly downstream of extracted facts.

---

## What is required before any of this is built

1. **Phase 1.1, vendor-plural severity.** Hard prerequisite for all three. Without it, `resolve_severity()` coerces every vendor onto Microsoft's scale.
2. **`updateStatus()` tri-state and vendor-dispatched.** Two states cannot express "we do not know whether your channel is fixed".
3. **`derive_product_tags()` parameterised by vendor**, with the rule table as data.
4. **Structured exploitation signal** (KEV + SSVC) replacing the prose regex.
5. **`month` → `cycle` + `published_at`**, since two of the three vendors have no month and Adobe's flagship 2026 bulletin landed on a Saturday.

Each of these is a change to shared code with existing tests, and each needs its own fixture that fails. None of them is vendor-specific work — they are the cost of the pipeline having been built against one vendor's assumptions.
