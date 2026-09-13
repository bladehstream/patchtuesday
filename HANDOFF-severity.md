# Handoff: implement Phase 1.1, vendor-plural severity

Everything in this task has been specified and decided. Nothing here needs a design decision; if you find one I missed, stop and ask rather than choosing.

Read first: `data/severity-scales.json`, `docs/severity-schema.md`, and the "rules that are not negotiable" section of `HANDOFF.md`.

## The problem

`severity` is a flat string on Microsoft's scale, and `resolve_severity()` coerces every other vendor onto it. The mappings and rules to fix this are already written in `data/severity-scales.json`, which **nothing currently reads**. The source facts are already captured in each record's `cve_program.vendor_severity`, which **nothing currently reads either**. Your job is to make the code consume both.

Concretely, today: nine Chromium records carry Google's own rating of High or Critical in the dataset while the engine still calls them `Unknown` and schedules them normally. CVE-2026-84353 is a Google **Critical** use-after-free showing as `Normal scheduled`.

## Already decided, do not relitigate

- **Normalise, never leave a foreign scale untranslated.** An earlier draft argued for `Unknown`; that was rejected because a severity filter that hides every non-Microsoft record is broken.
- **Target vocabulary is `critical`, `high`, `medium`, `low`.** Microsoft's Important and Moderate, and Adobe's Important, are the outliers and get mapped.
- **A vendor's published band always beats a CVSS score.** Never derive a band from a score when any party published one. Measured: MSRC bands and Microsoft's own CVSS bands agree on only 67% of September, and a Microsoft Critical is more often CVSS High than CVSS Critical. Deriving would demote 84 Criticals and 234 Importants against the vendor's own judgement.
- **Where two parties published a band, the highest wins**, compared after normalisation. `primary` still names whoever publishes the fix and does not change.

## The record shape

`severity` becomes an object. The full specification with worked examples is in `docs/severity-schema.md`; the short form is:

```json
"severity": {
  "assessments": [
    { "source": "microsoft", "role": "publisher", "scale": "msrc", "value": "Moderate", "basis": "vendor" },
    { "source": "Linux", "role": "assigning-cna", "scale": "cvss-qualitative", "value": "CRITICAL", "basis": "vendor", "base_score": 9.3 }
  ],
  "primary": "microsoft",
  "divergence": { "kind": "assessment", "spread": 4.6 },
  "normalized_band": "critical",
  "normalized_basis": "scale-mapping:cvss-qualitative:1.0"
}
```

## The algorithm

1. Collect assessments. The publisher's band is the existing `severity` string on scale `msrc`. The assigning CNA's band is `cve_program.vendor_severity`, which already carries its own `band` and `scale`.
2. **Exclude the CNA assessment when the assigner is the publisher.** See the traps below; this one is the difference between 5 disagreements and 332.
3. Normalise each band through `data/severity-scales.json`.
4. `normalized_band` is the highest normalised value. Where the candidates disagree, set `divergence.kind` to `assessment` when both were on the same scale and `scale` when they were not, and raise a review flag.
5. Where no party published a band, derive from a CVSS score with `normalized_basis: "cvss-derived"`.
6. Where there is no band and no score, `normalized_band` is `unknown` and the record keeps its review flag.

## Four traps, each of which has already caught someone

**Microsoft is itself a CNA.** 973 of 1,185 September records are assigned by Microsoft, so their CVE Program `baseSeverity` is Microsoft's own CVSS band rather than a second party's opinion. Comparing it against the MSRC band reports 332 phantom disagreements instead of the real 5.

**`assignerShortName` is lowercase `"microsoft"`.** An exact-case comparison against `"Microsoft"` silently matches nothing and lets all 973 through. Compare case-insensitively.

**Do not delete the `unknown` path even though nothing reaches it.** After this migration, zero September records are `unknown`, because Google's tier now covers all 23 that used to be. The `unknown-severity` baseline model in `risk-model.js` and the `missing-vendor-severity` review reason must both stay: they are the fail-loud guard for a month where a vendor publishes nothing or the enrichment fetch fails, and a future reader will otherwise remove them as dead code. Add a test that drives both, using a synthetic record with no band and no score.

**The enrichment must not reach the risk path except through this migration.** `scripts/apply_cve_enrichment.py` has a `RESERVED` guard asserting it never writes a risk-path field. That guard stays. SSVC in particular remains evidence and review flags only, and `tests/ssvc.test.mjs` asserts the deterministic floor is unmoved by it. Do not weaken that test.

## Expected outcome, which is the acceptance test

Measured against `data/2026-Sep.jsonl` as committed:

| band | before | after |
|---|---|---|
| Critical / critical | 138 | 140 |
| Important / high | 903 | 915 |
| Moderate / medium | 103 | 107 |
| Low / low | 18 | 23 |
| Unknown / unknown | 23 | 0 |

**Exactly 28 records change band**: the 23 Chromium records that gain Google's tier, and the 5 Linux records where the upstream CNA rates higher than Microsoft.

**Exactly one record changes action**: CVE-2026-80726, from `Normal scheduled` to `Expedited`, because Linux rates it CRITICAL 9.3 where Microsoft says Moderate. The other four Linux records land on `high`, which does not raise the action floor without elevated exploitation likelihood. CVE-2026-84353 becomes `critical` and its action follows whatever the existing `critical-technical` baseline gives it.

If your numbers differ from these, something is wrong. Report the difference rather than adjusting the expectation.

## Files

- `data/severity-scales.json` — read it, do not edit it.
- `scripts/enrich_cvrf.py` — `resolve_severity()` splits: parsing what a vendor said stays deterministic, choosing the primary becomes policy, normalising across scales is new.
- `risk-model.js` — `selectBaselineModel` branches on `record.severity === "Critical"` and `"Important"` and `"Unknown"`. These become the normalised vocabulary. This is executable policy, so keep the change mechanical and do not alter any threshold or action while renaming.
- `engine.js` — `reviewStatus` and `baselineProfile` read the flat string.
- `app.js` — the severity filter's labels are user-visible and change from Critical/Important/Moderate/Low to Critical/High/Medium/Low.
- `scripts/merge_inference.py` — `severity_order` for the publication sort, and `validate_framework_assessment`.
- Tests asserting on severity strings: `tests/september_record.test.mjs`, `tests/third-party-cna.test.mjs`, `tests/test_enrich_cvrf.py`, `tests/test_merge_inference.py`, `scripts/scorer_self_test.py`.
- A migration script for the published month, modelled on `scripts/refresh_product_tags.py`, which is the existing pattern for a deterministic rating-neutral rewrite. This one is not rating-neutral, so it must print what moved rather than assert nothing did.

Bump `schema_version`. Do **not** fold the `month` to `cycle` rename into this change; that is TODO item 4 and its premise is still being re-decided.

## Gates, each needing a fixture it rejects

1. A vendor band beats a CVSS score. Fixture: MSRC Critical with a Microsoft CVSS of 4.4, which is a real September record. Must produce `critical`. Rejecting fixture: one producing `medium` from the score.
2. A Chromium Medium produces `medium` with `normalized_basis: "scale-mapping:chromium:1.0"`. Rejecting fixture: one claiming `vendor-scale`, which would assert the vendor said "medium" when it said "Medium" on its own scale.
3. The publisher-as-own-CNA exclusion. Fixture: the full September dataset must yield 5 disagreements, not 332. Rejecting fixture: the same computation without the exclusion.
4. An empty assessment list yields `unknown` and a review flag. Rejecting fixture: one that yields a band.
5. A third-party enrichment role never sets `primary` and never reaches `normalized_band`. Rejecting fixture: a CISA-ADP CVSS presented as a vendor rating.
6. Every band in `data/severity-scales.json` maps into the target vocabulary, and each scale's band set matches what that vendor publishes. Adobe has no Low, so an Adobe Low is a parse error rather than a mapping.

Mutation-test each gate: break the code deliberately, confirm the test goes red, restore. A gate that has only ever passed is not evidence. This has bitten this project three times, most recently when a property test over all 1,185 records passed against three separate mutations that wired SSVC directly into the risk path.

## Verify

```
npm test
npm run build
for f in scripts/*_self_test.py tests/*.py; do python3 "$f"; done   # skip scorer_self_test.py, it needs a live model
```

Then open the built site and confirm the severity filter offers the new vocabulary, that the nine Chromium High and Critical records appear under those filters, and that CVE-2026-84353 no longer reads as unrated.

## Out of scope

Do not implement the two-axis output, the cadence change, the `sug/v2.0` endpoint, or any vendor ingestion. Do not re-run inference. Do not touch `data/2026-Sep.jsonl` other than through the migration script.
