# Phase 1.1 — vendor-plural severity

Draft of 12 Sep 2026. Per `GOAL.md` this item produces a schema and a worked example and then stops: it changes what the tool asserts to an administrator, so it needs a decision before it is implemented.

## What the flat string gets wrong

`severity` is a single string on a Microsoft scale, and `resolve_severity()` coerces anything else onto it. Three consequences, all measured on 2026-Sep.

**It invents comparability.** Chromium's scale is defined relative to the renderer sandbox — Critical means escape, High means code execution inside it. Microsoft's is not. `resolve_severity("High")` matches `"high" in lowered` and returns `("Important", "vendor")`, so a Chromium High and a Windows Important sort as the same claim in the same column. They are not the same claim.

**It has no way to say two vendors disagree.** 86 of September's records carry a severity from both Microsoft and the assigning CNA. 81 agree. Five do not, and all five run the same direction.

**It fails open on a second axis.** A record with no vendor severity but a third-party CVSS returns `("Important", "cvss")` — a machine-derived score presented as a vendor rating. That is the same family as the six coercions removed in Phase 0; it simply fails open to Important rather than to Low.

## Two kinds of divergence, and they are not the same problem

This is the finding that shapes the schema, and it was not obvious before the data was pulled.

**Scale divergence.** Two vendors rate on scales that do not map to each other. Chromium Critical against Microsoft Critical. There is no honest scalar that merges them, so the tool must not try.

**Assessment divergence.** Two vendors use the *same* scale and reach materially different conclusions. All five September disagreements are this kind, and they are the more serious of the two.

| CVE | Microsoft | assigning CNA | the difference |
|---|---|---|---|
| CVE-2026-80726 | 4.7 `AV:L/AC:H/PR:L/S:U/C:N/I:N/A:H` | 9.3 `AV:L/AC:L/PR:N/S:C/C:H/I:H/A:H` | complexity, privileges, scope and both of C and I |
| CVE-2026-80731 | 5.7 `AV:L/AC:H/PR:H/C:N/I:H/A:H` | 7.8 `AV:L/AC:L/PR:L/C:H/I:H/A:H` | complexity, privileges, confidentiality |
| CVE-2026-80738 | 5.5 `AV:L/AC:L/PR:L/C:N/I:N/A:H` | 7.3 `AV:L/AC:L/PR:L/C:H/I:H/A:L` | confidentiality and integrity |
| CVE-2026-80747 | 5.5 `AV:L/AC:L/PR:L/C:N/I:N/A:H` | 8.0 `AV:L/AC:L/PR:N/C:H/I:L/A:H` | privileges, confidentiality, integrity |
| CVE-2026-80752 | 5.5 `AV:L/AC:L/PR:L/C:N/I:N/A:H` | 8.4 `AV:L/AC:L/PR:N/C:H/I:H/A:H` | privileges, confidentiality, integrity |

Both parties used CVSS 3.1. Microsoft assigns `C:N/I:N` — availability only — on every one, while the upstream Linux CNA assigns `C:H` and mostly `I:H`. Three of the five carry a byte-identical Microsoft vector scoring 5.5, which reads as a template applied to Azure Linux kernel packages rather than a per-CVE assessment.

An administrator patching a kernel needs to see that. Today the record shows Moderate, 4.7, and nothing else.

## The schema

`severity` becomes an object. Every assertion carries the scale it was made on and who made it.

```json
"severity": {
  "assessments": [
    {
      "source": "microsoft",
      "role": "publisher",
      "scale": "msrc",
      "value": "Moderate",
      "cvss": { "version": "3.1", "base_score": 4.7, "vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" },
      "basis": "vendor",
      "retrieved": "2026-09-10T18:00:00Z"
    },
    {
      "source": "Linux",
      "role": "assigning-cna",
      "scale": "cvss",
      "value": "CRITICAL",
      "cvss": { "version": "3.1", "base_score": 9.3, "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
      "basis": "vendor",
      "retrieved": "2026-09-12T22:33:07Z",
      "url": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/80xxx/CVE-2026-80726.json"
    }
  ],
  "primary": "microsoft",
  "divergence": {
    "kind": "assessment",
    "detail": "Both assessments are CVSS 3.1. Microsoft scores confidentiality and integrity as None; the assigning CNA scores both High.",
    "spread": 4.6
  },
  "normalized_band": "high",
  "normalized_basis": "scale-mapping:msrc@1.0"
}
```

Rules the shape enforces:

- **`assessments` is a list and may be empty.** An empty list is the honest representation of a CVE nobody has rated, and it resolves to `normalized_band: "Unknown"` with a review flag. It never resolves to a band.
- **`scale` is mandatory on every entry.** `msrc`, `cvss`, `chromium`, `mozilla`, `adobe`. Two entries may only be compared when their `scale` matches.
- **`role` distinguishes who is speaking.** `publisher` is the vendor shipping the fix, `assigning-cna` is whoever assigned the CVE, `enrichment` is a third party such as CISA. Only `publisher` and `assigning-cna` may set `primary`.
- **`divergence.kind` is `scale` or `assessment` or absent.** `scale` means the two cannot be compared and both are shown. `assessment` means they can be and they disagree, which is a review flag.
- **`normalized_band` may be `"Unknown"`, and for a cross-scale value it should be.** See decision 1.

## Worked example: the Chromium case

```json
"severity": {
  "assessments": [
    {
      "source": "Chrome",
      "role": "assigning-cna",
      "scale": "chromium",
      "value": "Medium",
      "cvss": null,
      "basis": "vendor",
      "scale_definition": "https://chromium.googlesource.com/chromium/src/+/main/docs/security/severity-guidelines.md",
      "url": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/84xxx/CVE-2026-84323.json"
    }
  ],
  "primary": "Chrome",
  "publisher_declined": {
    "source": "microsoft",
    "reason": "Microsoft does not rate CVEs assigned by another CNA"
  },
  "normalized_band": "medium",
  "normalized_basis": "scale-mapping:chromium@1.0"
}
```

Microsoft declining to rate is recorded as a positive fact rather than as an absence, because it is policy and not a data gap. The Chromium tier is shown on its own scale with a link to what that scale means, and `normalized_band` stays `Unknown` because there is no scale to normalise onto. The record keeps its review flag and the reviewer now has a rating to read.

Note what is deliberately not here: no CVSS, because Google publishes none, and not the CISA-ADP CVSS of 9.6, because three Chromium tiers share that identical vector and a Chromium High scores 3.1. That evidence is in `docs/vendor-ingestion-design.md`.

## Decided 13 Sep 2026

**Normalisation is required, and the target vocabulary is Critical / High / Medium / Low.** `normalized_band` is always populated wherever any vendor published a band. An earlier draft of this document argued for leaving a cross-scale value as `Unknown`; that was wrong. A severity filter that hides every non-Microsoft record is not more honest, it is broken, and after the browser and Acrobat ingestion that is most of the non-Microsoft content rather than 23 records.

The objection that draft was really making was to an *unlabelled* mapping. The mapping now lives in `data/severity-scales.json`, versioned, with each band carrying the vendor's verbatim definition and the reasoning for where it lands, so it is a stated editorial position that can be argued with rather than a hidden coercion. `normalized_basis` names which mapping produced the value.

**Critical / High / Medium / Low rather than Microsoft's vocabulary.** It is what the CVE Program records carry in `baseSeverity` and what every third-party CNA in the dataset emits. Microsoft's Important and Moderate, and Adobe's Important, are the outliers.

**The mapping is definitional band to definitional band, and a CVSS score never overrules a vendor band.** This part was settled by measurement rather than preference. On the 968 Microsoft-assigned 2026-Sep records carrying a Microsoft CVSS score, the MSRC band and the CVSS band of Microsoft's own score agree on only 67%:

| MSRC band | CVSS Critical | High | Medium | Low | n | median | range |
|---|---|---|---|---|---|---|---|
| Critical | 44 | 84 | 3 | 0 | 131 | 8.8 | 4.4-10.0 |
| Important | 0 | 601 | 234 | 2 | 837 | 7.5 | 3.5-8.8 |

A Microsoft Critical is more often CVSS High than CVSS Critical. Microsoft states its ratings are not CVSS-derived and that severity is "distinct from the likelihood of a vulnerability being exploited". Deriving the band from the score would demote 84 Criticals and 234 Importants, silently, against the vendor's own published judgement. Score-derivation is therefore the fallback of last resort only, used where no party published a band, and always recorded as `normalized_basis: "cvss-derived"`.

**`Unknown` still exists and still fails loudly**, but only where nobody has rated the CVE at all - the 91 Linux records where neither party published a band, and Chromium records before the enrichment lands. That is a different state from "rated on a scale we translated", and conflating the two is what the earlier draft got wrong.

**Decided: where two parties published a band, the highest wins.** A lower rating from one party is not evidence against a higher rating from another - the same reasoning as the standing rule that absence of evidence is not evidence of absence. The record is flagged for review and both assessments are shown, so the disagreement is visible rather than resolved silently.

`primary` is unaffected and still names the party whose fix an administrator installs. Only `normalized_band` takes the maximum, which keeps "who publishes the patch" separate from "how bad is it". Comparison happens after normalisation, on the target vocabulary: a raw MSRC "Important" against a raw Chromium "High" is not a defined comparison, but the two `high` values they both map to is.

Measured cost on 2026-Sep, which is smaller than I first said: all five disagreements move from `medium` to `high` or `critical`, but **only one changes its action**. CVE-2026-80726 goes Scheduled to Out-of-cycle, because Linux rates it CRITICAL 9.3 against Microsoft's Moderate. The other four land on `high`, which does not raise the action floor on its own without elevated exploitation likelihood. I had said all five would move off Scheduled; that was wrong, and the distinction matters because the real change to what administrators are told is one record, not five.

## Migration

- `schema_version` bumps. `month` should become `cycle` plus `published_at` in the same bump rather than in a second migration; see TODO item 4.
- Every consumer of `record.severity` as a string changes: `engine.js` `reviewStatus` and `baselineProfile`, `risk-model.js` `selectBaselineModel`, `merge_inference.validate_framework_assessment`, `enrich_cvrf.resolve_severity`, the severity filter in `app.js`, and the tests that assert on severity strings.
- `resolve_severity()` splits: parsing what a vendor said stays deterministic, choosing the primary becomes policy, and normalising across scales stops existing.
- The 1,185 published records can be migrated without re-inference — Microsoft's assessment is already in the data and the CNA's is cached under `raw/cvelist/`.

## Gates this needs, each with a fixture it rejects

1. A record with an empty `assessments` list resolves to `Unknown` and carries a review flag. Rejecting fixture: one that resolves to a band.
2. Two assessments with different `scale` values never produce a `divergence.kind` of `assessment`. Rejecting fixture: a Chromium Medium and a Microsoft Moderate reported as agreeing.
3. An `enrichment` role never sets `primary` and never reaches `normalized_band`. Rejecting fixture: a CISA-ADP CVSS presented as a vendor rating — this is the Phase 0 fail-open in its new shape.
4. CVE-2026-80726 produces `divergence.kind: "assessment"` with a spread of 4.6. Rejecting fixture: the same record reporting no divergence.
5. A Chromium Medium produces `normalized_band: "medium"` with `normalized_basis: "scale-mapping:chromium@1.0"`. Rejecting fixture: one carrying `normalized_basis: "vendor-scale"`, which would claim the vendor said "medium" when it said "Medium" on its own scale.
6. **A vendor band always beats a CVSS score.** Fixture: MSRC Critical with a Microsoft CVSS of 4.4, which is a real 2026-Sep record. It must produce `critical`. Rejecting fixture: one producing `medium` from the score. 84 Criticals and 234 Importants depend on this rule.
7. Every band in `data/severity-scales.json` maps into the target vocabulary, and each scale's band set matches what that vendor actually publishes - Adobe has no Low, so an Adobe Low is a parse error rather than a mapping. Rejecting fixture: a band mapping to a value outside the vocabulary.
