# Independent random spot check: 20 CVEs

Reviewed on 10 September 2026 by Codex, the main assistant, independently of the Luna inference run. The live site and its ratings were not modified.

## Method

One random draw without replacement from the 1,185 CVEs published in the repository at commit 45eec84. Seed: **3606323612**. Selection: Python random.Random(seed).sample(sorted(CVE identifiers), 20). No substitutions or cherry-picking.

I recorded my judgments from source-only packets before inspecting the current Luna assessment for each sampled record. Previous conversation context remained available. I then compared the priorities, likelihood bands, exploit-path reasoning, each proposed mitigation, predicted profiles and review markers. This was my substantive review, not delegated model generation or only a test run.

The population SHA-256 was f1aff05543a699f2dd0e9fa3be4281382efac0e818a7456c7cd6fc5d3f2ff452. The frozen sample and source packets are retained under work/independent-20-review; a machine-readable comparison accompanies this report.

Fresh public feeds were retrieved programmatically at 2026-09-10T04:18:17Z from the [Microsoft CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep), [CISA KEV](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json) and [FIRST EPSS](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz). I also inspected the raw CVRF score and threat fields directly to avoid merely confirming the same parser twice.

## Results by dimension

| Check | Result |
|---|---|
| Raw CVSS representation | 20/20 correct, including two correctly missing CVSS vectors |
| Raw Microsoft severity provenance | 18 supported; two unsupported Low defaults |
| Microsoft exploitation status, KEV membership and EPSS value | 20/20 match freshly fetched data |
| Threat-likelihood band | 20/20 agree with the stated framework |
| Baseline patch priority | 17/20 exact agreement; three independent preferences for Expedited |
| Material mitigation-mapping error | One CVE: Undici CVE-2026-18149 |
| Missing review flags | Four CVEs: three SharePoint scope ambiguities and Undici |
| Conservative control-consistency note | CVE-2026-80843 PAM rationale |
| Software scenario replay | 88 candidate-control subsets and 340 individual catalogue selections checked |

These dimensions overlap; they must not be added into an overall pass/fail score. The three priority differences are contextual judgments, not three proven factual errors. The random sample contained no KEVs/Emergency cases, so it does not add independent evidence about that branch.

## Confirmed problems and recommended corrections

### 1. Missing severity is incorrectly displayed as Low

CVE-2026-84335 and CVE-2026-84358 contain empty severity descriptions and no CVSS score in both the stored and freshly fetched MSRC records. The parser supplies a score default of zero and normalizes the result to Low. That is unsupported source attribution.

Show severity as Unknown/Not supplied when neither source severity nor a valid score exists. Preserve the existing Review required marker. Normal browser updating is still reasonable, but the explanation must not cite a Microsoft Low rating that the feed did not supply.

The relevant implementation is scripts/enrich_cvrf.py: the missing-score default in main and the final Low return in normalize_severity. No parser changes were made during this review.

### 2. Undici has the wrong network-direction assumption

For [CVE-2026-18149](https://github.com/nodejs/undici/security/advisories/GHSA-pmjh-fq2x-6v4x), upstream describes a malicious server causing the HTTP client's retried response body to remain unresolved. Closing inbound access to a consuming Node.js application does not establish protection against that path.

The site currently gives public-ingress removal and generic client-to-service ACLs one likelihood band, changing Plausible to Low evidence while retaining Normal scheduled. I would remove those discounts until the actual outbound/server-response path is identified and constrained, and mark the item for review.

Upstream lists fixes in Undici 7.29.1 and 8.10.2, and an independent request-deadline/body-destruction workaround. Its applicability to the packaged Node.js deployment needs verification before any workaround credit.

### 3. Review flags miss SharePoint version-scope ambiguity

The raw products list names Subscription Edition, while the FAQ discusses Server 2016, for CVE-2026-69282, CVE-2026-69615 and CVE-2026-69402. This may be generic FAQ text, but it must not silently determine product applicability.

None currently has a review flag. Add explicit product-scope review reasons. In CVE-2026-69282 the model itself says the scope should be verified, but the keyword-based review detector misses that wording. Product references and structured review reasons would be more reliable than uncertainty keywords alone.

### 4. Three priority recommendations

| CVE | Site | My preferred baseline | Basis |
|---|---|---|---|
| CVE-2026-69282 | Normal scheduled | Expedited | Low-level list permissions can lead to server loading attacker-controlled code before authorization checks; shared-server impact warrants acceleration. |
| CVE-2026-69380 | Normal scheduled | Expedited | An ordinary mailbox account can impersonate users and access all mailboxes, creating concentrated confidentiality and integrity impact. |
| CVE-2026-69510 | Normal scheduled | Expedited for an enabled shared DHCP role | No authentication or victim interaction is required for RCE; high complexity tempers urgency but does not establish that required conditions are absent. Normal scheduling remains defensible with verified restrictive context. |

These are qualitative workload judgments. I would not mark exploitation Elevated merely to support the higher patch priority; each remains Plausible on the available threat evidence.

### 5. Conservative PAM inconsistency

CVE-2026-80843 rejects PAM as not relevant with high confidence because high privileges are already required. Other sampled PR:H records allow conditional credit when those privileges are removed or access is restricted. The zero-credit outcome is conservative, but the explanation overstates certainty. Use a qualified unknown/no-credit judgment unless the specific privileged entry path is established.

## CVE-by-CVE comparison

| CVE | Site priority | Independent priority | Review finding |
|---|---|---|---|
| [CVE-2026-73029](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-73029) | Normal scheduled | Normal scheduled | Agree. Authentication/ACL credit is conditional on restricting the actual SQL access path; authorized callers remain exposed. |
| [CVE-2026-69757](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69757) | Expedited | Expedited | Agree. More Likely drives Expedited despite high complexity and user interaction. Verify the exact TCP/IP route before accepting mitigation credit. |
| [CVE-2026-69282](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69282) | Normal scheduled | Expedited | Prefer Expedited for low-permission server code loading. Add a review flag for Subscription Edition versus the Server 2016 FAQ. |
| [CVE-2026-69510](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69510) | Normal scheduled | Expedited | Prefer Expedited for an enabled shared DHCP service. Normal scheduled is a defensible alternative after verifying the unusual exploit conditions are absent or exposure is tightly controlled. |
| [CVE-2026-81948](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81948) | Expedited | Expedited | Agree. Malicious-file opening is required, Preview Pane is excluded, and the Mac-update review flag is correctly present. |
| [CVE-2026-80806](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-80806) | Normal scheduled | Normal scheduled | Agree. Local high privileges and high complexity support routine patching; privileged-access credit is conditional. |
| [CVE-2026-84335](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-84335) | Normal scheduled | Normal scheduled | Normal scheduled remains provisional, but the displayed Low severity is unsupported by raw MSRC. Missing-prerequisite review is correctly flagged. |
| [CVE-2026-69469](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69469) | Normal scheduled | Normal scheduled | Agree. Physical access and user interaction matter; the site correctly offers no network-airgap or generic endpoint discount. |
| [CVE-2026-62744](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62744) | Normal scheduled | Normal scheduled | Agree. Correctly recognizes user-opened content and gives no public-ingress credit merely because AV:N is recorded. |
| [CVE-2026-72981](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72981) | Expedited | Expedited | Agree. Critical packet-triggered RCE warrants Expedited, with the race prerequisite keeping it below an automatic Emergency decision. |
| [CVE-2026-80080](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-80080) | Normal scheduled | Normal scheduled | Agree. File opening is required, Preview Pane is excluded, and the Mac-update exception is flagged. |
| [CVE-2026-84358](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-84358) | Normal scheduled | Normal scheduled | Normal scheduled remains provisional, but the displayed Low severity is a parser default. Missing-prerequisite review is correctly flagged. |
| [CVE-2026-18149](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-18149) | Normal scheduled | Normal scheduled | Confirmed mitigation error: the published discounts assume an inbound service path. Upstream describes malicious-server responses attacking the HTTP client. Add a review/correction flag. |
| [CVE-2026-67378](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-67378) | Expedited | Expedited | Agree. Critical authenticated SQL RCE warrants Expedited; reduced permissions help only if they remove the actual query/connect prerequisite. |
| [CVE-2026-69380](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69380) | Normal scheduled | Expedited | Prefer Expedited: a low-privilege mailbox can reach all mailboxes. Restricting unused mailbox assignments does not protect required mailbox users. |
| [CVE-2026-69615](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69615) | Normal scheduled | Normal scheduled | Agree on priority. Administrator privileges and victim interaction constrain XSS, but the Subscription Edition/2016 scope ambiguity needs a review flag. |
| [CVE-2026-80098](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-80098) | No customer action | No customer action | Agree. Microsoft explicitly reports completed hosted mitigation; no customer patch or mitigation discount should be manufactured. |
| [CVE-2026-80843](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-80843) | Normal scheduled | Normal scheduled | Agree on priority. The categorical high-confidence PAM rejection is inconsistent with other PR:H cases; conservative zero credit is safe, but its reasoning should be qualified. |
| [CVE-2026-72980](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72980) | Expedited | Expedited | Agree. Microsoft's Critical security-boundary designation supports Expedited despite low evidence and a high-privilege local prerequisite. |
| [CVE-2026-69402](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69402) | Normal scheduled | Normal scheduled | Agree on priority. A WAF discount requires an actual tested virtual-patch rule. Add a review flag for the structured-product/2016 FAQ ambiguity. |

## Freshness finding outside the sample

The fresh Microsoft feed contains **1,186 records**, including **CVE-2026-85046 — Chromium Type confusion in V8**, which is absent from the site's 1,185-record snapshot. It was not substituted into the random sample. It needs ingestion and inference before the next complete publication.

None of the sampled titles, product sets, CVSS/attack fields, advisory notes, remediation records, customer-action dispositions, Microsoft exploitation ratings, KEV membership or EPSS values changed in the fresh comparison. Matching the fresh normalized feed alone would have missed the severity-default defect, which is why the raw-field check matters.

## Recommended order of follow-up

1. Correct missing-severity handling and the Undici mitigation mapping.
2. Add the four missing review/correction flags.
3. Calibrate the three shared-service priority cases and qualify the PAM explanation.
4. Ingest and infer the newly present Microsoft record.
5. Repeat independent sampling after these changes, including a separate targeted check of rare Emergency/KEV cases.

This review improves confidence in the checked CVSS, threat bands and many exploit-path interpretations, but it found concrete issues to resolve before relying broadly on mitigation-based reductions. It is a limited sample and a qualitative independent comparison, not a population accuracy estimate.
