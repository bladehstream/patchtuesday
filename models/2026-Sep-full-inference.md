# September 2026 complete inference run

Completed 2026-09-10. This replaces the historical 25-record pilot.

| Coverage | Result |
|---|---:|
| Source CVEs | 1,185 |
| CVEs with actual Luna inference | 1,185 |
| Missing CVEs | 0 |
| Independently recorded model calls | 81 |
| Source-reviewed QA amendments | 44 |
| CVEs with a conditionally creditable mitigation | 918 |
| CVEs without supported quantified mitigation credit | 267 |

Each model call assessed 15 supplied advisory records, except three final batches of five. All calls used gpt-5.6-luna through the authenticated local CLI. Scripts assembled source facts and provenance; they did not generate the substantive risk explanations. Early classifier-generated attempts were rejected and were not published.

Every accepted output includes a CVSS basis, seven assessment factors, risk communication, curated tags, and a mitigation judgment. Empty or zero-credit mitigation findings still represent completed inference when the evidence does not support a safe discount.

## Verification and corrections

The collector checked exact CVE sets, duplicate/missing records, source-matching CVSS, allowed tags and controls, model-call receipts, input/response hashes, and equality of substantive reasoning with the recorded model response. Explicit source-policy floors and rejected unsupported effects are retained as policy adjustments.

The separately authored corrections in inference/2026-Sep-review-corrections.json record the reason for every QA amendment. They address incorrect EPSS thresholds, unsupported Immediate-archetype claims, misclassified RTF/physical/namespace controls, and double-counted consequence credit. Original model response digests remain in the final JSONL provenance.

Two reviewed consequence-credit claims were retained: scoped credentials in CVE-2026-81381 and CVE-2026-77909 can limit downstream authorized access after disclosure. Neither receives disclosure-prevention credit from that reasoning. A SQL-sysadmin escalation claim in CVE-2026-66820 lost its extra consequence credit because removing starting permissions changes opportunity, not the resulting privileges after successful exploitation.

The model's precautionary Immediate priority for Netlogon CVE-2026-72982 was retained as a workload-impact judgment, with Low evidence likelihood and an explicit qualification that actual domain-controller role and reachability require verification. Its priority is not presented as a mandatory CVSS or exploitation-evidence rule.

## Final baseline actions

| Action | CVEs |
|---|---:|
| Immediate | 5 |
| Out-of-cycle | 209 |
| Scheduled | 962 |
| Defer and review | 9 |

All source CVSS, product lists, Microsoft exploitation status, KEV, EPSS, advisory notes, remediation records and provenance were compared with the previous publication and remained unchanged.

Validation passed for 2,371 combinations of eligible controls and 20,145 individual catalogue selections across the entire release, as well as the JavaScript and Python regression suites. Browser checks confirmed that a previously unreviewed CVE now displays specific Luna reasoning and responds to a relevant mitigation. No browser errors were recorded.

Both publication and the production build now reject incomplete inference. The monthly merge can require exact source-to-overlay equality with --require-complete. Future runs retain raw prompts, model responses, event logs and receipts in the local run directory; these are not served by the public static site. QA corrections are tied to the reviewed source snapshot and must be reconsidered if source facts change.
