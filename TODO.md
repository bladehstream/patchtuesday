# TODO

Four items carried over from the third-party-CNA work of 12 Sep 2026. Each has a prerequisite, an acceptance test, and a note on what is already verified. Essential Eight timeframes are deliberately out of scope here.

---

## 1. Ingest the assigning CNA's own rating from cvelistV5

**Status:** investigated 12 Sep 2026. The SSVC half is **done and shipped**; the severity half is still blocked on Phase 1.1.

Microsoft declines to rate a CVE it did not assign. September has 212 such records from 15 CNAs, and 23 of them — every Chrome-assigned CVE — arrive with no severity, no CVSS and no Exploitability Index. The review flag now names the assigner and links its CVE Program record, but nothing fetches it.

**Measured, by fetching all 212 records from `raw.githubusercontent.com/CVEProject/cvelistV5`:**

| what the assigning CNA publishes | records | CNAs |
|---|---|---|
| CVSS with `baseSeverity` in `cna.metrics` | 86 | mitre, EEF, GitHub_M, redhat, Tcpdump, VulnCheck, f5, elastic, openjs, libreswan, and 7 of 98 Linux |
| a `(Chromium security severity: X)` parenthetical and never CVSS | 23 | Chrome |
| nothing at all | 103 | Linux 91, curl 8, Go 2, openssl 1, VulnCheck 1 |

All 212 fetched in 7 seconds with no key and no rate limit. Our CVRF Type 8 note title matched `assignerShortName` on 212 of 212, so the detector is sound.

**What the enrichment is actually worth:**

- **23 Chrome records gain their only rating.** Today they sit permanently at `Normal scheduled` with a review flag and no path to resolution.
- **5 records surface a disagreement, and all five run the same direction.** Microsoft rates every one of them lower than the assigning CNA, all Linux: CVE-2026-80726 is Microsoft **Moderate** against Linux **CRITICAL 9.3**, and CVE-2026-80731, -80738, -80747 and -80752 are Microsoft Moderate against Linux HIGH. Overall agreement is 81 of 86, so 6% disagreement — but a one-directional 6% is a finding, not noise.
- **81 records confirm agreement**, which is cheap assurance rather than new information.
- **103 records gain nothing.** 91 of those are Linux, where the upstream CNA publishes no severity and Microsoft's Moderate is the only rating that exists.

**Prerequisite: the vendor-plural severity schema, REMEDIATION_PLAN.md Phase 1.1.** Google's Critical and Microsoft's Critical are not the same claim, and there is no honest scalar that merges them. Writing either into the current flat `severity` field is exactly the coercion the Phase 0 work removed. This item cannot start before 1.1 lands.

**Done 12 Sep 2026 — the SSVC half shipped independently.** It does not touch severity, so it was not blocked by Phase 1.1. `scripts/fetch_cve_enrichment.py` and `scripts/apply_cve_enrichment.py` add a `cve_program` block carrying the assigner and the CISA-ADP SSVC decision points. Coverage is 1081 of 1185 records, 91.2%. What it actually found: 24 records carry a public proof of concept while KEV, the vendor assessment and EPSS all read as nothing known, and 15 of those had no review flag at all before. Review holds went from 100 to 115.

Do **not** use the ADP CVSS for Chromium — three tiers share one identical 9.6 vector, and a Chromium High scores ADP 3.1. That evidence is in `docs/vendor-ingestion-design.md`.

**Still to do here:** fetch the assigning CNA's own severity, which needs Phase 1.1 first. The raw records are already cached under `raw/cvelist/`, so that step is parsing rather than fetching.

**Acceptance:** a Chrome-assigned record carries the assigning CNA's rating on its own labelled scale, alongside Microsoft's absence, with neither mapped onto the other; a fixture asserts that no CNA rating is ever written into the Microsoft-scale field; and CVE-2026-80726 displays both Moderate and CRITICAL 9.3 with the disagreement visible.

---

## 2. Switch Edge and Chromium ingestion to the `sug/v2.0` OData endpoint

**Status:** not started. Endpoint verified by the handover, not yet by us.

The monthly CVRF carries Edge in the ProductTree but only a subset of Chromium CVEs as vulnerability entries — we see 23, and a live query of `api.msrc.microsoft.com/sug/v2.0` returned 51 since 1 Sep 2026. So more than half are missing. The CVRF's "we are republishing N non-Microsoft CVEs" note is unreliable: populated Sep 2025, empty Sep 2026, and in Aug 2026 it read "2 listed and 350 Chrome CVEs" while itemising only the two. Do not build on that note.

Poll shape: `/sug/v2.0/en-US/vulnerability?$filter=releaseDate ge {checkpoint}&$orderby=releaseDate asc&$top=100`, paging via `@odata.nextLink`. All Chromium records come back `severityId: 0`.

**Verify before building:** that the 51 figure reproduces, what the overlap with the 23 CVRF records is, and whether Microsoft's API terms permit storing and redistributing the results — that last one needs an answer in writing before a bundled snapshot ships.

**Acceptance:** the Chromium record count for a given month matches the OData query rather than the CVRF subset, and a fixture fails if the two silently diverge.

---

## 3. Two-axis output: impact separately from exploitation

**Status:** not started. Architectural, needs a decision before code.

The model currently emits one blended action. CVSS Base is not an exploitability measure — it mixes AV/AC/PR/UI with C/I/A and carries no signal about actual exploitation, which is why CVSS 4.0 split Threat and Exploit Maturity into their own group. Pairing a CVSS base score with the Chromium tier measures impact twice and exploitability never.

- **Impact axis:** the assigning CNA's own tier, or SSVC Technical Impact. Measured 12 Sep: Technical Impact tracks severity closely on rated records — Critical is 4% `partial`, Moderate 89% — so it restates rather than adds, except on the 23 records with no vendor severity, where it is the only impact signal there is.
- **Exploitation axis:** CISA KEV first, then the vendor's own in-the-wild wording, then SSVC Exploitation, then EPSS — and EPSS sorts within a tier, it never sets one.
- **SSVC Automatable is the genuinely independent signal** and is now ingested: 21% of network-vector CVEs are `yes` against 0% of the 530 local, adjacent and physical ones, so it is not a restatement of attack vector. It carries mass-exploitation potential, which nothing else in the dataset does.

SSVC is ingested as evidence and as review flags only. It is CISA's judgement rather than the vendor's, so it deliberately does not move a rating: KEV does that because a KEV listing is a fact, while SSVC is an assessment. If item 3 changes that, it is a decision to take explicitly.

Emit two fields, never one number: a **compliance window** that is fixed by policy and therefore auditable, and an **operational priority** of impact against exploitation, which is where the analyst value sits.

Calibration note worth carrying into the design: the Chromium tier is an impact scale that mentions CVSS zero times, and Google's own service levels are 30 days to all users for Critical and 60 for High. A Chromium Critical must not drive an emergency action on its own.

**Acceptance:** the two fields are separately rendered and separately explainable, and no code path multiplies or averages them into a single score.

---

## 4. Cadence: separate ingestion from publication

**Status:** decided once on a premise that turned out to be half wrong, needs re-deciding.

Twice-monthly publication was adopted because Adobe moved to twice-monthly on 14 Jul 2026. That move is real, but **Acrobat is not on it** — its 2026 bulletins were 03-10, 04-11 (a Saturday, out of band), 04-14, 06-09 and 09-08, which is quarterly. Meanwhile four vendors now ship faster than the cycle: Chrome moved to two-week milestones with weekly stable refreshes, Firefox to two weeks, and Edge to roughly two weeks at v152 plus out-of-band refreshes. A monthly or twice-monthly ingest shows Edge late or misses it entirely.

**Recommendation:** poll daily into a staging dataset, publish on whatever cycle suits, and keep an out-of-band publish path for anything that trips a KEV listing, SSVC `Exploitation: active`, a vendor Priority 1, or an out-of-band advisory. Cycle length then stops being load-bearing.

**Consequence if adopted:** the record field `month` stops being the unit and becomes `cycle` plus `published_at`, which is a schema change and should ride with the Phase 1.1 bump rather than happening separately.

**Acceptance:** a vendor advisory published on a Saturday reaches the site without waiting for a cycle boundary, and the site states when each vendor's data was last refreshed rather than inheriting the cycle label.
