# Vendor advisory source research — Chrome, Firefox, Adobe Acrobat

Researched 2026-09-10 by three independent agents, each fetching sources live.
Companion to `REMEDIATION_PLAN.md` Phase 2. Items the researchers could not verify
are flagged inline and collected at the end of the plan.

## The convergent finding

All three vendors resolve to the same primary source: the **CVE Program `cvelistV5`
corpus**, filtered by CNA. None of the three publishes CSAF. None publishes a usable
RSS feed except Chrome (Blogger GData). OSV.dev covers none of them.

Two of the three (**Google, Mozilla**) publish **no CVSS at all** — every CVSS vector
shown for a Chrome or Firefox CVE originates from the **CISA-ADP (Vulnrichment)**
container and is machine-derived from description text. NVD does not independently
enrich Chrome CVEs. Label this in the UI.

Ingestion spine:

```
git clone --depth 1 https://github.com/CVEProject/cvelistV5
# filter cveMetadata.assignerShortName in {Chrome, mozilla, adobe}
# CVSS + CWE + SSVC exploitation from containers.adp[shortName == "CISA-ADP"]
# incrementals via cves/deltaLog.json (hourly)
```

`containers.adp[].metrics[].other[type == "ssvc"].content.options[].Exploitation`
∈ `none | poc | active` is a **structured** exploited-in-the-wild signal, better
than parsing vendor prose. Verified working on Mozilla and Adobe CVEs.

---

## Chrome / Chromium

**CNA:** `Chrome`. **Vendor CVSS:** none.

**Severity is extractable from structured JSON** — Google appends it to the CNA
description:

```
(Chromium security severity: Critical|High|Medium|Low)
```

Google's own definitions (`chromium.googlesource.com/chromium/src/+/main/docs/security/severity-guidelines.md`):

- **Critical** — read/write arbitrary resources on the underlying platform with the
  user's full privileges, i.e. **full sandbox escape**.
- **High** — execute code in the context of, or impersonate, other origins; read
  cross-origin data. RCE *inside* the sandbox, UXSS.
- **Medium** — read/modify limited information, or harmful only when chained.
- **Low** — would normally be higher but has extreme mitigating factors.

The `S:C` vs `S:U` CVSS scope bit tracks the sandbox-escape distinction well.

**Fixed version:** `cna.affected[0].versions[0].lessThan`, single string.

**Optional enrichment — Chrome Releases feed** (bounty, reporter, per-platform builds,
Google's own "exploit exists in the wild" sentence):

```
https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?alt=json&max-results=500
```

`?alt=json` bypasses a 302 to the deprecated FeedBurner mirror. `max-results` caps
at 500; supports `published-min`/`published-max`. Post body line format:

```
[$2,500][544163112] Critical CVE-2026-87464: Use after free in WebGL.
  Reported by Lexi Groves (49016) on 2026-08-08
```

Post slugs are non-deterministic — always take `rel="alternate"` from the feed.
Not every Stable post contains security fixes. Bounties appear as `TBD` and are
revised later. **Make this enrichment non-blocking.**

**Current-version reference:** `https://versionhistory.googleapis.com/v1/chrome/platforms/{win64,mac,linux}/channels/{stable,extended}/versions/all/releases`
— no auth. Query `extended` separately or Extended Stable fleets read as universally
vulnerable.

**Edge:** MSRC republishes each Chromium CVE. Only authoritative mapping:

```
https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=cveNumber eq 'CVE-2026-85046'
→ {"product":"Microsoft Edge (Chromium-based)","fixedBuildNumber":"152.0.4191.62"}
```

Edge build numbers diverge from Chrome's — major matches, build does not.

**Negative results (verified):** `google.com/.well-known/csaf/provider-metadata.json`
→ 404. `api.osv.dev/v1/vulns/CVE-2026-85046` → 404; OSV has no browser ecosystem.
`issues.chromium.org` has no public API and details are restricted during exactly the
window the tool is most useful.

**Licensing:** redistribute facts, not Google prose. Source display text from the CVE
record. `robots.txt` allows `/feeds/`, disallows `/search/`.

---

## Firefox / Firefox ESR / Thunderbird

**CNA:** `mozilla`. **Vendor CVSS:** none (`cna.metrics: null` verified across
2024–2026 records).

**Two required sources.** The CVE record carries structured ESR version ranges; the
MFSA repo carries Mozilla's own impact rating and the MFSA↔CVE↔release join. Neither
alone is sufficient.

```
git clone --depth 1 https://github.com/mozilla/foundation-security-advisories
# announce/<YYYY>/mfsa<YYYY>-<NN>.yml   (2017+)
# announce/<YYYY>/mfsa<YYYY>-<NN>.md    (2016 and earlier: frontmatter + HTML)
```

Repo is **MPL-2.0** — redistributable. mozilla.org page prose is **CC BY-SA**
(viral); avoid it. Do not ship Mozilla trademarks or the Firefox logo.

Mozilla's advisory Impact key (verbatim from the advisories index):

- **Critical** — run attacker code and install software, no user interaction beyond
  normal browsing.
- **High** — gather sensitive data from other windows, or inject data/code into those
  sites, requiring no more than normal browsing.
- **Moderate** — would be High/Critical except they work only in uncommon non-default
  configurations or need complicated/unlikely user steps.
- **Low** — minor DoS, minor data leaks, spoofs.

### Parser hazards (each observed in real data)

1. **Two incompatible `affected` shapes.** 2026 uses branch-anchored `unaffected`
   thresholds with ESR folded into `product: "Firefox"`:
   `{"status":"unaffected","version":"140.15","lessThanOrEqual":"140.*","versionType":"rpm"}`.
   2024 uses separate `"Firefox ESR"` products with `affected` + `lessThan`.
2. **Duplicate product keys.** In the 2024 shape `"Firefox ESR"` appears twice (one
   entry per ESR line). Dict-keying by product name silently drops a line. Collect
   into a list.
3. **No `defaultStatus`** on modern records — per spec that means `unknown`, not
   `affected`. "Below the branch threshold is affected" is *your inference*; label it.
4. **`versionType: "rpm"`** is not semver. `140.15` has two components, `115.40.0`
   has three.
5. **`bugs[].url` has three shapes** — bare numeric ID, comma-separated IDs, or a
   full external URL.
6. **Files are mutable after publication** (`[Update March 4, 2025]` blocks).
   Re-ingest; do not append-only.
7. **Since ~2026 per-CVE prose descriptions were dropped.** Component now lives in
   the title: `"Use-after-free in the DOM: Core & HTML component"`.
8. **One CVE now spans up to 7 sibling MFSAs** (Firefox, 3 ESR lines, 3 Thunderbird).
   MFSA→CVE and CVE→MFSA are both one-to-many. Model as a join.
9. Firefox for Android and iOS are in the same stream — filter, or desktop admins
   see mobile CVEs.

**Cross-check:** the CNA description ends with a machine-friendly sentence listing
every fixed version. Regex it and assert agreement with the `affected` parse in CI —
that catches Mozilla changing the schema a third time.

**Current lines** (`https://product-details.mozilla.org/1.0/firefox_versions.json`,
2026-09-10): release `155.0.1`, `FIREFOX_ESR` `140.15.0esr`, `FIREFOX_ESR_NEXT`
`153.2.0esr`, `FIREFOX_ESR115` `115.40.0esr`. ESR 140 and ESR 153 both shipped
advisories on 2026-09-01 with **non-identical CVE sets**. ESR 140 EOL reported as
2026-09-29 — *medium confidence, third-party source, verify.*

**Negative results (verified):** no CSAF (404, and absent from the BSI aggregator);
no RSS (404); OSV returns ecosystem-less conversion records or 404s outright.

---

## Adobe Acrobat / Acrobat Reader

**CNA:** `adobe`. **Vendor CVSS: yes** — Adobe publishes its own base score and
vector, unlike Google and Mozilla.

**Adobe publishes no CSAF.** Checked four ways: `adobe.com/.well-known/csaf/...` →
404; `psirt.adobe.com` does not resolve; absent from the CERT-Bund CSAF aggregator;
absent from the OpenSSF State of VEX survey. Do not architect around it.

**HTML scraping is unavoidable** — Priority, Adobe Severity and platform exist
nowhere but the bulletin HTML.

```
index:    https://helpx.adobe.com/security/products/acrobat.html
bulletin: https://helpx.adobe.com/security/products/acrobat/apsb26-141.html
```

(The `adobe.com/trust/security/...` mirror lags — APSB26-141 404s there. Use helpx.)

### Adobe Priority — the highest-signal field for patch triage

Verbatim from `https://helpx.adobe.com/security/severity-ratings.html`:

| Priority | Definition | Recommended action |
|---|---|---|
| **1** | Resolves vulnerabilities being targeted, or at higher risk of being targeted, by exploits in the wild | **Within 72 hours** |
| **2** | Resolves vulnerabilities in a product historically at elevated risk. No known exploits | **Within 30 days** |
| **3** | Product historically not a target | Administrator discretion |

Priority is **bulletin-level**, not per-CVE — every CVE in a bulletin inherits it.
Acrobat sits at P2 by default and escalates to P1 out-of-band. It is not derivable
from CVSS and has no analogue in the other vendors' data. Give it its own field.

**Severity is independent of CVSS.** APSB26-141 lists CVEs as `Critical` with a CVSS
base of 7.8 (CVSS "High"). Do not derive one from the other.

**Table parsing:** columns are `Vulnerability Category | Vulnerability Impact |
Severity | CVSS base score | CVSS vector | CVE Number`. CWE is **not** its own
column — it is embedded in the category cell as `Out-of-bounds Write (CWE-787)`.

**Tracks (2026-09-10):** Continuous `26.002.21901`; Classic 2024 `24.001.30429`;
Classic 2020 **EOL 2025-11-30**, no longer in bulletins — a `20.005.x` install is
permanently unpatched, render as "unsupported track". Track must be inferred from
the version string; neither the CVE JSON nor NVD carries a track label. That
inference is undocumented — flag it in code.

**Versioning:** `YY.00X.NNNNN`. CVE records declare `versionType: "semver"` but
`26.002.21900` is **not** semver. Compare as integer 3-tuples.

### Cadence change — affects the whole product

**Effective 2026-07-14 Adobe moved from monthly to twice-monthly bulletins**, on the
2nd and 4th Tuesday (announced by Aanchal Gupta, 2026-06-25, citing AI-accelerated
vulnerability discovery). Bulletin format is unchanged, so parsers are unaffected —
only scheduling. The 2nd Tuesday still aligns with Microsoft Patch Tuesday; **the
4th Tuesday has no Microsoft counterpart**, so a Patch-Tuesday-shaped build misses
roughly half of Adobe's bulletins. Out-of-band P1 releases continue.

**NVD lag is disqualifying for freshness:** CVE-2026-81983, published 2026-09-08,
was still `Undergoing Analysis` on 2026-09-10 with no CVSS and no CPE.

**Licensing:** no explicit reuse grant in Adobe's terms. Redistribute structured
facts; link to the APSB rather than copying prose. `robots.txt` permits `/security/`
with no crawl-delay.

**CI assertion:** each parsed bulletin must yield ≥1 CVE, a priority in {1,2,3} and
≥1 affected-version row. Fail the build loudly rather than shipping empty JSONL.
