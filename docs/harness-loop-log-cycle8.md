## Cycle 8 — 2026-09-11, update availability as data, not prose

A user picked two records at random and both carried misleading review notes.

### What was wrong

CVE-2026-69632 said *"Release-note remediation references are supplied, while the affected Mac LTSC 2021 and 2024 updates are explicitly unavailable for now."* CVE-2026-78439 mentioned Android and Google Play.

Both statements were **factually accurate and operationally useless**:

- CVE-2026-78439 genuinely affects Microsoft Office for Android, so Google Play genuinely is where that fix lives. It is noise only because the reader does not run it — and the note appeared regardless of product selection.
- "Remediation" in CVRF means *the patch*. A security reader hears *workaround*. Saying "release-note remediation references are supplied" reads as "there is something to do besides patching". There is not.
- The `update-availability` review reason came from a **regex over the model's prose**, so any narrative mentioning a late build flagged the whole record for every reader. One late Mac LTSC build flagged every Office CVE, while 8 of that record's 11 products already had updates.

### Fix

`updateStatus()` reads the vendor's structured remediation list directly: type 2 is the fix, type 3 carries the KB in `subtype`, type 6 the KB link. It returns one row per affected product — product, update available, reference.

`updateSummary()` scopes the flag: with products selected, only an unfixed product *in the selection* matters; with nothing selected, only a record with no fix anywhere flags at all. A Windows-only estate is no longer warned about Mac builds.

The prose regex is deleted. The prompt now forbids narrating update availability at all, and caps every factor at one or two plain sentences.

### Detail pane restructured to three questions

1. **What is affected** — a table of product / update available / KB, pending rows sorted to the top and highlighted.
2. **Mitigations** — a table of control / credit / basis, or plainly "None. Patching is the only remediation the vendor documents."
3. **Priority** — baseline, with-controls, exploit path, evidence. The model's prose is collapsed behind a disclosure: it is context, not the answer.

### A bug the test found

`normalizeRecord()` did not preserve `vendor_guidance`, so `parseJsonl` stripped it. Every record looked as though no fix existed. The affected-products table would have shipped empty for all 1,185 records had the regression test not asserted a specific count on a real CVE rather than merely that the code ran.

### Result

CVE-2026-69632: 8 of 11 products have an update, pending builds named, **no review flag**. CVE-2026-78439: same, no flag. Review is now raised only where the vendor lists no fix for a product the reader actually runs.
