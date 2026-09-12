#!/usr/bin/env python3
"""Self-test for review_month.py. Plain python, no test framework.

    python3 scripts/review_month_self_test.py

Every Tier 1 check driven by review_month.py gets a fixture it REJECTS and a
fixture it ACCEPTS, plus the driver's own behaviours: unchecked-is-not-passed,
not-applicable-is-not-passed, the annotation boundary, and the deliberate absence
of any gating flag.

Two rules this file exists to enforce on itself:

  * A gate that has never been seen to fail is not evidence of anything. Each
    check below is shown failing on data built to break it.
  * A mutation that happens to match the original value is a false pass. Every
    negative fixture is diffed against its positive twin with `differs()` before
    the case runs, so a fixture that silently stopped differing is reported as a
    broken fixture rather than passing quietly.

Fixtures are real published records from data/2026-Sep.jsonl, selected by
predicate, so the checks run against advisory prose rather than a shape invented
to satisfy them.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "review_month.py"
PUBLISHED = ROOT / "data" / "2026-Sep.jsonl"
TAXONOMY = ROOT / "data" / "tag-taxonomy.json"

sys.path.insert(0, str(ROOT / "scripts"))
import tag_validators as tv  # noqa: E402

NAMESPACES = tv.load_namespaces(TAXONOMY)
WORKLOAD = NAMESPACES["workload"]
JUDGEMENT = NAMESPACES["workload"] | NAMESPACES["delivery"] | NAMESPACES["impact"]

FAILURES: list[str] = []
GATES = 0


# --------------------------------------------------------------------------
# fixture selection, from real records
# --------------------------------------------------------------------------

def published() -> list[dict]:
    return [json.loads(line) for line in PUBLISHED.read_text(encoding="utf-8").splitlines() if line.strip()]


def copy(record: dict) -> dict:
    return json.loads(json.dumps(record))


def pick(records: list[dict], predicate) -> dict:
    for record in records:
        if predicate(record):
            return copy(record)
    raise SystemExit("No published record matches a fixture predicate; fixtures need rewriting")


def description_text(record: dict) -> str:
    for note in (record.get("vendor_guidance") or {}).get("notes") or []:
        if note.get("title") == "Description":
            return re.sub(r"<[^>]+>", " ", note.get("value") or "")
    return ""


def single_recall_miss(record: dict) -> str | None:
    findings = tv.check_workload_recall(record, {"tags": []})
    return findings[0]["tag"] if len(findings) == 1 else None


def uncorroborated_tag(record: dict, avoid: str) -> str:
    text = tv.source_text(record)
    for tag in sorted(WORKLOAD):
        if tag == avoid:
            continue
        if not any(term in text for term in tv.WORKLOAD_TERMS.get(tag, (tag,))):
            return tag
    raise SystemExit("Every workload term appears in the fixture record; fixtures need rewriting")


def structured(record: dict, pairs: list[tuple[str, str]]) -> dict:
    out = copy(record)
    out["tags"] = [{"tag": tag, "evidence": evidence} for tag, evidence in pairs]
    return out


def bare(record: dict, tags: list[str]) -> dict:
    out = copy(record)
    out["tags"] = list(tags)
    return out


# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------

def note(name: str, ok: bool, detail: str) -> None:
    global GATES
    GATES += 1
    if not ok:
        FAILURES.append(f"{name}: {detail}")


def differs(name: str, negative, positive) -> None:
    """A negative fixture identical to its positive twin is a false pass."""
    note(f"{name} [fixture differs from its positive twin]", negative != positive,
         f"negative and positive fixtures are both {negative!r}")


def run(work: Path, name: str, records: list[dict], extra: tuple[str, ...] = ()) -> tuple[subprocess.CompletedProcess, dict | None, list[dict]]:
    source = work / f"{name}.jsonl"
    source.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8", newline="\n")
    report_path = work / f"{name}-report.json"
    annotated_path = work / f"{name}-annotated.jsonl"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--records", str(source), "--output", str(report_path),
         "--annotate", str(annotated_path), "--taxonomy", str(TAXONOMY), *extra],
        capture_output=True, text=True)
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
    annotated = []
    if annotated_path.exists():
        annotated = [json.loads(line) for line in
                     annotated_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return proc, report, annotated


def check_result(name: str, work: Path, records: list[dict], check: str, *,
                 findings: int | None = None, code: str | None = None, tag: str | None = None,
                 checked: int | None = None, unchecked: int | None = None,
                 not_applicable: int | None = None) -> dict | None:
    proc, report, _ = run(work, name, records)
    if proc.returncode != 0 or report is None:
        note(name, False, f"the driver failed to run\n{proc.stdout}{proc.stderr}")
        return None
    row = report["checks"][check]
    if findings is not None:
        note(name, row["findings"] == findings,
             f"{check}: expected {findings} findings, got {row['findings']} ({row['codes']})")
    if code is not None:
        note(f"{name} [code]", any(f["code"] == code for f in row["findings_detail"]),
             f"{check}: no finding with code {code!r}; got {row['codes']}")
    if tag is not None:
        note(f"{name} [tag]", any(f.get("tag") == tag for f in row["findings_detail"]),
             f"{check}: no finding for tag {tag!r}; got {[f.get('tag') for f in row['findings_detail']]}")
    for label, expected, actual in (
        ("records_checked", checked, row["records_checked"]),
        ("records_unchecked", unchecked, row["records_unchecked"]),
        ("records_not_applicable", not_applicable, row["records_not_applicable"]),
    ):
        if expected is not None:
            note(f"{name} [{label}]", actual == expected,
                 f"{check}: expected {label}={expected}, got {actual}")
    return report


def main() -> None:
    records = published()

    # ---- fixture sources, chosen by predicate from real data ----------------
    recall_source = pick(records, lambda r: single_recall_miss(r) is not None
                         and description_text(r).strip())
    missed_tag = single_recall_miss(recall_source)
    unrelated_workload = uncorroborated_tag(recall_source, missed_tag)

    ui_none = pick(records, lambda r: (r.get("attack") or {}).get("user_interaction") == "none")
    ui_required = pick(records, lambda r: (r.get("attack") or {}).get("user_interaction") == "required")

    impact_tag = "elevation-of-privilege" if "Elevation of Privilege" in recall_source["title"] \
        else sorted(set(recall_source.get("tags") or []) & JUDGEMENT or {"remote-code-execution"})[0]

    quote_tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9'\-]*", description_text(recall_source))
    if len(quote_tokens) < 10:
        raise SystemExit("Fixture record has no quotable description; fixtures need rewriting")
    real_quote = " ".join(quote_tokens[:8])
    # Word salad: every word is from the record, so a bag-of-words grounding check
    # accepts it. No six of them are contiguous in the source, so span verification
    # must not. That gap is the whole reason span_verify exists.
    salad_words = list(dict.fromkeys(word for word in quote_tokens if len(word) > 3))[:8]
    word_salad = " ".join(reversed(salad_words))

    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)

        # ---- 1. workload recall -------------------------------------------
        negative = bare(recall_source, [])
        positive = bare(recall_source, [missed_tag])
        differs("workload-recall", negative["tags"], positive["tags"])
        check_result("workload-recall rejects a named role that was not tagged", work,
                     [negative], "workload_recall", findings=1,
                     code="workload-recall-miss", tag=missed_tag, checked=1)
        check_result("workload-recall accepts the same record once tagged", work,
                     [positive], "workload_recall", findings=0, checked=1)

        # ---- 2. workload precision ----------------------------------------
        negative = bare(recall_source, [unrelated_workload])
        positive = bare(recall_source, [missed_tag])
        differs("workload-precision", negative["tags"], positive["tags"])
        check_result("workload-precision rejects an uncorroborated workload tag", work,
                     [negative], "workload_precision", findings=1,
                     code="workload-uncorroborated", tag=unrelated_workload, checked=1)
        check_result("workload-precision accepts a corroborated workload tag", work,
                     [positive], "workload_precision", findings=0, checked=1)

        # ---- 3. delivery consistency --------------------------------------
        negative = bare(ui_none, ["user-content"])
        positive = bare(ui_required, ["user-content"])
        differs("delivery-consistency",
                negative["attack"]["user_interaction"], positive["attack"]["user_interaction"])
        check_result("delivery-consistency rejects user-content against UI:N", work,
                     [negative], "delivery_consistency", findings=1,
                     code="delivery-contradicts-cvss", tag="user-content", checked=1)
        check_result("delivery-consistency accepts user-content against UI:R", work,
                     [positive], "delivery_consistency", findings=0, checked=1)

        # ---- 4. evidence present ------------------------------------------
        negative = structured(recall_source, [(impact_tag, "   ")])
        positive = structured(recall_source, [(impact_tag, real_quote)])
        differs("evidence-present", negative["tags"], positive["tags"])
        check_result("evidence-present rejects a judgement tag with a blank citation", work,
                     [negative], "evidence_present", findings=1, code="evidence-missing",
                     tag=impact_tag, checked=1)
        check_result("evidence-present accepts a judgement tag that carries one", work,
                     [positive], "evidence_present", findings=0, checked=1)

        # ---- 5. evidence grounded -----------------------------------------
        invented = "generally accepted industry practice for this component class"
        negative = structured(recall_source, [(impact_tag, invented)])
        positive = structured(recall_source, [(impact_tag, real_quote)])
        differs("evidence-grounded", invented, real_quote)
        check_result("evidence-grounded rejects a citation with no lexical contact", work,
                     [negative], "evidence_grounded", findings=1, code="evidence-ungrounded",
                     tag=impact_tag, checked=1)
        check_result("evidence-grounded accepts a citation quoted from the record", work,
                     [positive], "evidence_grounded", findings=0, checked=1)

        # ---- 6. citation verification (span_verify) ------------------------
        negative = structured(recall_source, [(impact_tag, word_salad)])
        positive = structured(recall_source, [(impact_tag, real_quote)])
        differs("citation-verification", word_salad, real_quote)
        check_result("citation-verification rejects word salad from the record's own vocabulary",
                     work, [negative], "citation_verification", findings=1,
                     code="citation-unverified", tag=impact_tag, checked=1)
        check_result("citation-verification accepts a verbatim quotation", work,
                     [positive], "citation_verification", findings=0, checked=1)
        # The bag-of-words check accepts that same salad. If it did not, the span
        # verifier would be duplicating work rather than catching what it misses.
        check_result("word salad passes the weaker grounding check, proving span verification adds something",
                     work, [negative], "evidence_grounded", findings=0, checked=1)

        # A citation must not be grounded in prose the model itself wrote. The same
        # salad is planted in a mitigation candidate's evidence; it must still fail.
        self_grounded = structured(recall_source, [(impact_tag, word_salad)])
        self_grounded["mitigation_candidates"] = [{
            "id": "edr_detection_response", "relevance": "not-relevant", "confidence": "low",
            "effect": {"likelihood_steps": 0, "consequence_steps": 0, "path_block": False},
            "evidence": word_salad,
        }]
        differs("citation-self-grounding",
                self_grounded["mitigation_candidates"], positive.get("mitigation_candidates"))
        check_result("citation-verification will not ground a citation in the model's own prose",
                     work, [self_grounded], "citation_verification", findings=1,
                     code="citation-unverified", checked=1)

        # ---- 7. unchecked is not passed ------------------------------------
        negative = bare(recall_source, [impact_tag])          # no evidence field at all
        positive = structured(recall_source, [(impact_tag, real_quote)])
        differs("unchecked-evidence", negative["tags"], positive["tags"])
        check_result("a bare-string tag list is unchecked for evidence, never clean", work,
                     [negative], "evidence_present", findings=0, checked=0, unchecked=1)
        check_result("a structured tag list is actually checked", work,
                     [positive], "evidence_present", findings=0, checked=1, unchecked=0)

        no_ui = bare(ui_none, ["user-content"])
        no_ui["attack"] = {k: v for k, v in no_ui["attack"].items() if k != "user_interaction"}
        differs("unchecked-delivery", no_ui["attack"], bare(ui_none, ["user-content"])["attack"])
        check_result("a missing CVSS user_interaction leaves delivery unchecked, never clean", work,
                     [no_ui], "delivery_consistency", findings=0, checked=0, unchecked=1)
        check_result("a supplied CVSS user_interaction is actually checked", work,
                     [bare(ui_required, ["user-content"])], "delivery_consistency",
                     findings=0, checked=1, unchecked=0)

        no_tags = copy(recall_source)
        no_tags.pop("tags", None)
        differs("unchecked-tagset", "tags" in no_tags, "tags" in positive)
        check_result("a record with no tag set is unchecked for recall, never clean", work,
                     [no_tags], "workload_recall", findings=0, checked=0, unchecked=1)

        # ---- 8. nothing to check is not a pass either ----------------------
        empty = bare(recall_source, [])
        differs("not-applicable", empty["tags"], positive["tags"])
        check_result("a record asserting no judgement tag is not applicable, not clean", work,
                     [empty], "evidence_present", findings=0, checked=0, not_applicable=1)
        check_result("a record asserting a judgement tag is applicable", work,
                     [positive], "evidence_present", checked=1, not_applicable=0)

        # ---- 9. the report names the offending CVEs ------------------------
        # A bare-string tag list, so the block must also report that the evidence
        # checks could not run on it - a flag that hid that would be half a review.
        flagged = bare(recall_source, [impact_tag])
        clean = bare(pick(records, lambda r: not tv.check_workload_recall(r, {"tags": []})), [])
        differs("offender-listing", flagged["cve"], clean["cve"])
        proc, report, annotated = run(work, "offenders", [flagged, clean])
        if report is None:
            note("the report lists offending CVEs per check", False, proc.stdout + proc.stderr)
        else:
            note("the report lists offending CVEs per check",
                 report["checks"]["workload_recall"]["cves"] == [flagged["cve"]],
                 f"expected [{flagged['cve']}], got {report['checks']['workload_recall']['cves']}")
            note("the report counts flagged records",
                 report["records_flagged"] == 1 and report["records_total"] == 2,
                 f"flagged={report['records_flagged']} total={report['records_total']}")

            # ---- 10. annotation is a review flag, not an edit --------------
            by_cve = {row["cve"]: row for row in annotated}
            flagged_row = by_cve.get(flagged["cve"], {})
            clean_row = by_cve.get(clean["cve"], {})
            note("a flagged record is annotated", "tier1_review" in flagged_row,
                 "the flagged record carries no tier1_review block")
            note("a record with no findings is not annotated", "tier1_review" not in clean_row,
                 "a clean record was annotated anyway")
            block = flagged_row.get("tier1_review") or {}
            note("the annotation names the failed check",
                 block.get("failed_checks") == ["workload_recall"],
                 f"failed_checks={block.get('failed_checks')}")
            note("the annotation names the specific evidence that failed",
                 any(f.get("tag") == missed_tag and f.get("matched_term")
                     for f in block.get("findings") or []),
                 f"findings={block.get('findings')}")
            note("the annotation reports what could not be checked",
                 any(item.get("check") == "evidence_present" for item in block.get("unchecked") or []),
                 f"unchecked={block.get('unchecked')}")
            for cve, before in ((flagged["cve"], flagged), (clean["cve"], clean)):
                after = {k: v for k, v in by_cve.get(cve, {}).items() if k != "tier1_review"}
                note(f"annotation changes nothing else on {cve}", after == before,
                     "a field other than tier1_review differs after annotation")

            annotated_bytes = (work / "offenders-annotated.jsonl").read_bytes()
            note("annotated output is LF with compact separators",
                 b"\r" not in annotated_bytes and b'", "' not in annotated_bytes
                 and b'": "' not in annotated_bytes,
                 "CRLF or non-compact JSON separators in the annotated output")

        # ---- 11. it reports, it does not gate ------------------------------
        proc, report, _ = run(work, "no-gate", [bare(recall_source, [])])
        note("findings do not fail the command", proc.returncode == 0,
             f"exit {proc.returncode} on a month with findings - this command must not gate")
        note("the report says it does not gate",
             bool(report) and report["findings_total"] > 0 and "none" in report["gating"],
             "the report claims a gating role")
        proc, _, _ = run(work, "fail-under", [bare(recall_source, [])], extra=("--fail-under", "1"))
        note("there is no --fail-under flag", proc.returncode != 0,
             "--fail-under was accepted; gating belongs to the runbook and a human")

        # ---- 12. annotate must not overwrite the input ---------------------
        source = work / "inplace.jsonl"
        source.write_text(json.dumps(bare(recall_source, []), separators=(",", ":")) + "\n",
                          encoding="utf-8", newline="\n")
        before = source.read_bytes()
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--records", str(source), "--output", str(work / "inplace.json"),
             "--annotate", str(source), "--taxonomy", str(TAXONOMY)], capture_output=True, text=True)
        note("--annotate refuses to overwrite --records",
             proc.returncode != 0 and source.read_bytes() == before,
             "the driver wrote its annotation over its own input")

    for failure in FAILURES:
        print(f"FAIL {failure}")
    print(f"{GATES - len(FAILURES)}/{GATES} review_month gates behaved as specified")
    raise SystemExit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
