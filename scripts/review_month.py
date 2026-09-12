#!/usr/bin/env python3
"""Tier 1 review of a merged month. One command, one machine-readable report.

    python3 scripts/review_month.py \
      --records work/2026-Oct-merged.jsonl \
      --output  work/2026-Oct-tier1.json \
      --annotate work/2026-Oct-reviewed.jsonl      # optional

Runs every deterministic check in `tag_validators.py` plus citation verification
from `span_verify.py` over every record, counts them, names the offending CVEs,
and - with --annotate - writes a copy of the input carrying a `tier1_review`
block on each affected record.

THE BOUNDARY, inherited from tag_validators.py and not to be eroded here:

    assigning a tag from prose  -> a pattern match becomes a risk decision. Banned.
    flagging a tag for review   -> a pattern match raises a question for a human
                                   or for the Tier 2 scorer.

`tier1_review` is a review flag and nothing else. This driver never adds, removes
or rewrites a tag, never touches `mitigation_candidates`, `priority`, `review`,
`severity` or `inference`, and never changes a rating. The annotate mode asserts
that byte-for-byte before it writes (see `annotate`).

THIS COMMAND REPORTS; IT DOES NOT GATE. There is deliberately no --fail-under and
no non-zero exit on findings. A release decision belongs to the runbook and to a
human, not to a threshold hidden in a review tool. Exit status means "the review
ran", not "the month is good".

UNCHECKED IS NOT PASSED. A record that does not carry the data a check needs -
no attack vector for the delivery check, no per-tag evidence for the citation
checks - is counted as `unchecked` with its reason and its CVE listed. It is
never folded into the clean count. This matters on real data: months assessed
before 2026-09-11 stored tags as bare strings with no evidence field at all, so
every evidence and citation check over them is unchecked, not clean.

NOR IS "NOTHING TO CHECK" A PASS. A record that asserts no delivery tag cannot
contradict a CVSS vector, and a record that asserts no judgement tag has no
citation to verify. Those are counted as `not_applicable` and kept out of the
rate denominator, so a month of empty tag sets cannot report itself as clean.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import span_verify as sv  # noqa: E402
import tag_validators as tv  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION = "1.0"

CHECKS = (
    "workload_recall",
    "workload_precision",
    "delivery_consistency",
    "evidence_present",
    "evidence_grounded",
    "citation_verification",
)

# Fields a record carries because a model wrote them. A citation must be traceable
# to the advisory the model was shown, so these are excluded from the haystack -
# otherwise a fabricated span could "verify" against the assessor's own prose.
MODEL_AUTHORED = ("inference", "mitigation_candidates", "priority", "review",
                  "tags", "tier1_review")

# Mitigation-candidate `evidence` is deliberately NOT span-verified. The authoring
# contract asks there for reasoning about a control ("AV:N does not establish
# public exposure..."), not for a quotation, so contiguous-run matching would
# reject 1,391 of September's 1,532 candidates for being what they were asked to
# be. Citation verification applies to per-tag evidence, which the contract does
# require to be quoted from the record.

NO_TAG_SET = "record carries no tag set"
NO_SOURCE_TEXT = "record carries no source text"
NO_EVIDENCE_FIELD = "tags carry no evidence field (pre-2026-09-11 bare-string tag shape)"
NO_CITATION = "every judgement tag was asserted with an empty citation"
NO_WORKLOAD_TAG = "record asserts no workload tag"
NO_DELIVERY_TAG = "record asserts no delivery tag that presupposes a CVSS value"
NO_JUDGEMENT_TAG = "record asserts no judgement tag"


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON in {path} line {line_no}: {exc}") from exc
    return rows


def supplied_view(record: dict) -> dict:
    """The advisory as supplied to the assessor: source facts, nothing it authored."""
    return {key: value for key, value in record.items() if key not in MODEL_AUTHORED}


def evidence_shape(record: dict) -> str:
    """'structured' when tags carry an evidence field, 'bare' when they do not.

    A bare-string tag list is not a tag asserted without evidence; it is a record
    whose format never had a place to put one. The difference decides whether the
    evidence checks report a failure or report `unchecked`.
    """
    items = record.get("tags") or []
    if not items:
        return "empty"
    return "structured" if all(isinstance(item, dict) for item in items) else "bare"


class CheckAccumulator:
    def __init__(self, name: str) -> None:
        self.name = name
        self.checked: list[str] = []
        self.unchecked: list[dict] = []
        self.not_applicable: list[dict] = []
        self.findings: list[dict] = []
        self.offenders: set[str] = set()
        self.extra: Counter = Counter()

    def mark_checked(self, cve: str) -> None:
        self.checked.append(cve)

    def mark_unchecked(self, cve: str, reason: str) -> None:
        self.unchecked.append({"cve": cve, "reason": reason})

    def mark_not_applicable(self, cve: str, reason: str) -> None:
        self.not_applicable.append({"cve": cve, "reason": reason})

    def add(self, cve: str, findings: list[dict]) -> None:
        for finding in findings:
            item = dict(finding)
            item["cve"] = cve
            item["check"] = self.name
            self.findings.append(item)
        if findings:
            self.offenders.add(cve)

    def summary(self) -> dict:
        checked = len(self.checked)
        offenders = len(self.offenders)
        out = {
            "records_checked": checked,
            "records_unchecked": len(self.unchecked),
            "records_not_applicable": len(self.not_applicable),
            "records_with_findings": offenders,
            "findings": len(self.findings),
            # null, not 0.0, when nothing was checked: a rate over an empty
            # denominator is not a clean month.
            "record_finding_rate": round(offenders / checked, 6) if checked else None,
            "findings_per_checked_record": round(len(self.findings) / checked, 6) if checked else None,
            "codes": dict(sorted(Counter(f["code"] for f in self.findings).items())),
            "unchecked_reasons": dict(sorted(Counter(u["reason"] for u in self.unchecked).items())),
            "not_applicable_reasons": dict(sorted(Counter(n["reason"] for n in self.not_applicable).items())),
            "cves": sorted(self.offenders),
            "unchecked_cves": sorted({u["cve"] for u in self.unchecked}),
            "findings_detail": self.findings,
        }
        if self.extra:
            out["counts"] = dict(sorted(self.extra.items()))
        return out


def review(records: list[dict], namespaces: dict[str, set[str]]) -> dict[str, CheckAccumulator]:
    workload = namespaces["workload"]
    judgement = namespaces["workload"] | namespaces["delivery"] | namespaces["impact"]
    acc = {name: CheckAccumulator(name) for name in CHECKS}

    for record in records:
        cve = record.get("cve") or "(no cve)"
        has_tags = "tags" in record
        text = tv.source_text(record).strip()
        shape = evidence_shape(record)
        asserted = tv.asserted(record) if has_tags else {}

        # --- workload recall -------------------------------------------------
        if not has_tags:
            acc["workload_recall"].mark_unchecked(cve, NO_TAG_SET)
        elif not text:
            acc["workload_recall"].mark_unchecked(cve, NO_SOURCE_TEXT)
        else:
            acc["workload_recall"].mark_checked(cve)
            acc["workload_recall"].add(cve, tv.check_workload_recall(record, record))

        # --- workload precision ----------------------------------------------
        if not has_tags:
            acc["workload_precision"].mark_unchecked(cve, NO_TAG_SET)
        elif not set(asserted) & workload:
            acc["workload_precision"].mark_not_applicable(cve, NO_WORKLOAD_TAG)
        elif not text:
            acc["workload_precision"].mark_unchecked(cve, NO_SOURCE_TEXT)
        else:
            acc["workload_precision"].mark_checked(cve)
            acc["workload_precision"].add(cve, tv.check_workload_precision(record, record, workload))

        # --- delivery consistency --------------------------------------------
        attack = record.get("attack") or {}
        needed = []
        if set(asserted) & tv.DELIVERY_REQUIRES_USER_INTERACTION:
            needed.append("user_interaction")
        if set(asserted) & tv.DELIVERY_REQUIRES_NON_NETWORK:
            needed.append("vector")
        missing = [field for field in needed if attack.get(field) is None]
        if not has_tags:
            acc["delivery_consistency"].mark_unchecked(cve, NO_TAG_SET)
        elif not needed:
            acc["delivery_consistency"].mark_not_applicable(cve, NO_DELIVERY_TAG)
        elif missing:
            acc["delivery_consistency"].mark_unchecked(
                cve, "record carries no " + " or ".join(f"attack.{field}" for field in missing))
        else:
            acc["delivery_consistency"].mark_checked(cve)
            acc["delivery_consistency"].add(cve, tv.check_delivery_consistency(record, record))

        judged = {tag for tag in asserted if tag in judgement}

        # --- evidence present -------------------------------------------------
        if not has_tags:
            acc["evidence_present"].mark_unchecked(cve, NO_TAG_SET)
        elif not judged:
            acc["evidence_present"].mark_not_applicable(cve, NO_JUDGEMENT_TAG)
        elif shape == "bare":
            acc["evidence_present"].mark_unchecked(cve, NO_EVIDENCE_FIELD)
        else:
            acc["evidence_present"].mark_checked(cve)
            acc["evidence_present"].extra["judgement_tags"] += len(judged)
            acc["evidence_present"].add(cve, tv.check_evidence_present(record, record, judgement))

        # --- evidence grounded ------------------------------------------------
        if not has_tags:
            acc["evidence_grounded"].mark_unchecked(cve, NO_TAG_SET)
        elif not judged:
            acc["evidence_grounded"].mark_not_applicable(cve, NO_JUDGEMENT_TAG)
        elif shape == "bare":
            acc["evidence_grounded"].mark_unchecked(cve, NO_EVIDENCE_FIELD)
        elif not text:
            acc["evidence_grounded"].mark_unchecked(cve, NO_SOURCE_TEXT)
        else:
            acc["evidence_grounded"].mark_checked(cve)
            acc["evidence_grounded"].add(cve, tv.check_evidence_grounded(record, record, judgement))

        # --- citation verification (span_verify) ------------------------------
        citation = acc["citation_verification"]
        if not has_tags:
            citation.mark_unchecked(cve, NO_TAG_SET)
        elif not judged:
            citation.mark_not_applicable(cve, NO_JUDGEMENT_TAG)
        elif shape == "bare":
            citation.mark_unchecked(cve, NO_EVIDENCE_FIELD)
        elif not text:
            citation.mark_unchecked(cve, NO_SOURCE_TEXT)
        elif not any(evidence.strip() for tag, evidence in asserted.items() if tag in judgement):
            # Every judgement tag was asserted with an empty citation. There is
            # nothing to verify - and evidence_present has already flagged it.
            citation.mark_unchecked(cve, NO_CITATION)
        else:
            citation.mark_checked(cve)
            view = supplied_view(record)
            findings = []
            for tag, evidence in asserted.items():
                if tag not in judgement or not evidence.strip():
                    # An empty citation is the evidence_present check's business,
                    # not a verification failure.
                    continue
                citation.extra["citations"] += 1
                result = sv.verify(evidence, view)
                if not result["verified"]:
                    citation.extra["citations_unverified"] += 1
                    findings.append({
                        "code": "citation-unverified", "tag": tag, "evidence": evidence,
                        "components": result["components"], "matched": result["matched"],
                        "unmatched_examples": result["unmatched_examples"],
                        "message": (f"{tag} evidence does not appear in the supplied record: "
                                    f"no run of {sv.MIN_RUN} consecutive tokens matches"),
                    })
                elif not result["fully_verified"]:
                    # Reported, not a finding: span_verify's contract is that a
                    # composite citation passes when any component matches.
                    citation.extra["citations_partially_verified"] += 1
                else:
                    citation.extra["citations_fully_verified"] += 1
            citation.add(cve, findings)

    return acc


def build_report(records_path: Path, records: list[dict], taxonomy_path: Path,
                 acc: dict[str, CheckAccumulator]) -> dict:
    digest = hashlib.sha256(records_path.read_bytes()).hexdigest()
    taxonomy = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    per_check = {name: acc[name].summary() for name in CHECKS}
    flagged = sorted({f["cve"] for check in acc.values() for f in check.findings})
    total_findings = sum(len(check.findings) for check in acc.values())
    return {
        "tool": "scripts/review_month.py",
        "tool_version": TOOL_VERSION,
        "tier": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records_path": str(records_path),
        "records_sha256": digest,
        "taxonomy_path": str(taxonomy_path),
        "taxonomy_version": taxonomy.get("version"),
        "records_total": len(records),
        "records_flagged": len(flagged),
        "records_without_findings": len(records) - len(flagged),
        "findings_total": total_findings,
        "gating": "none: this report does not decide a release",
        "checks": per_check,
        "flagged_cves": flagged,
    }


def annotate(records: list[dict], acc: dict[str, CheckAccumulator]) -> list[dict]:
    """Return a copy of the records with a `tier1_review` block where flagged.

    Review flag only. Every other field is passed through untouched and that is
    asserted here rather than assumed - a review tool that quietly rewrote a tag
    would be exactly the failure this project banned.
    """
    by_cve: dict[str, list[dict]] = {}
    unchecked_by_cve: dict[str, list[dict]] = {}
    na_by_cve: dict[str, list[dict]] = {}
    for name in CHECKS:
        for finding in acc[name].findings:
            by_cve.setdefault(finding["cve"], []).append(finding)
        for item in acc[name].unchecked:
            unchecked_by_cve.setdefault(item["cve"], []).append(
                {"check": name, "reason": item["reason"]})
        for item in acc[name].not_applicable:
            na_by_cve.setdefault(item["cve"], []).append(
                {"check": name, "reason": item["reason"]})

    reviewed_at = datetime.now(timezone.utc).isoformat()
    out = []
    for record in records:
        original = {k: v for k, v in record.items() if k != "tier1_review"}
        cve = record.get("cve") or "(no cve)"
        findings = by_cve.get(cve, [])
        if not findings:
            out.append(original)
            continue
        annotated = dict(original)
        annotated["tier1_review"] = {
            "tool": "scripts/review_month.py",
            "tool_version": TOOL_VERSION,
            "reviewed_at": reviewed_at,
            "status": "flagged",
            "failed_checks": sorted({f["check"] for f in findings}),
            "findings": [
                {k: v for k, v in finding.items() if k != "cve"} for finding in findings
            ],
            "unchecked": unchecked_by_cve.get(cve, []),
            "not_applicable": na_by_cve.get(cve, []),
            "note": ("Review flag only. No tag was assigned, altered or removed and no "
                     "rating was changed. Tier 1 raises a question; it does not answer it."),
        }
        leftover = {k: v for k, v in annotated.items() if k != "tier1_review"}
        if leftover != original:
            raise SystemExit(f"{cve}: annotation altered the record; refusing to write")
        out.append(annotated)
    return out


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def print_summary(report: dict) -> None:
    print(f"Tier 1 review of {report['records_path']}")
    print(f"  sha256 {report['records_sha256'][:16]}  records {report['records_total']}"
          f"  taxonomy {report['taxonomy_version']}")
    print()
    header = (f"  {'check':<24}{'checked':>9}{'unchecked':>11}{'n/a':>7}"
              f"{'flagged':>9}{'findings':>10}{'rate':>9}")
    print(header)
    print("  " + "-" * (len(header) - 2))
    for name in CHECKS:
        row = report["checks"][name]
        rate = row["record_finding_rate"]
        rate_text = "n/a" if rate is None else f"{rate * 100:.1f}%"
        print(f"  {name:<24}{row['records_checked']:>9}{row['records_unchecked']:>11}"
              f"{row['records_not_applicable']:>7}{row['records_with_findings']:>9}"
              f"{row['findings']:>10}{rate_text:>9}")
    print()
    for name in CHECKS:
        row = report["checks"][name]
        for reason, count in row["unchecked_reasons"].items():
            print(f"  unchecked: {name} on {count} record(s) - {reason}")
    counts = report["checks"]["citation_verification"].get("counts") or {}
    if counts:
        print("  citations: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print()
    print(f"  {report['records_flagged']} of {report['records_total']} records carry at least "
          f"one finding ({report['findings_total']} findings in total).")
    print("  This report does not gate the release.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", required=True, type=Path, help="merged month JSONL")
    parser.add_argument("--output", required=True, type=Path, help="JSON report to write")
    parser.add_argument("--annotate", type=Path,
                        help="write a copy of the input with a tier1_review block on flagged records")
    parser.add_argument("--taxonomy", type=Path, default=ROOT / "data" / "tag-taxonomy.json")
    args = parser.parse_args()

    if args.annotate and args.annotate.resolve() == args.records.resolve():
        raise SystemExit("--annotate must not overwrite --records")

    records = read_jsonl(args.records)
    if not records:
        raise SystemExit(f"No records in {args.records}")
    namespaces = tv.load_namespaces(args.taxonomy)
    acc = review(records, namespaces)
    report = build_report(args.records, records, args.taxonomy, acc)

    if args.annotate:
        annotated = annotate(records, acc)
        write_jsonl(args.annotate, annotated)
        report["annotated_path"] = str(args.annotate)
        report["annotated_records"] = sum(1 for row in annotated if "tier1_review" in row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print_summary(report)
    print(f"  report: {args.output}")
    if args.annotate:
        print(f"  annotated records: {report['annotated_records']} -> {args.annotate}")


if __name__ == "__main__":
    main()
