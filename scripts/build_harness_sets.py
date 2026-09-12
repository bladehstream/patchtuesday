"""Draw the dev and holdout sets for the harness development loop.

Both sets are drawn from the same strata by the same seeded process, so a score gap
between them is overfitting rather than sampling noise. Dev is iterated against;
holdout is measured at milestones and must not be inspected while tuning.

Strata are weighted towards cases that exercise judgement rather than clerical
recall. A uniform sample of 1,185 Patch Tuesday records is dominated by routine
advisories and would report a flattering number that means nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

IMPACT_TAGS = {
    "remote-code-execution", "elevation-of-privilege", "security-feature-bypass",
    "information-disclosure", "denial-of-service", "spoofing",
}

# Named in ASSESSOR_HANDOFF.md as cases the previous assessor got wrong or
# was challenged on. These, plus the missing-impact records, form a REFERENCE
# FAILURES set that goes to dev only. They are deliberately excluded from the
# dev-versus-holdout comparison: they are too few to split, and including them on
# one side would make a dev/holdout gap reflect composition rather than
# overfitting, which is the only thing that gap is meant to measure.
NAMED_HARD = [
    "CVE-2026-18149",  # Undici: malicious server attacks the HTTP client (outbound)
    "CVE-2026-69282", "CVE-2026-69380", "CVE-2026-69510",  # scope and privilege
    "CVE-2026-69615", "CVE-2026-69402",  # Subscription Edition vs Server 2016 scope
    "CVE-2026-80843",  # PAM consistency at PR:H
]


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def strata_of(record: dict, flagged: set[str]) -> str | None:
    """Classify a record into at most one stratum, most specific first."""
    cve = record["cve"]
    cvss = record.get("cvss") or {}
    attack = record.get("attack") or {}
    threat = record.get("threat") or {}
    tags = set(record.get("tags") or [])
    score = cvss.get("base_score")

    if cve in NAMED_HARD or cve in flagged:
        return "reference-failure"
    if record.get("severity") == "Unknown":
        return "unknown-severity"
    if (
        isinstance(score, (int, float)) and score >= 9
        and attack.get("vector") == "network"
        and attack.get("privileges_required") == "none"
        and attack.get("user_interaction") == "none"
        and not (tags & IMPACT_TAGS)
    ):
        return "reference-failure"

    # EPSS conflict threshold is 0.01, not the risk model's 0.10 "elevated" constant.
    # Measured on 2026-Sep the entire population maxes out at EPSS 0.018, so a 0.10
    # cut selects nothing. Worth noting separately: RISK_MODEL.epss.elevatedScore is
    # therefore dead for this month's data and never fires.
    epss = threat.get("epss")
    assessment = threat.get("exploitation_assessment")
    if isinstance(epss, (int, float)) and epss >= 0.01 and assessment in {"unlikely", "less-likely"}:
        return "signal-conflict"
    if not (record.get("mitigation_candidates") or []):
        return "no-mitigation-candidates"
    return "routine"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--published", required=True, type=Path)
    parser.add_argument("--independent-review", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=20260910)
    parser.add_argument("--per-set", type=int, default=50)
    args = parser.parse_args()

    records = read_jsonl(args.published)
    by_cve = {record["cve"]: record for record in records}

    flagged: set[str] = set()
    if args.independent_review and args.independent_review.exists():
        review = json.loads(args.independent_review.read_text(encoding="utf-8"))
        flagged = {case["cve"] for case in review.get("cases", []) if case.get("findings")}

    buckets: dict[str, list[str]] = {}
    for record in records:
        buckets.setdefault(strata_of(record, flagged), []).append(record["cve"])

    rng = random.Random(args.seed)
    for cves in buckets.values():
        cves.sort()
        rng.shuffle(cves)

    # Symmetric strata only. Judgement-heavy strata are over-sampled against the
    # routine control floor. reference-failure is handled separately below.
    weights = {"unknown-severity": 5, "signal-conflict": 6, "no-mitigation-candidates": 5, "routine": 4}
    total_weight = sum(weights.values())

    dev: dict[str, list[str]] = {}
    holdout: dict[str, list[str]] = {}
    for stratum, weight in weights.items():
        available = buckets.get(stratum, [])
        want = round(args.per_set * weight / total_weight)
        # Each stratum must fill both sets disjointly, or it cannot support the
        # dev-versus-holdout comparison at all.
        want = min(want, len(available) // 2)
        dev[stratum] = available[:want]
        holdout[stratum] = available[want:want * 2]

    # Top both sets up from routine so each reaches per-set, still disjointly.
    routine_pool = buckets.get("routine", [])
    used = len(dev["routine"]) + len(holdout["routine"])
    for split in (dev, holdout):
        shortfall = args.per_set - sum(len(v) for v in split.values())
        if shortfall > 0:
            split["routine"] = split["routine"] + routine_pool[used:used + shortfall]
            used += shortfall

    reference = buckets.get("reference-failure", [])
    dev["reference-failure"] = sorted(reference)

    overlap = {c for v in dev.values() for c in v} & {c for v in holdout.values() for c in v}
    assert not overlap, f"dev and holdout must be disjoint, overlap: {sorted(overlap)}"

    args.out_dir.mkdir(parents=True, exist_ok=True)
    population_hash = hashlib.sha256(args.published.read_bytes()).hexdigest()

    for name, split in (("dev", dev), ("holdout", holdout)):
        comparable = sorted(c for stratum, v in split.items() if stratum != "reference-failure" for c in v)
        cves = sorted(c for v in split.values() for c in v)
        payload = {
            "set": name,
            "seed": args.seed,
            "population": len(records),
            "population_sha256": population_hash,
            "size": len(cves),
            "comparable_size": len(comparable),
            "comparable_cves": comparable,
            "strata": {stratum: sorted(v) for stratum, v in split.items() if v},
            "cves": cves,
            "note": (
                "Dev is iterated against. Holdout is measured at milestones only and "
                "must not be inspected during tuning. Both drawn from identical strata "
                "by the same seed, so a dev/holdout gap is overfitting, not sampling."
            ),
        }
        (args.out_dir / f"{name}-set.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        with (args.out_dir / f"{name}-records.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
            for cve in cves:
                handle.write(json.dumps(by_cve[cve], separators=(",", ":")) + "\n")

    print(f"population: {len(records)} records, sha256 {population_hash[:16]}")
    print(f"{'stratum':26} {'available':>9} {'dev':>4} {'holdout':>8}")
    for stratum in list(weights) + ["reference-failure"]:
        dev.setdefault(stratum, []); holdout.setdefault(stratum, [])
        print(f"  {stratum:24} {len(buckets.get(stratum, [])):>9} {len(dev[stratum]):>4} {len(holdout[stratum]):>8}")
    print(f"  {'TOTAL':24} {len(records):>9} {sum(len(v) for v in dev.values()):>4} {sum(len(v) for v in holdout.values()):>8}")


if __name__ == "__main__":
    main()
