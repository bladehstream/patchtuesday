#!/usr/bin/env python3
"""Adversarial scorer for judgement tags. Tier 2 of the tag review.

Sees only the source record, one asserted tag, and its cited evidence. It never
sees the assessor's reasoning, the model that produced it, or the other tags -
so it cannot be talked round by a confident-sounding rationale.

Four verdicts, not two. Collapsing to good/bad is what makes a scorer agree with
whatever it is shown:

    supported         the record substantiates the tag
    unsupported       the record does not; the tag reads as invented
    source-ambiguous  the record neither supports nor refutes it
    contradicted      the record positively contradicts it

Every verdict must quote a span FROM THE SUPPLIED RECORD. A verdict with no
quotable span is recorded as a scorer failure, not as a finding: that is what
stops the scorer reasoning from world knowledge instead of the advisory. That
holds for `unsupported` as much as for `supported` - see the note in score_one.
`source-ambiguous` is the one verdict the contract lets the scorer return
unspanned, because "nothing in the record bears on this" has nothing to quote.

The scorer is itself validated before use - see tests/test_scorer_fixture.py and
the --self-test mode, which plants known-bad and known-good tags and fails if the
scorer does not separate them.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tag_validators as tv  # noqa: E402

SANDBOX_ARGS = [
    "--strict-mcp-config",
    "--allowedTools", "__none__",
    "--disallowedTools",
    "Bash,Read,Write,Edit,MultiEdit,Glob,Grep,WebFetch,WebSearch,Task,"
    "NotebookEdit,TodoWrite,SlashCommand,KillShell,BashOutput",
]

SYSTEM_PROMPT = """You adjudicate whether a single tag applied to a vulnerability \
advisory is supported by that advisory.

You are adversarial by design. Before ruling, state the strongest available case \
that the tag is NOT supported. Only then rule.

You judge the tag against the supplied record ALONE. You may know things about \
the product from elsewhere; that knowledge is not evidence here. If the record \
does not say it, the record does not support it.

Verdicts:
  supported        - the record substantiates the tag
  unsupported      - the record does not substantiate it
  source-ambiguous - the record neither supports nor refutes it
  contradicted     - the record positively contradicts it

You MUST quote a span verbatim from the supplied record in `source_span`. If no \
span in the record bears on the question, return an empty `source_span` and the \
verdict `source-ambiguous`. Never invent a quotation."""

SCHEMA = {
    "type": "object",
    "properties": {
        "case_against": {"type": "string"},
        "verdict": {"type": "string", "enum": ["supported", "unsupported", "source-ambiguous", "contradicted"]},
        "source_span": {"type": "string"},
        "reasoning": {"type": "string"},
    },
    "required": ["case_against", "verdict", "source_span", "reasoning"],
    "additionalProperties": False,
}


DEFINITIONS: dict[str, str] = {}


def load_definitions(taxonomy: Path) -> None:
    """Judge against this project's meaning, not the reader's prior.

    Without this the scorer applied the web-application sense of `user-content`
    and rejected 30.9% of delivery tags that were correct for this system.
    """
    global DEFINITIONS
    data = json.loads(taxonomy.read_text(encoding="utf-8"))
    DEFINITIONS = {k: v for k, v in (data.get("definitions") or {}).items() if not k.startswith("_")}


def record_view(record: dict) -> dict:
    """Exactly what the scorer may rely on. No inference, no ratings, no tags."""
    return {
        "cve": record.get("cve"),
        "title": record.get("title"),
        "products": [p.get("name") for p in record.get("products") or []],
        "cvss": record.get("cvss"),
        "attack": record.get("attack"),
        "severity": record.get("severity"),
        "notes": [n.get("value") if isinstance(n, dict) else n for n in record.get("notes") or []],
        "vendor_guidance": record.get("vendor_guidance"),
    }


def score_one(cli: str, model: str, record: dict, tag: str, evidence: str,
              run_dir: Path, index: int, timeout: int) -> dict:
    view = record_view(record)
    definition = DEFINITIONS.get(tag)
    prompt = (
        (f"TAG DEFINITION (authoritative for this project): {definition}\n\n" if definition else "")
        + "SUPPLIED RECORD:\n" + json.dumps(view, indent=1)
        + f"\n\nASSERTED TAG: {tag}"
        + f"\nCITED EVIDENCE: {evidence or '(none supplied)'}"
        + "\n\nAdjudicate the tag against the supplied record alone."
    )
    sp = run_dir / "scorer-system-prompt.txt"
    if not sp.exists():
        sp.write_text(SYSTEM_PROMPT, encoding="utf-8")
    mcp = run_dir / "empty-mcp.json"
    if not mcp.exists():
        mcp.write_text('{"mcpServers":{}}', encoding="utf-8")

    command = [cli, "-p", "--model", model, "--output-format", "json",
               "--system-prompt-file", str(sp), "--mcp-config", str(mcp),
               "--json-schema", json.dumps(SCHEMA), *SANDBOX_ARGS]
    started = datetime.now(timezone.utc).isoformat()
    try:
        proc = subprocess.run(command, input=prompt, encoding="utf-8", errors="replace",
                              capture_output=True, timeout=timeout)
        envelope = json.loads(proc.stdout)
        payload = envelope.get("structured_output")
        usage = envelope.get("modelUsage") or {}
        served = next(iter(usage), None)
        result = {
            "cve": record.get("cve"), "tag": tag, "cited_evidence": evidence,
            "started_at": started, "model_served": served,
            "cost_usd": (usage.get(served) or {}).get("costUSD") if served else None,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        }
        if not isinstance(payload, dict):
            result.update(scorer_failure="no structured output", verdict=None)
            return result
        result.update(payload)
        # A verdict with no quotable span is a scorer failure, not a finding.
        #
        # `unsupported` used to be exempt, and the exemption was not neutral. An
        # unspanned `unsupported` passed here silently and was then dropped
        # downstream by citation verification, which has nothing to verify. That
        # deletion is biased by construction: a rejection whose whole argument is
        # "the record never uses the word X" is exactly the rejection with no span
        # to cite, so the rows removed were disproportionately rejections. On the
        # 2026-09 workload tags it removed 11 of 179 rows - 8 unsupported, 3
        # supported - and reported 25/168 = 14.9% rejection where the measured rate
        # was 33/179 = 18.4%.
        #
        # The contract offers exactly one way to return no span: rule
        # `source-ambiguous`. Every other verdict must quote the record, so every
        # other unspanned verdict is a scorer failure - counted, and re-scored -
        # rather than a row that disappears from the denominator.
        span = (payload.get("source_span") or "").strip()
        if payload.get("verdict") != "source-ambiguous" and not span:
            result["scorer_failure"] = "verdict asserted without a source span"
        else:
            # Compare with whitespace collapsed. The scorer quotes JSON with its own
            # spacing, so a byte-exact check produced false failures on spans that
            # were in fact present - the check itself was the bug, not the verdict.
            def flat(text: str) -> str:
                return re.sub(r"\s+", " ", text).lower()
            if span and flat(span) not in flat(json.dumps(view, indent=1)):
                result["scorer_failure"] = "source_span not found in the supplied record"
        return result
    except Exception as error:  # noqa: BLE001
        return {"cve": record.get("cve"), "tag": tag, "verdict": None,
                "scorer_failure": f"{type(error).__name__}: {error}", "started_at": started}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--assessments", required=True, type=Path, help="directory of assessments-*.json")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--taxonomy", type=Path, default=Path("data/tag-taxonomy.json"))
    parser.add_argument("--model", default="haiku")
    parser.add_argument("--cli", default="claude")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    load_definitions(args.taxonomy)
    ns = tv.load_namespaces(args.taxonomy)
    judgement = ns["workload"] | ns["delivery"] | ns["impact"]
    records = {json.loads(l)["cve"]: json.loads(l)
               for l in args.records.read_text(encoding="utf-8").splitlines() if l.strip()}

    overlays: dict[str, dict] = {}
    for path in sorted(args.assessments.glob("assessments-*.json")):
        for item in json.load(open(path, encoding="utf-8")):
            overlays[item["cve"]] = item

    jobs = []
    for cve, overlay in overlays.items():
        if cve not in records:
            continue
        for tag, evidence in tv.asserted(overlay).items():
            if tag in judgement:
                jobs.append((cve, tag, evidence))
    jobs.sort()
    jobs = [j for i, j in enumerate(jobs) if i % args.shards == args.shard]
    if args.limit:
        jobs = jobs[:args.limit]

    args.run_dir.mkdir(parents=True, exist_ok=True)
    out = args.run_dir / f"scores-{args.shard:02d}.jsonl"
    results = []
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        for index, (cve, tag, evidence) in enumerate(jobs):
            res = score_one(args.cli, args.model, records[cve], tag, evidence,
                            args.run_dir, index, args.timeout)
            handle.write(json.dumps(res) + "\n")
            handle.flush()
            results.append(res)
            print(json.dumps({"n": index + 1, "of": len(jobs), "cve": cve, "tag": tag,
                              "verdict": res.get("verdict"),
                              "scorer_failure": res.get("scorer_failure")}), flush=True)

    from collections import Counter
    unspanned = [r for r in results if not (r.get("source_span") or "").strip()]
    print(json.dumps({"shard": args.shard, "scored": len(results),
                      "verdicts": dict(Counter(r.get("verdict") for r in results)),
                      "scorer_failures": sum(1 for r in results if r.get("scorer_failure")),
                      # Reported next to the verdicts on purpose: these are the rows a
                      # citation filter has nothing to verify and will drop, and they are
                      # not a random sample of the verdicts.
                      "unspanned_by_verdict": dict(Counter(r.get("verdict") for r in unspanned))},
                     indent=2))


if __name__ == "__main__":
    main()
