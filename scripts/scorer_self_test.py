#!/usr/bin/env python3
"""Validate the scorer before trusting it. A judge that cannot fail is not a judge.

Plants tags whose correct verdict is known and checks the scorer separates them.
Known-bad tags must NOT come back `supported`; known-good tags must NOT come back
`unsupported` or `contradicted`. Ambiguity is tolerated in both directions - the
scorer is allowed to be cautious, but not to be wrong.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_tags  # noqa: E402

DNS = {"cve": "CVE-FIXTURE-1", "title": "Windows DNS Server Remote Code Execution Vulnerability",
       "products": [{"name": "Windows Server 2025"}],
       "cvss": {"base_score": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
       "attack": {"vector": "network", "privileges_required": "none", "user_interaction": "none"},
       "severity": "Critical"}

EXCEL = {"cve": "CVE-FIXTURE-2", "title": "Microsoft Excel Remote Code Execution Vulnerability",
         "products": [{"name": "Microsoft Office LTSC 2024"}],
         "cvss": {"base_score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
         "attack": {"vector": "local", "privileges_required": "none", "user_interaction": "required"},
         "severity": "Important"}

CHROMIUM = {"cve": "CVE-FIXTURE-3", "title": "Chromium: CVE-2026-84350 Use after free in TabStrip",
            "products": [{"name": "Microsoft Edge (Chromium-based)"}],
            "cvss": {"base_score": None, "vector": None},
            "attack": {"vector": "unknown", "privileges_required": "unknown", "user_interaction": "unknown"},
            "severity": "Unknown"}

# (label, record, tag, evidence, expectation)
#   expectation "good" -> must not be unsupported/contradicted
#   expectation "bad"  -> must not be supported
CASES = [
    ("dns tag on a DNS advisory", DNS, "dns", "Windows DNS Server", "good"),
    ("rce tag on an RCE advisory", DNS, "remote-code-execution", "Remote Code Execution Vulnerability", "good"),
    ("user-content on an Excel file-open bug", EXCEL, "user-content", "user must open a crafted file; UI:R", "good"),

    ("dns tag on an Excel advisory", EXCEL, "dns", "the component resolves names", "bad"),
    ("hyper-v tag on a DNS advisory", DNS, "hyper-v", "server virtualisation stack", "bad"),
    ("user-content where the vendor says UI:N", DNS, "user-content", "a user must open the payload", "bad"),
    ("dhcp tag with fabricated citation", EXCEL, "dhcp", "the advisory describes DHCP lease handling", "bad"),
    ("identity tag on a Chromium passthrough", CHROMIUM, "identity", "browser credential handling implies directory services", "bad"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--model", default="haiku")
    # Default is the name of the CLI executable on disk, not a provider credit.
    parser.add_argument("--cli", default="claude")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    args.run_dir.mkdir(parents=True, exist_ok=True)

    results, failures = [], []
    for index, (label, record, tag, evidence, expectation) in enumerate(CASES):
        res = score_tags.score_one(args.cli, args.model, record, tag, evidence,
                                   args.run_dir, index, args.timeout)
        verdict = res.get("verdict")
        if expectation == "bad" and verdict == "supported":
            ok = False
        elif expectation == "good" and verdict in {"unsupported", "contradicted"}:
            ok = False
        elif verdict is None:
            ok = False
        else:
            ok = True
        if not ok:
            failures.append({"case": label, "expected": expectation, "verdict": verdict,
                             "scorer_failure": res.get("scorer_failure"),
                             "reasoning": (res.get("reasoning") or "")[:200]})
        results.append({"case": label, "expected": expectation, "verdict": verdict, "ok": ok,
                        "span": (res.get("source_span") or "")[:80],
                        "scorer_failure": res.get("scorer_failure")})
        print(json.dumps(results[-1]), flush=True)

    (args.run_dir / "self-test.json").write_text(
        json.dumps({"cases": len(CASES), "failures": failures, "results": results}, indent=2),
        encoding="utf-8")
    print()
    print(f"scorer self-test: {len(CASES) - len(failures)}/{len(CASES)} cases separated correctly")
    for f in failures:
        print(f"  FAIL {f['case']}: expected {f['expected']}, got {f['verdict']} | {f['reasoning'][:120]}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
