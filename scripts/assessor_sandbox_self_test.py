#!/usr/bin/env python3
"""Self-test for the assessor sandbox. Plain python, no test framework.

    python3 scripts/assessor_sandbox_self_test.py

Regression fixture for a real incident on 2026-09-10: an adapter passed no tool
restrictions, so assessor invocations ran as full agents with the session's MCP
servers attached and wrote five documents into the user's claude.ai project while
being asked to assess advisories.

An assessor needs no tools. It is handed a record on stdin and returns a verdict.
Anything it can reach beyond that is blast radius, not capability - so this checks
the restrictions by name rather than trusting that the command "looks sandboxed".

Previously carried as tests/test_assessor_sandbox.py, which nothing in this
repository ever ran, and which asserted against scripts/run_claude_inference.py -
a module that has never defined SANDBOX_ARGS. So the check had never passed
either. The constant lives in scripts/score_tags.py; that is what is checked here.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import score_tags  # noqa: E402

# Anything that can write, execute, or reach the network. Read and Grep are in the
# list too: the assessor is given its record, so a file read is either useless or
# a route to material the record does not contain.
WRITE_OR_REACH = ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task", "NotebookEdit")


def sandbox_args_are_present():
    args = score_tags.SANDBOX_ARGS
    assert "--strict-mcp-config" in args, "MCP servers must be stripped, not inherited"
    assert "--allowedTools" in args, "an allowlist must be stated, not left to the default"
    assert "--disallowedTools" in args, "a denylist must be stated as well as the allowlist"


def the_allowlist_names_nothing_real():
    args = score_tags.SANDBOX_ARGS
    allowed = args[args.index("--allowedTools") + 1]
    assert allowed == "__none__", f"allowlist must name no real tool, got {allowed!r}"


def write_capable_tools_are_denied_by_name():
    args = score_tags.SANDBOX_ARGS
    denied = args[args.index("--disallowedTools") + 1]
    names = {name.strip() for name in denied.split(",")}
    missing = [tool for tool in WRITE_OR_REACH if tool not in names]
    assert not missing, f"must be denied to the assessor: {missing}"


def the_invocation_actually_applies_the_sandbox():
    """A constant nothing passes to the CLI is decoration. Check the call site."""
    source = (ROOT / "scripts" / "score_tags.py").read_text(encoding="utf-8")
    assert "*SANDBOX_ARGS" in source, "SANDBOX_ARGS must be spread into the CLI command"
    assert '--mcp-config' in source, "an empty MCP config must be passed explicitly"
    assert '{"mcpServers":{}}' in source, "the MCP config written for the run must be empty"


CASES = [
    ("the sandbox arguments are present", sandbox_args_are_present),
    ("the allowlist names nothing real", the_allowlist_names_nothing_real),
    ("write-capable tools are denied by name", write_capable_tools_are_denied_by_name),
    ("the invocation actually applies the sandbox", the_invocation_actually_applies_the_sandbox),
]


def main() -> None:
    failures = []
    for label, case in CASES:
        try:
            case()
        except AssertionError as error:
            failures.append(f"{label}: {error}")
        except Exception as error:  # noqa: BLE001 - a crash is a failure, not an error to hide
            failures.append(f"{label}: {type(error).__name__}: {error}")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(CASES) - len(failures)}/{len(CASES)} assessor sandbox checks behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
