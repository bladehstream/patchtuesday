"""The assessor must have no tools and no MCP servers.

Regression fixture for a real incident on 2026-09-10: the adapter passed no tool
restrictions, so assessor invocations ran as full agents with the session's MCP
servers attached and wrote five documents into the user's claude.ai project while
being asked to assess advisories.
"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("adapter", ROOT / "scripts" / "run_claude_inference.py")
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


def test_sandbox_args_present():
    args = ADAPTER.SANDBOX_ARGS
    assert "--strict-mcp-config" in args, "MCP servers must be stripped, not inherited"
    assert "--allowedTools" in args
    assert "--disallowedTools" in args


def test_write_capable_tools_are_denied_by_name():
    denied = ADAPTER.SANDBOX_ARGS[ADAPTER.SANDBOX_ARGS.index("--disallowedTools") + 1]
    for tool in ("Bash", "Write", "Edit", "Task", "WebFetch"):
        assert tool in denied, f"{tool} must be denied to the assessor"


def test_allowlist_names_nothing_real():
    allowed = ADAPTER.SANDBOX_ARGS[ADAPTER.SANDBOX_ARGS.index("--allowedTools") + 1]
    assert allowed == "__none__"
