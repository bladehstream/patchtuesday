#!/usr/bin/env python3
"""Self-test for the inference adapter's sandbox. Plain python, no test framework.

    python3 scripts/inference_sandbox_self_test.py

Companion to scripts/assessor_sandbox_self_test.py, which covers the scorer. This
one covers scripts/run_claude_inference.py, which had never been sandboxed at all
despite the runbook saying it was.

WHY THIS IS NOT A CANARY TEST. On 2026-09-10 the sandbox was declared "verified by
canary": an assessor was told to write /tmp/canary.txt, the file did not appear,
and that was taken as proof. It proved only that local Write and Bash were denied.
MCP was still attached, and the next cycle wrote six more documents into the user's
claude.ai project. A canary can only demonstrate the absence of the one capability
it probes; it cannot demonstrate that the restrictions were passed at all. So this
asserts on the constructed command line and on the call site, by name.

The checks that matter are the last three. They fail if `*SANDBOX_ARGS` is dropped
from build_command, if main() stops calling build_command, or if the empty MCP
config stops being written - each of which leaves the constant present, correct,
and doing nothing. That is the exact shape of the original defect.
"""

from __future__ import annotations

import inspect
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_claude_inference as rci  # noqa: E402
import score_tags  # noqa: E402

# Anything that can write, execute, or reach the network. Read and Grep are in the
# list too: the assessor is handed its records on stdin, so a file read is either
# useless or a route to material the records do not contain.
WRITE_OR_REACH = ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch",
                  "WebSearch", "Task", "NotebookEdit")

SOURCE = (ROOT / "scripts" / "run_claude_inference.py").read_text(encoding="utf-8")


def command_for(arm: str) -> list[str]:
    """Build a real command the way main() does, for the named arm."""
    schema = {"type": "object"} if arm == "scaffolded" else None
    return rci.build_command("claude", "haiku", Path("/tmp/system-prompt.txt"),
                             Path("/tmp/empty-mcp.json"), schema)


def sandbox_args_are_imported_not_copied():
    """A second copy is how the scorer and the adapter drifted apart."""
    assert rci.SANDBOX_ARGS is score_tags.SANDBOX_ARGS, \
        "run_claude_inference must import the one SANDBOX_ARGS, not hold its own list"
    assert "SANDBOX_ARGS = [" not in SOURCE, \
        "SANDBOX_ARGS must not be redefined in run_claude_inference.py"


def the_scaffolded_command_carries_every_restriction():
    command = command_for("scaffolded")
    for flag in ("--strict-mcp-config", "--allowedTools", "--disallowedTools", "--mcp-config"):
        assert flag in command, f"{flag} missing from the scaffolded invocation"
    assert command[command.index("--allowedTools") + 1] == "__none__", \
        "the allowlist must name no real tool"
    denied = {name.strip() for name in command[command.index("--disallowedTools") + 1].split(",")}
    missing = [tool for tool in WRITE_OR_REACH if tool not in denied]
    assert not missing, f"must be denied to the assessor: {missing}"


def the_minimal_ablation_is_sandboxed_too():
    """The ablation drops the schema and the contract. It must not drop the sandbox.

    The sandbox is a safety control, not part of the scaffolding under test. An
    unsandboxed ablation arm is the 2026-09-10 incident with a smaller audience.
    """
    minimal = command_for("minimal")
    assert "--json-schema" not in minimal, \
        "the ablation must still run without schema enforcement - that is what it measures"
    for flag in ("--strict-mcp-config", "--allowedTools", "--disallowedTools", "--mcp-config"):
        assert flag in minimal, f"{flag} missing from the minimal ablation invocation"
    scaffolded = command_for("scaffolded")
    for arg in score_tags.SANDBOX_ARGS:
        assert arg in minimal and arg in scaffolded, f"{arg!r} must be in both arms"


def the_empty_mcp_config_is_written_and_is_empty():
    """--strict-mcp-config needs a config to be strict about."""
    with tempfile.TemporaryDirectory() as raw:
        path = rci.write_sandbox_mcp_config(Path(raw))
        assert path.is_file(), "the empty MCP config was not written"
        assert json.loads(path.read_text(encoding="utf-8")) == {"mcpServers": {}}, \
            "the MCP config handed to the run must declare no servers"
        command = rci.build_command("claude", "haiku", Path("/tmp/sp.txt"), path, None)
        assert command[command.index("--mcp-config") + 1] == str(path), \
            "the written config must be the one passed to the CLI"


def the_builder_actually_spreads_the_sandbox():
    """Delete `*SANDBOX_ARGS` from build_command and this goes red."""
    body = inspect.getsource(rci.build_command)
    assert "*SANDBOX_ARGS" in body, \
        "build_command must spread SANDBOX_ARGS into the command it returns"
    assert '"--mcp-config"' in body, \
        "build_command must pass the empty MCP config explicitly"


def main_actually_calls_the_builder():
    """A sandboxed builder nothing calls is the enforce_direction failure again.

    Remove `build_command(` from main - hand-roll the command list again - and this
    goes red even though build_command itself is still perfectly correct.
    """
    body = inspect.getsource(rci.main)
    assert "build_command(" in body, \
        "main() must construct its CLI command through build_command"
    assert "write_sandbox_mcp_config(" in body, \
        "main() must write the empty MCP config for the run"
    assert "mcp_config_path" in body, \
        "main() must pass the written MCP config into build_command"


def no_invocation_bypasses_the_builder():
    """Every subprocess call in this adapter must run a command build_command made."""
    assert SOURCE.count("subprocess.run(") == 1, \
        "more than one subprocess call site: each one needs the sandbox proved separately"
    invoke_body = inspect.getsource(rci.invoke)
    assert "subprocess.run(" in invoke_body, \
        "the single subprocess call must be the one in invoke()"
    # main() builds exactly one command and hands it straight to invoke().
    main_body = inspect.getsource(rci.main)
    assert "invoke(command," in main_body, \
        "main() must pass the built command to invoke() unmodified"
    assert main_body.count("command = ") == 1 and "command +=" not in main_body, \
        "main() must not amend the command after build_command returned it"


CASES = [
    ("SANDBOX_ARGS is imported, not copied", sandbox_args_are_imported_not_copied),
    ("the scaffolded command carries every restriction", the_scaffolded_command_carries_every_restriction),
    ("the minimal ablation is sandboxed too", the_minimal_ablation_is_sandboxed_too),
    ("an empty MCP config is written and passed", the_empty_mcp_config_is_written_and_is_empty),
    ("build_command spreads the sandbox", the_builder_actually_spreads_the_sandbox),
    ("main() calls build_command", main_actually_calls_the_builder),
    ("no invocation bypasses the builder", no_invocation_bypasses_the_builder),
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
    print(f"{len(CASES) - len(failures)}/{len(CASES)} inference sandbox checks behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
