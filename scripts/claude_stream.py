"""Strict Claude CLI parser extracted mechanically from evaluate_historical.

The research implementation remains frozen.
"""
from __future__ import annotations
import json
from typing import Any
TIMEOUT_S = 900
STRUCTURED_OUTPUT_TOOL = "StructuredOutput"
BAD_STOPS = ("max_tokens", "refusal", "model_context_window_exceeded")

def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def strict_loads(text: str) -> Any:
    """Parse JSON exactly: duplicate keys and non-finite numbers are errors."""
    def bad_constant(name: str) -> Any:
        raise ValueError(f"non-standard JSON constant {name}")
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=bad_constant)


def items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def analyze_stream(raw: bytes, returncode: int | None, timed_out: bool, schema_requested: bool,
                   expected_model: str | None = None) -> dict[str, Any]:
    """Strict terminal checks. Errors, refusals, truncation, empty results and tools all fail."""
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        errors.append("stream is not UTF-8")
        text = ""
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = strict_loads(line)
        except ValueError as error:
            errors.append(f"stream line {n} is not strict JSON: {error}")
            continue
        if isinstance(event, dict):
            events.append(event)
        else:
            errors.append(f"stream line {n} is not an object")
    if timed_out:
        errors.append(f"timed out after {TIMEOUT_S}s")
    if returncode != 0:
        errors.append(f"process exit status {returncode}")
    allowed = {STRUCTURED_OUTPUT_TOOL} if schema_requested else set()
    init = next((x for x in events if x.get("type") == "system" and x.get("subtype") == "init"), None)
    if init is None:
        errors.append("no init event")
    else:
        extra = [t for t in items(init.get("tools")) if t not in allowed]
        if extra:
            errors.append(f"tools available: {extra}")
        if items(init.get("mcp_servers")):
            errors.append("MCP servers attached")
    formatter_inputs, formatter_ids, tool_names, models, message_ids, request_ids = [], set(), [], set(), [], []
    for event in events:
        if event.get("type") == "assistant":
            message = event.get("message") or {}
            if message.get("model"):
                models.add(message["model"])
            if message.get("id"):
                message_ids.append(message["id"])
            if event.get("request_id"):
                request_ids.append(event["request_id"])
            if message.get("stop_reason") in BAD_STOPS:
                errors.append(f"assistant stop_reason {message['stop_reason']}")
            for block in items(message.get("content")):
                if isinstance(block, dict) and block.get("type") in ("tool_use", "server_tool_use", "mcp_tool_use"):
                    tool_names.append(block.get("name"))
                    if block.get("type") == "tool_use" and block.get("name") in allowed:
                        formatter_inputs.append(block.get("input"))
                        formatter_ids.add(block.get("id"))
                    else:
                        errors.append(f"tool call not allowed: {block.get('name')}")
        elif event.get("type") == "user":
            for block in items((event.get("message") or {}).get("content")):
                if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") not in formatter_ids:
                    errors.append("tool result for a non-formatter tool")
    results = [x for x in events if x.get("type") == "result"]
    result = results[-1] if results else None
    if len(results) != 1:
        errors.append(f"expected exactly one result event, found {len(results)}")
    elif events[-1] is not result:
        errors.append("result event is not terminal")
    response, canonical = None, set()
    if result is not None:
        if result.get("subtype") != "success":
            errors.append(f"result subtype {result.get('subtype')!r}")
        if result.get("is_error") is not False:
            errors.append("result is_error is not false")
        if result.get("terminal_reason") != "completed":
            errors.append(f"terminal_reason {result.get('terminal_reason')!r}")
        if result.get("api_error_status") is not None:
            errors.append(f"api_error_status {result.get('api_error_status')!r}")
        if result.get("stop_reason") in BAD_STOPS:
            errors.append(f"result stop_reason {result['stop_reason']}")
        if result.get("permission_denials"):
            errors.append("permission denials recorded")
        for model, usage in (result.get("modelUsage") or {}).items():
            models.add(model)
            if isinstance(usage, dict) and usage.get("canonicalModel"):
                canonical.add(usage["canonicalModel"])
        if schema_requested:
            response = result.get("structured_output")
            if response is None:
                errors.append("schema requested but no structured_output")
            elif not formatter_inputs or formatter_inputs[-1] != response:
                errors.append("structured_output differs from the formatter input")
        elif isinstance(result.get("result"), str) and result["result"].strip():
            try:
                response = strict_loads(result["result"])
            except ValueError as error:
                errors.append(f"result text is not strict JSON: {error}")
        else:
            errors.append("empty result")
    if expected_model is not None and canonical != {expected_model}:
        errors.append(f"served model identity {sorted(canonical) or None} is not exactly {expected_model}")
    receipt = {"session_ids": sorted({x["session_id"] for x in events if isinstance(x.get("session_id"), str)}),
               "result_uuid": result.get("uuid") if result else None, "message_ids": message_ids, "request_ids": request_ids,
               "models_reported": sorted(models), "canonical_models": sorted(canonical),
               "model_served": next(iter(canonical)) if len(canonical) == 1 else None, "tool_names": tool_names,
               "subtype": result.get("subtype") if result else None, "is_error": result.get("is_error") if result else None,
               "terminal_reason": result.get("terminal_reason") if result else None,
               "stop_reason": result.get("stop_reason") if result else None, "num_turns": result.get("num_turns") if result else None,
               "usage": result.get("usage") if result else None, "model_usage": result.get("modelUsage") if result else None,
               "total_cost_usd": result.get("total_cost_usd") if result else None,
               "provider_duration_ms": result.get("duration_ms") if result else None,
               "provider_duration_api_ms": result.get("duration_api_ms") if result else None}
    return {"errors": errors, "response": response, "receipt": receipt}
