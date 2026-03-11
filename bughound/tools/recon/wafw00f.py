"""Wafw00f WAF/CDN detection wrapper.

Detects Web Application Firewalls on live hosts.
Uses -o - -f json for structured output to stdout.
"""

from __future__ import annotations

import json
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "wafw00f"
TIMEOUT = 90


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target: str,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Run wafw00f against a single URL or domain."""
    # Ensure target has a scheme for wafw00f
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    result = await tool_runner.run(
        BINARY,
        [target, "-o", "-", "-f", "json"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # wafw00f JSON output may be wrapped in text. Extract the JSON array.
    raw = "\n".join(result.results)
    waf_results: list[dict[str, Any]] = []

    start = raw.find("[")
    end = raw.rfind("]")
    if start != -1 and end != -1:
        try:
            waf_results = json.loads(raw[start : end + 1])
        except json.JSONDecodeError:
            pass

    # Normalize to consistent format
    parsed: list[dict[str, Any]] = []
    for entry in waf_results:
        parsed.append({
            "url": entry.get("url", target),
            "waf": entry.get("firewall", entry.get("waf", None)),
            "manufacturer": entry.get("manufacturer", ""),
            "detected": entry.get("detected", False),
        })

    result.results = parsed
    result.result_count = len(parsed)
    return result
