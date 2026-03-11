"""Amass passive subdomain enumeration wrapper.

Uses passive mode only for speed. Outputs JSONL with subdomain names.
"""

from __future__ import annotations

import json

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "amass"
TIMEOUT = 120


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run amass enum -passive against a domain."""
    result = await tool_runner.run(
        BINARY,
        ["enum", "-passive", "-d", target, "-json", "-"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # Parse JSONL: each line has {"name": "sub.example.com", ...}
    subdomains: set[str] = set()
    for line in result.results:
        try:
            obj = json.loads(line)
            name = obj.get("name", "").strip().lower()
            if name:
                subdomains.add(name)
        except (json.JSONDecodeError, AttributeError):
            # Fallback: treat line as plain subdomain
            line = line.strip().lower()
            if line and "." in line:
                subdomains.add(line)

    deduped = sorted(subdomains)
    result.results = deduped
    result.result_count = len(deduped)
    return result
