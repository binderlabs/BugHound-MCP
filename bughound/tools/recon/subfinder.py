"""Subfinder subdomain discovery wrapper.

Primary passive subdomain enumerator. Uses JSON output mode for structured parsing.
"""

from __future__ import annotations

import json

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "subfinder"
TIMEOUT = 60


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run subfinder against a domain. Returns subdomains as results list."""
    result = await tool_runner.run(
        BINARY,
        ["-d", target, "-silent", "-json"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # Parse JSONL output: each line is {"host": "sub.example.com", "source": "..."}
    subdomains: list[str] = []
    sources: dict[str, list[str]] = {}

    for line in result.results:
        try:
            obj = json.loads(line)
            host = obj.get("host", "").strip().lower()
            source = obj.get("source", "unknown")
            if host:
                subdomains.append(host)
                sources.setdefault(host, []).append(source)
        except (json.JSONDecodeError, AttributeError):
            continue

    deduped = sorted(set(subdomains))
    result.results = deduped
    result.result_count = len(deduped)

    return result
