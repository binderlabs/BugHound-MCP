"""Assetfinder subdomain discovery wrapper.

Secondary passive subdomain source. Outputs line-delimited text.
"""

from __future__ import annotations

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "assetfinder"
TIMEOUT = 60


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run assetfinder against a domain."""
    result = await tool_runner.run(
        BINARY,
        ["--subs-only", target],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # Output is line-delimited subdomains
    deduped = sorted(set(
        line.strip().lower() for line in result.results if line.strip()
    ))
    result.results = deduped
    result.result_count = len(deduped)

    return result
