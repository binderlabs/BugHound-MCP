"""Findomain subdomain discovery wrapper.

Additional passive subdomain source. Outputs line-delimited text.
"""

from __future__ import annotations

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "findomain"
TIMEOUT = 60


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run findomain against a domain."""
    result = await tool_runner.run(
        BINARY,
        ["-t", target, "-q"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    deduped = sorted(set(
        line.strip().lower() for line in result.results if line.strip()
    ))
    result.results = deduped
    result.result_count = len(deduped)

    return result
