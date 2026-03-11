"""GAU (GetAllUrls) historical URL discovery wrapper.

Fetches known URLs from Wayback Machine, CommonCrawl, OTX, URLScan.
Outputs line-delimited URLs to stdout.
"""

from __future__ import annotations

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "gau"
TIMEOUT = 120


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run gau against a domain. Returns deduplicated URL list."""
    result = await tool_runner.run(
        BINARY,
        [target, "--subs"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    urls = sorted(set(
        line.strip() for line in result.results
        if line.strip() and line.strip().startswith("http")
    ))
    result.results = urls
    result.result_count = len(urls)
    return result
