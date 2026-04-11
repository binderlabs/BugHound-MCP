"""GAU (GetAllUrls) historical URL discovery wrapper.

Fetches known URLs from Wayback Machine, CommonCrawl, OTX, URLScan.
Outputs line-delimited URLs to stdout.
"""

from __future__ import annotations

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "gau"
# Bigger timeout — gau queries 4 APIs (wayback, commoncrawl, otx, urlscan)
# and can be very slow on large targets. waybackurls still runs alongside
# as a fast fallback for Wayback-only data.
TIMEOUT = 300


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run gau against a domain. Returns deduplicated URL list.

    Uses --threads 5 for parallelism. Skips OTX (often slow/rate-limited)
    by default — our passive_sources module queries OTX separately.
    """
    result = await tool_runner.run(
        BINARY,
        [
            target,
            "--subs",
            "--threads", "5",
            "--providers", "wayback,commoncrawl,urlscan",  # skip otx (slow)
            "--timeout", "30",  # per-provider timeout
        ],
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
