"""GoSpider active web crawler wrapper.

Crawls live hosts for URLs, JS files, forms, and links.
Uses --json output for structured parsing.
"""

from __future__ import annotations

import json
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "gospider"
TIMEOUT = 300


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target: str,
    depth: int = 2,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Crawl a single URL with gospider.

    Returns URLs discovered during crawl with source attribution.
    """
    # Ensure target has scheme
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    result = await tool_runner.run(
        BINARY,
        ["-s", url, "-d", str(depth), "--json", "-q", "--no-redirect"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # Parse JSONL: each line is {"output": "url", "type": "...", "source": "..."}
    urls: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in result.results:
        try:
            obj = json.loads(line)
            found_url = obj.get("output", "").strip()
            if found_url and found_url.startswith("http") and found_url not in seen:
                seen.add(found_url)
                urls.append({
                    "url": found_url,
                    "type": obj.get("type", ""),
                    "source": obj.get("source", ""),
                    "tag": obj.get("tag", ""),
                })
        except (json.JSONDecodeError, AttributeError):
            continue

    result.results = urls
    result.result_count = len(urls)
    return result
