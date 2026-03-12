"""Katana active web crawler wrapper (ProjectDiscovery).

Crawls live hosts for URLs, JS files, forms, and links.
Uses -jsonl output for structured parsing. Includes JS crawling.
"""

from __future__ import annotations

import json
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "katana"
TIMEOUT = 300


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target: str,
    depth: int = 3,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Crawl a single URL with katana.

    Returns URLs discovered during crawl with source attribution.
    """
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    result = await tool_runner.run(
        BINARY,
        ["-u", url, "-d", str(depth), "-jsonl", "-silent", "-js-crawl"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # Parse JSONL: each line is {"request":{"url":"..."},"response":{...}}
    urls: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in result.results:
        try:
            obj = json.loads(line)
            # katana JSONL has request.endpoint or request.url
            req = obj.get("request", {})
            found_url = req.get("endpoint", req.get("url", "")).strip()
            if found_url and found_url.startswith("http") and found_url not in seen:
                seen.add(found_url)
                urls.append({
                    "url": found_url,
                    "source": obj.get("request", {}).get("source", ""),
                    "tag": obj.get("request", {}).get("tag", ""),
                })
        except (json.JSONDecodeError, AttributeError):
            # Fallback: plain URL line
            line = line.strip()
            if line.startswith("http") and line not in seen:
                seen.add(line)
                urls.append({"url": line, "source": "", "tag": ""})

    result.results = urls
    result.result_count = len(urls)
    return result
