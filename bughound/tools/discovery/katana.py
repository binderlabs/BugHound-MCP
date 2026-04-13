"""Katana active web crawler wrapper (ProjectDiscovery).

Crawls live hosts for URLs, JS files, forms, and links.
Light mode: fast, shallow (depth 2). Deep mode: form extraction, JS crawl (depth 5).
Uses -jsonl output for structured parsing.
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


async def execute_light(
    target: str,
    timeout: int = 120,
) -> ToolResult:
    """Light crawl — fast, shallow, passive-only JS parsing."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    result = await tool_runner.run(
        BINARY,
        ["-u", url, "-d", "2", "-jsonl", "-silent", "-js-crawl"],
        target=target,
        timeout=timeout,
    )
    return _parse_results(result)


async def execute_deep(
    target: str,
    timeout: int = TIMEOUT,
    scope: str = "rdn",
) -> ToolResult:
    """Deep crawl — form extraction, JS crawl, deeper depth.

    scope: 'fqdn' = exact hostname only, 'rdn' = root domain (includes www).
    """
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    result = await tool_runner.run(
        BINARY,
        [
            "-u", url,
            "-d", "5",
            "-jsonl", "-silent",
            "-js-crawl",
            "-form-extraction",
            "-automatic-form-fill",
            "-field-scope", scope,
        ],
        target=target,
        timeout=timeout,
    )
    return _parse_results(result)


async def execute(
    target: str,
    depth: int = 3,
    timeout: int = TIMEOUT,
    scope: str = "rdn",
) -> ToolResult:
    """Crawl with custom depth and scope."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"

    result = await tool_runner.run(
        BINARY,
        ["-u", url, "-d", str(depth), "-jsonl", "-silent", "-js-crawl",
         "-field-scope", scope],
        target=target,
        timeout=timeout,
    )
    return _parse_results(result)


async def execute_batch(
    targets: list[str],
    depth: int = 3,
    timeout: int = TIMEOUT,
    scope: str = "rdn",
    concurrency: int = 10,
) -> ToolResult:
    """Crawl multiple URLs in ONE katana invocation using -list flag.

    Much faster than running katana N times sequentially — katana handles
    parallelism internally with -c (concurrency).
    """
    if not targets:
        return ToolResult(
            tool="katana", success=True, results=[], result_count=0,
        )

    # Normalize URLs
    normalized = [
        t if t.startswith(("http://", "https://")) else f"https://{t}"
        for t in targets
    ]

    # Write URLs to temp file (katana -list reads from file)
    import tempfile, os
    fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="bh_katana_list_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(normalized))

        result = await tool_runner.run(
            BINARY,
            [
                "-list", tmp,
                "-d", str(depth),
                "-c", str(concurrency),  # internal concurrency
                "-jsonl", "-silent",
                "-js-crawl",
                "-form-extraction",
                "-automatic-form-fill",
                "-field-scope", scope,
            ],
            target=f"{len(targets)} URLs",
            timeout=timeout,
        )
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    return _parse_results(result)


def _parse_results(result: ToolResult) -> ToolResult:
    """Parse JSONL output into structured URL list."""
    if not result.success:
        return result

    urls: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    seen: set[str] = set()

    for line in result.results:
        try:
            obj = json.loads(line)
            req = obj.get("request", {})
            found_url = req.get("endpoint", req.get("url", "")).strip()

            if found_url and found_url.startswith("http") and found_url not in seen:
                seen.add(found_url)
                entry: dict[str, Any] = {
                    "url": found_url,
                    "source": req.get("source", ""),
                    "tag": req.get("tag", ""),
                }

                # Extract form data if present in response
                resp = obj.get("response", {})
                if resp.get("forms"):
                    for form in resp["forms"]:
                        forms.append({
                            "page_url": found_url,
                            "action": form.get("action", ""),
                            "method": (form.get("method") or "GET").upper(),
                            "inputs": form.get("inputs", []),
                            "source": "katana",
                        })

                urls.append(entry)
        except (json.JSONDecodeError, AttributeError):
            line = line.strip()
            if line.startswith("http") and line not in seen:
                seen.add(line)
                urls.append({"url": line, "source": "", "tag": ""})

    result.results = urls
    result.result_count = len(urls)
    # Attach forms as extra metadata
    if forms:
        result.warnings = [f"__forms__:{json.dumps(forms)}"]
    return result
