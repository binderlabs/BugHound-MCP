"""HTTPx probing + fingerprinting wrapper.

The most important tool in the pipeline. Probes targets for HTTP/HTTPS,
captures status codes, titles, technologies, server headers, redirect chains.
Uses -json mode for structured output.

Accepts either a single target string or a file path (for batch probing).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "httpx"
TIMEOUT = 180


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target: str | list[str],
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Run httpx against one or more targets.

    target can be:
      - a single domain/URL string
      - a list of domains/URLs (written to temp file, passed via -l)
    """
    args = [
        "-silent",
        "-json",
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-content-type",
        "-content-length",
        "-no-color",
    ]

    cleanup_file: Path | None = None

    if isinstance(target, list):
        # Write targets to temp file
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="bughound_httpx_"
        )
        for t in target:
            tmp.write(f"{t}\n")
        tmp.close()
        cleanup_file = Path(tmp.name)
        args.extend(["-l", tmp.name])
        target_label = f"{len(target)} targets"
    else:
        args.extend(["-u", target])
        target_label = target

    try:
        result = await tool_runner.run(
            BINARY, args, target=target_label, timeout=timeout,
        )
    finally:
        if cleanup_file and cleanup_file.exists():
            cleanup_file.unlink(missing_ok=True)

    if not result.success:
        return result

    # Parse JSONL output into structured host records
    hosts: list[dict[str, Any]] = []
    for line in result.results:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        host_record = {
            "url": obj.get("url", ""),
            "host": obj.get("host", ""),
            "port": obj.get("port", ""),
            "scheme": obj.get("scheme", ""),
            "status_code": obj.get("status_code", 0),
            "title": obj.get("title", ""),
            "web_server": obj.get("webserver", ""),
            "content_type": obj.get("content_type", ""),
            "content_length": obj.get("content_length", 0),
            "technologies": obj.get("tech", []),
            "cdn": obj.get("cdn_name", ""),
            "final_url": obj.get("final_url", ""),
            "chain": obj.get("chain", []),
            "response_time": obj.get("response_time", ""),
            "failed": obj.get("failed", False),
        }

        if not host_record["failed"] and host_record["status_code"] > 0:
            hosts.append(host_record)

    hosts.sort(key=lambda h: (h["status_code"], h["host"]))

    result.results = hosts
    result.result_count = len(hosts)
    return result
