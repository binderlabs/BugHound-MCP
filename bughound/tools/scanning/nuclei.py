"""Nuclei vulnerability scanner wrapper.

The workhorse of Stage 4. Runs targeted template scans via tags/severity.
Parses JSONL output into structured finding dicts.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "nuclei"
TIMEOUT = 600


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target: str | list[str],
    *,
    tags: list[str] | None = None,
    severity: str | None = None,
    template_path: str | None = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    no_interactsh: bool = False,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Run nuclei against one or more targets.

    target: single URL or list of URLs.
    tags: nuclei template tags (e.g. ["sqli", "xss"]).
    severity: comma-separated severity filter (e.g. "critical,high,medium").
    template_path: specific template file/dir path.
    rate_limit: requests per second.
    concurrency: max concurrent template executions.
    no_interactsh: disable interactsh-based templates.
    timeout: overall execution timeout in seconds.

    Returns ToolResult with results as list of parsed finding dicts.
    """
    args = ["-jsonl", "-silent", "-no-color", "-disable-update-check", "-include-rr"]

    # Rate limit and concurrency
    args.extend(["-rate-limit", str(rate_limit)])
    args.extend(["-concurrency", str(concurrency)])

    # Interactsh control
    if no_interactsh:
        args.append("-no-interactsh")

    # Severity filter
    if severity:
        args.extend(["-severity", severity])

    # Template tags
    if tags:
        args.extend(["-tags", ",".join(tags)])

    # Specific template path
    if template_path:
        args.extend(["-t", template_path])

    # Target handling
    cleanup_file: Path | None = None

    if isinstance(target, list):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="bughound_nuclei_",
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

    # Parse JSONL output into structured finding dicts
    findings: list[dict[str, Any]] = []
    for line in result.results:
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        info = obj.get("info", {})
        # Capture response body (truncated) for FP validation
        response_body = ""
        if isinstance(obj.get("response"), str):
            response_body = obj["response"][:2000]
        finding = {
            "template_id": obj.get("template-id", "unknown"),
            "template_name": info.get("name", "Unknown"),
            "severity": info.get("severity", "unknown").lower(),
            "description": info.get("description", ""),
            "host": obj.get("host", ""),
            "matched_at": obj.get("matched-at", ""),
            "extracted_results": obj.get("extracted-results", []),
            "curl_command": obj.get("curl-command", ""),
            "matcher_name": obj.get("matcher-name", ""),
            "type": obj.get("type", "http"),
            "response_body": response_body,
        }
        findings.append(finding)

    # Sort by severity
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 5))

    result.results = findings
    result.result_count = len(findings)
    return result
