"""Dalfox XSS scanner wrapper.

Used in Stage 4 for XSS validation. Parses JSON output for confirmed XSS findings.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "dalfox"
TIMEOUT = 300


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target_url: str,
    *,
    skip_bav: bool = True,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Run dalfox against a single URL.

    target_url: URL with parameter to test (e.g. https://example.com/page?q=test).
    skip_bav: skip basic auth verification.
    timeout: overall execution timeout.

    Returns ToolResult with confirmed XSS findings.
    """
    # Use temp file for JSON output
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="bughound_dalfox_",
    )
    tmp.close()
    output_file = Path(tmp.name)

    args = [
        "url", target_url,
        "-o", str(output_file),
        "--format", "json",
        "--silence",
    ]

    if skip_bav:
        args.append("--skip-bav")

    try:
        result = await tool_runner.run(
            BINARY, args, target=target_url, timeout=timeout,
        )
    finally:
        # Parse output file regardless of exit code (dalfox may still write findings)
        findings = _parse_output_file(output_file)
        if output_file.exists():
            output_file.unlink(missing_ok=True)

    if not result.success and not findings:
        return result

    # Override results with parsed findings
    result.success = True
    result.results = findings
    result.result_count = len(findings)
    return result


def _parse_output_file(output_file: Path) -> list[dict[str, Any]]:
    """Parse dalfox JSON output file."""
    if not output_file.exists():
        return []

    try:
        text = output_file.read_text().strip()
        if not text:
            return []

        data = json.loads(text)
        if not isinstance(data, list):
            data = [data]

        findings: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            # Skip empty dicts — dalfox writes [{}] when no XSS found
            if not item or not any(item.get(k) for k in ("data", "url", "payload", "param")):
                continue
            findings.append({
                "xss_type": _classify_xss_type(item),
                "url": item.get("data", item.get("url", "")),
                "payload": item.get("payload", ""),
                "param": item.get("param", ""),
                "evidence": item.get("evidence", item.get("data", "")),
                "severity": item.get("severity", "high"),
                "cwe": item.get("cwe", "CWE-79"),
            })
        return findings

    except (json.JSONDecodeError, OSError):
        return []


def _classify_xss_type(item: dict[str, Any]) -> str:
    """Classify XSS as reflected, stored, or DOM-based."""
    xss_type = (item.get("type") or "").lower()
    payload = (item.get("payload") or "").lower()

    if "dom" in xss_type or "document." in payload:
        return "dom"
    if "stored" in xss_type or "persist" in xss_type:
        return "stored"
    return "reflected"
