"""Trufflehog secret verification wrapper.

Verifies secrets found by js_analyzer by calling the actual API.
Verified = ACTIVE secret = CRITICAL finding.
Unverified = maybe-real = MEDIUM confidence.

Integration in discover.py Phase 2C (JS analysis) as an optional verification layer.
"""

from __future__ import annotations

import json
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "trufflehog"
TIMEOUT = 600


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def scan_filesystem(
    path: str,
    *,
    only_verified: bool = True,
    timeout: int = 300,
) -> ToolResult:
    """Scan a local directory/file for verified secrets.

    path: absolute path to directory or single file.
    only_verified: if True, trufflehog calls the API to verify secrets are live.
    timeout: overall execution timeout.
    """
    args = ["filesystem", path, "--json", "--no-update"]
    if only_verified:
        args.append("--only-verified")

    result = await tool_runner.run(BINARY, args, target=path, timeout=timeout)

    if result.success and result.results:
        parsed = _parse_output(result.results)
        result.results = parsed
        result.result_count = len(parsed)

    return result


async def scan_git(
    repo_url: str,
    *,
    only_verified: bool = True,
    max_depth: int = 500,
    timeout: int = 600,
) -> ToolResult:
    """Scan a git repository (including history) for secrets.

    repo_url: git URL (https://github.com/org/repo or local .git path).
    only_verified: if True, trufflehog calls the API to verify secrets are live.
    max_depth: max number of commits to scan back through history.
    timeout: overall execution timeout.
    """
    args = [
        "git", repo_url, "--json", "--no-update",
        f"--max-depth={max_depth}",
    ]
    if only_verified:
        args.append("--only-verified")

    result = await tool_runner.run(BINARY, args, target=repo_url, timeout=timeout)

    if result.success and result.results:
        parsed = _parse_output(result.results)
        result.results = parsed
        result.result_count = len(parsed)

    return result


def _parse_output(raw_lines: list[Any]) -> list[dict[str, Any]]:
    """Parse trufflehog JSONL output into BugHound finding format."""
    findings: list[dict[str, Any]] = []

    for line in raw_lines:
        try:
            if isinstance(line, dict):
                entry = line
            elif isinstance(line, str):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
            else:
                continue

            if not isinstance(entry, dict):
                continue

            detector = entry.get("DetectorName", "unknown")
            verified = bool(entry.get("Verified", False))
            raw = str(entry.get("Raw", ""))
            redacted = str(entry.get("Redacted", raw[:20] + "..." if raw else ""))

            # Extract source file from metadata
            source_meta = entry.get("SourceMetadata", {}) or {}
            data_meta = source_meta.get("Data", {}) or {}
            fs_meta = data_meta.get("Filesystem", {}) or {}
            git_meta = data_meta.get("Git", {}) or {}

            source_file = fs_meta.get("file") or git_meta.get("file") or "unknown"
            commit = git_meta.get("commit", "")
            line_num = fs_meta.get("line") or git_meta.get("line", 0)

            # Severity based on verification + detector
            severity = "critical" if verified else "high"
            confidence = "HIGH" if verified else "MEDIUM"

            findings.append({
                "detector": detector,
                "verified": verified,
                "confidence": confidence,
                "severity": severity,
                "raw_snippet": redacted[:100],
                "source_file": source_file,
                "commit": commit,
                "line": line_num,
                "description": (
                    f"Verified {detector} secret" if verified
                    else f"Unverified {detector} secret"
                ),
            })
        except (json.JSONDecodeError, TypeError, KeyError, AttributeError):
            continue

    return findings
