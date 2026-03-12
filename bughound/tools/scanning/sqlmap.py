"""SQLMap SQL injection scanner wrapper.

Used in Stage 4 for SQL injection validation. Runs in --batch mode (non-interactive).
Fast validation via --technique=BEU (boolean, error, union — no time-based).
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "sqlmap"
TIMEOUT = 300


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target_url: str,
    *,
    level: int = 1,
    risk: int = 1,
    technique: str = "BEU",
    forms: bool = False,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Run sqlmap against a single URL.

    target_url: URL with parameter (e.g. https://example.com/page?id=1).
    level: sqlmap level (1-5). Default 1 for speed.
    risk: sqlmap risk (1-3). Default 1 for safety.
    technique: injection techniques to test (B=boolean, E=error, U=union, T=time, S=stacked).
    forms: test forms on the page.
    timeout: overall execution timeout.

    Returns ToolResult with injection details if vulnerable.
    """
    args = [
        "-u", target_url,
        "--batch",           # non-interactive
        "--random-agent",
        "--level", str(level),
        "--risk", str(risk),
        "--technique", technique,
        "--threads", "1",
        "--disable-coloring",
    ]

    if forms:
        args.append("--forms")

    # Don't dump data - just detect injection
    args.append("--dbs")

    result = await tool_runner.run(
        BINARY, args, target=target_url, timeout=timeout,
    )

    if not result.success:
        return result

    # Parse sqlmap stdout for injection confirmation
    output = "\n".join(result.results) if isinstance(result.results, list) else ""
    parsed = _parse_output(output, target_url)
    result.results = [parsed] if parsed.get("vulnerable") else []
    result.result_count = 1 if parsed.get("vulnerable") else 0
    return result


def _parse_output(output: str, target_url: str) -> dict[str, Any]:
    """Parse sqlmap stdout for injection results."""
    vulnerable = False
    payloads: list[str] = []
    db_type = ""
    injectable_params: list[str] = []

    for line in output.splitlines():
        line_stripped = line.strip()

        # Detect vulnerability confirmation
        if "is vulnerable" in line_stripped or "appears to be" in line_stripped:
            vulnerable = True

        # Extract payloads
        if "Payload:" in line_stripped:
            payload = line_stripped.split("Payload:", 1)[1].strip()
            if payload:
                payloads.append(payload)

        # Extract DB type
        db_match = re.search(r"back-end DBMS:\s*(.+)", line_stripped)
        if db_match:
            db_type = db_match.group(1).strip()

        # Extract injectable parameter
        param_match = re.search(r"Parameter:\s*(\S+)", line_stripped)
        if param_match:
            injectable_params.append(param_match.group(1))

    return {
        "vulnerable": vulnerable,
        "target_url": target_url,
        "injectable_params": list(set(injectable_params)),
        "db_type": db_type,
        "payloads": payloads[:5],
        "technique": "sqlmap",
    }
