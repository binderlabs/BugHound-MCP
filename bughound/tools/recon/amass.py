"""Amass passive subdomain enumeration wrapper.

v5 changed the CLI: passive is now the default, -json flag removed.
Output is plain text (one subdomain per line) to stdout.
Uses -timeout 1 (minutes) and -nocolor to keep execution brief.
"""

from __future__ import annotations

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "amass"
TIMEOUT = 300  # 5 min — amass is slow but thorough, only used in deep mode


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run amass enum against a domain (passive by default in v5).

    Only called from deep enumeration — amass is too slow for light mode.
    Uses -timeout 4 (minutes, amass internal) so it finishes before our process timeout.
    """
    result = await tool_runner.run(
        BINARY,
        ["enum", "-d", target, "-nocolor", "-timeout", "4"],
        target=target,
        timeout=timeout,
    )

    if not result.success:
        return result

    # v5 outputs plain text: one subdomain per line
    subdomains: set[str] = set()
    for line in result.results:
        line = line.strip().lower()
        if line and "." in line and not line.startswith("#"):
            subdomains.add(line)

    deduped = sorted(subdomains)
    result.results = deduped
    result.result_count = len(deduped)
    return result
