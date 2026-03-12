"""Amass passive subdomain enumeration wrapper.

Amass v5 is a two-step process:
  1. `amass enum -d target` — enumerates and stores results in its OAM database
  2. `amass subs -d target -names` — extracts subdomain names from the database

stdout is empty during enum (results go to DB), so we run both steps.
Only used in deep enumeration — too slow for light mode.
"""

from __future__ import annotations

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "amass"
TIMEOUT = 660  # 11 min — amass is slow but thorough, only used in deep mode


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Run amass enum + subs to discover subdomains.

    Only called from deep enumeration — amass is too slow for light mode.
    Step 1: enum populates the OAM database (up to 10 min).
    Step 2: subs extracts names from the database to stdout.
    """
    # Step 1: enumerate (results go to internal DB, stdout is empty)
    enum_result = await tool_runner.run(
        BINARY,
        ["enum", "-d", target, "-nocolor", "-timeout", "10"],
        target=target,
        timeout=timeout,
    )

    # enum may exit non-zero but still populate the DB — always try step 2
    # Step 2: extract subdomains from DB
    subs_result = await tool_runner.run(
        BINARY,
        ["subs", "-d", target, "-names"],
        target=target,
        timeout=60,
    )

    if not subs_result.success and not enum_result.success:
        return enum_result  # both failed, return the enum error

    # Parse plain text output: one subdomain per line
    subdomains: set[str] = set()
    for line in subs_result.results:
        line = line.strip().lower()
        if line and "." in line and not line.startswith("#"):
            subdomains.add(line)

    # Use subs_result as the return value, override with parsed data
    result = subs_result if subs_result.success else enum_result
    result.success = True
    result.results = sorted(subdomains)
    result.result_count = len(subdomains)
    return result
