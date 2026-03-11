"""Certificate Transparency (crt.sh) subdomain discovery wrapper.

API-based — no binary needed. Always available.
"""

from __future__ import annotations

import asyncio

import aiohttp
import structlog

from bughound.schemas.models import ToolResult

logger = structlog.get_logger()

TIMEOUT = 30


def is_available() -> bool:
    return True  # API-based, always available


async def execute(target: str, timeout: int = TIMEOUT) -> ToolResult:
    """Query crt.sh for certificate transparency subdomains."""
    import time

    url = f"https://crt.sh/?q=%.{target}&output=json"
    start = time.monotonic()

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status != 200:
                    return ToolResult(
                        tool="crtsh",
                        target=target,
                        success=False,
                        errors=[f"crt.sh returned HTTP {resp.status}"],
                    )

                data = await resp.json(content_type=None)

    except asyncio.TimeoutError:
        return ToolResult(
            tool="crtsh",
            target=target,
            success=False,
            errors=[f"crt.sh request timed out after {timeout}s"],
        )
    except Exception as exc:
        return ToolResult(
            tool="crtsh",
            target=target,
            success=False,
            errors=[f"crt.sh request failed: {exc}"],
        )

    elapsed = time.monotonic() - start

    # Parse: each entry has "name_value" which may contain multiple names
    subdomains: set[str] = set()
    if isinstance(data, list):
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                clean = name.strip().lower().lstrip("*.")
                if clean and "." in clean:
                    subdomains.add(clean)

    deduped = sorted(subdomains)
    return ToolResult(
        tool="crtsh",
        target=target,
        success=True,
        execution_time_seconds=round(elapsed, 2),
        result_count=len(deduped),
        results=deduped,
        raw_output_lines=len(data) if isinstance(data, list) else 0,
    )
