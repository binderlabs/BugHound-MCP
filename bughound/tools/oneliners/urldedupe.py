"""urldedupe wrapper — smart URL deduplication by parameter structure.

Unlike simple string deduplication, urldedupe keeps one URL per unique
parameter structure (same host + path + param names = one representative).
If the binary is not installed, uses a pure-Python fallback.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from bughound.core import tool_runner

BINARY = "urldedupe"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    urls: list[str], similar: bool = True, timeout: int = 30,
) -> list[str]:
    """Smart deduplicate URLs by parameter structure.

    Args:
        urls: List of URLs to deduplicate.
        similar: If True, use similar mode (-s) for aggressive dedup.
        timeout: Max seconds for binary execution.

    Returns deduplicated URLs.
    """
    if not urls:
        return []

    if is_available():
        result = await _run_binary(urls, similar, timeout)
        if result is not None:
            return result

    return _python_fallback(urls, similar)


async def _run_binary(
    urls: list[str], similar: bool, timeout: int,
) -> list[str] | None:
    """Pipe URLs into urldedupe binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    args = [binary_path]
    if similar:
        args.append("-s")

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None

    return [
        line.strip()
        for line in stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def _python_fallback(urls: list[str], similar: bool) -> list[str]:
    """Pure-Python urldedupe: deduplicate by param structure template.

    Creates a template key from: scheme + netloc + normalized_path + sorted_param_names.
    In similar mode, also normalizes numeric path segments and UUIDs.
    """
    seen: set[str] = set()
    results: list[str] = []

    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.lower().rstrip("/")

        if similar:
            # Normalize numeric segments: /users/123/posts → /users/{N}/posts
            path = re.sub(r"/\d+(?=/|$)", "/{N}", path)
            # Normalize UUIDs
            path = re.sub(
                r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "/{UUID}", path, flags=re.IGNORECASE,
            )
            # Normalize hex hashes (32+ chars)
            path = re.sub(r"/[0-9a-f]{32,}", "/{HASH}", path, flags=re.IGNORECASE)

        # Extract and sort param names
        param_names = sorted(set(re.findall(r"[?&]([^=&]+)=", parsed.query)))
        template = f"{parsed.scheme}://{parsed.netloc}{path}?{'&'.join(param_names)}"

        if template not in seen:
            seen.add(template)
            results.append(url)

    return results
