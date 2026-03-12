"""unfurl wrapper — extract components from URLs (keys, values, paths, domains).

If the binary is not installed, uses a pure-Python fallback.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlparse

from bughound.core import tool_runner

BINARY = "unfurl"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    urls: list[str], mode: str = "keys", timeout: int = 30,
) -> list[str]:
    """Extract URL components.

    Modes: keys, values, paths, domains, apexes.
    """
    if not urls:
        return []

    if is_available():
        result = await _run_binary(urls, mode, timeout)
        if result is not None:
            return result

    return _python_fallback(urls, mode)


async def _run_binary(urls: list[str], mode: str, timeout: int) -> list[str] | None:
    """Pipe URLs into unfurl binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    proc = await asyncio.create_subprocess_exec(
        binary_path, "--unique", mode,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None

    return [line.strip() for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]


def _python_fallback(urls: list[str], mode: str) -> list[str]:
    """Pure-Python unfurl."""
    results: set[str] = set()

    for url in urls:
        parsed = urlparse(url)

        if mode == "keys":
            params = parse_qs(parsed.query, keep_blank_values=True)
            results.update(params.keys())

        elif mode == "values":
            params = parse_qs(parsed.query, keep_blank_values=True)
            for vals in params.values():
                results.update(v for v in vals if v)

        elif mode == "paths":
            path = parsed.path.strip("/")
            if path:
                results.add(path)
                # Also add individual path segments
                for segment in path.split("/"):
                    if segment:
                        results.add(segment)

        elif mode == "domains":
            if parsed.hostname:
                results.add(parsed.hostname)

        elif mode == "apexes":
            if parsed.hostname:
                parts = parsed.hostname.split(".")
                if len(parts) >= 2:
                    results.add(".".join(parts[-2:]))
                else:
                    results.add(parsed.hostname)

    return sorted(results)
