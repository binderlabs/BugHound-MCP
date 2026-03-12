"""bhedak wrapper — upgraded qsreplace with append mode and param targeting.

If the binary is not installed, uses a pure-Python fallback.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from bughound.core import tool_runner

BINARY = "bhedak"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    urls: list[str],
    payload: str,
    append: bool = False,
    timeout: int = 30,
) -> list[str]:
    """Replace (or append to) all query param values with payload.

    Args:
        urls: List of URLs to process.
        payload: Value to inject into parameters.
        append: If True, append payload to existing value instead of replacing.
        timeout: Max seconds for binary execution.

    Returns deduplicated modified URLs.
    """
    if not urls:
        return []

    if is_available():
        result = await _run_binary(urls, payload, append, timeout)
        if result is not None:
            return result

    return _python_fallback(urls, payload, append)


async def _run_binary(
    urls: list[str], payload: str, append: bool, timeout: int,
) -> list[str] | None:
    """Pipe URLs into bhedak binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    args = [binary_path, payload]
    if append:
        args.append("-a")

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

    results = [
        line.strip()
        for line in stdout.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    return list(dict.fromkeys(results))


def _python_fallback(urls: list[str], payload: str, append: bool) -> list[str]:
    """Pure-Python bhedak: replace or append param values."""
    seen: set[str] = set()
    results: list[str] = []

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        if append:
            new_params = {k: [v[0] + payload if v else payload] for k, v in params.items()}
        else:
            new_params = {k: [payload] for k in params}

        new_query = urlencode(new_params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))

        # Deduplicate by URL template
        template = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(sorted(params.keys()))}"
        if template not in seen:
            seen.add(template)
            results.append(new_url)

    return results
