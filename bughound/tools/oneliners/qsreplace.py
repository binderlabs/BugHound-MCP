"""qsreplace wrapper — replace query string parameter values.

If the binary is not installed, uses a pure-Python fallback.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from bughound.core import tool_runner

BINARY = "qsreplace"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(urls: list[str], replacement: str, timeout: int = 30) -> list[str]:
    """Replace all query param values with *replacement*.

    Returns deduplicated URLs with substituted values.
    Uses the binary if available, otherwise pure-Python fallback.
    """
    if not urls:
        return []

    if is_available():
        return await _run_binary(urls, replacement, timeout)
    return _python_fallback(urls, replacement)


async def _run_binary(urls: list[str], replacement: str, timeout: int) -> list[str]:
    """Pipe URLs into qsreplace binary."""
    stdin_data = "\n".join(urls).encode()

    import asyncio

    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return _python_fallback(urls, replacement)

    proc = await asyncio.create_subprocess_exec(
        binary_path, replacement,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return _python_fallback(urls, replacement)

    results = [line.strip() for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
    return list(dict.fromkeys(results))


def _python_fallback(urls: list[str], replacement: str) -> list[str]:
    """Pure-Python qsreplace: for each URL, replace every param value."""
    seen: set[str] = set()
    results: list[str] = []

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            continue

        new_params = {k: [replacement] * len(v) for k, v in params.items()}
        new_query = urlencode(new_params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))

        # Deduplicate by URL template (same host+path+param names)
        template = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(sorted(params.keys()))}"
        if template not in seen:
            seen.add(template)
            results.append(new_url)

    return results
