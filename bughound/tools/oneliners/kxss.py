"""kxss wrapper — check if URL parameters are reflected in response.

If the binary is not installed, uses a pure-Python fallback via aiohttp.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp

from bughound.core import tool_runner

BINARY = "kxss"
_CANARY = "kxss8bh"
_DANGEROUS_CHARS = re.compile(r'[<>"\'`]')


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(urls: list[str], timeout: int = 60) -> list[dict]:
    """Check which URLs reflect parameter values unfiltered.

    Returns list of dicts: {url, param, reflected, unfiltered_chars}.
    """
    if not urls:
        return []

    if is_available():
        return await _run_binary(urls, timeout)
    return await _python_fallback(urls, timeout)


async def _run_binary(urls: list[str], timeout: int) -> list[dict]:
    """Pipe URLs into kxss binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return await _python_fallback(urls, timeout)

    proc = await asyncio.create_subprocess_exec(
        binary_path,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return await _python_fallback(urls, timeout)

    results: list[dict] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        # kxss output: URL param unfiltered_chars
        results.append({"url": line, "reflected": True, "source": "kxss"})
    return results


async def _python_fallback(urls: list[str], timeout: int) -> list[dict]:
    """Pure-Python reflection check: inject canary, check if reflected."""
    results: list[dict] = []
    sem = asyncio.Semaphore(10)

    async def _check(session: aiohttp.ClientSession, url: str) -> None:
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return

            for param_name in params:
                test_value = f"{_CANARY}<>\"'"
                new_params = dict(params)
                new_params[param_name] = [test_value]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                        body = await resp.text()
                        if _CANARY in body:
                            # Check which dangerous chars are reflected
                            unfiltered = []
                            for ch in '<>"\'`':
                                if f"{_CANARY}{ch}" in body or ch in body[body.index(_CANARY):body.index(_CANARY)+50]:
                                    unfiltered.append(ch)
                            results.append({
                                "url": url,
                                "param": param_name,
                                "reflected": True,
                                "unfiltered_chars": unfiltered,
                                "source": "python_fallback",
                            })
                except Exception:
                    pass

    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check(session, url) for url in urls[:100]]
        await asyncio.gather(*tasks)

    return results
