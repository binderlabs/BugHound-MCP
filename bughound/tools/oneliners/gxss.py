"""Gxss wrapper — reflection check with context analysis.

Like kxss but shows WHERE the value is reflected (in attribute, tag, script, comment).
If the binary is not installed, uses a pure-Python fallback via aiohttp.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp

from bughound.core import tool_runner

BINARY = "Gxss"
_DEFAULT_PROBE = "BugHoundProbe"

# Context detection patterns
_CONTEXT_PATTERNS = {
    "in_script": re.compile(r"<script[^>]*>[^<]*{probe}[^<]*</script>", re.IGNORECASE | re.DOTALL),
    "in_attribute": re.compile(r'(?:value|href|src|action|data-\w+)\s*=\s*["\'][^"\']*{probe}', re.IGNORECASE),
    "in_tag": re.compile(r"<[^>]*{probe}[^>]*>", re.IGNORECASE),
    "in_comment": re.compile(r"<!--[^>]*{probe}[^>]*-->", re.IGNORECASE),
    "in_body": re.compile(r"{probe}"),
}


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    urls: list[str], probe: str = _DEFAULT_PROBE, timeout: int = 60,
) -> list[dict]:
    """Check which URLs reflect the probe value and determine reflection context.

    Returns list of dicts: {url, param, reflected, context, probe}.
    Context is one of: in_script, in_attribute, in_tag, in_comment, in_body.
    """
    if not urls:
        return []

    if is_available():
        result = await _run_binary(urls, probe, timeout)
        if result is not None:
            return result

    return await _python_fallback(urls, probe, timeout)


async def _run_binary(urls: list[str], probe: str, timeout: int) -> list[dict] | None:
    """Pipe URLs into Gxss binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    proc = await asyncio.create_subprocess_exec(
        binary_path, "-p", probe,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return None

    results: list[dict] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        # Gxss output format: URL [context info]
        results.append({
            "url": line,
            "reflected": True,
            "probe": probe,
            "context": _parse_gxss_context(line),
            "source": "gxss",
        })
    return results


def _parse_gxss_context(line: str) -> str:
    """Parse Gxss output line to extract context type."""
    lower = line.lower()
    if "unfiltered" in lower or "special" in lower:
        return "in_attribute"
    if "script" in lower:
        return "in_script"
    if "attribute" in lower:
        return "in_attribute"
    if "tag" in lower:
        return "in_tag"
    if "comment" in lower:
        return "in_comment"
    return "in_body"


async def _python_fallback(
    urls: list[str], probe: str, timeout: int,
) -> list[dict]:
    """Pure-Python reflection check with context analysis."""
    results: list[dict] = []
    sem = asyncio.Semaphore(10)

    # Build context regexes for this probe
    ctx_patterns = {
        name: re.compile(pattern.pattern.replace("{probe}", re.escape(probe)), pattern.flags)
        for name, pattern in _CONTEXT_PATTERNS.items()
    }

    async def _check(session: aiohttp.ClientSession, url: str) -> None:
        async with sem:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                return

            for param_name in params:
                new_params = dict(params)
                new_params[param_name] = [probe]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                    ) as resp:
                        body = await resp.text()
                        if probe not in body:
                            continue

                        # Determine reflection context
                        context = "in_body"
                        for ctx_name, ctx_re in ctx_patterns.items():
                            if ctx_name == "in_body":
                                continue
                            if ctx_re.search(body):
                                context = ctx_name
                                break

                        results.append({
                            "url": url,
                            "param": param_name,
                            "reflected": True,
                            "context": context,
                            "probe": probe,
                            "source": "python_fallback",
                        })
                except Exception:
                    pass

    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check(session, url) for url in urls[:200]]
        await asyncio.gather(*tasks)

    return results
