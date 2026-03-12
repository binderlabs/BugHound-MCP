"""gf wrapper — pattern-based URL filtering (grep for URLs).

If the binary is not installed, uses built-in regex patterns as fallback.
"""

from __future__ import annotations

import asyncio
import re

from bughound.core import tool_runner

BINARY = "gf"

# Built-in patterns matching common gf patterns
_PATTERNS: dict[str, re.Pattern] = {
    "xss": re.compile(
        r"[?&](q|search|query|s|keyword|term|name|text|value|input|data|body|"
        r"content|message|comment|title|redirect|url|next|return|callback|"
        r"error|msg|desc|html|template)=",
        re.IGNORECASE,
    ),
    "sqli": re.compile(
        r"[?&](id|user|account|number|order|no|select|report|role|update|"
        r"query|key|code|table|name|password|pass|field|column|search|"
        r"category|type|sort|where|params|process|row|view|results|"
        r"limit|offset|page)=",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(
        r"[?&](url|uri|path|dest|destination|rurl|src|source|link|"
        r"go|target|proxy|request|fetch|file|load|ref|site|html|"
        r"val|validate|domain|callback|return|page|feed|host|port|"
        r"to|out|view|dir|show|navigation|open|img|image)=",
        re.IGNORECASE,
    ),
    "lfi": re.compile(
        r"[?&](file|document|folder|root|path|pg|style|pdf|template|"
        r"php_path|doc|page|name|cat|dir|action|board|date|detail|"
        r"download|prefix|include|inc|locate|show|site|type|view|"
        r"content|layout|mod|conf|url)=",
        re.IGNORECASE,
    ),
    "redirect": re.compile(
        r"[?&](next|url|target|rurl|dest|destination|redir|redirect_url|"
        r"redirect_uri|redirect|return|return_url|return_to|checkout_url|"
        r"continue|go|goto|out|view|to|ref|uri|link|forward|"
        r"image_url|success|data|RelayState|SAMLRequest)=",
        re.IGNORECASE,
    ),
    "ssti": re.compile(
        r"[?&](template|preview|id|view|activity|name|content|redirect|"
        r"page|url|return)=",
        re.IGNORECASE,
    ),
    "idor": re.compile(
        r"[?&](id|user|account|number|order|no|doc|key|email|group|"
        r"profile|edit|report)=",
        re.IGNORECASE,
    ),
    "debug_logic": re.compile(
        r"[?&](debug|test|admin|access|role|grant|dbg|adm|root|"
        r"disable|enable|exec)=",
        re.IGNORECASE,
    ),
}


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    urls: list[str], pattern: str, timeout: int = 30,
) -> list[str]:
    """Filter URLs matching a gf pattern.

    Pattern must be one of: xss, sqli, ssrf, lfi, redirect, ssti, idor, debug_logic.
    """
    if not urls:
        return []

    if is_available():
        result = await _run_binary(urls, pattern, timeout)
        if result is not None:
            return result

    return _python_fallback(urls, pattern)


async def _run_binary(urls: list[str], pattern: str, timeout: int) -> list[str] | None:
    """Pipe URLs into gf binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

    proc = await asyncio.create_subprocess_exec(
        binary_path, pattern,
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


def _python_fallback(urls: list[str], pattern: str) -> list[str]:
    """Pure-Python gf: regex-match URLs against built-in patterns."""
    regex = _PATTERNS.get(pattern)
    if regex is None:
        return []
    return [url for url in urls if regex.search(url)]
