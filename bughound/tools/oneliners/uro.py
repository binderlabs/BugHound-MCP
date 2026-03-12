"""uro wrapper — URL deduplication and noise reduction.

If the binary is not installed, uses a pure-Python fallback.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from bughound.core import tool_runner

BINARY = "uro"

# Extensions to filter out (static assets, media)
_STATIC_EXTENSIONS = frozenset({
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi",
    ".pdf", ".zip", ".tar", ".gz", ".rar",
})

# Common noise patterns in URLs
_NOISE_PATTERNS = [
    re.compile(r"/wp-content/(?:uploads|themes|plugins)/.*\.(jpg|jpeg|png|gif|css|js)", re.IGNORECASE),
    re.compile(r"/static/.*\.(css|js|jpg|png|gif|svg)", re.IGNORECASE),
    re.compile(r"/assets/.*\.(css|js|jpg|png|gif|svg|woff)", re.IGNORECASE),
    re.compile(r"\.(css|js|jpg|jpeg|png|gif|svg|ico|woff2?|ttf|eot)\?", re.IGNORECASE),
]


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(urls: list[str], timeout: int = 30) -> list[str]:
    """Deduplicate and reduce noise from URL list.

    Removes static assets, deduplicates by URL template pattern.
    """
    if not urls:
        return []

    if is_available():
        result = await _run_binary(urls, timeout)
        if result is not None:
            return result

    return _python_fallback(urls)


async def _run_binary(urls: list[str], timeout: int) -> list[str] | None:
    """Pipe URLs into uro binary."""
    stdin_data = "\n".join(urls).encode()
    binary_path = tool_runner.find_binary(BINARY)
    if not binary_path:
        return None

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
        return None

    return [line.strip() for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]


def _python_fallback(urls: list[str]) -> list[str]:
    """Pure-Python uro: deduplicate by path template + filter noise."""
    seen_templates: set[str] = set()
    results: list[str] = []

    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Filter static assets
        if any(path.endswith(ext) for ext in _STATIC_EXTENSIONS):
            continue

        # Filter noise patterns
        if any(p.search(url) for p in _NOISE_PATTERNS):
            continue

        # Normalize path: replace numeric segments with {N}
        normalized = re.sub(r"/\d+(?=/|$)", "/{N}", path)
        # Replace UUIDs with {UUID}
        normalized = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{UUID}", normalized, flags=re.IGNORECASE,
        )

        # Build template: scheme+host+normalized_path+sorted_param_names
        param_names = sorted(set(re.findall(r"[?&]([^=&]+)=", parsed.query)))
        template = f"{parsed.scheme}://{parsed.netloc}{normalized}?{'&'.join(param_names)}"

        if template not in seen_templates:
            seen_templates.add(template)
            results.append(url)

    return results
