"""JavaScript file analyzer for secret and endpoint extraction.

Downloads JS files via aiohttp and applies regex patterns to find:
- API keys, tokens, passwords, private keys, Firebase, S3 buckets, internal IPs
- API endpoints and internal paths
No external binary needed — pure Python.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Secret patterns: (name, compiled regex, description)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    ("AWS_SECRET_KEY", re.compile(r"""(?:aws_secret|secret_?access_?key)['":\s=]+([A-Za-z0-9/+=]{40})""", re.I), "AWS Secret Key"),
    ("GOOGLE_API", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    ("SLACK_TOKEN", re.compile(r"xox[bpors]-[0-9a-zA-Z-]{10,}"), "Slack Token"),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Private Key"),
    ("API_KEY", re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret)[\s:="']+([A-Za-z0-9_\-]{16,})""", re.I), "API Key"),
    ("BEARER_TOKEN", re.compile(r"""(?:token|bearer|authorization|auth[_-]?token)[\s:="']+([A-Za-z0-9_\-\.]{20,})""", re.I), "Bearer/Auth Token"),
    ("GENERIC_SECRET", re.compile(r"""(?:secret|password|passwd|pwd)[\s:="']+([^\s"']{8,64})""", re.I), "Generic Secret/Password"),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), "GitHub Token"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JSON Web Token"),
    ("FIREBASE", re.compile(r"[a-z0-9-]+\.firebaseio\.com"), "Firebase Database URL"),
    ("S3_BUCKET", re.compile(r"[a-z0-9.-]+\.s3\.amazonaws\.com"), "AWS S3 Bucket"),
    ("INTERNAL_IP", re.compile(
        r"(?:^|[\"'\s,;=])("
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r")(?:[\"'\s,;:]|$)"
    ), "Internal/Private IP Address"),
]

# ---------------------------------------------------------------------------
# Endpoint patterns
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: list[re.Pattern] = [
    # fetch/axios/jQuery ajax calls
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"](\/[^'"]{2,}?)['"]"""),
    # XMLHttpRequest .open("METHOD", "/url")
    re.compile(r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'](\/[^"']+)["']"""),
    # /api/... paths in strings
    re.compile(r"""["'](\/api\/[^"']+)["']"""),
    # /v1/... /v2/... versioned paths
    re.compile(r"""["'](\/v[0-9]+\/[a-zA-Z0-9/_\-\.]{2,}?)["']"""),
    # Generic multi-segment paths in strings
    re.compile(r"""["'](\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9/_\-\.]{2,}?)["']"""),
    # url/endpoint/path/href assignments
    re.compile(r"""(?:url|endpoint|path|href|action)\s*[:=]\s*["'](\/[^"']{2,}?)["']""", re.I),
]

# Filter out common non-interesting paths
_ENDPOINT_IGNORE = re.compile(
    r"^/(favicon|static|assets|css|img|images|fonts|vendor|node_modules|\.)",
    re.I,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def analyze_js_files(
    js_urls: list[str],
    target_domain: str = "",
    concurrency: int = 20,
    timeout: int = 15,
) -> dict[str, Any]:
    """Download and analyze JS files for secrets and endpoints.

    Returns:
        {
            "secrets": [...],
            "endpoints": [...],
            "files_analyzed": N,
            "files_failed": N,
            "errors": [...]
        }
    """
    sem = asyncio.Semaphore(concurrency)
    all_secrets: list[dict[str, Any]] = []
    all_endpoints: list[dict[str, Any]] = []
    errors: list[str] = []
    analyzed = 0
    failed = 0

    async def _analyze_one(url: str) -> None:
        nonlocal analyzed, failed
        async with sem:
            content = await _download_js(url, timeout)
            if content is None:
                failed += 1
                return
            analyzed += 1

            secrets = _extract_secrets(content, url)
            endpoints = _extract_endpoints(content, url, target_domain)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)

    tasks = [_analyze_one(u) for u in js_urls]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate endpoints by path
    seen_paths: set[str] = set()
    unique_endpoints: list[dict[str, Any]] = []
    for ep in all_endpoints:
        if ep["path"] not in seen_paths:
            seen_paths.add(ep["path"])
            unique_endpoints.append(ep)

    return {
        "secrets": all_secrets,
        "endpoints": unique_endpoints,
        "files_analyzed": analyzed,
        "files_failed": failed,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


async def _download_js(url: str, timeout: int) -> str | None:
    """Download a JS file. Returns content or None on failure."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": "Mozilla/5.0 BugHound/1.0"},
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return None
                content = await resp.text(encoding="utf-8", errors="replace")
                if len(content) > 5_000_000:
                    content = content[:5_000_000]
                return content
    except Exception:
        return None


def _extract_secrets(content: str, source_file: str) -> list[dict[str, Any]]:
    """Extract secrets from JS content using regex patterns."""
    secrets: list[dict[str, Any]] = []

    for name, pattern, description in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            display_value = value.strip()[:60] + ("..." if len(value.strip()) > 60 else "")
            secrets.append({
                "type": name,
                "value": display_value,
                "description": description,
                "source_file": source_file,
                "match_position": match.start(),
            })

    return secrets


def _extract_endpoints(
    content: str,
    source_file: str,
    target_domain: str,
) -> list[dict[str, Any]]:
    """Extract API endpoints from JS content."""
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Standard path patterns
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            path = match.group(1) if match.lastindex else match.group(0)
            _add_endpoint(path, match, content, source_file, endpoints, seen)

    # Full URLs matching target domain
    if target_domain:
        domain_pattern = re.compile(
            r"""["'](https?://[^"']*"""
            + re.escape(target_domain)
            + r"""[^"']*)["']"""
        )
        for match in domain_pattern.finditer(content):
            full_url = match.group(1).strip()
            try:
                path = urlparse(full_url).path
                if path and path != "/":
                    _add_endpoint(path, match, content, source_file, endpoints, seen)
            except Exception:
                pass

    return endpoints


def _add_endpoint(
    path: str,
    match: re.Match,
    content: str,
    source_file: str,
    endpoints: list[dict[str, Any]],
    seen: set[str],
) -> None:
    """Add an endpoint if it passes filters."""
    path = path.strip()
    if not path or path in seen:
        return
    if _ENDPOINT_IGNORE.match(path):
        return
    if len(path) < 3 or len(path) > 200:
        return

    seen.add(path)

    # Detect HTTP method from surrounding context
    method = "GET"
    ctx_start = max(0, match.start() - 60)
    context = content[ctx_start : match.start()].lower()
    if ".post" in context or '"post"' in context or "'post'" in context:
        method = "POST"
    elif ".put" in context or '"put"' in context:
        method = "PUT"
    elif ".delete" in context or '"delete"' in context:
        method = "DELETE"
    elif ".patch" in context:
        method = "PATCH"

    endpoints.append({
        "path": path,
        "method": method,
        "source_file": source_file,
    })
