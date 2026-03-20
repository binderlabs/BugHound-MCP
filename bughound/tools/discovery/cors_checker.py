"""CORS misconfiguration checker — pure aiohttp, no external binary.

Tests live hosts for reflected origins, wildcard ACAO, and credential leaks.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    # Subdomain bypass will be constructed per-target
]


async def check_cors(
    host_urls: list[str],
    max_hosts: int = 50,
    concurrency: int = 5,
    timeout: int = 8,
) -> list[dict[str, Any]]:
    """Test CORS configuration on live host URLs.

    Returns list of CORS findings with severity classification.
    """
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    async def _check_one(url: str) -> None:
        async with sem:
            finding = await _test_cors(url, timeout)
            if finding:
                results.append(finding)

    tasks = [_check_one(u) for u in host_urls[:max_hosts]]
    await asyncio.gather(*tasks, return_exceptions=True)

    results.sort(key=lambda r: _severity_order(r.get("severity", "INFO")))
    return results


async def _test_cors(url: str, timeout: int) -> dict[str, Any] | None:
    """Test CORS on a single URL with multiple origin payloads."""
    best_finding: dict[str, Any] | None = None

    # Build subdomain bypass origin from the target URL
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        bypass_origin = f"https://{parsed.hostname}.evil.com"
    except Exception:
        bypass_origin = "https://target.evil.com"

    origins_to_test = [
        "https://evil.com",
        bypass_origin,
        "null",
    ]

    for origin in origins_to_test:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Origin": origin,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                }
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                    has_credentials = acac == "true"

                    if not acao:
                        continue

                    severity = _classify_cors(acao, origin, has_credentials)
                    if severity is None:
                        continue

                    finding = {
                        "url": url,
                        "origin_tested": origin,
                        "acao": acao,
                        "credentials_allowed": has_credentials,
                        "severity": severity,
                    }

                    # Keep the most severe finding
                    if best_finding is None or _severity_order(severity) < _severity_order(best_finding["severity"]):
                        best_finding = finding

        except Exception:
            continue

    return best_finding


def _classify_cors(
    acao: str, origin: str, has_credentials: bool,
) -> str | None:
    """Classify CORS finding severity. Returns None if not vulnerable."""
    acao = acao.strip()

    # Reflected origin
    if acao == origin and origin not in ("", "null"):
        if has_credentials:
            return "CRITICAL"
        return "HIGH"

    # Null origin reflected
    if acao == "null" and origin == "null":
        if has_credentials:
            return "HIGH"
        return "INFO"

    # Wildcard
    if acao == "*":
        if has_credentials:
            return "MEDIUM"
        return "LOW"

    return None


def _severity_order(severity: str) -> int:
    """Lower number = more severe (for sorting)."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)
