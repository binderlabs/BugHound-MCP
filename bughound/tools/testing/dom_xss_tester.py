"""DOM XSS tester — Playwright-based DOM injection with aiohttp fallback.

Tests for DOM-based XSS by injecting payloads into URL fragments and parameters,
then observing DOM changes (dialog events, title changes, DOM mutations).
Falls back to source-based sink analysis when Playwright is unavailable.
"""

from __future__ import annotations

import re
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=20)
_HEADERS = {"User-Agent": "Mozilla/5.0 (BugHound Scanner)"}

# ---------------------------------------------------------------------------
# DOM XSS sink patterns (for source-based fallback analysis)
# ---------------------------------------------------------------------------

_DOM_SINKS = re.compile(
    r"(document\.write|\.innerHTML\s*=|\.outerHTML\s*=|eval\s*\(|"
    r"setTimeout\s*\(|setInterval\s*\(|Function\s*\(|"
    r"document\.location|window\.location\s*=|location\.href\s*=|"
    r"location\.assign\s*\(|location\.replace\s*\(|"
    r"\.insertAdjacentHTML\s*\(|\.append\s*\(|"
    r"jQuery\.html\s*\(|\$\s*\(\s*['\"]<)",
    re.I,
)

_DOM_SOURCES = re.compile(
    r"(location\.hash|location\.search|location\.href|"
    r"document\.URL|document\.referrer|document\.cookie|"
    r"window\.name|postMessage|URLSearchParams|"
    r"localStorage\.getItem|sessionStorage\.getItem)",
    re.I,
)

# Payloads for Playwright-based testing
_HASH_PAYLOADS = [
    '<img src=x onerror=document.title="BUGHOUND_DOM_XSS">',
    '"><img src=x onerror=document.title="BUGHOUND_DOM_XSS">',
    "'-document.title='BUGHOUND_DOM_XSS'-'",
    "javascript:document.title='BUGHOUND_DOM_XSS'",
]

_PARAM_PAYLOADS = [
    '<img src=x onerror=document.title="BUGHOUND_DOM_XSS">',
    '"><svg/onload=document.title="BUGHOUND_DOM_XSS">',
]

_MARKER = "BUGHOUND_DOM_XSS"


# ---------------------------------------------------------------------------
# Playwright availability check
# ---------------------------------------------------------------------------

def _patch_playwright_driver() -> None:
    """Fix Playwright Node.js driver path if system default is broken."""
    import os
    from pathlib import Path

    try:
        import playwright._impl._driver as driver
        _, cli_path = driver.compute_driver_executable()
        if not Path(cli_path).exists():
            # Search for cli.js in common npm locations
            # Search npm cache and global installs for a working cli.js
            search_paths = list(Path.home().glob(".npm/_npx/*/node_modules/playwright/cli.js"))
            search_paths.extend([
                Path("/usr/local/lib/node_modules/@playwright/cli/node_modules/playwright/cli.js"),
                Path.home() / "node_modules/playwright/cli.js",
            ])
            for p in search_paths:
                if p.exists():
                    original = driver.compute_driver_executable
                    node_path = os.getenv("PLAYWRIGHT_NODEJS_PATH", "/usr/bin/node")
                    driver.compute_driver_executable = lambda: (node_path, str(p))
                    logger.info("playwright.driver_patched", path=str(p))
                    break
    except Exception:
        pass


def _playwright_available() -> bool:
    """Check if playwright is installed and usable."""
    try:
        import playwright  # noqa: F401
        _patch_playwright_driver()
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Playwright-based DOM XSS testing
# ---------------------------------------------------------------------------


async def _test_with_playwright(
    target_url: str,
    params: list[str] | None = None,
) -> dict[str, Any]:
    """Test DOM XSS using Playwright browser automation."""
    from playwright.async_api import async_playwright

    findings: list[dict[str, Any]] = []
    dialog_messages: list[str] = []

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            page = await context.new_page()

            # Capture dialog events
            page.on("dialog", lambda d: (dialog_messages.append(d.message), d.dismiss()))

            # Test 1: Hash-based injection
            for payload in _HASH_PAYLOADS:
                test_url = f"{target_url}#{payload}"
                try:
                    await page.goto(test_url, wait_until="networkidle", timeout=10000)
                    await page.wait_for_timeout(1000)

                    title = await page.title()
                    if _MARKER in title:
                        findings.append({
                            "type": "dom_xss_hash",
                            "payload": payload,
                            "injection_point": "location.hash",
                            "evidence": f"Title changed to contain marker via hash injection",
                            "url": test_url,
                        })
                        break
                except Exception:
                    continue

            # Test 2: Parameter-based injection
            if params:
                from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

                for param in params[:3]:
                    for payload in _PARAM_PAYLOADS:
                        parsed = urlparse(target_url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[param] = [payload]
                        new_query = urlencode(qs, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))

                        try:
                            await page.goto(test_url, wait_until="networkidle", timeout=10000)
                            await page.wait_for_timeout(1000)

                            title = await page.title()
                            if _MARKER in title:
                                findings.append({
                                    "type": "dom_xss_param",
                                    "param": param,
                                    "payload": payload,
                                    "injection_point": f"parameter:{param}",
                                    "evidence": "Title changed to contain marker via param injection",
                                    "url": test_url,
                                })
                                break
                        except Exception:
                            continue

            # Test 3: postMessage injection
            try:
                await page.goto(target_url, wait_until="networkidle", timeout=10000)

                # Check if page has message event listeners
                has_listener = await page.evaluate("""
                    () => {
                        const events = window._bughound_events || [];
                        return events.length > 0 || document.querySelectorAll('[onmessage]').length > 0;
                    }
                """)

                # Try postMessage with XSS payload
                for payload in ['<img src=x onerror=document.title="BUGHOUND_DOM_XSS">', _MARKER]:
                    await page.evaluate(f'window.postMessage("{payload}", "*")')
                    await page.wait_for_timeout(500)

                    title = await page.title()
                    if _MARKER in title:
                        findings.append({
                            "type": "dom_xss_postmessage",
                            "payload": payload,
                            "injection_point": "postMessage",
                            "evidence": "Title changed via postMessage injection",
                            "url": target_url,
                        })
                        break
            except Exception:
                pass

            # Check for dialog-based XSS
            if dialog_messages:
                findings.append({
                    "type": "dom_xss_dialog",
                    "evidence": f"Dialog triggered: {dialog_messages[0][:200]}",
                    "url": target_url,
                })

            await browser.close()

    except Exception as exc:
        logger.warning("dom_xss.playwright_error", error=str(exc))

    return {
        "method": "playwright",
        "findings": findings,
        "vulnerable": bool(findings),
    }


# ---------------------------------------------------------------------------
# Lite fallback: source-based sink analysis
# ---------------------------------------------------------------------------


async def _test_lite(target_url: str) -> dict[str, Any]:
    """Fallback DOM XSS analysis — scan JS for dangerous sink patterns."""
    sink_matches: list[dict[str, Any]] = []
    source_matches: list[str] = []
    dangerous_flows: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession(headers=_HEADERS) as session:
            async with session.get(
                target_url, ssl=False, timeout=_TIMEOUT, allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="replace")
                body = body[:200_000]

            # Find sinks
            for match in _DOM_SINKS.finditer(body):
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 50)
                context = body[start:end].replace("\n", " ").strip()
                sink_matches.append({
                    "sink": match.group(0).strip(),
                    "context": context[:200],
                })

            # Find sources
            for match in _DOM_SOURCES.finditer(body):
                source_matches.append(match.group(0).strip())

            # Find inline scripts with both source and sink
            scripts = re.findall(r"<script[^>]*>(.*?)</script>", body, re.S | re.I)
            for script in scripts:
                script_sinks = _DOM_SINKS.findall(script)
                script_sources = _DOM_SOURCES.findall(script)
                if script_sinks and script_sources:
                    dangerous_flows.append({
                        "sources": list(set(script_sources))[:5],
                        "sinks": list(set(script_sinks))[:5],
                        "script_preview": script[:300],
                    })

    except Exception as exc:
        logger.warning("dom_xss.lite_error", error=str(exc))

    vulnerable = bool(sink_matches and source_matches)

    return {
        "method": "lite",
        "vulnerable": vulnerable,
        "sinks": sink_matches[:20],
        "sources": list(set(source_matches))[:10],
        "dangerous_flows": dangerous_flows[:5],
        "note": "Source-based analysis only — no runtime verification. Needs manual review." if vulnerable else "",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def test_dom_xss(
    target_url: str,
    params: list[str] | None = None,
    force_lite: bool = False,
) -> dict[str, Any]:
    """Test for DOM-based XSS.

    Uses Playwright for full DOM testing when available.
    Falls back to source-based sink analysis otherwise.

    params: query parameters to test for injection.
    force_lite: skip Playwright even if available.
    """
    if not force_lite and _playwright_available():
        result = await _test_with_playwright(target_url, params)
    else:
        result = await _test_lite(target_url)

    result["url"] = target_url
    return result
