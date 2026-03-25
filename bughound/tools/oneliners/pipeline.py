"""Pipeline engine — shell-pipe-style chaining of one-liner tools.

17 pre-built pipelines for fast pre-filtering before deep injection testing.
Each pipeline chains tools: filter → transform → check, with Python fallbacks.
Smart pipelines use urldedupe, gxss, bhedak for enhanced accuracy.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import aiohttp
import structlog

from bughound.core import workspace
from bughound.tools.oneliners import (
    anew,
    bhedak,
    gf_tool,
    gxss,
    kxss,
    qsreplace,
    unfurl,
    urldedupe,
    uro,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Pipeline Registry
# ---------------------------------------------------------------------------

PIPELINE_REGISTRY: list[dict[str, Any]] = [
    # --- Original 9 basic pipelines ---
    {
        "id": "xss_reflection_check",
        "name": "XSS Reflection Check",
        "description": "Filter XSS-likely params → qsreplace canary → check reflection",
        "steps": "gf(xss) → uro → qsreplace(canary) → kxss",
        "vuln_class": "xss",
        "requires_data": ["urls"],
    },
    {
        "id": "sqli_candidates_from_urls",
        "name": "SQLi Candidate URLs",
        "description": "Filter SQLi-likely params → deduplicate → replace with probe",
        "steps": "gf(sqli) → uro → qsreplace(probe)",
        "vuln_class": "sqli",
        "requires_data": ["urls"],
    },
    {
        "id": "ssrf_quick_test",
        "name": "SSRF Quick Test",
        "description": "Filter SSRF-likely params → replace with canary URL",
        "steps": "gf(ssrf) → uro → qsreplace(canary)",
        "vuln_class": "ssrf",
        "requires_data": ["urls"],
    },
    {
        "id": "redirect_quick_test",
        "name": "Open Redirect Quick Test",
        "description": "Filter redirect params → replace with external URL",
        "steps": "gf(redirect) → uro → qsreplace(canary)",
        "vuln_class": "open_redirect",
        "requires_data": ["urls"],
    },
    {
        "id": "lfi_quick_test",
        "name": "LFI Quick Test",
        "description": "Filter file-inclusion params → replace with traversal payload",
        "steps": "gf(lfi) → uro → qsreplace(payload)",
        "vuln_class": "lfi",
        "requires_data": ["urls"],
    },
    {
        "id": "xss_quick_test",
        "name": "XSS Quick Test",
        "description": "Filter XSS params → replace with XSS probe → check reflection",
        "steps": "gf(xss) → uro → qsreplace(<script>) → kxss",
        "vuln_class": "xss",
        "requires_data": ["urls"],
    },
    {
        "id": "js_secret_extract",
        "name": "JS Secret Extraction",
        "description": "Extract unique JS file paths from URLs for secret scanning",
        "steps": "filter(.js) → uro → unfurl(paths)",
        "vuln_class": "info_disclosure",
        "requires_data": ["urls"],
    },
    {
        "id": "param_bruteforce",
        "name": "Parameter Key Extraction",
        "description": "Extract all unique parameter names from URL corpus",
        "steps": "uro → unfurl(keys)",
        "vuln_class": "recon",
        "requires_data": ["urls"],
    },
    {
        "id": "crlf_quick_test",
        "name": "CRLF Quick Test",
        "description": "Inject CRLF payload into all param values",
        "steps": "uro → qsreplace(crlf_payload)",
        "vuln_class": "crlf",
        "requires_data": ["urls"],
    },
    # --- 8 new smart pipelines ---
    {
        "id": "xss_deep_reflection_check",
        "name": "XSS Deep Reflection + Context",
        "description": "Check XSS reflection with context analysis (where exactly is value reflected)",
        "steps": "urldedupe(-s) → gf(xss) → gxss(-p BugHoundProbe)",
        "vuln_class": "xss",
        "requires_data": ["urls"],
    },
    {
        "id": "mass_ssrf_test",
        "name": "Mass SSRF Test",
        "description": "Parallel SSRF testing across many URLs — inject metadata URL and check response",
        "steps": "gf(ssrf) → urldedupe(-s) → qsreplace(metadata_url) → httpx(match ami-id)",
        "vuln_class": "ssrf",
        "requires_data": ["urls"],
    },
    {
        "id": "mass_redirect_test",
        "name": "Mass Open Redirect Test",
        "description": "Parallel open redirect testing — inject evil.com and check Location header",
        "steps": "gf(redirect) → urldedupe(-s) → bhedak(evil.com) → httpx(match-location)",
        "vuln_class": "open_redirect",
        "requires_data": ["urls"],
    },
    {
        "id": "mass_lfi_test",
        "name": "Mass LFI Test",
        "description": "Parallel LFI testing with traversal payloads — check for /etc/passwd",
        "steps": "gf(lfi) → urldedupe(-s) → qsreplace(traversal) → httpx(match root:x:0)",
        "vuln_class": "lfi",
        "requires_data": ["urls"],
    },
    {
        "id": "smart_xss_pipeline",
        "name": "Smart XSS Pipeline",
        "description": "Full XSS pipeline: dedupe → filter → reflection check with context → feed to dalfox",
        "steps": "urldedupe(-s) → gf(xss) → gxss(-p BugHound123) → [dalfox on confirmed]",
        "vuln_class": "xss",
        "requires_data": ["urls"],
    },
    {
        "id": "smart_sqli_pipeline",
        "name": "Smart SQLi Pipeline",
        "description": "SQLi pipeline: dedupe → filter → error check → only error URLs to sqlmap",
        "steps": "urldedupe(-s) → gf(sqli) → qsreplace(probe) → httpx(match sql error)",
        "vuln_class": "sqli",
        "requires_data": ["urls"],
    },
    {
        "id": "mass_crlf_test",
        "name": "Mass CRLF Test",
        "description": "CRLF injection across all params — check for injected header in response",
        "steps": "urldedupe(-s) → qsreplace(crlf) → httpx(match-header X-Injected)",
        "vuln_class": "crlf",
        "requires_data": ["urls"],
    },
    {
        "id": "ssti_quick_test",
        "name": "SSTI Quick Test",
        "description": "Quick SSTI detection — inject {{1337*7331}} and check for 9799447 in response",
        "steps": "gf(ssti) → urldedupe(-s) → qsreplace({{1337*7331}}) → httpx(match 9799447)",
        "vuln_class": "ssti",
        "requires_data": ["urls"],
    },
]


def list_pipelines() -> list[dict[str, Any]]:
    """Return all pipeline definitions."""
    return PIPELINE_REGISTRY


def get_pipeline(pipeline_id: str) -> dict[str, Any] | None:
    """Get a pipeline by ID."""
    for p in PIPELINE_REGISTRY:
        if p["id"] == pipeline_id:
            return p
    return None


# ---------------------------------------------------------------------------
# Pipeline Execution
# ---------------------------------------------------------------------------


async def run_pipeline(
    pipeline_id: str,
    workspace_id: str,
) -> dict[str, Any]:
    """Execute a named pipeline against workspace URL data.

    Returns structured results with candidates for further testing.
    """
    pipeline = get_pipeline(pipeline_id)
    if pipeline is None:
        return _error("unknown_pipeline", f"Pipeline '{pipeline_id}' not found.")

    # Load URLs from workspace
    urls = await _load_workspace_urls(workspace_id)
    if not urls:
        return _error("no_data", "No URLs found in workspace. Run bughound_discover first.")

    start = time.monotonic()
    logger.info("pipeline.start", pipeline=pipeline_id, url_count=len(urls))

    # Dispatch to pipeline function
    executor = _PIPELINE_EXECUTORS.get(pipeline_id)
    if executor is None:
        return _error("not_implemented", f"Pipeline '{pipeline_id}' not implemented.")

    try:
        results = await executor(urls, workspace_id)
    except Exception as exc:
        logger.error("pipeline.error", pipeline=pipeline_id, error=str(exc))
        return _error("execution_failed", f"Pipeline '{pipeline_id}' failed: {exc}")

    elapsed = round(time.monotonic() - start, 2)
    logger.info("pipeline.done", pipeline=pipeline_id, elapsed=elapsed, results=len(results))

    return {
        "status": "success",
        "pipeline_id": pipeline_id,
        "pipeline_name": pipeline["name"],
        "description": pipeline["description"],
        "steps": pipeline["steps"],
        "vuln_class": pipeline["vuln_class"],
        "workspace_id": workspace_id,
        "input_urls": len(urls),
        "candidates_found": len(results),
        "candidates": results[:100],
        "execution_time_seconds": elapsed,
        "tools_used": _tools_used_summary(),
        "next_step": (
            f"Found {len(results)} candidates. Use bughound_execute_tests or "
            f"bughound_test_single to verify these with deep injection testing."
            if results
            else "No candidates found. Try a different pipeline or check URL data."
        ),
    }


async def run_prefilter(
    workspace_id: str,
    vuln_classes: list[str],
) -> dict[str, Any]:
    """Run relevant pipelines as pre-filter for given vuln classes.

    Prefers smart pipelines when tools are available, falls back to basic ones.
    Uses urldedupe globally before dispatching if available.
    """
    urls = await _load_workspace_urls(workspace_id)
    if not urls:
        return {"candidates_by_class": {}, "total_candidates": 0}

    start = time.monotonic()

    # Global urldedupe pass — biggest single optimization
    original_count = len(urls)
    urls = await _smart_dedupe(urls)
    deduped_count = len(urls)

    candidates_by_class: dict[str, list] = {}
    stats: dict[str, int] = {"urldedupe_reduction": original_count - deduped_count}

    # Map vuln classes to pipeline IDs (prefer smart pipelines when available)
    _has_gxss = gxss.is_available()
    _has_urldedupe = urldedupe.is_available()

    class_to_pipeline: dict[str, str] = {
        "xss": "smart_xss_pipeline" if _has_gxss else "xss_reflection_check",
        "sqli": "smart_sqli_pipeline" if _has_urldedupe else "sqli_candidates_from_urls",
        "ssrf": "mass_ssrf_test" if _has_urldedupe else "ssrf_quick_test",
        "open_redirect": "mass_redirect_test" if _has_urldedupe else "redirect_quick_test",
        "lfi": "mass_lfi_test" if _has_urldedupe else "lfi_quick_test",
        "crlf": "mass_crlf_test" if _has_urldedupe else "crlf_quick_test",
        "ssti": "ssti_quick_test",
    }

    for vc in vuln_classes:
        pid = class_to_pipeline.get(vc)
        if pid is None:
            continue

        executor = _PIPELINE_EXECUTORS.get(pid)
        if executor is None:
            continue

        try:
            results = await executor(urls, workspace_id)
            if results:
                candidates_by_class[vc] = results
                stats[pid] = len(results)
        except Exception as exc:
            logger.warning("prefilter.error", pipeline=pid, error=str(exc))
            stats[pid] = 0

    total = sum(len(v) for v in candidates_by_class.values())
    elapsed = round(time.monotonic() - start, 2)

    return {
        "candidates_by_class": candidates_by_class,
        "total_candidates": total,
        "pipeline_stats": stats,
        "execution_time_seconds": elapsed,
        "urls_before_dedupe": original_count,
        "urls_after_dedupe": deduped_count,
    }


# ---------------------------------------------------------------------------
# Smart deduplication helper
# ---------------------------------------------------------------------------


async def _smart_dedupe(urls: list[str]) -> list[str]:
    """Deduplicate URLs using urldedupe (native) or fallback."""
    if not urls:
        return urls
    return await urldedupe.execute(urls, similar=True)


# ---------------------------------------------------------------------------
# httpx verification helper (used by mass_* pipelines)
# ---------------------------------------------------------------------------


async def _httpx_verify(
    urls: list[str],
    match_strings: list[str],
    match_header: str | None = None,
    match_location: str | None = None,
    concurrency: int = 15,
    timeout_per: int = 10,
) -> list[dict]:
    """Send HTTP requests and check for match conditions.

    Pure-Python httpx verification via aiohttp — no external binary needed.
    """
    hits: list[dict] = []
    sem = asyncio.Semaphore(concurrency)

    async def _check(session: aiohttp.ClientSession, url: str) -> None:
        async with sem:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_per),
                    ssl=False,
                    allow_redirects=False,
                ) as resp:
                    body = await resp.text()
                    headers = resp.headers

                    # Check body match strings
                    body_matched = any(ms in body for ms in match_strings) if match_strings else False

                    # Check header match (name AND value must contain canary)
                    header_matched = False
                    if match_header:
                        hdr_lower = match_header.lower()
                        for k, v in headers.items():
                            if k.lower() == hdr_lower and "BugHound" in v:
                                header_matched = True
                                break

                    # Check location match + verify redirect is to external domain
                    location_matched = False
                    if match_location:
                        location = headers.get("Location", "")
                        if match_location in location:
                            # Verify redirect host differs from original URL host
                            from urllib.parse import urlparse as _urlparse
                            orig_host = _urlparse(url).hostname or ""
                            redir_host = _urlparse(location).hostname or ""
                            if redir_host and redir_host != orig_host and not redir_host.endswith(f".{orig_host}"):
                                location_matched = True

                    if body_matched or header_matched or location_matched:
                        hit = {
                            "url": url,
                            "status_code": resp.status,
                            "matched": True,
                            "source": "pipeline_httpx",
                        }
                        if body_matched:
                            hit["match_type"] = "body"
                            hit["matched_strings"] = [
                                ms for ms in match_strings if ms in body
                            ]
                        if header_matched:
                            hit["match_type"] = "header"
                            hit["matched_header"] = match_header
                        if location_matched:
                            hit["match_type"] = "location"
                            hit["location"] = headers.get("Location", "")
                        hits.append(hit)
            except Exception:
                pass

    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check(session, url) for url in urls[:500]]
        await asyncio.gather(*tasks)

    return hits


# ---------------------------------------------------------------------------
# Original 9 Pipeline Executors
# ---------------------------------------------------------------------------


async def _exec_xss_reflection_check(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(xss) → uro → qsreplace(canary) → kxss."""
    xss_urls = await gf_tool.execute(urls, "xss")
    if not xss_urls:
        return []

    deduped = await uro.execute(xss_urls)
    if not deduped:
        return []

    reflected = await kxss.execute(deduped)
    return reflected


async def _exec_sqli_candidates(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(sqli) → uro → qsreplace(probe) → return candidates."""
    sqli_urls = await gf_tool.execute(urls, "sqli")
    if not sqli_urls:
        return []

    deduped = await uro.execute(sqli_urls)
    if not deduped:
        return []

    probed = await qsreplace.execute(deduped, "1 OR 1=1--")
    return [{"url": u, "type": "sqli_candidate", "source": "pipeline"} for u in probed]


async def _exec_ssrf_quick(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(ssrf) → uro → qsreplace(canary URL)."""
    ssrf_urls = await gf_tool.execute(urls, "ssrf")
    if not ssrf_urls:
        return []

    deduped = await uro.execute(ssrf_urls)
    if not deduped:
        return []

    canary = "http://169.254.169.254/latest/meta-data/"
    probed = await qsreplace.execute(deduped, canary)
    return [{"url": u, "type": "ssrf_candidate", "source": "pipeline"} for u in probed]


async def _exec_redirect_quick(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(redirect) → uro → qsreplace(external URL)."""
    redirect_urls = await gf_tool.execute(urls, "redirect")
    if not redirect_urls:
        return []

    deduped = await uro.execute(redirect_urls)
    if not deduped:
        return []

    probed = await qsreplace.execute(deduped, "https://evil.com")
    return [{"url": u, "type": "redirect_candidate", "source": "pipeline"} for u in probed]


async def _exec_lfi_quick(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(lfi) → uro → qsreplace(traversal)."""
    lfi_urls = await gf_tool.execute(urls, "lfi")
    if not lfi_urls:
        return []

    deduped = await uro.execute(lfi_urls)
    if not deduped:
        return []

    probed = await qsreplace.execute(deduped, "../../../../etc/passwd")
    return [{"url": u, "type": "lfi_candidate", "source": "pipeline"} for u in probed]


async def _exec_xss_quick(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(xss) → uro → kxss (full reflection check)."""
    xss_urls = await gf_tool.execute(urls, "xss")
    if not xss_urls:
        return []

    deduped = await uro.execute(xss_urls)
    if not deduped:
        return []

    reflected = await kxss.execute(deduped)
    return reflected


async def _exec_js_secret_extract(urls: list[str], workspace_id: str) -> list[dict]:
    """Filter .js URLs → deduplicate → extract paths."""
    js_urls = [u for u in urls if ".js" in u.lower() and not u.lower().endswith(".json")]
    if not js_urls:
        return []

    deduped = await uro.execute(js_urls)
    paths = await unfurl.execute(deduped, mode="paths")
    return [{"path": p, "type": "js_path", "source": "pipeline"} for p in paths]


async def _exec_param_bruteforce(urls: list[str], workspace_id: str) -> list[dict]:
    """uro → unfurl(keys) — extract all param names."""
    deduped = await uro.execute(urls)
    keys = await unfurl.execute(deduped, mode="keys")
    return [{"param": k, "type": "param_name", "source": "pipeline"} for k in keys]


async def _exec_crlf_quick(urls: list[str], workspace_id: str) -> list[dict]:
    """uro → qsreplace(crlf_payload)."""
    deduped = await uro.execute(urls)
    if not deduped:
        return []

    with_params = [u for u in deduped if "?" in u and "=" in u]
    if not with_params:
        return []

    payload = "%0d%0aX-Injected:BugHound"
    probed = await qsreplace.execute(with_params, payload)
    return [{"url": u, "type": "crlf_candidate", "source": "pipeline"} for u in probed]


# ---------------------------------------------------------------------------
# 8 New Smart Pipeline Executors
# ---------------------------------------------------------------------------


async def _exec_xss_deep_reflection(urls: list[str], workspace_id: str) -> list[dict]:
    """urldedupe(-s) → gf(xss) → gxss(-p BugHoundProbe).

    Returns reflected URLs with context (in_script, in_attribute, etc.).
    Only in-script and in-attribute reflections are high-probability XSS.
    """
    deduped = await _smart_dedupe(urls)
    xss_urls = await gf_tool.execute(deduped, "xss")
    if not xss_urls:
        return []

    reflected = await gxss.execute(xss_urls, probe="BugHoundProbe")
    # Tag high-probability ones
    for r in reflected:
        ctx = r.get("context", "in_body")
        r["xss_probability"] = "high" if ctx in ("in_script", "in_attribute") else "medium"
    return reflected


async def _exec_mass_ssrf(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(ssrf) → urldedupe(-s) → qsreplace(metadata) → httpx(match ami-id)."""
    ssrf_urls = await gf_tool.execute(urls, "ssrf")
    if not ssrf_urls:
        return []

    deduped = await _smart_dedupe(ssrf_urls)
    if not deduped:
        return []

    canary = "http://169.254.169.254/latest/meta-data/"
    probed = await qsreplace.execute(deduped, canary)
    if not probed:
        return []

    hits = await _httpx_verify(
        probed,
        match_strings=["ami-id", "instance-id", "iam", "security-credentials"],
    )
    for h in hits:
        h["type"] = "ssrf_confirmed"
        h["severity"] = "critical"
        h["description"] = "SSRF — cloud metadata accessible"
    return hits


async def _exec_mass_redirect(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(redirect) → urldedupe(-s) → bhedak(evil.com) → httpx(match-location)."""
    redirect_urls = await gf_tool.execute(urls, "redirect")
    if not redirect_urls:
        return []

    deduped = await _smart_dedupe(redirect_urls)
    if not deduped:
        return []

    probed = await bhedak.execute(deduped, "https://evil.com")
    if not probed:
        return []

    hits = await _httpx_verify(
        probed,
        match_strings=[],
        match_location="evil.com",
    )
    for h in hits:
        h["type"] = "redirect_confirmed"
        h["severity"] = "medium"
        h["description"] = "Open redirect — external URL in Location header"
    return hits


async def _exec_mass_lfi(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(lfi) → urldedupe(-s) → qsreplace(traversal) → httpx(match root:x:0)."""
    lfi_urls = await gf_tool.execute(urls, "lfi")
    if not lfi_urls:
        return []

    deduped = await _smart_dedupe(lfi_urls)
    if not deduped:
        return []

    probed = await qsreplace.execute(deduped, "../../../../../../etc/passwd")
    if not probed:
        return []

    hits = await _httpx_verify(
        probed,
        match_strings=["root:x:0:0"],
    )
    for h in hits:
        h["type"] = "lfi_confirmed"
        h["severity"] = "high"
        h["description"] = "LFI — /etc/passwd readable via path traversal"
    return hits


async def _exec_smart_xss(urls: list[str], workspace_id: str) -> list[dict]:
    """urldedupe(-s) → gf(xss) → gxss(-p BugHound123).

    Full pipeline. Only confirmed reflections (especially in-script/attribute)
    should be fed to dalfox for payload generation.
    """
    deduped = await _smart_dedupe(urls)
    xss_urls = await gf_tool.execute(deduped, "xss")
    if not xss_urls:
        return []

    reflected = await gxss.execute(xss_urls, probe="BugHound123")

    for r in reflected:
        ctx = r.get("context", "in_body")
        r["xss_probability"] = "high" if ctx in ("in_script", "in_attribute") else "medium"
        r["next_action"] = (
            "feed_to_dalfox" if ctx in ("in_script", "in_attribute")
            else "manual_review"
        )
    return reflected


async def _exec_smart_sqli(urls: list[str], workspace_id: str) -> list[dict]:
    """urldedupe(-s) → gf(sqli) → qsreplace(probe) → httpx(match sql error).

    Only URLs that trigger SQL error messages go to sqlmap.
    This cuts sqlmap runtime from hours to minutes.
    """
    deduped = await _smart_dedupe(urls)
    sqli_urls = await gf_tool.execute(deduped, "sqli")
    if not sqli_urls:
        return []

    probed = await qsreplace.execute(sqli_urls, "1'\"())")
    if not probed:
        return []

    hits = await _httpx_verify(
        probed,
        match_strings=[
            "sql syntax",
            "You have an error in your SQL",
            "ERROR:  syntax error",
            "ORA-",
            "SQLite3::",
            "unclosed quotation",
            "quoted string not properly terminated",
            "warning: mysql",
            "PG::", "SQLSTATE",
        ],
    )
    for h in hits:
        h["type"] = "sqli_error_url"
        h["severity"] = "high"
        h["description"] = "SQL error triggered — likely injectable"
        h["next_action"] = "feed_to_sqlmap"
    return hits


async def _exec_mass_crlf(urls: list[str], workspace_id: str) -> list[dict]:
    """urldedupe(-s) → qsreplace(crlf) → httpx(match-header X-Injected)."""
    deduped = await _smart_dedupe(urls)
    with_params = [u for u in deduped if "?" in u and "=" in u]
    if not with_params:
        return []

    probed = await qsreplace.execute(with_params, "%0d%0aX-Injected:BugHound")
    if not probed:
        return []

    hits = await _httpx_verify(
        probed,
        match_strings=[],
        match_header="X-Injected",
    )
    for h in hits:
        h["type"] = "crlf_confirmed"
        h["severity"] = "medium"
        h["description"] = "CRLF injection — custom header injected"
    return hits


async def _exec_ssti_quick(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(ssti) → urldedupe(-s) → qsreplace({{1337*7331}}) → httpx(match 9799447)."""
    ssti_urls = await gf_tool.execute(urls, "ssti")
    if not ssti_urls:
        return []

    deduped = await _smart_dedupe(ssti_urls)
    if not deduped:
        return []

    probed = await qsreplace.execute(deduped, "{{1337*7331}}")
    if not probed:
        return []

    hits = await _httpx_verify(probed, match_strings=["9799447"])
    confirmed: list[dict] = []
    for h in hits:
        h["type"] = "ssti_candidate"
        h["severity"] = "critical"
        h["description"] = "SSTI — template expression evaluated ({{1337*7331}} = 9799447)"
        confirmed.append(h)
    return confirmed


# ---------------------------------------------------------------------------
# Executor dispatch
# ---------------------------------------------------------------------------

_PIPELINE_EXECUTORS: dict[str, Any] = {
    # Original 9
    "xss_reflection_check": _exec_xss_reflection_check,
    "sqli_candidates_from_urls": _exec_sqli_candidates,
    "ssrf_quick_test": _exec_ssrf_quick,
    "redirect_quick_test": _exec_redirect_quick,
    "lfi_quick_test": _exec_lfi_quick,
    "xss_quick_test": _exec_xss_quick,
    "js_secret_extract": _exec_js_secret_extract,
    "param_bruteforce": _exec_param_bruteforce,
    "crlf_quick_test": _exec_crlf_quick,
    # New 8 smart pipelines
    "xss_deep_reflection_check": _exec_xss_deep_reflection,
    "mass_ssrf_test": _exec_mass_ssrf,
    "mass_redirect_test": _exec_mass_redirect,
    "mass_lfi_test": _exec_mass_lfi,
    "smart_xss_pipeline": _exec_smart_xss,
    "smart_sqli_pipeline": _exec_smart_sqli,
    "mass_crlf_test": _exec_mass_crlf,
    "ssti_quick_test": _exec_ssti_quick,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_workspace_urls(workspace_id: str) -> list[str]:
    """Load all URLs from workspace crawled data."""
    raw = await workspace.read_data(workspace_id, "urls/crawled.json")
    if not raw:
        return []

    items = raw
    if isinstance(raw, dict):
        items = raw.get("data", [])

    urls: list[str] = []
    for item in items:
        if isinstance(item, str):
            urls.append(item)
        elif isinstance(item, dict):
            url = item.get("url") or item.get("input", "")
            if url:
                urls.append(url)

    return urls


def _tools_used_summary() -> dict[str, str]:
    """Report which tools are native vs fallback."""
    tools = {
        "qsreplace": "native" if qsreplace.is_available() else "python_fallback",
        "kxss": "native" if kxss.is_available() else "python_fallback",
        "gf": "native" if gf_tool.is_available() else "python_fallback",
        "uro": "native" if uro.is_available() else "python_fallback",
        "unfurl": "native" if unfurl.is_available() else "python_fallback",
        "anew": "native" if anew.is_available() else "python_fallback",
        "Gxss": "native" if gxss.is_available() else "python_fallback",
        "bhedak": "native" if bhedak.is_available() else "python_fallback",
        "urldedupe": "native" if urldedupe.is_available() else "python_fallback",
    }
    return tools


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
