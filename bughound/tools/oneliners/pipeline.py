"""Pipeline engine — shell-pipe-style chaining of one-liner tools.

9 pre-built pipelines for fast pre-filtering before deep injection testing.
Each pipeline chains tools: filter → transform → check, with Python fallbacks.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from bughound.core import workspace
from bughound.tools.oneliners import anew, gf_tool, kxss, qsreplace, unfurl, uro

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Pipeline Registry
# ---------------------------------------------------------------------------

PIPELINE_REGISTRY: list[dict[str, Any]] = [
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

    Returns aggregated candidates grouped by vuln class.
    """
    urls = await _load_workspace_urls(workspace_id)
    if not urls:
        return {"candidates_by_class": {}, "total_candidates": 0}

    start = time.monotonic()
    candidates_by_class: dict[str, list] = {}
    stats: dict[str, int] = {}

    # Map vuln classes to pipeline IDs
    class_to_pipeline = {
        "xss": "xss_reflection_check",
        "sqli": "sqli_candidates_from_urls",
        "ssrf": "ssrf_quick_test",
        "open_redirect": "redirect_quick_test",
        "lfi": "lfi_quick_test",
        "crlf": "crlf_quick_test",
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
    }


# ---------------------------------------------------------------------------
# Individual Pipeline Executors
# ---------------------------------------------------------------------------


async def _exec_xss_reflection_check(urls: list[str], workspace_id: str) -> list[dict]:
    """gf(xss) → uro → qsreplace(canary) → kxss."""
    # Step 1: Filter XSS-likely URLs
    xss_urls = await gf_tool.execute(urls, "xss")
    if not xss_urls:
        return []

    # Step 2: Deduplicate
    deduped = await uro.execute(xss_urls)
    if not deduped:
        return []

    # Step 3+4: Check reflection (kxss does qsreplace internally)
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

    # Replace param values with SQLi probe
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

    # Only keep URLs with params
    with_params = [u for u in deduped if "?" in u and "=" in u]
    if not with_params:
        return []

    payload = "%0d%0aX-Injected:BugHound"
    probed = await qsreplace.execute(with_params, payload)

    return [{"url": u, "type": "crlf_candidate", "source": "pipeline"} for u in probed]


# ---------------------------------------------------------------------------
# Executor dispatch
# ---------------------------------------------------------------------------

_PIPELINE_EXECUTORS: dict[str, Any] = {
    "xss_reflection_check": _exec_xss_reflection_check,
    "sqli_candidates_from_urls": _exec_sqli_candidates,
    "ssrf_quick_test": _exec_ssrf_quick,
    "redirect_quick_test": _exec_redirect_quick,
    "lfi_quick_test": _exec_lfi_quick,
    "xss_quick_test": _exec_xss_quick,
    "js_secret_extract": _exec_js_secret_extract,
    "param_bruteforce": _exec_param_bruteforce,
    "crlf_quick_test": _exec_crlf_quick,
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
    }
    return tools


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
