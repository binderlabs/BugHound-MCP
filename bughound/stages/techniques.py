"""Technique library — defines and executes testing techniques for Stage 4.

Each technique declares its requirements (tools, data) and execution logic.
The test orchestrator (test.py) selects techniques based on the scan plan
and delegates execution here.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from bughound.core import tool_runner, workspace

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Technique registry
# ---------------------------------------------------------------------------

TECHNIQUE_REGISTRY: list[dict[str, Any]] = [
    {
        "id": "nuclei_scan",
        "name": "Nuclei Template Scan",
        "phase": "4A",
        "requires_tools": ["nuclei"],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["all"],
        "description": "Broad template-based vulnerability scanning",
    },
    {
        "id": "sqli_param_fuzz",
        "name": "SQL Injection Parameter Fuzzing",
        "phase": "4D",
        "requires_tools": ["sqlmap"],
        "requires_data": ["parameter_classification.sqli_candidates"],
        "vuln_classes": ["sqli"],
        "description": "Test SQL injection on classified parameters using sqlmap",
    },
    {
        "id": "xss_param_fuzz",
        "name": "XSS Parameter Fuzzing",
        "phase": "4D",
        "requires_tools": ["dalfox"],
        "requires_data": ["parameter_classification.xss_candidates"],
        "vuln_classes": ["xss"],
        "description": "Test reflected/DOM XSS using dalfox on classified parameters",
    },
    {
        "id": "ssrf_test",
        "name": "SSRF Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.ssrf_candidates"],
        "vuln_classes": ["ssrf"],
        "description": "Test SSRF with cloud metadata and internal IP payloads",
    },
    {
        "id": "open_redirect_test",
        "name": "Open Redirect Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.redirect_candidates"],
        "vuln_classes": ["open_redirect"],
        "description": "Test open redirect with external domain payloads",
    },
    {
        "id": "lfi_test",
        "name": "Local File Inclusion Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.lfi_candidates"],
        "vuln_classes": ["lfi"],
        "description": "Test LFI with traversal payloads",
    },
    {
        "id": "idor_test",
        "name": "IDOR Detection",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.idor_candidates"],
        "vuln_classes": ["idor"],
        "description": "Test insecure direct object references by manipulating ID values",
    },
    {
        "id": "crlf_test",
        "name": "CRLF Injection Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification"],
        "vuln_classes": ["crlf"],
        "description": "Test CRLF injection in parameters",
    },
    {
        "id": "ssti_test",
        "name": "Server-Side Template Injection Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.ssti_candidates"],
        "vuln_classes": ["ssti"],
        "description": "Test SSTI with template expression payloads",
    },
    {
        "id": "header_injection_test",
        "name": "Header Injection Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["header_injection"],
        "description": "Test Host header, X-Forwarded-For, and path override injections",
    },
    {
        "id": "graphql_test",
        "name": "GraphQL Exploitation",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["flags.GRAPHQL"],
        "vuln_classes": ["graphql"],
        "description": "Test introspection, depth limits, batch queries, unauthorized mutations",
    },
    {
        "id": "jwt_test",
        "name": "JWT Security Testing",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["detected_jwt"],
        "vuln_classes": ["jwt"],
        "description": "Test JWT algorithm confusion, none bypass, expiry enforcement",
    },
    {
        "id": "deep_dirfuzz",
        "name": "Deep Directory Fuzzing",
        "phase": "4B",
        "requires_tools": ["ffuf"],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["content_discovery"],
        "description": "Full directory brute-force with large wordlists",
    },
    {
        "id": "deep_param_discovery",
        "name": "Deep Parameter Discovery",
        "phase": "4C",
        "requires_tools": ["arjun"],
        "requires_data": ["urls"],
        "vuln_classes": ["param_discovery"],
        "description": "Discover hidden parameters on target endpoints",
    },
    {
        "id": "wordpress_test",
        "name": "WordPress Security Testing",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["technologies.WordPress"],
        "vuln_classes": ["wordpress"],
        "description": "Test xmlrpc, user enum, plugin enum, debug log exposure",
    },
    {
        "id": "spring_actuator_test",
        "name": "Spring Boot Actuator Exploitation",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["flags.ACTUATOR_FOUND"],
        "vuln_classes": ["spring"],
        "description": "Test actuator endpoints for env vars, heap dump, bean enumeration",
    },
    {
        "id": "cookie_sqli",
        "name": "Cookie SQL Injection",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["auth_discovery.injectable_cookies"],
        "vuln_classes": ["sqli"],
        "description": "Test injectable cookies for SQL injection",
    },
    {
        "id": "cookie_deserialization",
        "name": "Cookie Deserialization",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["auth_discovery.injectable_cookies"],
        "vuln_classes": ["deserialization"],
        "description": "Test cookies for insecure deserialization",
    },
    {
        "id": "rce_test",
        "name": "Command Injection Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.rce_candidates"],
        "vuln_classes": ["rce"],
        "description": "Test for OS command injection via time-based and output-based techniques",
    },
    {
        "id": "broken_access_control",
        "name": "Broken Access Control Testing",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["live_hosts", "crawled_urls", "auth_discovery"],
        "vuln_classes": ["bac"],
        "description": "Test for unauthenticated admin access, privilege escalation, and verb tampering",
    },
    {
        "id": "rate_limit_test",
        "name": "Rate Limiting Detection",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["auth_discovery.auth_endpoints"],
        "vuln_classes": ["rate_limiting"],
        "description": "Test authentication endpoints for missing rate limiting",
    },
    {
        "id": "post_sqli",
        "name": "POST SQL Injection",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.post_endpoints"],
        "vuln_classes": ["sqli"],
        "description": "Test POST endpoints for SQL injection via form/JSON body",
    },
    {
        "id": "stored_xss",
        "name": "Stored XSS Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.post_endpoints"],
        "vuln_classes": ["xss"],
        "description": "Test POST endpoints for stored XSS with marker verification",
    },
    {
        "id": "post_ssti",
        "name": "POST SSTI Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.post_endpoints"],
        "vuln_classes": ["ssti"],
        "description": "Test POST endpoints for server-side template injection",
    },
    {
        "id": "post_rce",
        "name": "POST Command Injection",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.post_endpoints"],
        "vuln_classes": ["rce"],
        "description": "Test POST endpoints for OS command injection",
    },
    {
        "id": "path_idor_test",
        "name": "Path-Based IDOR",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.path_idor_candidates"],
        "vuln_classes": ["idor"],
        "description": "Test URL path segments for IDOR (numeric IDs, UUIDs)",
    },
    {
        "id": "dom_xss",
        "name": "DOM XSS Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["crawled_urls"],
        "vuln_classes": ["xss"],
        "description": "Test for DOM-based XSS via Playwright or source analysis",
    },
    {
        "id": "mass_assignment_test",
        "name": "Mass Assignment Testing",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["parameter_classification.post_endpoints"],
        "vuln_classes": ["mass_assignment"],
        "description": "Test POST/PUT endpoints for mass assignment privilege escalation",
    },
    {
        "id": "cookie_xss",
        "name": "Cookie XSS Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["auth_discovery.injectable_cookies"],
        "vuln_classes": ["xss"],
        "description": "Test injectable cookies for reflected XSS",
    },
]

# Test class → technique ID mapping
_CLASS_TO_TECHNIQUES: dict[str, list[str]] = {
    "sqli": ["nuclei_scan", "sqli_param_fuzz", "cookie_sqli", "post_sqli"],
    "xss": ["nuclei_scan", "xss_param_fuzz", "stored_xss", "dom_xss", "cookie_xss"],
    "ssrf": ["nuclei_scan", "ssrf_test"],
    "lfi": ["nuclei_scan", "lfi_test"],
    "rfi": ["nuclei_scan"],
    "open_redirect": ["nuclei_scan", "open_redirect_test"],
    "idor": ["idor_test", "path_idor_test"],
    "crlf": ["crlf_test"],
    "ssti": ["ssti_test", "post_ssti"],
    "header_injection": ["header_injection_test"],
    "graphql": ["nuclei_scan", "graphql_test"],
    "jwt": ["jwt_test"],
    "content_discovery": ["deep_dirfuzz"],
    "param_discovery": ["deep_param_discovery"],
    "wordpress": ["nuclei_scan", "wordpress_test"],
    "spring": ["nuclei_scan", "spring_actuator_test"],
    "subdomain_takeover": ["nuclei_scan"],
    "misconfig": ["nuclei_scan"],
    "default_creds": ["nuclei_scan"],
    "file_exposure": ["nuclei_scan"],
    "rce": ["nuclei_scan", "rce_test", "post_rce"],
    "deserialization": ["cookie_deserialization"],
    "bac": ["broken_access_control"],
    "rate_limiting": ["rate_limit_test"],
    "mass_assignment": ["mass_assignment_test"],
    "auth_bypass": ["nuclei_scan"],
    "api_abuse": ["nuclei_scan"],
    "cve_specific": ["nuclei_scan"],
    "nuclei_general": ["nuclei_scan"],
}


# ---------------------------------------------------------------------------
# Technique availability check
# ---------------------------------------------------------------------------


def get_techniques_for_classes(test_classes: list[str]) -> list[dict[str, Any]]:
    """Return technique definitions for the given test classes."""
    technique_ids: set[str] = set()
    for tc in test_classes:
        for tid in _CLASS_TO_TECHNIQUES.get(tc, []):
            technique_ids.add(tid)

    registry_map = {t["id"]: t for t in TECHNIQUE_REGISTRY}
    return [registry_map[tid] for tid in technique_ids if tid in registry_map]


def check_technique_availability(technique: dict[str, Any]) -> dict[str, Any]:
    """Check if a technique's requirements are met."""
    missing_tools = [
        t for t in technique.get("requires_tools", [])
        if not tool_runner.is_available(t)
    ]
    return {
        "id": technique["id"],
        "name": technique["name"],
        "available": len(missing_tools) == 0,
        "missing_tools": missing_tools,
    }


def list_all_techniques() -> list[dict[str, Any]]:
    """List all techniques with availability status."""
    result: list[dict[str, Any]] = []
    for tech in TECHNIQUE_REGISTRY:
        avail = check_technique_availability(tech)
        result.append({
            **tech,
            "available": avail["available"],
            "missing_tools": avail["missing_tools"],
        })
    return result


# ---------------------------------------------------------------------------
# Technique execution
# ---------------------------------------------------------------------------


def _extract_items(data: list | dict | None) -> list[Any]:
    """Unwrap DataWrapper envelope."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("data", [])
    return []


def _get_param_candidates(
    pc_data: list[Any], candidate_key: str,
) -> list[dict[str, Any]]:
    """Extract parameter candidates from classification data."""
    if not pc_data:
        return []
    pc = pc_data[0] if pc_data and isinstance(pc_data[0], dict) else {}
    return pc.get(candidate_key, [])


async def _load_param_classification(workspace_id: str) -> list[Any]:
    """Load parameter classification from workspace."""
    raw = await workspace.read_data(workspace_id, "urls/parameter_classification.json")
    return _extract_items(raw)


async def _filter_to_scope(
    candidates: list[dict[str, Any]],
    approved_hosts: set[str],
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Filter candidates to approved scan plan hosts, with limit."""
    from urllib.parse import urlparse

    filtered: list[dict[str, Any]] = []
    for c in candidates:
        url = c.get("url", "")
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            continue
        if host.lower() in approved_hosts:
            filtered.append(c)
            if len(filtered) >= limit:
                break
    return filtered


async def execute_technique(
    technique_id: str,
    workspace_id: str,
    targets: list[dict[str, Any]],
    concurrency: int = 5,
) -> list[dict[str, Any]]:
    """Execute a specific technique and return findings.

    targets: scan plan targets (list of dicts with 'host', 'test_classes', etc.)

    Returns list of finding dicts.
    """
    # Build set of approved hosts
    approved_hosts = {
        t.get("host", "").lower() for t in targets if t.get("host")
    }

    if technique_id == "sqli_param_fuzz":
        return await _exec_sqli_fuzz(workspace_id, approved_hosts)
    elif technique_id == "xss_param_fuzz":
        return await _exec_xss_fuzz(workspace_id, approved_hosts)
    elif technique_id == "ssrf_test":
        return await _exec_ssrf(workspace_id, approved_hosts, concurrency)
    elif technique_id == "open_redirect_test":
        return await _exec_redirect(workspace_id, approved_hosts, concurrency)
    elif technique_id == "lfi_test":
        return await _exec_lfi(workspace_id, approved_hosts, concurrency)
    elif technique_id == "idor_test":
        return await _exec_idor(workspace_id, approved_hosts, concurrency)
    elif technique_id == "crlf_test":
        return await _exec_crlf(workspace_id, approved_hosts, concurrency)
    elif technique_id == "ssti_test":
        return await _exec_ssti(workspace_id, approved_hosts, concurrency)
    elif technique_id == "header_injection_test":
        return await _exec_header_injection(workspace_id, approved_hosts, concurrency)
    elif technique_id == "graphql_test":
        return await _exec_graphql(workspace_id, approved_hosts)
    elif technique_id == "jwt_test":
        return await _exec_jwt(workspace_id, approved_hosts)
    elif technique_id == "deep_dirfuzz":
        return await _exec_dirfuzz(workspace_id, approved_hosts)
    elif technique_id == "wordpress_test":
        return await _exec_wordpress(workspace_id, approved_hosts)
    elif technique_id == "spring_actuator_test":
        return await _exec_spring_actuator(workspace_id, approved_hosts)
    elif technique_id == "cookie_sqli":
        return await _exec_cookie_sqli(workspace_id, approved_hosts)
    elif technique_id == "cookie_deserialization":
        return await _exec_cookie_deser(workspace_id, approved_hosts)
    elif technique_id == "rce_test":
        return await _exec_rce(workspace_id, approved_hosts, concurrency)
    elif technique_id == "broken_access_control":
        return await _exec_broken_access(workspace_id, approved_hosts)
    elif technique_id == "rate_limit_test":
        return await _exec_rate_limit(workspace_id, approved_hosts)
    elif technique_id == "post_sqli":
        return await _exec_post_sqli(workspace_id, approved_hosts)
    elif technique_id == "stored_xss":
        return await _exec_stored_xss(workspace_id, approved_hosts)
    elif technique_id == "post_ssti":
        return await _exec_post_ssti(workspace_id, approved_hosts)
    elif technique_id == "post_rce":
        return await _exec_post_rce(workspace_id, approved_hosts)
    elif technique_id == "path_idor_test":
        return await _exec_path_idor(workspace_id, approved_hosts, concurrency)
    elif technique_id == "dom_xss":
        return await _exec_dom_xss(workspace_id, approved_hosts, concurrency)
    elif technique_id == "mass_assignment_test":
        return await _exec_mass_assignment(workspace_id, approved_hosts)
    elif technique_id == "cookie_xss":
        return await _exec_cookie_xss(workspace_id, approved_hosts)
    else:
        logger.warning("technique.unknown", technique_id=technique_id)
        return []


# ---------------------------------------------------------------------------
# Technique implementations
# ---------------------------------------------------------------------------


async def _exec_sqli_fuzz(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Run sqlmap on top SQLi candidates."""
    from bughound.tools.scanning import sqlmap

    if not sqlmap.is_available():
        return []

    pc = await _load_param_classification(workspace_id)
    candidates = _get_param_candidates(pc, "sqli_candidates")
    scoped = await _filter_to_scope(candidates, approved_hosts, limit=5)

    findings: list[dict[str, Any]] = []
    for c in scoped:
        url = c.get("url", "")
        param = c.get("param", "")
        if not url or not param:
            continue

        # Build URL with param if needed
        test_url = url if f"{param}=" in url else f"{url}?{param}=1"

        try:
            result = await sqlmap.execute(test_url, timeout=120)
            if result.success and result.results:
                for r in result.results:
                    if isinstance(r, dict) and r.get("vulnerable"):
                        findings.append({
                            "vulnerability_class": "sqli",
                            "tool": "sqlmap",
                            "technique_id": "sqli_param_fuzz",
                            "host": _host_from_url(url),
                            "endpoint": test_url,
                            "severity": "critical",
                            "description": f"SQL injection confirmed in parameter '{param}'",
                            "evidence": f"DB: {r.get('db_type', 'unknown')}, Payloads: {r.get('payloads', [])}",
                            "payload_used": r.get("payloads", [""])[0] if r.get("payloads") else "",
                            "confidence": "high",
                            "needs_validation": False,
                        })
        except Exception as exc:
            logger.warning("technique.sqli_error", url=url, error=str(exc))

    return findings


async def _exec_xss_fuzz(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Run dalfox on top XSS candidates."""
    from bughound.tools.scanning import dalfox

    if not dalfox.is_available():
        return []

    pc = await _load_param_classification(workspace_id)
    candidates = _get_param_candidates(pc, "xss_candidates")
    scoped = await _filter_to_scope(candidates, approved_hosts, limit=10)

    findings: list[dict[str, Any]] = []
    for c in scoped:
        url = c.get("url", "")
        param = c.get("param", "")
        if not url:
            continue

        test_url = url if f"{param}=" in url else f"{url}?{param}=test"

        try:
            result = await dalfox.execute(test_url, timeout=120)
            if result.success and result.results:
                for r in result.results:
                    if not isinstance(r, dict):
                        continue
                    findings.append({
                        "vulnerability_class": "xss",
                        "tool": "dalfox",
                        "technique_id": "xss_param_fuzz",
                        "host": _host_from_url(url),
                        "endpoint": r.get("url", test_url),
                        "severity": "high",
                        "description": f"{r.get('xss_type', 'reflected')} XSS in param '{param}'",
                        "evidence": r.get("evidence", ""),
                        "payload_used": r.get("payload", ""),
                        "confidence": "high",
                        "needs_validation": False,
                    })
        except Exception as exc:
            logger.warning("technique.xss_error", url=url, error=str(exc))

    return findings


async def _run_injection_batch(
    workspace_id: str,
    approved_hosts: set[str],
    candidate_key: str,
    test_func: Any,
    vuln_class: str,
    technique_id: str,
    severity: str,
    concurrency: int = 5,
    limit: int = 10,
    result_key: str = "vulnerable",
) -> list[dict[str, Any]]:
    """Generic batch runner for injection_tester functions."""
    pc = await _load_param_classification(workspace_id)
    candidates = _get_param_candidates(pc, candidate_key)
    scoped = await _filter_to_scope(candidates, approved_hosts, limit=limit)

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _test_one(c: dict[str, Any]) -> dict[str, Any] | None:
        url = c.get("url", "")
        param = c.get("param", "")
        sample = c.get("sample_value", "")
        if not url or not param:
            return None
        async with sem:
            try:
                result = await test_func(url, param, sample)
                if result.get(result_key):
                    return {
                        "vulnerability_class": vuln_class,
                        "tool": "injection_tester",
                        "technique_id": technique_id,
                        "host": _host_from_url(url),
                        "endpoint": result.get("url", url),
                        "severity": severity,
                        "description": f"{vuln_class.upper()} detected in param '{param}'",
                        "evidence": result.get("evidence", str(result)),
                        "payload_used": result.get("payload", ""),
                        "confidence": "medium",
                        "needs_validation": True,
                    }
            except Exception as exc:
                logger.warning(f"technique.{technique_id}_error", url=url, error=str(exc))
            return None

    tasks = [_test_one(c) for c in scoped]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _exec_ssrf(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    from bughound.tools.testing.injection_tester import test_ssrf
    return await _run_injection_batch(
        workspace_id, approved_hosts, "ssrf_candidates",
        test_ssrf, "ssrf", "ssrf_test", "critical", concurrency,
    )


async def _exec_redirect(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    from bughound.tools.testing.injection_tester import test_open_redirect
    return await _run_injection_batch(
        workspace_id, approved_hosts, "redirect_candidates",
        test_open_redirect, "open_redirect", "open_redirect_test", "medium", concurrency,
    )


async def _exec_lfi(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    from bughound.tools.testing.injection_tester import test_lfi
    return await _run_injection_batch(
        workspace_id, approved_hosts, "lfi_candidates",
        test_lfi, "lfi", "lfi_test", "high", concurrency,
    )


async def _exec_idor(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    from bughound.tools.testing.injection_tester import test_idor
    return await _run_injection_batch(
        workspace_id, approved_hosts, "idor_candidates",
        test_idor, "idor", "idor_test", "medium", concurrency,
        limit=10, result_key="potential_idor",
    )


async def _exec_crlf(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    from bughound.tools.testing.injection_tester import test_crlf

    # CRLF: test a sample of params across all types
    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    high_value = pc_dict.get("high_value_params", [])

    # Get unique URLs from high-value params
    all_candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for vtype in ("xss_candidates", "sqli_candidates", "ssrf_candidates"):
        for c in pc_dict.get(vtype, [])[:5]:
            key = f"{c.get('url')}:{c.get('param')}"
            if key not in seen:
                seen.add(key)
                all_candidates.append(c)

    scoped = await _filter_to_scope(all_candidates, approved_hosts, limit=10)
    return await _run_injection_batch_direct(
        scoped, test_crlf, "crlf", "crlf_test", "medium", concurrency,
    )


async def _exec_ssti(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    from bughound.tools.testing.injection_tester import test_ssti
    return await _run_injection_batch(
        workspace_id, approved_hosts, "ssti_candidates",
        test_ssti, "ssti", "ssti_test", "critical", concurrency,
    )


async def _exec_header_injection(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Run header injection tests on live hosts."""
    from bughound.tools.testing.injection_tester import test_header_injection

    raw = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw)

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _test_one(h: dict[str, Any]) -> list[dict[str, Any]]:
        url = h.get("url", "")
        host = (h.get("host") or "").lower()
        if not url or host not in approved_hosts:
            return []
        async with sem:
            try:
                result = await test_header_injection(url)
                if result.get("vulnerable"):
                    return [
                        {
                            "vulnerability_class": "header_injection",
                            "tool": "injection_tester",
                            "technique_id": "header_injection_test",
                            "host": host,
                            "endpoint": url,
                            "severity": f.get("severity", "medium"),
                            "description": f"Header injection: {f['technique']}",
                            "evidence": f.get("evidence", ""),
                            "payload_used": f["technique"],
                            "confidence": "medium",
                            "needs_validation": True,
                        }
                        for f in result.get("findings", [])
                    ]
            except Exception:
                pass
            return []

    tasks = [_test_one(h) for h in hosts[:20]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings


async def _exec_graphql(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Run GraphQL tests on flagged hosts."""
    from bughound.tools.testing.graphql_tester import test_graphql

    raw = await workspace.read_data(workspace_id, "hosts/flags.json")
    flags = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    for f in flags:
        host = (f.get("host") or "").lower()
        if host not in approved_hosts:
            continue
        if not any("GRAPHQL" in flag for flag in f.get("flags", [])):
            continue

        url = f.get("url", f"https://{host}")
        # Try common GraphQL paths
        for gql_path in ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]:
            gql_url = url.rstrip("/") + gql_path
            try:
                result = await test_graphql(gql_url)
                if result.get("introspection_enabled"):
                    finding = {
                        "vulnerability_class": "graphql",
                        "tool": "graphql_tester",
                        "technique_id": "graphql_test",
                        "host": host,
                        "endpoint": gql_url,
                        "severity": "medium",
                        "description": "GraphQL introspection enabled",
                        "evidence": f"{len(result.get('schema_types', []))} types, {len(result.get('mutations', []))} mutations exposed",
                        "confidence": "high",
                        "needs_validation": False,
                    }
                    findings.append(finding)

                    if not result.get("depth_limited"):
                        findings.append({
                            **finding,
                            "description": "GraphQL: no query depth limiting (DoS risk)",
                            "severity": "low",
                        })
                    if not result.get("batch_limited"):
                        findings.append({
                            **finding,
                            "description": "GraphQL: batch queries not rate-limited",
                            "severity": "low",
                        })
                    if result.get("unauthorized_mutations"):
                        mutations = result["unauthorized_mutations"]
                        findings.append({
                            **finding,
                            "description": f"GraphQL: {len(mutations)} unauthorized mutations accessible",
                            "severity": "high",
                            "evidence": str(mutations[:5]),
                        })
                    break  # Found working endpoint

            except Exception:
                continue

    return findings


async def _exec_jwt(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Run JWT tests — requires JWT tokens to be detected in secrets."""
    from bughound.tools.testing.jwt_tester import test_jwt

    raw = await workspace.read_data(workspace_id, "secrets/js_secrets.json")
    secrets = _extract_items(raw)

    # Find JWT tokens
    jwt_tokens: list[tuple[str, str]] = []
    for s in secrets:
        if s.get("type") == "JWT" or "eyJ" in str(s.get("value", "")):
            token = s.get("value", "")
            source = s.get("source_file", "")
            if token and token.count(".") == 2:
                jwt_tokens.append((token, source))

    if not jwt_tokens:
        return []

    findings: list[dict[str, Any]] = []
    # Get a target URL for testing
    raw_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw_hosts)
    host_urls = {
        (h.get("host") or "").lower(): h.get("url", "")
        for h in hosts if h.get("url")
    }

    for token, source in jwt_tokens[:3]:
        # Try to find the right host
        from urllib.parse import urlparse
        try:
            source_host = urlparse(source).hostname or ""
        except Exception:
            source_host = ""

        target_url = host_urls.get(source_host.lower(), "")
        if not target_url or source_host.lower() not in approved_hosts:
            continue

        try:
            result = await test_jwt(token, target_url)
            if result.get("alg_none_bypass"):
                findings.append({
                    "vulnerability_class": "jwt",
                    "tool": "jwt_tester",
                    "technique_id": "jwt_test",
                    "host": source_host,
                    "endpoint": target_url,
                    "severity": "critical",
                    "description": "JWT algorithm 'none' bypass — authentication bypass",
                    "evidence": f"alg=none accepted, claims: {result.get('token_claims', {})}",
                    "confidence": "high",
                    "needs_validation": True,
                })
            if result.get("alg_confusion"):
                findings.append({
                    "vulnerability_class": "jwt",
                    "tool": "jwt_tester",
                    "technique_id": "jwt_test",
                    "host": source_host,
                    "endpoint": target_url,
                    "severity": "critical",
                    "description": "JWT algorithm confusion (RS256→HS256)",
                    "evidence": "HMAC-signed token accepted as RSA-signed",
                    "confidence": "high",
                    "needs_validation": True,
                })
            if not result.get("expiry_enforced"):
                findings.append({
                    "vulnerability_class": "jwt",
                    "tool": "jwt_tester",
                    "technique_id": "jwt_test",
                    "host": source_host,
                    "endpoint": target_url,
                    "severity": "medium",
                    "description": "JWT expiry not enforced — expired tokens accepted",
                    "confidence": "medium",
                    "needs_validation": True,
                })
        except Exception as exc:
            logger.warning("technique.jwt_error", error=str(exc))

    return findings


async def _exec_dirfuzz(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Run ffuf deep directory fuzzing."""
    from bughound.tools.scanning import ffuf

    if not ffuf.is_available():
        return []

    raw = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    for h in hosts[:5]:  # Cap at 5 hosts
        host = (h.get("host") or "").lower()
        url = h.get("url", "")
        if not url or host not in approved_hosts:
            continue

        try:
            result = await ffuf.execute(url, wordlist_size="medium", timeout=300)
            if result.success and result.results:
                for r in result.results:
                    if not isinstance(r, dict):
                        continue
                    sc = r.get("status_code", 0)
                    if sc in (200, 401, 403):
                        findings.append({
                            "vulnerability_class": "content_discovery",
                            "tool": "ffuf",
                            "technique_id": "deep_dirfuzz",
                            "host": host,
                            "endpoint": r.get("url", ""),
                            "severity": "info",
                            "description": f"Directory found: {r.get('path', '')} ({sc})",
                            "evidence": f"Size: {r.get('content_length', 0)} bytes",
                            "confidence": "high",
                            "needs_validation": False,
                        })
        except Exception as exc:
            logger.warning("technique.dirfuzz_error", host=host, error=str(exc))

    return findings


async def _exec_wordpress(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """WordPress-specific checks via aiohttp."""
    import aiohttp as _aiohttp

    raw = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    timeout = _aiohttp.ClientTimeout(total=10)

    for h in hosts:
        host = (h.get("host") or "").lower()
        url = h.get("url", "")
        techs = " ".join(h.get("technologies", [])).lower()
        if not url or host not in approved_hosts or "wordpress" not in techs:
            continue

        base = url.rstrip("/")

        async with _aiohttp.ClientSession() as session:
            # Test xmlrpc.php
            try:
                async with session.post(
                    f"{base}/xmlrpc.php",
                    data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                    headers={"Content-Type": "text/xml"},
                    ssl=False, timeout=timeout,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        if "methodResponse" in body:
                            findings.append({
                                "vulnerability_class": "wordpress",
                                "tool": "wordpress_tester",
                                "technique_id": "wordpress_test",
                                "host": host,
                                "endpoint": f"{base}/xmlrpc.php",
                                "severity": "medium",
                                "description": "WordPress xmlrpc.php enabled — brute force and SSRF possible",
                                "evidence": "system.listMethods returned valid response",
                                "confidence": "high",
                                "needs_validation": False,
                            })
            except Exception:
                pass

            # Test user enumeration
            try:
                async with session.get(
                    f"{base}/wp-json/wp/v2/users",
                    ssl=False, timeout=timeout,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        if '"slug"' in body:
                            findings.append({
                                "vulnerability_class": "wordpress",
                                "tool": "wordpress_tester",
                                "technique_id": "wordpress_test",
                                "host": host,
                                "endpoint": f"{base}/wp-json/wp/v2/users",
                                "severity": "low",
                                "description": "WordPress user enumeration via REST API",
                                "evidence": body[:300],
                                "confidence": "high",
                                "needs_validation": False,
                            })
            except Exception:
                pass

            # Test debug.log
            try:
                async with session.get(
                    f"{base}/wp-content/debug.log",
                    ssl=False, timeout=timeout,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        if "PHP" in body or "Warning" in body or "Fatal" in body:
                            findings.append({
                                "vulnerability_class": "wordpress",
                                "tool": "wordpress_tester",
                                "technique_id": "wordpress_test",
                                "host": host,
                                "endpoint": f"{base}/wp-content/debug.log",
                                "severity": "medium",
                                "description": "WordPress debug.log exposed — potential info disclosure",
                                "evidence": body[:300],
                                "confidence": "high",
                                "needs_validation": False,
                            })
            except Exception:
                pass

    return findings


async def _exec_spring_actuator(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Spring Boot actuator endpoint checks via aiohttp."""
    import aiohttp as _aiohttp

    raw = await workspace.read_data(workspace_id, "hosts/flags.json")
    flags = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    timeout = _aiohttp.ClientTimeout(total=10)

    actuator_paths = [
        ("/actuator/env", "high", "Environment variables exposed"),
        ("/actuator/heapdump", "critical", "Heap dump available — memory secrets"),
        ("/actuator/mappings", "medium", "URL mappings exposed"),
        ("/actuator/configprops", "high", "Configuration properties exposed"),
        ("/actuator/beans", "low", "Spring beans enumeration"),
        ("/actuator/loggers", "medium", "Logger configuration exposed"),
    ]

    for f in flags:
        host = (f.get("host") or "").lower()
        if host not in approved_hosts:
            continue
        if not any("ACTUATOR" in flag for flag in f.get("flags", [])):
            continue

        url = f.get("url", f"https://{host}")
        base = url.rstrip("/")

        async with _aiohttp.ClientSession() as session:
            for path, severity, desc in actuator_paths:
                try:
                    async with session.get(
                        f"{base}{path}", ssl=False, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (BugHound Scanner)"},
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            if len(body) > 50:
                                findings.append({
                                    "vulnerability_class": "spring",
                                    "tool": "spring_actuator_tester",
                                    "technique_id": "spring_actuator_test",
                                    "host": host,
                                    "endpoint": f"{base}{path}",
                                    "severity": severity,
                                    "description": desc,
                                    "evidence": body[:300],
                                    "confidence": "high",
                                    "needs_validation": False,
                                })
                except Exception:
                    continue

    return findings


async def _run_injection_batch_direct(
    scoped: list[dict[str, Any]],
    test_func: Any,
    vuln_class: str,
    technique_id: str,
    severity: str,
    concurrency: int,
) -> list[dict[str, Any]]:
    """Run injection tests on pre-filtered candidates."""
    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _test_one(c: dict[str, Any]) -> dict[str, Any] | None:
        url = c.get("url", "")
        param = c.get("param", "")
        sample = c.get("sample_value", "")
        if not url or not param:
            return None
        async with sem:
            try:
                result = await test_func(url, param, sample)
                if result.get("vulnerable"):
                    return {
                        "vulnerability_class": vuln_class,
                        "tool": "injection_tester",
                        "technique_id": technique_id,
                        "host": _host_from_url(url),
                        "endpoint": result.get("url", url),
                        "severity": severity,
                        "description": f"{vuln_class.upper()} detected in param '{param}'",
                        "evidence": result.get("evidence", str(result)),
                        "payload_used": result.get("payload", ""),
                        "confidence": "medium",
                        "needs_validation": True,
                    }
            except Exception:
                pass
            return None

    tasks = [_test_one(c) for c in scoped]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


def _get_all_cookies(auth: dict[str, Any]) -> list[dict[str, str]]:
    """Get ALL cookies from auth data, not just injectable ones.

    Returns list of {name, value} dicts from both 'cookies' (all cookies)
    and 'injectable_cookies', deduped by name.
    """
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    # All cookies first (broadest set)
    for cookie in auth.get("cookies", []):
        name = cookie.get("name", "")
        if name and name not in seen:
            seen.add(name)
            result.append({"name": name, "value": cookie.get("value", "")})
    # Also include injectable_cookies in case they have different values
    for cookie in auth.get("injectable_cookies", []):
        name = cookie.get("name", "")
        if name and name not in seen:
            seen.add(name)
            result.append({"name": name, "value": cookie.get("value", "")})
    return result


async def _exec_cookie_sqli(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test ALL cookies for SQL injection."""
    from bughound.tools.testing.injection_tester import test_cookie_injection

    auth_data = await _load_auth_discovery(workspace_id)
    if not auth_data:
        return []

    findings: list[dict[str, Any]] = []
    for auth in auth_data:
        target_url = auth.get("target_url", "")
        if not target_url:
            continue

        host = _host_from_url(target_url)
        if host not in approved_hosts:
            continue

        for cookie in _get_all_cookies(auth):
            cookie_name = cookie["name"]
            cookie_value = cookie["value"]

            try:
                result = await test_cookie_injection(
                    target_url, cookie_name, cookie_value, "sqli",
                )
                if result.get("vulnerable"):
                    findings.append({
                        "vulnerability_class": "sqli",
                        "tool": "injection_tester",
                        "technique_id": "cookie_sqli",
                        "host": host,
                        "endpoint": target_url,
                        "severity": "critical",
                        "description": f"SQL injection in cookie '{cookie_name}'",
                        "evidence": result.get("evidence", ""),
                        "payload_used": result.get("payload", ""),
                        "confidence": "high",
                        "needs_validation": True,
                    })
            except Exception as exc:
                logger.warning("technique.cookie_sqli_error", error=str(exc))

    return findings


async def _exec_cookie_deser(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test ALL cookies for insecure deserialization."""
    from bughound.tools.testing.injection_tester import test_cookie_injection

    auth_data = await _load_auth_discovery(workspace_id)
    if not auth_data:
        return []

    findings: list[dict[str, Any]] = []
    for auth in auth_data:
        target_url = auth.get("target_url", "")
        if not target_url:
            continue

        host = _host_from_url(target_url)
        if host not in approved_hosts:
            continue

        for cookie in _get_all_cookies(auth):
            cookie_name = cookie["name"]
            cookie_value = cookie["value"]

            try:
                result = await test_cookie_injection(
                    target_url, cookie_name, cookie_value, "deserialization",
                )
                if result.get("vulnerable"):
                    findings.append({
                        "vulnerability_class": "deserialization",
                        "tool": "injection_tester",
                        "technique_id": "cookie_deserialization",
                        "host": host,
                        "endpoint": target_url,
                        "severity": "critical",
                        "description": f"Insecure deserialization in cookie '{cookie_name}'",
                        "evidence": result.get("evidence", ""),
                        "payload_used": result.get("payload", ""),
                        "confidence": "medium",
                        "needs_validation": True,
                    })
            except Exception as exc:
                logger.warning("technique.cookie_deser_error", error=str(exc))

    return findings


async def _exec_rce(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Test RCE/command injection on classified parameters."""
    from bughound.tools.testing.injection_tester import test_rce
    return await _run_injection_batch(
        workspace_id, approved_hosts, "rce_candidates",
        test_rce, "rce", "rce_test", "critical", concurrency,
    )


async def _exec_broken_access(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test broken access control on admin/internal endpoints."""
    from bughound.tools.testing.injection_tester import test_broken_access

    # Gather endpoints from crawled URLs and directory findings
    raw_urls = await workspace.read_data(workspace_id, "urls/crawled.json")
    urls = _extract_items(raw_urls)
    raw_dir = await workspace.read_data(workspace_id, "dirfuzz/light_results.json")
    dir_findings = _extract_items(raw_dir)

    # Collect candidate endpoint URLs
    endpoints: list[str] = []
    seen: set[str] = set()
    for u in urls:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        host = _host_from_url(url)
        if host in approved_hosts and url not in seen:
            seen.add(url)
            endpoints.append(url)
    for d in dir_findings:
        url = d.get("url", "")
        host = _host_from_url(url)
        if host in approved_hosts and url not in seen:
            seen.add(url)
            endpoints.append(url)

    if not endpoints:
        return []

    # Get auth token if available
    auth_data = await _load_auth_discovery(workspace_id)
    auth_token = None
    for ad in auth_data:
        if ad.get("auth_token"):
            auth_token = ad["auth_token"]
            break

    try:
        results = await test_broken_access(endpoints[:100], auth_token)
    except Exception as exc:
        logger.warning("technique.bac_error", error=str(exc))
        return []

    findings: list[dict[str, Any]] = []
    for r in results:
        if r.get("accessible"):
            findings.append({
                "vulnerability_class": "bac",
                "tool": "injection_tester",
                "technique_id": "broken_access_control",
                "host": _host_from_url(r.get("endpoint", "")),
                "endpoint": r.get("endpoint", ""),
                "severity": "high",
                "description": f"Broken access control: {r.get('technique', 'unauthenticated access')}",
                "evidence": r.get("evidence", f"Status {r.get('status_code')} with {r.get('content_length', 0)} bytes"),
                "confidence": "medium",
                "needs_validation": True,
            })

    return findings


async def _exec_rate_limit(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test auth endpoints for missing rate limiting."""
    from bughound.tools.testing.injection_tester import test_rate_limit

    auth_data = await _load_auth_discovery(workspace_id)
    if not auth_data:
        return []

    findings: list[dict[str, Any]] = []
    tested: set[str] = set()

    for auth in auth_data:
        for ep in auth.get("auth_endpoints", []):
            path = ep.get("path", "")
            target_url = auth.get("target_url", "")
            if not target_url or not path:
                continue

            host = _host_from_url(target_url)
            if host not in approved_hosts:
                continue

            base = target_url.rstrip("/")
            full_url = f"{base}{path}"
            if full_url in tested:
                continue
            tested.add(full_url)

            # Only test login/auth endpoints
            if not any(k in path.lower() for k in ("/login", "/signin", "/auth", "/token")):
                continue

            try:
                result = await test_rate_limit(full_url, method="POST")
                if not result.get("rate_limited"):
                    findings.append({
                        "vulnerability_class": "rate_limiting",
                        "tool": "injection_tester",
                        "technique_id": "rate_limit_test",
                        "host": host,
                        "endpoint": full_url,
                        "severity": "medium",
                        "description": f"No rate limiting on auth endpoint: {path}",
                        "evidence": result.get("evidence", "30 requests without 429 response"),
                        "confidence": "high",
                        "needs_validation": False,
                    })
            except Exception as exc:
                logger.warning("technique.rate_limit_error", error=str(exc))

    return findings


async def _exec_post_sqli(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test POST endpoints for SQL injection."""
    from bughound.tools.testing.post_tester import test_post_sqli

    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    post_eps = pc_dict.get("post_endpoints", [])

    findings: list[dict[str, Any]] = []
    for ep in post_eps[:10]:
        url = ep.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts or not url:
            continue
        params = ep.get("params", [])
        if not params:
            continue

        try:
            result = await test_post_sqli(url, params)
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "sqli",
                    "tool": "post_tester",
                    "technique_id": "post_sqli",
                    "host": host,
                    "endpoint": url,
                    "severity": "critical",
                    "description": f"POST SQL injection: {result.get('type', 'sqli')}",
                    "evidence": result.get("evidence", ""),
                    "payload_used": result.get("payload", ""),
                    "confidence": "medium",
                    "needs_validation": True,
                })
        except Exception as exc:
            logger.warning("technique.post_sqli_error", error=str(exc))

    return findings


async def _exec_stored_xss(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test POST endpoints for stored XSS."""
    from bughound.tools.testing.post_tester import test_stored_xss

    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    post_eps = pc_dict.get("post_endpoints", [])

    findings: list[dict[str, Any]] = []
    for ep in post_eps[:10]:
        url = ep.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts or not url:
            continue
        params = ep.get("params", [])
        if not params:
            continue

        try:
            result = await test_stored_xss(url, params)
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "xss",
                    "tool": "post_tester",
                    "technique_id": "stored_xss",
                    "host": host,
                    "endpoint": url,
                    "severity": "high",
                    "description": f"Stored XSS: {result.get('type', 'stored')}",
                    "evidence": result.get("evidence", ""),
                    "payload_used": result.get("payload", ""),
                    "confidence": "medium",
                    "needs_validation": True,
                })
        except Exception as exc:
            logger.warning("technique.stored_xss_error", error=str(exc))

    return findings


async def _exec_post_ssti(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test POST endpoints for SSTI."""
    from bughound.tools.testing.post_tester import test_post_ssti

    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    post_eps = pc_dict.get("post_endpoints", [])

    findings: list[dict[str, Any]] = []
    for ep in post_eps[:10]:
        url = ep.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts or not url:
            continue
        params = ep.get("params", [])
        if not params:
            continue

        try:
            result = await test_post_ssti(url, params)
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "ssti",
                    "tool": "post_tester",
                    "technique_id": "post_ssti",
                    "host": host,
                    "endpoint": url,
                    "severity": "critical",
                    "description": f"POST SSTI ({result.get('template_engine', 'unknown')} engine)",
                    "evidence": result.get("evidence", ""),
                    "payload_used": result.get("payload", ""),
                    "confidence": "medium",
                    "needs_validation": True,
                })
        except Exception as exc:
            logger.warning("technique.post_ssti_error", error=str(exc))

    return findings


async def _exec_post_rce(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test POST endpoints for command injection."""
    from bughound.tools.testing.post_tester import test_post_rce

    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    post_eps = pc_dict.get("post_endpoints", [])

    findings: list[dict[str, Any]] = []
    for ep in post_eps[:5]:
        url = ep.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts or not url:
            continue
        params = ep.get("params", [])
        if not params:
            continue

        try:
            result = await test_post_rce(url, params)
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "rce",
                    "tool": "post_tester",
                    "technique_id": "post_rce",
                    "host": host,
                    "endpoint": url,
                    "severity": "critical",
                    "description": f"POST command injection ({result.get('technique', 'unknown')})",
                    "evidence": result.get("evidence", ""),
                    "payload_used": result.get("payload", ""),
                    "confidence": "medium",
                    "needs_validation": True,
                })
        except Exception as exc:
            logger.warning("technique.post_rce_error", error=str(exc))

    return findings


async def _exec_path_idor(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Test path-based IDOR on URLs with ID-like segments."""
    from bughound.tools.testing.injection_tester import test_path_idor

    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    candidates = pc_dict.get("path_idor_candidates", [])

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _test_one(c: dict[str, Any]) -> dict[str, Any] | None:
        url = c.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts:
            return None
        async with sem:
            try:
                result = await test_path_idor(url)
                if result.get("potential_idor"):
                    return {
                        "vulnerability_class": "idor",
                        "tool": "injection_tester",
                        "technique_id": "path_idor_test",
                        "host": host,
                        "endpoint": result.get("url", url),
                        "severity": "medium",
                        "description": f"Path IDOR: {result.get('segment_type', 'unknown')} segment '{result.get('path_segment', '')}'",
                        "evidence": result.get("response_diff", ""),
                        "confidence": result.get("confidence", "low"),
                        "needs_validation": True,
                    }
            except Exception:
                pass
            return None

    tasks = [_test_one(c) for c in candidates[:15]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _exec_dom_xss(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Test for DOM-based XSS on crawled URLs."""
    from bughound.tools.testing.dom_xss_tester import test_dom_xss

    raw_urls = await workspace.read_data(workspace_id, "urls/crawled.json")
    urls = _extract_items(raw_urls)

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _test_one(u: Any) -> list[dict[str, Any]]:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        host = _host_from_url(url)
        if host not in approved_hosts:
            return []
        async with sem:
            try:
                result = await test_dom_xss(url)
                if result.get("vulnerable"):
                    out: list[dict[str, Any]] = []
                    if result.get("method") == "playwright":
                        for f in result.get("findings", []):
                            out.append({
                                "vulnerability_class": "xss",
                                "tool": "dom_xss_tester",
                                "technique_id": "dom_xss",
                                "host": host,
                                "endpoint": f.get("url", url),
                                "severity": "high",
                                "description": f"DOM XSS ({f.get('type', 'unknown')}): {f.get('injection_point', '')}",
                                "evidence": f.get("evidence", ""),
                                "payload_used": f.get("payload", ""),
                                "confidence": "high",
                                "needs_validation": False,
                            })
                    else:
                        # Lite mode — sink/source analysis
                        out.append({
                            "vulnerability_class": "xss",
                            "tool": "dom_xss_tester",
                            "technique_id": "dom_xss",
                            "host": host,
                            "endpoint": url,
                            "severity": "medium",
                            "description": f"Potential DOM XSS: {len(result.get('sinks', []))} sinks, {len(result.get('sources', []))} sources",
                            "evidence": str(result.get("dangerous_flows", []))[:500],
                            "confidence": "low",
                            "needs_validation": True,
                        })
                    return out
            except Exception:
                pass
            return []

    # Test a sample of URLs — DOM XSS testing is slow
    sample_urls = urls[:20]
    tasks = [_test_one(u) for u in sample_urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings


async def _exec_mass_assignment(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test POST endpoints for mass assignment."""
    from bughound.tools.testing.mass_assignment_tester import test_mass_assignment

    pc = await _load_param_classification(workspace_id)
    pc_dict = pc[0] if pc and isinstance(pc[0], dict) else {}
    post_eps = pc_dict.get("post_endpoints", [])

    # Get auth token for authenticated testing
    auth_data = await _load_auth_discovery(workspace_id)
    auth_token = None
    for ad in auth_data:
        if ad.get("auth_token"):
            auth_token = ad["auth_token"]
            break

    findings: list[dict[str, Any]] = []
    for ep in post_eps[:10]:
        url = ep.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts or not url:
            continue

        params = ep.get("params", [])
        original = {p: "test" for p in params} if params else None

        try:
            result = await test_mass_assignment(
                url, original_params=original, auth_token=auth_token,
            )
            if result.get("vulnerable"):
                for f in result.get("findings", []):
                    findings.append({
                        "vulnerability_class": "mass_assignment",
                        "tool": "mass_assignment_tester",
                        "technique_id": "mass_assignment_test",
                        "host": host,
                        "endpoint": url,
                        "severity": f.get("severity", "high"),
                        "description": f"Mass assignment: field '{f.get('field', '?')}' accepted",
                        "evidence": f.get("evidence", ""),
                        "payload_used": str(f.get("injected_value", "")),
                        "confidence": "medium",
                        "needs_validation": True,
                    })
        except Exception as exc:
            logger.warning("technique.mass_assignment_error", error=str(exc))

    return findings


async def _exec_cookie_xss(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test ALL cookies for XSS."""
    from bughound.tools.testing.injection_tester import test_cookie_injection

    auth_data = await _load_auth_discovery(workspace_id)
    if not auth_data:
        return []

    findings: list[dict[str, Any]] = []
    for auth in auth_data:
        target_url = auth.get("target_url", "")
        if not target_url:
            continue

        host = _host_from_url(target_url)
        if host not in approved_hosts:
            continue

        for cookie in _get_all_cookies(auth):
            cookie_name = cookie["name"]
            cookie_value = cookie["value"]

            try:
                result = await test_cookie_injection(
                    target_url, cookie_name, cookie_value, "xss",
                )
                if result.get("vulnerable"):
                    findings.append({
                        "vulnerability_class": "xss",
                        "tool": "injection_tester",
                        "technique_id": "cookie_xss",
                        "host": host,
                        "endpoint": target_url,
                        "severity": "medium",
                        "description": f"Cookie XSS in '{cookie_name}'",
                        "evidence": result.get("evidence", ""),
                        "payload_used": result.get("payload", ""),
                        "confidence": "medium",
                        "needs_validation": True,
                    })
            except Exception as exc:
                logger.warning("technique.cookie_xss_error", error=str(exc))

    return findings


async def _load_auth_discovery(workspace_id: str) -> list[dict[str, Any]]:
    """Load auth discovery data from workspace."""
    raw = await workspace.read_data(workspace_id, "hosts/auth_discovery.json")
    return _extract_items(raw)


def _host_from_url(url: str) -> str:
    """Extract hostname from URL."""
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
