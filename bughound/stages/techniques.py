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
        "id": "sqli_error_test",
        "name": "SQL Injection Testing (Pure-Python)",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.sqli_candidates"],
        "vuln_classes": ["sqli"],
        "description": "Pure-Python SQLi detection — error-based + boolean-blind, no external tools needed",
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
        "id": "csti_test",
        "name": "Client-Side Template Injection Testing",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.xss_candidates"],
        "vuln_classes": ["csti"],
        "description": "Test for AngularJS/Vue.js client-side template injection",
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
    {
        "id": "reflected_xss_test",
        "name": "Reflected XSS Testing (Pure-Python)",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification.xss_candidates"],
        "vuln_classes": ["xss"],
        "description": "Pure-Python reflected XSS testing — fallback when dalfox unavailable or for additional coverage",
    },
    {
        "id": "cors_misconfig",
        "name": "CORS Misconfiguration",
        "phase": "4E",
        "requires_tools": [],
        "requires_data": ["cors_results"],
        "vuln_classes": ["cors"],
        "description": "Promote CORS misconfigurations detected in discovery to findings",
    },
    {
        "id": "prototype_pollution_test",
        "name": "Prototype Pollution",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["parameter_classification"],
        "vuln_classes": ["prototype_pollution"],
        "description": "Test for client-side prototype pollution via __proto__ and constructor.prototype",
    },
    {
        "id": "sensitive_leakage_test",
        "name": "Sensitive Field Leakage",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["urls"],
        "vuln_classes": ["info_leak"],
        "description": "Check API responses for leaked sensitive fields (password_hash, totp_secret, etc.)",
    },
    {
        "id": "security_headers_check",
        "name": "Security Headers Audit",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["misconfig"],
        "description": "Check for missing security headers (CSP, X-Frame-Options, HSTS, etc.)",
    },
    {
        "id": "version_disclosure_check",
        "name": "Version Disclosure",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["info_leak"],
        "description": "Detect server version disclosure in response headers",
    },
    {
        "id": "transport_security_check",
        "name": "Transport Security",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["misconfig"],
        "description": "Check HTTPS availability and HSTS enforcement",
    },
    {
        "id": "pii_html_leakage",
        "name": "PII Leakage in HTML",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["urls"],
        "vuln_classes": ["info_leak"],
        "description": "Scan HTML responses for leaked email addresses and PII",
    },
    {
        "id": "vulnerable_components_check",
        "name": "Vulnerable Components",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["technologies"],
        "vuln_classes": ["vulnerable_component"],
        "description": "Detect known vulnerable library/framework versions (jQuery, ASP.NET, etc.)",
    },
    {
        "id": "viewstate_mac_check",
        "name": "ViewState MAC Validation",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["live_hosts"],
        "vuln_classes": ["deserialization"],
        "description": "Test ASP.NET ViewState MAC validation — disabled MAC enables deserialization RCE",
    },
    {
        "id": "default_credentials_test",
        "name": "Default Credentials",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["auth_discovery"],
        "vuln_classes": ["default_creds"],
        "description": "Test login forms with common default credential pairs",
    },
    {
        "id": "xxe_test",
        "name": "XML External Entity Injection",
        "phase": "4D",
        "requires_tools": [],
        "requires_data": ["urls"],
        "vuln_classes": ["xxe"],
        "description": "Test for XXE via XML/SOAP POST with file:// entity injection",
    },
]

# Test class → technique ID mapping
_CLASS_TO_TECHNIQUES: dict[str, list[str]] = {
    "sqli": ["nuclei_scan", "sqli_param_fuzz", "sqli_error_test", "cookie_sqli", "post_sqli"],
    "xss": ["nuclei_scan", "xss_param_fuzz", "reflected_xss_test", "stored_xss", "dom_xss", "cookie_xss"],
    "ssrf": ["nuclei_scan", "ssrf_test"],
    "lfi": ["nuclei_scan", "lfi_test"],
    "rfi": ["nuclei_scan"],
    "open_redirect": ["nuclei_scan", "open_redirect_test"],
    "idor": ["idor_test", "path_idor_test"],
    "crlf": ["crlf_test"],
    "ssti": ["ssti_test", "post_ssti"],
    "csti": ["csti_test"],
    "header_injection": ["header_injection_test"],
    "graphql": ["nuclei_scan", "graphql_test"],
    "jwt": ["jwt_test"],
    "content_discovery": ["deep_dirfuzz"],
    "param_discovery": ["deep_param_discovery"],
    "wordpress": ["nuclei_scan", "wordpress_test"],
    "spring": ["nuclei_scan", "spring_actuator_test"],
    "subdomain_takeover": ["nuclei_scan"],
    "misconfig": ["nuclei_scan", "security_headers_check", "transport_security_check"],
    "default_creds": ["nuclei_scan", "default_credentials_test"],
    "file_exposure": ["nuclei_scan"],
    "rce": ["nuclei_scan", "rce_test", "post_rce"],
    "deserialization": ["cookie_deserialization", "viewstate_mac_check"],
    "cors": ["cors_misconfig"],
    "bac": ["broken_access_control"],
    "rate_limiting": ["rate_limit_test"],
    "mass_assignment": ["mass_assignment_test"],
    "auth_bypass": ["nuclei_scan"],
    "api_abuse": ["nuclei_scan"],
    "cve_specific": ["nuclei_scan"],
    "nuclei_general": ["nuclei_scan"],
    "prototype_pollution": ["prototype_pollution_test"],
    "info_leak": ["sensitive_leakage_test", "version_disclosure_check", "pii_html_leakage"],
    "vulnerable_component": ["vulnerable_components_check"],
    "xxe": ["xxe_test"],
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
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Filter candidates to approved scan plan hosts, with limit."""
    from urllib.parse import urlparse

    # Normalize approved_hosts: strip scheme/port, keep just hostname
    normalized_hosts: set[str] = set()
    for h in approved_hosts:
        h_clean = h.lower().strip()
        if "://" in h_clean:
            parsed_h = urlparse(h_clean)
            normalized_hosts.add(parsed_h.hostname or h_clean)
        elif ":" in h_clean:
            # host:port — take just the host part
            normalized_hosts.add(h_clean.split(":")[0])
        else:
            normalized_hosts.add(h_clean)

    # Pick a base URL from approved hosts to resolve relative URLs
    base_url = ""
    for h in approved_hosts:
        if "://" in h:
            base_url = h.rstrip("/")
            break
    if not base_url and normalized_hosts:
        base_url = f"https://{next(iter(normalized_hosts))}"

    filtered: list[dict[str, Any]] = []
    for c in candidates:
        url = c.get("url", "")
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except Exception:
            continue

        # Resolve relative URLs (e.g. "/api/products?limit=100")
        if not host and url.startswith("/") and base_url:
            url = base_url + url
            c = {**c, "url": url}  # shallow copy with fixed URL
            try:
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
            except Exception:
                continue

        if host in normalized_hosts:
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
    # Build set of approved hosts, normalized (strip schemes and ports)
    from urllib.parse import urlparse as _urlparse
    approved_hosts: set[str] = set()
    for t in targets:
        h = (t.get("host") or "").lower().strip()
        if not h:
            continue
        if "://" in h:
            parsed_h = _urlparse(h)
            approved_hosts.add(parsed_h.hostname or h)
        elif ":" in h:
            approved_hosts.add(h.split(":")[0])
        else:
            approved_hosts.add(h)

    # For broad domains: auto-approve ALL live subdomains
    try:
        meta = await workspace.get_workspace(workspace_id)
        if meta and meta.target_type and meta.target_type.value == "broad_domain":
            raw_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
            live_items = raw_hosts.get("data", raw_hosts) if isinstance(raw_hosts, dict) else (raw_hosts or [])
            for h in live_items:
                if isinstance(h, dict):
                    host = (h.get("host") or "").lower().strip()
                    if host:
                        approved_hosts.add(host)
    except Exception:
        pass  # Graceful fallback — use scan plan hosts only

    if technique_id == "sqli_param_fuzz":
        return await _exec_sqli_fuzz(workspace_id, approved_hosts)
    elif technique_id == "sqli_error_test":
        return await _exec_sqli_pure(workspace_id, approved_hosts, concurrency)
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
    elif technique_id == "csti_test":
        return await _exec_csti(workspace_id, approved_hosts, concurrency)
    elif technique_id == "reflected_xss_test":
        return await _exec_reflected_xss(workspace_id, approved_hosts, concurrency)
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
    elif technique_id == "cors_misconfig":
        return await _exec_cors(workspace_id, approved_hosts)
    elif technique_id == "prototype_pollution_test":
        return await _exec_prototype_pollution(workspace_id, approved_hosts, concurrency)
    elif technique_id == "sensitive_leakage_test":
        return await _exec_sensitive_leakage(workspace_id, approved_hosts, concurrency)
    elif technique_id == "security_headers_check":
        return await _exec_security_headers(workspace_id, approved_hosts)
    elif technique_id == "version_disclosure_check":
        return await _exec_version_disclosure(workspace_id, approved_hosts)
    elif technique_id == "transport_security_check":
        return await _exec_transport_security(workspace_id, approved_hosts)
    elif technique_id == "pii_html_leakage":
        return await _exec_pii_leakage(workspace_id, approved_hosts, concurrency)
    elif technique_id == "vulnerable_components_check":
        return await _exec_vulnerable_components(workspace_id, approved_hosts)
    elif technique_id == "viewstate_mac_check":
        return await _exec_viewstate_mac(workspace_id, approved_hosts)
    elif technique_id == "default_credentials_test":
        return await _exec_default_credentials(workspace_id, approved_hosts)
    elif technique_id == "xxe_test":
        return await _exec_xxe(workspace_id, approved_hosts, concurrency)
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

    # Also test endpoints from JS analysis and dirfuzz that have params
    extra_candidates: list[dict[str, Any]] = []

    # API endpoints from JS analysis
    raw_api = await workspace.read_data(workspace_id, "endpoints/api_endpoints.json")
    api_eps = _extract_items(raw_api)
    existing_urls = {c.get("url", "") for c in candidates}
    for ep in api_eps:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if not url or url in existing_urls:
            continue
        # Add common injectable params for debug/admin endpoints
        if any(kw in url.lower() for kw in ("debug", "admin", "search", "query", "filter")):
            for param in ("search", "q", "query", "filter", "id"):
                extra_candidates.append({
                    "url": url, "param": param, "sample_value": "test", "method": "GET",
                })

    # Sensitive paths
    raw_sens = await workspace.read_data(workspace_id, "hosts/sensitive_paths.json")
    sens = _extract_items(raw_sens)
    for s in sens:
        url = s.get("url", "") if isinstance(s, dict) else ""
        if url and "?" in url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            for param in parse_qs(parsed.query):
                extra_candidates.append({
                    "url": url, "param": param, "sample_value": "test", "method": "GET",
                })

    # Dirfuzz results with interesting paths
    raw_dirfuzz = await workspace.read_data(workspace_id, "dirfuzz/light_results.json")
    dirfuzz_items = _extract_items(raw_dirfuzz)
    for d in dirfuzz_items:
        url = d.get("url", "") if isinstance(d, dict) else str(d)
        if not url or url in existing_urls:
            continue
        if any(kw in url.lower() for kw in ("debug", "admin", "search", "query", "filter")):
            for param in ("search", "q", "query", "filter", "id"):
                extra_candidates.append({
                    "url": url, "param": param, "sample_value": "test", "method": "GET",
                })

    candidates.extend(extra_candidates)
    scoped = await _filter_to_scope(candidates, approved_hosts, limit=30)

    findings: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(2)

    async def _test_one(c: dict[str, Any]) -> list[dict[str, Any]]:
        url = c.get("url", "")
        param = c.get("param", "")
        if not url or not param:
            return []

        test_url = url if f"{param}=" in url else f"{url}?{param}=1"

        try:
            async with sem:
                result = await sqlmap.execute(test_url, timeout=300)
                if result.success and result.results:
                    hits = []
                    for r in result.results:
                        if isinstance(r, dict) and r.get("vulnerable"):
                            hits.append({
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
                    return hits
        except Exception as exc:
            logger.warning("technique.sqli_error", url=url, error=str(exc))
        return []

    tasks = [_test_one(c) for c in scoped]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings


async def _exec_sqli_pure(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Pure-Python SQLi detection — error-based + boolean-blind, no sqlmap needed."""
    from bughound.tools.testing.injection_tester import test_sqli
    return await _run_injection_batch(
        workspace_id, approved_hosts, "sqli_candidates",
        test_sqli, "sqli", "sqli_error_test", "critical", concurrency,
        limit=20,
    )


async def _exec_xss_fuzz(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Run dalfox on top XSS candidates.

    For API endpoints (returning JSON), also generate a frontend URL variant
    since SPAs often reflect the same params in HTML on the root page.
    """
    from urllib.parse import urlparse, urlunparse
    from bughound.tools.scanning import dalfox

    if not dalfox.is_available():
        return []

    pc = await _load_param_classification(workspace_id)
    candidates = _get_param_candidates(pc, "xss_candidates")
    scoped = await _filter_to_scope(candidates, approved_hosts, limit=10)

    findings: list[dict[str, Any]] = []
    tested_urls: set[str] = set()

    for c in scoped:
        url = c.get("url", "")
        param = c.get("param", "")
        if not url:
            continue

        test_url = url if f"{param}=" in url else f"{url}?{param}=test"

        # Build list of URLs to test: original + frontend variant
        urls_to_test = [test_url]

        # If URL is an API path, also test the frontend root with same param
        # e.g. /api/products/?search=test → /?search=test
        parsed = urlparse(test_url)
        if "/api/" in parsed.path or parsed.path.startswith("/api"):
            frontend_url = urlunparse(parsed._replace(path="/"))
            if frontend_url not in tested_urls:
                urls_to_test.append(frontend_url)

        for t_url in urls_to_test:
            if t_url in tested_urls:
                continue
            tested_urls.add(t_url)

            try:
                result = await dalfox.execute(t_url, timeout=180)
                if result.success and result.results:
                    for r in result.results:
                        if not isinstance(r, dict):
                            continue
                        findings.append({
                            "vulnerability_class": "xss",
                            "tool": "dalfox",
                            "technique_id": "xss_param_fuzz",
                            "host": _host_from_url(url),
                            "endpoint": r.get("url", t_url),
                            "severity": "high",
                            "description": f"{r.get('xss_type', 'reflected')} XSS in param '{param}'",
                            "evidence": r.get("evidence", ""),
                            "payload_used": r.get("payload", ""),
                            "confidence": "high",
                            "needs_validation": False,
                        })
            except Exception as exc:
                logger.warning("technique.xss_error", url=t_url, error=str(exc))

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
    limit: int = 20,
    result_key: str = "vulnerable",
) -> list[dict[str, Any]]:
    """Generic batch runner for injection_tester functions."""
    from urllib.parse import urlparse, urlunparse

    pc = await _load_param_classification(workspace_id)
    candidates = _get_param_candidates(pc, candidate_key)

    # Sort candidates BEFORE scope filtering so probe-confirmed don't get cut
    candidates.sort(key=lambda c: (
        0 if c.get("probe") else          # probe-confirmed = highest priority
        1 if c.get("sample_value") not in ("test", "1", "") else  # real sample values
        2                                   # inferred/generic
    ))

    scoped = await _filter_to_scope(candidates, approved_hosts, limit=limit)

    # For API-only candidates, also generate frontend URL variants
    extra: list[dict[str, Any]] = []
    seen_urls: set[str] = {c.get("url", "") for c in scoped}
    for c in scoped:
        url = c.get("url", "")
        parsed = urlparse(url)
        if "/api/" in parsed.path or parsed.path.startswith("/api"):
            frontend_url = urlunparse(parsed._replace(path="/"))
            if frontend_url not in seen_urls:
                seen_urls.add(frontend_url)
                extra.append({**c, "url": frontend_url})
    scoped.extend(extra)

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
                result = await asyncio.wait_for(
                    test_func(url, param, sample), timeout=60,
                )
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

    # Primary: ssti_candidates
    findings = await _run_injection_batch(
        workspace_id, approved_hosts, "ssti_candidates",
        test_ssti, "ssti", "ssti_test", "critical", concurrency,
    )

    # Cross-classify: XSS params also accept user input, try SSTI on them
    if not findings:
        pc = await _load_param_classification(workspace_id)
        xss_candidates = _get_param_candidates(pc, "xss_candidates")
        ssti_seen = {
            f"{c.get('url')}:{c.get('param')}"
            for c in _get_param_candidates(pc, "ssti_candidates")
        }
        # Filter out candidates already tested as ssti
        extra = [
            c for c in xss_candidates
            if f"{c.get('url')}:{c.get('param')}" not in ssti_seen
        ]
        if extra:
            scoped = await _filter_to_scope(extra, approved_hosts, limit=5)
            sem = asyncio.Semaphore(concurrency)

            async def _test(c: dict[str, Any]) -> dict[str, Any] | None:
                url, param = c.get("url", ""), c.get("param", "")
                sample = c.get("sample_value", "")
                if not url or not param:
                    return None
                async with sem:
                    try:
                        result = await test_ssti(url, param, sample)
                        if result.get("vulnerable"):
                            return {
                                "vulnerability_class": "ssti",
                                "tool": "injection_tester",
                                "technique_id": "ssti_test",
                                "host": _host_from_url(url),
                                "endpoint": result.get("url", url),
                                "severity": "critical",
                                "description": f"SSTI detected in param '{param}' (cross-classified from XSS)",
                                "evidence": result.get("evidence", str(result)),
                                "payload_used": result.get("payload", ""),
                                "confidence": "medium",
                                "needs_validation": True,
                            }
                    except Exception:
                        pass
                    return None

            results = await asyncio.gather(*[_test(c) for c in scoped], return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    findings.append(r)

    return findings


async def _exec_csti(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Run Client-Side Template Injection tests on XSS + SSTI candidates."""
    from bughound.tools.testing.injection_tester import test_csti

    # CSTI uses XSS candidates + SSTI candidates (template injection params)
    pc = await _load_param_classification(workspace_id)
    xss = _get_param_candidates(pc, "xss_candidates")
    ssti = _get_param_candidates(pc, "ssti_candidates")

    # Combine and dedupe
    all_candidates = list(xss) + list(ssti)
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in all_candidates:
        key = f"{c.get('url')}:{c.get('param')}"
        if key not in seen:
            seen.add(key)
            unique.append(c)

    scoped = await _filter_to_scope(unique, approved_hosts, limit=15)

    return await _run_injection_batch_direct(
        scoped, test_csti, "csti", "csti_test", "medium", concurrency,
    )


async def _exec_reflected_xss(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Pure-Python reflected XSS testing — runs alongside dalfox for extra coverage."""
    from urllib.parse import urlparse, urlunparse
    from bughound.tools.testing.injection_tester import test_reflected_xss

    pc = await _load_param_classification(workspace_id)
    candidates = _get_param_candidates(pc, "xss_candidates")
    scoped = await _filter_to_scope(candidates, approved_hosts, limit=15)

    # Generate frontend URL variants for API endpoints
    extra: list[dict[str, Any]] = []
    seen_urls: set[str] = {c.get("url", "") for c in scoped}
    for c in scoped:
        url = c.get("url", "")
        parsed = urlparse(url)
        if "/api/" in parsed.path or parsed.path.startswith("/api"):
            frontend_url = urlunparse(parsed._replace(path="/"))
            if frontend_url not in seen_urls:
                seen_urls.add(frontend_url)
                extra.append({**c, "url": frontend_url})
    scoped.extend(extra)

    return await _run_injection_batch_direct(
        scoped, test_reflected_xss, "xss", "reflected_xss_test", "high", concurrency,
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
                            "description": f"Header injection: {f.get('technique', 'unknown')}",
                            "evidence": f.get("evidence", ""),
                            "payload_used": f.get("technique", "unknown"),
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
    from bughound.tools.testing.graphql_tester import test_graphql, test_graphql_data_leaks

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

                    # Test for unauthenticated data leaks
                    try:
                        leak_result = await test_graphql_data_leaks(gql_url)
                        if leak_result.get("vulnerable"):
                            leak_count = len(leak_result.get("leaks", []))
                            total_records = sum(
                                l.get("record_count", 0)
                                for l in leak_result.get("leaks", [])
                            )
                            all_fields = []
                            for l in leak_result.get("leaks", []):
                                all_fields.extend(l.get("fields_exposed", []))
                            findings.append({
                                **finding,
                                "description": (
                                    f"GraphQL: {leak_count} queries return data "
                                    f"without authentication ({total_records} total records)"
                                ),
                                "severity": "high",
                                "evidence": leak_result.get("evidence", ""),
                                "confidence": leak_result.get("confidence", "high"),
                                "needs_validation": True,
                                "details": {
                                    "leaks": leak_result.get("leaks", []),
                                    "fields_exposed": sorted(set(all_fields)),
                                },
                            })
                    except Exception:
                        pass  # Data leak check failed; don't block other findings

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

    # Also check auth_discovery for JWT tokens from login responses
    if not jwt_tokens:
        raw_auth = await workspace.read_data(workspace_id, "hosts/auth_discovery.json")
        auth_items = _extract_items(raw_auth)
        for auth in auth_items:
            token = auth.get("auth_token", "")
            if token and token.startswith("eyJ") and token.count(".") == 2:
                host = auth.get("host", "")
                jwt_tokens.append((token, host))
            # Also check cookies for JWT-like values
            for cookie in auth.get("cookies", []):
                val = cookie.get("value", "")
                if val and val.startswith("eyJ") and val.count(".") == 2:
                    host = auth.get("host", "")
                    jwt_tokens.append((val, host))

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
        # Try to find the right host — handle both URLs and bare hostnames
        from urllib.parse import urlparse
        try:
            parsed_source = urlparse(source)
            source_host = parsed_source.hostname or ""
            # urlparse treats bare hostnames (no scheme) as path, not hostname
            if not source_host and source and "://" not in source:
                source_host = source.split(":")[0].split("/")[0]
        except Exception:
            source_host = ""

        target_url = host_urls.get(source_host.lower(), "")
        # If no exact match, try matching against approved hosts directly
        if not target_url and source_host.lower() in approved_hosts:
            target_url = f"https://{source_host}"
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
            if result.get("weak_secret"):
                desc = f"JWT weak secret cracked: '{result.get('cracked_secret', '')}'"
                if result.get("forged_admin_token"):
                    desc += " — admin token forgeable"
                findings.append({
                    "vulnerability_class": "jwt",
                    "tool": "jwt_tester",
                    "technique_id": "jwt_test",
                    "host": source_host,
                    "endpoint": target_url,
                    "severity": "critical",
                    "description": desc,
                    "evidence": f"Secret: {result.get('cracked_secret', '')}, Algorithm: {result.get('original_alg', 'HS256')}",
                    "confidence": "high",
                    "needs_validation": False,
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

    async with _aiohttp.ClientSession() as session:
        for h in hosts:
            host = (h.get("host") or "").lower()
            url = h.get("url", "")
            techs = " ".join(h.get("technologies", [])).lower()
            if not url or host not in approved_hosts or "wordpress" not in techs:
                continue

            base = url.rstrip("/")

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

    async with _aiohttp.ClientSession() as session:
        for f in flags:
            host = (f.get("host") or "").lower()
            if host not in approved_hosts:
                continue
            if not any("ACTUATOR" in flag for flag in f.get("flags", [])):
                continue

            url = f.get("url", f"https://{host}")
            base = url.rstrip("/")

            for path, severity, desc in actuator_paths:
                try:
                    async with session.get(
                        f"{base}{path}", ssl=False, timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
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
                result = await asyncio.wait_for(
                    test_func(url, param, sample), timeout=60,
                )
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

    # Generate admin paths to test on all live hosts
    raw_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw_hosts)
    admin_paths = [
        "/admin", "/admin/users", "/admin/orders", "/admin/products",
        "/admin/settings", "/admin/dashboard", "/admin/config",
        "/dashboard", "/manage", "/console", "/panel",
        "/api/admin", "/api/admin/users", "/api/admin/orders",
        "/api/internal", "/api/debug", "/api/config",
    ]
    for h in hosts:
        base = (h.get("url") or "").rstrip("/")
        host = _host_from_url(base)
        if host not in approved_hosts or not base:
            continue
        for path in admin_paths:
            full = f"{base}{path}"
            if full not in seen:
                seen.add(full)
                endpoints.append(full)

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

                # Skip if endpoint doesn't actually accept requests
                # (405/404 means it doesn't exist for POST — no rate limit issue)
                status_dist = result.get("evidence", "")
                if "405:" in status_dist or "404:" in status_dist:
                    continue

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


async def _exec_cors(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Promote CORS misconfigurations from Stage 2 to Stage 4 findings."""
    raw = await workspace.read_data(workspace_id, "hosts/cors_results.json")
    cors_results = _extract_items(raw)
    if not cors_results:
        return []

    findings: list[dict[str, Any]] = []
    for cr in cors_results:
        url = cr.get("url", "")
        host = _host_from_url(url)
        if host not in approved_hosts:
            continue

        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
        severity = sev_map.get(cr.get("severity", "INFO"), "info")

        # Skip INFO-level (wildcard without credentials) — not reportable
        if severity == "info":
            continue

        origin = cr.get("origin_tested", "")
        acao = cr.get("acao", "")
        creds = cr.get("credentials_allowed", False)

        desc = f"CORS misconfiguration: origin '{origin}' reflected in Access-Control-Allow-Origin"
        if creds:
            desc += " with credentials allowed"

        findings.append({
            "vulnerability_class": "cors",
            "tool": "cors_checker",
            "technique_id": "cors_misconfig",
            "host": host,
            "endpoint": url,
            "severity": severity,
            "description": desc,
            "evidence": f"ACAO: {acao}, Origin: {origin}, Credentials: {creds}",
            "confidence": "high",
            "needs_validation": False,
        })

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
            ct = ep.get("content_type", "form")
            result = await test_post_sqli(url, params, content_type=ct)
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
            ct = ep.get("content_type", "form")
            result = await test_stored_xss(url, params, content_type=ct)
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
            ct = ep.get("content_type", "form")
            result = await test_post_ssti(url, params, content_type=ct)
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
            ct = ep.get("content_type", "form")
            result = await test_post_rce(url, params, content_type=ct)
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
    """Test for DOM-based XSS on live hosts using Playwright.

    Instead of testing every crawled URL (slow), test each live host's
    root URL with XSS-classified params from param classification.
    """
    from bughound.tools.testing.dom_xss_tester import test_dom_xss

    # Get unique hosts + their XSS params
    pc = await _load_param_classification(workspace_id)
    xss_candidates = _get_param_candidates(pc, "xss_candidates")

    # Build per-host param list
    host_params: dict[str, set[str]] = {}
    host_urls: dict[str, str] = {}
    for c in xss_candidates:
        url = c.get("url", "")
        host = _host_from_url(url)
        if host in approved_hosts:
            host_params.setdefault(host, set()).add(c.get("param", ""))
            if host not in host_urls:
                # Use the host's root URL for DOM testing
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(url)
                host_urls[host] = urlunparse(parsed._replace(path="/", query=""))

    sem = asyncio.Semaphore(max(1, concurrency // 2))  # Playwright is heavy
    findings: list[dict[str, Any]] = []

    async def _test_one(host: str) -> list[dict[str, Any]]:
        url = host_urls.get(host, f"https://{host}")
        all_p = list(host_params.get(host, set()))
        # Prioritize: search/q/query first (most common XSS vectors)
        _TOP_XSS = {"search", "q", "query", "key", "keyword", "s"}
        _MED_XSS = {"name", "input", "text", "value", "msg", "content", "body", "title"}
        all_p.sort(key=lambda p: (
            0 if p.lower() in _TOP_XSS else
            1 if p.lower() in _MED_XSS else 2
        ))
        params = all_p[:10]  # test up to 10 params
        if not params:
            return []
        async with sem:
            try:
                result = await test_dom_xss(url, params=params)
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

    # Test each unique host (not every URL — Playwright is expensive)
    tasks = [_test_one(host) for host in host_urls]
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


async def _exec_prototype_pollution(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Test for prototype pollution via __proto__ injection."""
    from bughound.tools.testing.injection_tester import test_prototype_pollution

    pc = await _load_param_classification(workspace_id)
    # Use XSS + SSTI candidates (template/DOM params are most likely targets)
    xss = _get_param_candidates(pc, "xss_candidates")
    ssti = _get_param_candidates(pc, "ssti_candidates")

    all_candidates = list(xss) + list(ssti)
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in all_candidates:
        key = f"{c.get('url')}:{c.get('param')}"
        if key not in seen:
            seen.add(key)
            unique.append(c)

    scoped = await _filter_to_scope(unique, approved_hosts, limit=15)

    return await _run_injection_batch_direct(
        scoped, test_prototype_pollution, "prototype_pollution",
        "prototype_pollution_test", "high", concurrency,
    )


async def _exec_sensitive_leakage(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Check API endpoints for leaked sensitive fields."""
    from bughound.tools.testing.injection_tester import test_sensitive_leakage

    # Gather all API endpoints from crawled URLs
    raw_urls = await workspace.read_data(workspace_id, "urls/crawled.json")
    urls = _extract_items(raw_urls)

    # Filter to API/JSON endpoints
    api_urls: list[str] = []
    seen: set[str] = set()
    for u in urls:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        host = _host_from_url(url)
        if host not in approved_hosts or url in seen:
            continue
        # Focus on API endpoints (most likely to return JSON with sensitive data)
        if "/api/" in url or url.endswith(".json") or "/rest/" in url:
            seen.add(url)
            api_urls.append(url)

    # Also add dir scan findings (admin/debug endpoints)
    raw_dir = await workspace.read_data(workspace_id, "dirfuzz/light_results.json")
    dir_findings = _extract_items(raw_dir)
    for d in dir_findings:
        url = d.get("url", "")
        host = _host_from_url(url)
        if host in approved_hosts and url not in seen:
            seen.add(url)
            api_urls.append(url)

    if not api_urls:
        return []

    # Limit to avoid excessive requests
    api_urls = api_urls[:30]

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _test_one(url: str) -> dict[str, Any] | None:
        async with sem:
            try:
                result = await asyncio.wait_for(
                    test_sensitive_leakage(url), timeout=30,
                )
                if result.get("vulnerable"):
                    return {
                        "vulnerability_class": "info_leak",
                        "tool": "injection_tester",
                        "technique_id": "sensitive_leakage_test",
                        "host": _host_from_url(url),
                        "endpoint": url,
                        "severity": "high",
                        "description": f"Sensitive fields leaked: {', '.join(result.get('fields_found', []))}",
                        "evidence": result.get("evidence", ""),
                        "confidence": result.get("confidence", "high"),
                        "needs_validation": False,
                    }
            except Exception:
                pass
            return None

    tasks = [_test_one(u) for u in api_urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _exec_security_headers(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Check hosts for missing security headers."""
    from bughound.tools.testing.config_checker import check_security_headers

    raw = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    for h in hosts:
        base = (h.get("url") or "").rstrip("/")
        host = _host_from_url(base)
        if host not in approved_hosts or not base:
            continue
        try:
            result = await asyncio.wait_for(
                check_security_headers(base), timeout=30,
            )
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "misconfig",
                    "tool": "config_checker",
                    "technique_id": "security_headers_check",
                    "host": host,
                    "endpoint": base,
                    "severity": "medium",
                    "description": f"Missing security headers: {', '.join(result.get('missing_headers', []))}",
                    "evidence": result.get("evidence", ""),
                    "confidence": "high",
                    "needs_validation": False,
                })
        except Exception:
            pass

    return findings


async def _exec_version_disclosure(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Detect server version disclosure in response headers."""
    from bughound.tools.testing.config_checker import check_version_disclosure

    raw = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    for h in hosts:
        base = (h.get("url") or "").rstrip("/")
        host = _host_from_url(base)
        if host not in approved_hosts or not base:
            continue
        try:
            result = await asyncio.wait_for(
                check_version_disclosure(base), timeout=30,
            )
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "info_leak",
                    "tool": "config_checker",
                    "technique_id": "version_disclosure_check",
                    "host": host,
                    "endpoint": base,
                    "severity": "medium",
                    "description": f"Server version disclosed: {result.get('evidence', '')}",
                    "evidence": result.get("evidence", ""),
                    "disclosed_versions": result.get("disclosed_versions", {}),
                    "confidence": "high",
                    "needs_validation": False,
                })
        except Exception:
            pass

    return findings


async def _exec_transport_security(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Check HTTPS availability and HSTS enforcement."""
    from bughound.tools.testing.config_checker import check_transport_security

    raw = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw)

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for h in hosts:
        base = (h.get("url") or "").rstrip("/")
        host = _host_from_url(base)
        if host not in approved_hosts or not base or host in seen:
            continue
        seen.add(host)
        try:
            result = await asyncio.wait_for(
                check_transport_security(base), timeout=30,
            )
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "misconfig",
                    "tool": "config_checker",
                    "technique_id": "transport_security_check",
                    "host": host,
                    "endpoint": base,
                    "severity": "medium",
                    "description": result.get("evidence", "No HTTPS available"),
                    "evidence": result.get("evidence", ""),
                    "confidence": result.get("confidence", "high"),
                    "needs_validation": False,
                })
        except Exception:
            pass

    return findings


async def _exec_pii_leakage(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Scan HTML pages for leaked PII (emails, etc.)."""
    from bughound.tools.testing.config_checker import check_pii_leakage_html

    raw_urls = await workspace.read_data(workspace_id, "urls/crawled.json")
    urls = _extract_items(raw_urls)

    # Pick a subset of interesting URLs (login, admin, profile pages)
    targets: list[str] = []
    seen: set[str] = set()
    _PII_KEYWORDS = ("login", "profile", "account", "user", "admin", "contact",
                     "register", "signup", "dashboard", "settings", "order")
    for u in urls:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        host = _host_from_url(url)
        if host not in approved_hosts or url in seen:
            continue
        if any(kw in url.lower() for kw in _PII_KEYWORDS):
            seen.add(url)
            targets.append(url)
    # Also check the root URL of each host
    raw_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw_hosts)
    for h in hosts:
        base = (h.get("url") or "").rstrip("/")
        host = _host_from_url(base)
        if host in approved_hosts and base and base not in seen:
            seen.add(base)
            targets.append(base)

    if not targets:
        return []
    targets = targets[:20]

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _check(url: str) -> dict[str, Any] | None:
        async with sem:
            try:
                result = await asyncio.wait_for(
                    check_pii_leakage_html(url), timeout=30,
                )
                if result.get("vulnerable"):
                    return {
                        "vulnerability_class": "info_leak",
                        "tool": "config_checker",
                        "technique_id": "pii_html_leakage",
                        "host": _host_from_url(url),
                        "endpoint": url,
                        "severity": "medium",
                        "description": f"PII leaked: {', '.join(result.get('emails_found', [])[:3])}",
                        "evidence": result.get("evidence", ""),
                        "confidence": result.get("confidence", "medium"),
                        "needs_validation": False,
                    }
            except Exception:
                pass
            return None

    tasks = [_check(u) for u in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


async def _exec_vulnerable_components(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Detect known vulnerable component versions from tech detection data."""
    from bughound.tools.testing.config_checker import check_vulnerable_components

    raw = await workspace.read_data(workspace_id, "hosts/technologies.json")
    techs = _extract_items(raw)

    # Filter to approved hosts
    approved_techs = [
        t for t in techs
        if isinstance(t, dict) and _host_from_url(t.get("host", t.get("url", ""))) in approved_hosts
    ]

    vuln_findings = check_vulnerable_components(approved_techs)

    findings: list[dict[str, Any]] = []
    for vf in vuln_findings:
        findings.append({
            "vulnerability_class": "vulnerable_component",
            "tool": "config_checker",
            "technique_id": "vulnerable_components_check",
            "host": vf.get("host", ""),
            "endpoint": vf.get("url", ""),
            "severity": "medium",
            "description": vf.get("description", ""),
            "evidence": vf.get("evidence", ""),
            "cves": vf.get("cves", []),
            "confidence": "high",
            "needs_validation": False,
        })

    return findings


async def _exec_viewstate_mac(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test ASP.NET ViewState MAC validation."""
    from bughound.tools.testing.config_checker import check_viewstate_mac

    # Check hosts that have ASP.NET detected
    raw_tech = await workspace.read_data(workspace_id, "hosts/technologies.json")
    techs = _extract_items(raw_tech)
    raw_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    hosts = _extract_items(raw_hosts)

    # Find ASP.NET hosts
    aspnet_hosts: set[str] = set()
    for t in techs:
        if not isinstance(t, dict):
            continue
        tech_list = [s.lower() for s in t.get("technologies", [])]
        if any("asp" in s or ".net" in s or "iis" in s for s in tech_list):
            h = t.get("host", t.get("url", ""))
            aspnet_hosts.add(_host_from_url(h))

    findings: list[dict[str, Any]] = []
    # Also check all hosts if we find ViewState on any page
    targets: set[str] = set()
    for h in hosts:
        base = (h.get("url") or "").rstrip("/")
        host = _host_from_url(base)
        if host in approved_hosts and base:
            if host in aspnet_hosts or not aspnet_hosts:
                targets.add(base)

    # Also crawl URLs that end in .aspx
    raw_urls = await workspace.read_data(workspace_id, "urls/crawled.json")
    urls = _extract_items(raw_urls)
    for u in urls:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        if url.lower().endswith(".aspx") and _host_from_url(url) in approved_hosts:
            targets.add(url)

    for url in list(targets)[:10]:
        try:
            result = await asyncio.wait_for(
                check_viewstate_mac(url), timeout=30,
            )
            if result.get("vulnerable"):
                findings.append({
                    "vulnerability_class": "deserialization",
                    "tool": "config_checker",
                    "technique_id": "viewstate_mac_check",
                    "host": _host_from_url(url),
                    "endpoint": url,
                    "severity": "high",
                    "description": "ViewState MAC validation disabled — deserialization RCE possible",
                    "evidence": result.get("evidence", ""),
                    "confidence": result.get("confidence", "medium"),
                    "needs_validation": True,
                })
                break  # One finding per host is enough
        except Exception:
            pass

    return findings


async def _exec_default_credentials(
    workspace_id: str, approved_hosts: set[str],
) -> list[dict[str, Any]]:
    """Test login forms with common default credential pairs."""
    from bughound.tools.testing.config_checker import test_default_credentials

    # Build login form targets from TWO sources:
    # 1. auth_discovery — has auth_endpoints (login/register URLs)
    # 2. forms.json — has classified login_form entries with field names
    login_targets: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    # Source 1: form_extractor login forms (most reliable — has field names)
    raw_forms = await workspace.read_data(workspace_id, "urls/forms.json")
    forms = _extract_items(raw_forms)
    for form in forms:
        if not isinstance(form, dict):
            continue
        classification = form.get("classification", "")
        if classification not in ("login_form", "registration_form"):
            continue
        testable = form.get("testable", {})
        action_url = testable.get("url", form.get("page_url", ""))
        if not action_url or action_url in seen_urls:
            continue
        host = _host_from_url(action_url)
        if host not in approved_hosts:
            continue
        seen_urls.add(action_url)

        # Extract username/password field names from inputs
        username_field = "username"
        password_field = "password"
        for inp in form.get("inputs", []):
            inp_name = inp.get("name", "")
            inp_type = inp.get("type", "")
            if inp_type == "password" or inp_name.lower() in ("password", "passwd", "pass", "pwd"):
                password_field = inp_name
            elif inp_type in ("text", "email") or inp_name.lower() in (
                "username", "user", "email", "login", "txtusername", "user_name",
            ):
                username_field = inp_name

        login_targets.append({
            "action_url": action_url,
            "username_field": username_field,
            "password_field": password_field,
            "method": form.get("method", "POST"),
        })

    # Source 2: auth_discovery endpoints (fallback — uses default field names)
    auth_data = await _load_auth_discovery(workspace_id)
    for ad in auth_data:
        for ep in ad.get("auth_endpoints", []):
            url = ep.get("url", "")
            if not url or url in seen_urls:
                continue
            path = ep.get("path", "").lower()
            if "login" not in path and "signin" not in path and "auth" not in path:
                continue
            host = _host_from_url(url)
            if host not in approved_hosts:
                continue
            seen_urls.add(url)
            login_targets.append({
                "action_url": url,
                "username_field": "username",
                "password_field": "password",
            })

    findings: list[dict[str, Any]] = []
    for form in login_targets[:5]:  # Limit to 5 login forms
        action_url = form["action_url"]
        host = _host_from_url(action_url)
        try:
            result = await asyncio.wait_for(
                test_default_credentials(action_url, form), timeout=120,
            )
            if result.get("vulnerable"):
                creds = result.get("credentials", [{}])[0]
                findings.append({
                    "vulnerability_class": "default_creds",
                    "tool": "config_checker",
                    "technique_id": "default_credentials_test",
                    "host": host,
                    "endpoint": action_url,
                    "severity": "high",
                    "description": f"Default credentials accepted: {creds.get('username', '?')}:{creds.get('password', '?')}",
                    "evidence": result.get("evidence", ""),
                    "confidence": "high",
                    "needs_validation": False,
                })
                break  # Found working creds, stop
        except Exception:
            pass

    return findings


async def _exec_xxe(
    workspace_id: str, approved_hosts: set[str], concurrency: int,
) -> list[dict[str, Any]]:
    """Test for XXE via XML/SOAP POST with file:// entity injection."""
    from urllib.parse import urlparse
    from bughound.tools.testing.injection_tester import test_xxe

    findings: list[dict[str, Any]] = []

    # Collect candidate URLs from crawled data
    raw_crawled = await workspace.read_data(workspace_id, "urls/crawled.json")
    crawled_items = _extract_items(raw_crawled)
    candidate_urls: set[str] = set()

    # Filter for XML/SOAP/API endpoints
    _XXE_URL_KEYWORDS = ("xml", "soap", "api", "parse", "upload", "import", "feed", "rss", "wsdl")
    for item in crawled_items:
        url = item.get("url", item) if isinstance(item, dict) else str(item)
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        url_lower = url.lower()
        if any(kw in url_lower for kw in _XXE_URL_KEYWORDS):
            try:
                host = (urlparse(url).hostname or "").lower()
                if host in approved_hosts:
                    candidate_urls.add(url)
            except Exception:
                continue

    # Also test POST endpoints from param classification (they might accept XML)
    pc = await _load_param_classification(workspace_id)
    if pc and isinstance(pc[0], dict):
        for ep in pc[0].get("post_endpoints", []):
            url = ep.get("url", "") if isinstance(ep, dict) else ""
            if url and url.startswith("http"):
                try:
                    host = (urlparse(url).hostname or "").lower()
                    if host in approved_hosts:
                        candidate_urls.add(url)
                except Exception:
                    continue

    # Also test root URLs of live hosts
    raw_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    live_items = _extract_items(raw_hosts)
    for h in live_items:
        if not isinstance(h, dict):
            continue
        url = h.get("url", "")
        if url:
            try:
                host = (urlparse(url).hostname or "").lower()
                if host in approved_hosts:
                    candidate_urls.add(url)
            except Exception:
                continue

    # Limit to 20 URLs max
    urls_to_test = sorted(candidate_urls)[:20]

    if not urls_to_test:
        return findings

    sem = asyncio.Semaphore(concurrency)

    async def _test_one(url: str) -> dict[str, Any] | None:
        async with sem:
            try:
                result = await test_xxe(url)
                if result.get("vulnerable"):
                    conf = result.get("confidence", "medium")
                    # Error-based XXE (low confidence) = medium severity
                    # File-read confirmed (high confidence) = critical
                    sev = "critical" if conf == "high" else "medium"
                    return {
                        "vulnerability_class": "xxe",
                        "tool": "injection_tester",
                        "technique_id": "xxe_test",
                        "host": _host_from_url(url),
                        "endpoint": url,
                        "severity": sev,
                        "description": f"XXE injection via {result.get('technique', 'unknown')} at {url}",
                        "evidence": result.get("evidence", ""),
                        "payload_used": result.get("payload", ""),
                        "confidence": conf,
                        "needs_validation": conf != "high",
                    }
            except Exception as exc:
                logger.debug("xxe_test_error", url=url, error=str(exc))
            return None

    tasks = [_test_one(url) for url in urls_to_test]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

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
