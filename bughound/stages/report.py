"""Stage 6: Generate security assessment reports.

Three report types:
  full       -- Professional HTML security assessment (client-facing)
  bug_bounty -- Markdown per-finding report (copy-paste for platforms)
  executive  -- One-page markdown summary for management

All reports merge Stage 4 scan_results with Stage 5 confirmed findings
to present a unified view with validation status.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiofiles
import structlog

from bughound.config.settings import WORKSPACE_BASE_DIR
from bughound.core import workspace

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Logo (base64 data URI, shared with html_report.py)
# ---------------------------------------------------------------------------

_LOGO_B64_PATH = Path(__file__).parent.parent / "utils" / "logo_b64.txt"
try:
    _LOGO_B64 = _LOGO_B64_PATH.read_text().strip()
except Exception:
    _LOGO_B64 = ""

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#6c757d",
}

# ---------------------------------------------------------------------------
# Generic remediation per vulnerability class
# ---------------------------------------------------------------------------

_REMEDIATION: dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements for all database interactions.",
    "sqli_blind": "Use parameterized queries / prepared statements for all database interactions.",
    "sqli_error_based": "Use parameterized queries / prepared statements. Disable verbose error messages in production.",
    "xss": "Implement context-aware output encoding. Use Content-Security-Policy headers.",
    "xss_reflected": "Implement context-aware output encoding. Use Content-Security-Policy headers.",
    "xss_stored": "Implement server-side input validation and context-aware output encoding.",
    "xss_dom": "Avoid using dangerous DOM sinks (innerHTML, document.write). Use textContent instead.",
    "ssrf": "Validate and whitelist allowed URLs/IP ranges. Block internal network access from user input.",
    "ssrf_blind": "Validate and whitelist allowed URLs/IP ranges. Block internal network access.",
    "lfi": "Avoid user input in file paths. Use a whitelist of allowed files if necessary.",
    "lfi_rce": "Never use user-controlled input in file inclusion. Apply strict input validation.",
    "rfi": "Disable remote file inclusion. Validate all file paths against a whitelist.",
    "rce": "Never pass user input to system commands. Use safe APIs and sandboxed execution.",
    "crlf": "Strip or encode CR/LF characters from all user input used in HTTP headers.",
    "ssti": "Never pass user input directly to template engines. Use sandboxed template rendering.",
    "open_redirect": "Validate redirect URLs against a whitelist of allowed domains.",
    "idor": "Implement proper authorization checks. Use indirect object references.",
    "cors_misconfiguration": "Restrict Access-Control-Allow-Origin to trusted domains. Never reflect arbitrary origins.",
    "insecure_cookie": "Set Secure, HttpOnly, and SameSite attributes on all sensitive cookies.",
    "content_discovery": "Remove or restrict access to sensitive files and directories. Return 404 for non-existent resources.",
    "file_exposure": "Remove sensitive files from web-accessible directories. Restrict directory listings.",
    "exposed_git": "Remove .git directory from web root. Add server rules to block access to dotfiles.",
    "exposed_env": "Remove .env files from web root. Store secrets in environment variables or a secrets manager.",
    "exposed_credentials": "Rotate all exposed credentials immediately. Remove credential files from web root.",
    "subdomain_takeover": "Remove dangling DNS records pointing to decommissioned services.",
    "default_creds": "Change all default credentials. Enforce strong password policies.",
    "misconfig": "Review and harden server configuration according to security best practices.",
    "broken_access_control": "Implement proper authorization checks on all endpoints.",
    "mass_assignment": "Whitelist allowed fields for mass assignment. Use DTOs for input binding.",
    "rate_limiting": "Implement rate limiting on authentication and sensitive endpoints.",
    "cookie_injection": "Validate cookie values server-side. Use signed or encrypted cookies.",
    "graphql_introspection": "Disable GraphQL introspection in production environments.",
    "jwt_none_algorithm": "Reject JWTs with 'none' algorithm. Enforce algorithm whitelist on verification.",
    "jwt_weak_secret": "Use strong, randomly generated secrets for JWT signing (256+ bits of entropy).",
    "exposed_actuator": "Restrict Spring Boot Actuator endpoints to internal networks only.",
    "exposed_phpinfo": "Remove phpinfo() calls from production. Restrict access to diagnostic pages.",
    "exposed_backup": "Remove backup files from web-accessible directories.",
}

# ---------------------------------------------------------------------------
# Vuln class display names
# ---------------------------------------------------------------------------

_VULN_DISPLAY: dict[str, str] = {
    "sqli": "SQL Injection",
    "sqli_blind": "Blind SQL Injection",
    "sqli_error_based": "Error-Based SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "xss_reflected": "Reflected XSS",
    "xss_stored": "Stored XSS",
    "xss_dom": "DOM-Based XSS",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "ssrf_blind": "Blind SSRF",
    "lfi": "Local File Inclusion (LFI)",
    "lfi_rce": "LFI to Remote Code Execution",
    "rfi": "Remote File Inclusion (RFI)",
    "rce": "Remote Code Execution (RCE)",
    "crlf": "CRLF Injection",
    "ssti": "Server-Side Template Injection (SSTI)",
    "open_redirect": "Open Redirect",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "cors_misconfiguration": "CORS Misconfiguration",
    "insecure_cookie": "Insecure Cookie Configuration",
    "content_discovery": "Sensitive Content Discovery",
    "file_exposure": "Sensitive File Exposure",
    "exposed_git": "Exposed Git Repository",
    "exposed_env": "Exposed Environment File",
    "exposed_credentials": "Exposed Credentials",
    "subdomain_takeover": "Subdomain Takeover",
    "default_creds": "Default Credentials",
    "misconfig": "Security Misconfiguration",
    "broken_access_control": "Broken Access Control",
    "mass_assignment": "Mass Assignment",
    "rate_limiting": "Missing Rate Limiting",
    "cookie_injection": "Cookie Injection",
    "graphql_introspection": "GraphQL Introspection Enabled",
    "jwt_none_algorithm": "JWT None Algorithm Bypass",
    "jwt_weak_secret": "JWT Weak Secret",
    "exposed_actuator": "Exposed Spring Actuator",
    "exposed_phpinfo": "Exposed phpinfo()",
    "exposed_backup": "Exposed Backup Files",
}

# ---------------------------------------------------------------------------
# Impact descriptions per vulnerability class
# ---------------------------------------------------------------------------

_IMPACT: dict[str, str] = {
    "sqli": "Database compromise, credential extraction, data exfiltration.",
    "sqli_blind": "Database compromise through blind extraction, data exfiltration.",
    "sqli_error_based": "Database compromise, credential extraction, data exfiltration.",
    "xss": "Session hijacking, credential theft, defacement.",
    "xss_reflected": "Session hijacking, phishing, credential theft.",
    "xss_stored": "Persistent session hijacking, credential theft, worm propagation.",
    "xss_dom": "Client-side code execution, session hijacking.",
    "ssrf": "Internal network scanning, cloud metadata access, service compromise.",
    "ssrf_blind": "Internal network discovery, potential data exfiltration.",
    "lfi": "Sensitive data exposure, configuration file leakage.",
    "lfi_rce": "Full server compromise through code execution via file inclusion.",
    "rfi": "Remote code execution, full server compromise.",
    "rce": "Full server takeover, lateral movement, data exfiltration.",
    "crlf": "HTTP response splitting, cache poisoning, XSS via header injection.",
    "ssti": "Remote code execution, full server compromise.",
    "open_redirect": "Phishing attacks, OAuth token theft, credential harvesting.",
    "idor": "Unauthorized data access, privilege escalation.",
    "cors_misconfiguration": "Cross-origin data theft, credential exposure.",
    "insecure_cookie": "Session hijacking, credential theft over unencrypted connections.",
    "content_discovery": "Information disclosure, attack surface expansion.",
    "file_exposure": "Sensitive data leakage, source code disclosure.",
    "exposed_git": "Full source code disclosure, credential extraction from history.",
    "exposed_env": "Database credentials, API keys, and secrets exposure.",
    "exposed_credentials": "Direct access to authentication credentials.",
    "subdomain_takeover": "Phishing, cookie theft, reputation damage.",
    "default_creds": "Unauthorized administrative access.",
    "misconfig": "Varies by misconfiguration; may enable further attacks.",
    "broken_access_control": "Unauthorized access to resources and functionality.",
    "mass_assignment": "Privilege escalation, unauthorized data modification.",
    "rate_limiting": "Brute-force attacks, credential stuffing, denial of service.",
}


# ===================================================================
# PUBLIC API
# ===================================================================


async def generate_report(
    workspace_id: str,
    report_type: str = "all",
) -> dict[str, Any]:
    """Generate security assessment report(s).

    Parameters
    ----------
    workspace_id : str
        Target workspace.
    report_type : str
        One of: 'full' (HTML), 'bug_bounty' (MD), 'executive' (MD), 'all'.

    Returns
    -------
    dict with status, file paths, finding counts.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Load all data
    data = await _load_report_data(workspace_id)
    if not data["findings"]:
        return _error(
            "no_findings",
            "No scan results found. Run bughound_execute_tests first.",
        )

    # Process findings — merge with validation data, sort, group
    processed = _process_findings(data)

    target = meta.target
    report_dir = WORKSPACE_BASE_DIR / workspace_id / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    reports: dict[str, str] = {}
    valid_types = {"full", "bug_bounty", "executive", "all"}
    if report_type not in valid_types:
        return _error(
            "invalid_type",
            f"Invalid report_type '{report_type}'. Choose from: {', '.join(sorted(valid_types))}",
        )

    types_to_generate = (
        ["full", "bug_bounty", "executive"] if report_type == "all"
        else [report_type]
    )

    for rt in types_to_generate:
        if rt == "full":
            content = _generate_full_html(target, workspace_id, processed, data)
            fpath = report_dir / "security_assessment.html"
            async with aiofiles.open(fpath, "w") as f:
                await f.write(content)
            reports["full_html"] = str(fpath)

        elif rt == "bug_bounty":
            content = _generate_bug_bounty_md(target, processed)
            fpath = report_dir / "bug_bounty_findings.md"
            async with aiofiles.open(fpath, "w") as f:
                await f.write(content)
            reports["bug_bounty_md"] = str(fpath)

        elif rt == "executive":
            content = _generate_executive_md(target, processed)
            fpath = report_dir / "executive_summary.md"
            async with aiofiles.open(fpath, "w") as f:
                await f.write(content)
            reports["executive_md"] = str(fpath)

    # Mark stage complete
    await workspace.add_stage_history(workspace_id, 6, "completed")

    return {
        "status": "success",
        "workspace_id": workspace_id,
        "target": target,
        "reports": reports,
        "total_findings": processed["total"],
        "confirmed": processed["confirmed_count"],
        "by_severity": processed["by_severity"],
        "next_step": "Reports generated. Share file paths with the user.",
    }


# ===================================================================
# DATA LOADING
# ===================================================================


async def _load_report_data(workspace_id: str) -> dict[str, Any]:
    """Load all workspace data needed for reports."""
    # scan_results.json (DataWrapper envelope)
    scan_results_raw = await workspace.read_data(
        workspace_id, "vulnerabilities/scan_results.json",
    )
    findings: list[dict[str, Any]] = []
    if isinstance(scan_results_raw, dict) and "data" in scan_results_raw:
        findings = scan_results_raw.get("data", [])
    elif isinstance(scan_results_raw, list):
        findings = scan_results_raw

    # Confirmed findings from vulnerabilities/confirmed/ directory
    confirmed_dir = WORKSPACE_BASE_DIR / workspace_id / "vulnerabilities" / "confirmed"
    confirmed_findings: list[dict[str, Any]] = []
    if confirmed_dir.is_dir():
        for fpath in sorted(confirmed_dir.glob("*.json")):
            try:
                async with aiofiles.open(fpath) as f:
                    raw = json.loads(await f.read())
                # Confirmed files are DataWrapper envelopes with a list in "data"
                if isinstance(raw, dict) and "data" in raw:
                    for item in raw["data"]:
                        if isinstance(item, dict):
                            confirmed_findings.append(item)
                elif isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict):
                            confirmed_findings.append(item)
                elif isinstance(raw, dict):
                    confirmed_findings.append(raw)
            except (json.JSONDecodeError, OSError):
                continue

    # False positives
    false_positives_raw = await workspace.read_data(
        workspace_id, "vulnerabilities/false_positives.json",
    )
    false_positives: list[dict[str, Any]] = []
    if isinstance(false_positives_raw, dict) and "data" in false_positives_raw:
        false_positives = false_positives_raw.get("data", [])
    elif isinstance(false_positives_raw, list):
        false_positives = false_positives_raw

    # Attack surface (direct JSON, not DataWrapper)
    attack_surface: dict[str, Any] = {}
    as_path = WORKSPACE_BASE_DIR / workspace_id / "analysis" / "attack_surface.json"
    if as_path.exists():
        try:
            async with aiofiles.open(as_path) as f:
                attack_surface = json.loads(await f.read())
        except (json.JSONDecodeError, OSError):
            pass

    # Metadata (Pydantic model already loaded, but get raw for extra fields)
    metadata_raw: dict[str, Any] = {}
    meta_path = WORKSPACE_BASE_DIR / workspace_id / "metadata.json"
    if meta_path.exists():
        try:
            async with aiofiles.open(meta_path) as f:
                metadata_raw = json.loads(await f.read())
        except (json.JSONDecodeError, OSError):
            pass

    # Live hosts
    live_hosts_raw = await workspace.read_data(
        workspace_id, "hosts/live_hosts.json",
    )
    live_hosts: list[dict[str, Any]] = []
    if isinstance(live_hosts_raw, dict) and "data" in live_hosts_raw:
        live_hosts = live_hosts_raw.get("data", [])
    elif isinstance(live_hosts_raw, list):
        live_hosts = live_hosts_raw

    # Technologies
    tech_raw = await workspace.read_data(
        workspace_id, "hosts/technologies.json",
    )
    technologies: list[dict[str, Any]] = []
    if isinstance(tech_raw, dict) and "data" in tech_raw:
        technologies = tech_raw.get("data", [])
    elif isinstance(tech_raw, list):
        technologies = tech_raw

    return {
        "findings": findings,
        "confirmed_findings": confirmed_findings,
        "false_positives": false_positives,
        "attack_surface": attack_surface,
        "metadata": metadata_raw,
        "live_hosts": live_hosts,
        "technologies": technologies,
    }


# ===================================================================
# FINDING PROCESSING
# ===================================================================


def _process_findings(data: dict[str, Any]) -> dict[str, Any]:
    """Merge, sort, group, and compute stats for all findings."""
    findings = list(data["findings"])
    confirmed_map: dict[str, dict[str, Any]] = {}
    for cf in data.get("confirmed_findings", []):
        fid = cf.get("finding_id")
        if fid:
            confirmed_map[fid] = cf

    false_pos_ids: set[str] = set()
    for fp in data.get("false_positives", []):
        fid = fp.get("finding_id")
        if fid:
            false_pos_ids.add(fid)

    # Merge validation data into findings
    merged: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for f in findings:
        fid = f.get("finding_id", "")
        if fid in seen_ids:
            continue
        seen_ids.add(fid)

        if fid in false_pos_ids:
            continue  # Skip false positives

        # If we have a confirmed version, use it (richer data)
        if fid in confirmed_map:
            merged_finding = {**f, **confirmed_map[fid]}
            merged_finding["status"] = "CONFIRMED"
        else:
            merged_finding = dict(f)
            if f.get("validation_status") == "CONFIRMED":
                merged_finding["status"] = "CONFIRMED"
            elif f.get("validated"):
                merged_finding["status"] = f.get("validation_status", "PENDING")
            else:
                merged_finding["status"] = "PENDING"

        merged.append(merged_finding)

    # Also add any confirmed findings not in scan_results (e.g. immediate wins)
    for fid, cf in confirmed_map.items():
        if fid not in seen_ids:
            seen_ids.add(fid)
            cf_copy = dict(cf)
            cf_copy["status"] = "CONFIRMED"
            merged.append(cf_copy)

    # Sort by severity
    merged.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info").lower(), 5))

    # Group by vulnerability class
    by_class: dict[str, list[dict[str, Any]]] = {}
    for f in merged:
        vc = f.get("vulnerability_class", "other")
        by_class.setdefault(vc, []).append(f)

    # Stats
    by_severity: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    confirmed_count = 0
    pending_count = 0
    for f in merged:
        sev = f.get("severity", "info").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        if f.get("status") == "CONFIRMED":
            confirmed_count += 1
        elif f.get("status") == "PENDING":
            pending_count += 1

    # Overall risk level
    if by_severity["critical"] > 0:
        risk_level = "CRITICAL"
    elif by_severity["high"] > 0:
        risk_level = "HIGH"
    elif by_severity["medium"] > 0:
        risk_level = "MEDIUM"
    elif by_severity["low"] > 0:
        risk_level = "LOW"
    else:
        risk_level = "INFO"

    return {
        "findings": merged,
        "by_class": by_class,
        "by_severity": by_severity,
        "total": len(merged),
        "confirmed_count": confirmed_count,
        "pending_count": pending_count,
        "false_positive_count": len(false_pos_ids),
        "risk_level": risk_level,
    }


# ===================================================================
# HELPERS
# ===================================================================


def _e(text: Any) -> str:
    """HTML-escape user-controlled data."""
    return html.escape(str(text)) if text else ""


def _severity_badge_class(severity: str) -> str:
    return f"badge-{severity.lower()}"


def _finding_card_class(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return "finding-card critical"
    return f"finding-card {sev}"


def _display_name(vulnerability_class: str) -> str:
    """Get human-readable name for a vulnerability class."""
    return _VULN_DISPLAY.get(vulnerability_class, vulnerability_class.replace("_", " ").title())


def _auto_curl(finding: dict[str, Any]) -> str:
    """Generate a curl command from a finding if one is not already present."""
    existing = finding.get("curl_command", "")
    if existing:
        return existing

    endpoint = finding.get("endpoint", "")
    if not endpoint:
        return ""

    payload = finding.get("payload_used", "")
    param = finding.get("parameter", "")

    # If we have a complete endpoint URL, use it directly
    if endpoint.startswith("http"):
        cmd = f"curl -sk '{endpoint}'"
        if payload and param:
            # The endpoint may already contain the payload
            if payload not in endpoint:
                cmd = f"curl -sk '{endpoint}' -d '{param}={payload}'"
        return cmd

    return ""


def _auto_summary(target: str, processed: dict[str, Any]) -> str:
    """Generate an auto-summary paragraph from data."""
    total = processed["total"]
    by_sev = processed["by_severity"]
    confirmed = processed["confirmed_count"]
    pending = processed["pending_count"]
    risk = processed["risk_level"]

    parts = []
    if by_sev.get("critical"):
        parts.append(f"{by_sev['critical']} critical")
    if by_sev.get("high"):
        parts.append(f"{by_sev['high']} high")
    if by_sev.get("medium"):
        parts.append(f"{by_sev['medium']} medium")
    if by_sev.get("low"):
        parts.append(f"{by_sev['low']} low")
    if by_sev.get("info"):
        parts.append(f"{by_sev['info']} informational")

    severity_breakdown = ", ".join(parts) if parts else "no"

    summary = (
        f"The security assessment of {target} identified {total} "
        f"finding{'s' if total != 1 else ''}, including {severity_breakdown} "
        f"severity issue{'s' if total != 1 else ''}. "
    )

    if confirmed:
        summary += (
            f"Of these, {confirmed} "
            f"{'have' if confirmed != 1 else 'has'} been confirmed through "
            f"surgical validation. "
        )
    if pending:
        summary += (
            f"{pending} finding{'s' if pending != 1 else ''} "
            f"{'are' if pending != 1 else 'is'} pending manual review. "
        )

    if risk in ("CRITICAL", "HIGH"):
        summary += "Immediate remediation is strongly recommended."
    elif risk == "MEDIUM":
        summary += "Remediation should be prioritized in the next development cycle."
    else:
        summary += "The findings represent a low overall risk posture."

    return summary


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _date_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ===================================================================
# FULL HTML REPORT
# ===================================================================


def _generate_full_html(
    target: str,
    workspace_id: str,
    processed: dict[str, Any],
    data: dict[str, Any],
) -> str:
    """Generate the full professional HTML security assessment report.

    Produces a self-contained HTML file with:
    - Dark sidebar with navigation, scan metadata, severity counts
    - Main content with executive summary, Chart.js donut, findings,
      technologies, testing coverage
    - Tailwind CSS + Chart.js via CDN
    - Inter + JetBrains Mono fonts
    - JavaScript for filtering, smooth scroll, copy-to-clipboard
    - Print-optimized CSS
    """
    findings = processed["findings"]
    by_severity = processed["by_severity"]
    risk_level = processed["risk_level"]
    now = _now_str()
    date = _date_str()

    total = processed["total"]
    confirmed_count = processed["confirmed_count"]
    pending_count = processed["pending_count"]
    fp_count = processed["false_positive_count"]

    # Build severity data for Chart.js
    chart_data = json.dumps([
        by_severity.get("critical", 0),
        by_severity.get("high", 0),
        by_severity.get("medium", 0),
        by_severity.get("low", 0),
        by_severity.get("info", 0),
    ])

    # Risk banner colors
    _RISK_BANNER = {
        "CRITICAL": ("bg-red-900", "text-white"),
        "HIGH": ("bg-red-600", "text-white"),
        "MEDIUM": ("bg-amber-500", "text-white"),
        "LOW": ("bg-blue-600", "text-white"),
        "INFO": ("bg-slate-500", "text-white"),
    }
    risk_bg, risk_text = _RISK_BANNER.get(risk_level, ("bg-slate-500", "text-white"))

    # Severity border/badge mapping
    _SEV_CSS = {
        "critical": {"border": "border-red-900", "badge_bg": "bg-red-900", "badge_text": "text-white", "card_bg": "bg-red-50"},
        "high": {"border": "border-red-600", "badge_bg": "bg-red-600", "badge_text": "text-white", "card_bg": "bg-red-50"},
        "medium": {"border": "border-amber-600", "badge_bg": "bg-amber-600", "badge_text": "text-white", "card_bg": "bg-amber-50"},
        "low": {"border": "border-blue-600", "badge_bg": "bg-blue-600", "badge_text": "text-white", "card_bg": "bg-blue-50"},
        "info": {"border": "border-emerald-600", "badge_bg": "bg-emerald-600", "badge_text": "text-white", "card_bg": "bg-green-50"},
    }

    # Severity bar max
    max_count = max(by_severity.values()) if by_severity else 1
    if max_count == 0:
        max_count = 1

    # --- Build findings HTML ---
    findings_html_parts: list[str] = []
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        vc = f.get("vulnerability_class", "other")
        title = _display_name(vc)
        status = f.get("status", "PENDING")
        endpoint = f.get("endpoint", "")
        param = f.get("parameter", "")
        tool = f.get("tool", "")
        technique = f.get("technique_id", "")
        description = f.get("description", "")
        evidence = f.get("evidence", "")
        curl_cmd = _auto_curl(f)
        repro_steps = f.get("reproduction_steps", [])
        payload = f.get("payload_used", "")
        cvss = f.get("cvss_score", "")
        impact = f.get("impact", "") or _IMPACT.get(vc, "")
        remediation = _REMEDIATION.get(vc, "Review and remediate according to security best practices.")
        host = f.get("host", "")
        instances = f.get("instances", 0)

        css = _SEV_CSS.get(sev, _SEV_CSS["info"])
        status_badge = (
            '<span class="inline-block px-2 py-0.5 rounded text-xs font-bold uppercase bg-emerald-100 text-emerald-800">CONFIRMED</span>'
            if status == "CONFIRMED"
            else '<span class="inline-block px-2 py-0.5 rounded text-xs font-bold uppercase bg-amber-100 text-amber-800">PENDING</span>'
        )

        # Meta rows
        meta_rows = []
        if endpoint:
            meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap align-top">Endpoint</td><td class="py-1 font-mono text-sm break-all">{_e(endpoint)}</td></tr>')
        if host:
            meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap">Host</td><td class="py-1">{_e(host)}</td></tr>')
        if tool:
            meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap">Tool</td><td class="py-1">{_e(tool)}</td></tr>')
        if technique:
            meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap">Technique</td><td class="py-1">{_e(technique)}</td></tr>')
        if param:
            meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap">Parameter</td><td class="py-1 font-mono">{_e(param)}</td></tr>')
        meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap">Status</td><td class="py-1">{status_badge}</td></tr>')
        if cvss:
            meta_rows.append(f'<tr><td class="font-semibold text-slate-500 pr-4 py-1 whitespace-nowrap">CVSS 3.1</td><td class="py-1 font-bold">{_e(str(cvss))}</td></tr>')
        meta_html = "\n".join(meta_rows)

        # Evidence block
        evidence_html = ""
        if evidence:
            evidence_html = f'''
            <div class="mt-4">
                <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Evidence</h4>
                <div class="bg-slate-900 rounded-lg p-4 overflow-auto max-h-64">
                    <code class="text-green-400 text-xs font-mono whitespace-pre-wrap break-all">{_e(evidence)}</code>
                </div>
            </div>'''

        # Payload block
        payload_html = ""
        if payload:
            payload_html = f'''
            <div class="mt-4">
                <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Payload Used</h4>
                <div class="bg-slate-900 rounded-lg p-4 overflow-auto">
                    <code class="text-amber-400 text-xs font-mono whitespace-pre-wrap break-all">{_e(payload)}</code>
                </div>
            </div>'''

        # Curl reproduction block
        curl_html = ""
        if curl_cmd:
            curl_id = f"curl-{i}"
            curl_html = f'''
            <div class="mt-4">
                <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Reproduction Command</h4>
                <div class="bg-slate-900 rounded-lg p-4 relative group">
                    <code id="{curl_id}" class="text-green-400 text-xs font-mono whitespace-pre-wrap break-all">{_e(curl_cmd)}</code>
                    <button onclick="copyCmd('{curl_id}')" class="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-700 hover:bg-slate-600 text-slate-300 hover:text-white px-2 py-1 rounded text-xs font-bold">COPY</button>
                </div>
            </div>'''

        # Repro steps
        repro_html = ""
        if repro_steps:
            steps_li = "\n".join(f"<li class='text-sm text-slate-600 mb-1'>{_e(s)}</li>" for s in repro_steps)
            repro_html = f'''
            <div class="mt-4">
                <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Steps to Reproduce</h4>
                <ol class="list-decimal list-inside space-y-1 pl-2">{steps_li}</ol>
            </div>'''

        # Impact callout
        impact_html = ""
        if impact:
            impact_html = f'''
            <div class="mt-4 bg-amber-50 border border-amber-200 rounded-lg p-4">
                <h4 class="text-xs font-bold text-amber-700 uppercase tracking-wider mb-1">Impact</h4>
                <p class="text-sm text-amber-800">{_e(impact)}</p>
            </div>'''

        # Remediation callout
        remediation_html = f'''
            <div class="mt-4 bg-emerald-50 border border-emerald-200 rounded-lg p-4">
                <h4 class="text-xs font-bold text-emerald-700 uppercase tracking-wider mb-1">Remediation</h4>
                <p class="text-sm text-emerald-800">{_e(remediation)}</p>
            </div>'''

        # Instances badge
        instances_html = ""
        if instances and instances > 1:
            instances_html = f'<span class="ml-2 text-xs bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full font-bold">{instances} instances</span>'

        # Description section
        desc_html = ""
        if description:
            desc_html = f'<p class="text-sm text-slate-600 leading-relaxed mt-3">{_e(description)}</p>'

        findings_html_parts.append(f'''
        <div class="finding-card bg-white border border-slate-200 rounded-lg overflow-hidden shadow-sm hover:shadow-md transition-shadow mb-6" data-severity="{sev}" id="finding-{i}">
            <div class="border-l-4 {css['border']}">
                <div class="p-5 border-b border-slate-100 flex flex-wrap items-center gap-3">
                    <span class="text-sm font-bold text-slate-400">#{i}</span>
                    <span class="inline-block px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wide {css['badge_bg']} {css['badge_text']}">{_e(sev)}</span>
                    <h3 class="text-lg font-bold text-slate-800">{_e(title)}</h3>
                    {instances_html}
                </div>
                <div class="p-5">
                    <table class="text-sm">{meta_html}</table>
                    {desc_html}
                    {evidence_html}
                    {payload_html}
                    {curl_html}
                    {repro_html}
                    {impact_html}
                    {remediation_html}
                </div>
            </div>
        </div>''')

    findings_html = "\n".join(findings_html_parts)

    # --- Build technologies HTML ---
    technologies = data.get("technologies", [])
    tech_rows: list[str] = []
    for t in technologies[:50]:
        if not isinstance(t, dict):
            continue
        t_host = t.get("host", t.get("url", ""))
        techs = t.get("technologies", t.get("tech", []))
        if isinstance(techs, list):
            tech_str = ", ".join(str(x) for x in techs)
        else:
            tech_str = str(techs)
        flags = t.get("flags", t.get("security_flags", []))
        if isinstance(flags, list):
            flags_str = ", ".join(str(x) for x in flags)
        else:
            flags_str = str(flags) if flags else ""
        flag_badge = ""
        if flags_str and "OLD_TECH" in flags_str.upper():
            flag_badge = '<span class="inline-block px-2 py-0.5 rounded text-xs font-bold bg-red-100 text-red-700">OLD_TECH</span>'
        elif flags_str:
            flag_badge = f'<span class="text-xs text-slate-500">{_e(flags_str)}</span>'
        tech_rows.append(
            f'<tr class="border-b border-slate-100 hover:bg-slate-50/50">'
            f'<td class="px-4 py-3 font-mono text-sm">{_e(t_host)}</td>'
            f'<td class="px-4 py-3 text-sm">{_e(tech_str)}</td>'
            f'<td class="px-4 py-3">{flag_badge}</td>'
            f'</tr>'
        )
    tech_rows_html = "\n".join(tech_rows)
    tech_section_html = ""
    if tech_rows:
        tech_section_html = f'''
        <section id="technologies" class="mb-12">
            <h2 class="text-2xl font-bold text-slate-800 mb-6 pb-3 border-b border-slate-200">Technologies Detected</h2>
            <div class="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-sm">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-slate-50 border-b border-slate-200">
                            <th class="text-left px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Host</th>
                            <th class="text-left px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Technologies</th>
                            <th class="text-left px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Status</th>
                        </tr>
                    </thead>
                    <tbody>{tech_rows_html}</tbody>
                </table>
            </div>
        </section>'''

    # --- Build testing coverage HTML ---
    attack_surface = data.get("attack_surface", {})
    test_classes = attack_surface.get("suggested_test_classes", [])
    coverage_rows: list[str] = []
    # Also compute per-technique finding counts
    technique_counts: dict[str, int] = {}
    tools_used: set[str] = set()
    for f in findings:
        tid = f.get("technique_id", "")
        if tid:
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
        t = f.get("tool", "")
        if t:
            tools_used.add(t)

    for tc in test_classes:
        if isinstance(tc, dict):
            tc_name = tc.get("test_class", "")
            tc_priority = tc.get("priority", "")
            tc_reason = tc.get("reason", "")
            fc = technique_counts.get(tc_name, 0)
            count_badge = f'<span class="font-bold text-emerald-600">{fc}</span>' if fc else '<span class="text-slate-400">0</span>'
            coverage_rows.append(
                f'<tr class="border-b border-slate-100 hover:bg-slate-50/50">'
                f'<td class="px-4 py-3 font-mono text-sm">{_e(tc_name)}</td>'
                f'<td class="px-4 py-3 text-sm">{_e(tc_priority)}</td>'
                f'<td class="px-4 py-3 text-center">{count_badge}</td>'
                f'<td class="px-4 py-3 text-sm text-slate-500">{_e(tc_reason)}</td>'
                f'</tr>'
            )
        elif isinstance(tc, str):
            fc = technique_counts.get(tc, 0)
            count_badge = f'<span class="font-bold text-emerald-600">{fc}</span>' if fc else '<span class="text-slate-400">0</span>'
            coverage_rows.append(
                f'<tr class="border-b border-slate-100 hover:bg-slate-50/50">'
                f'<td class="px-4 py-3 font-mono text-sm">{_e(tc)}</td>'
                f'<td class="px-4 py-3"></td>'
                f'<td class="px-4 py-3 text-center">{count_badge}</td>'
                f'<td class="px-4 py-3"></td>'
                f'</tr>'
            )
    coverage_rows_html = "\n".join(coverage_rows)
    tools_list_html = ", ".join(f'<span class="inline-block bg-slate-100 text-slate-700 text-xs font-mono px-2 py-0.5 rounded mr-1 mb-1">{_e(t)}</span>' for t in sorted(tools_used))
    coverage_section_html = ""
    if coverage_rows:
        coverage_section_html = f'''
        <section id="coverage" class="mb-12">
            <h2 class="text-2xl font-bold text-slate-800 mb-6 pb-3 border-b border-slate-200">Testing Coverage</h2>
            <div class="bg-white border border-slate-200 rounded-lg overflow-hidden shadow-sm">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-slate-50 border-b border-slate-200">
                            <th class="text-left px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Technique</th>
                            <th class="text-left px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Priority</th>
                            <th class="text-center px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Findings</th>
                            <th class="text-left px-4 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Reason</th>
                        </tr>
                    </thead>
                    <tbody>{coverage_rows_html}</tbody>
                </table>
            </div>
            {('<div class="mt-4"><span class="text-xs font-bold text-slate-500 uppercase tracking-wider mr-2">Tools Used:</span>' + tools_list_html + '</div>') if tools_list_html else ''}
        </section>'''

    # --- Severity bars HTML ---
    sev_bars: list[str] = []
    _SEV_BAR_COLORS = {
        "critical": "bg-red-900", "high": "bg-red-600",
        "medium": "bg-amber-500", "low": "bg-blue-600", "info": "bg-emerald-600",
    }
    for sev_name in ("critical", "high", "medium", "low", "info"):
        count = by_severity.get(sev_name, 0)
        pct = int((count / max_count) * 100) if max_count else 0
        bar_color = _SEV_BAR_COLORS.get(sev_name, "bg-slate-500")
        sev_bars.append(f'''
            <div class="flex items-center gap-3 mb-2">
                <span class="w-20 text-right text-sm font-semibold text-slate-600">{sev_name.title()}</span>
                <div class="flex-1 h-5 bg-slate-100 rounded-full overflow-hidden">
                    <div class="h-full {bar_color} rounded-full transition-all" style="width:{pct}%"></div>
                </div>
                <span class="w-8 text-sm font-bold text-slate-700">{count}</span>
            </div>''')
    severity_bars_html = "\n".join(sev_bars)

    # --- Sidebar nav finding counts ---
    sidebar_counts = {
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "medium": by_severity.get("medium", 0),
        "low": by_severity.get("low", 0),
        "info": by_severity.get("info", 0),
    }

    # Logo in sidebar
    logo_html = ""
    if _LOGO_B64:
        logo_html = f'<img src="data:image/jpeg;base64,{_LOGO_B64}" alt="BugHound" class="w-10 h-10 rounded-lg object-cover">'
    else:
        logo_html = '<div class="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-xl text-white">B</div>'

    summary_text = _auto_summary(target, processed)

    # --- Assemble the full HTML ---
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment &mdash; {_e(target)}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {{
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace']
                    }}
                }}
            }}
        }}
    </script>
    <style>
        body {{ font-family: 'Inter', system-ui, sans-serif; }}
        code, .font-mono {{ font-family: 'JetBrains Mono', monospace; }}

        /* Smooth scroll */
        html {{ scroll-behavior: smooth; }}

        /* Sidebar nav links */
        .nav-link {{
            display: block;
            padding: 0.5rem 1rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            font-weight: 500;
            color: #94a3b8;
            transition: all 0.15s;
        }}
        .nav-link:hover {{
            background: rgba(255,255,255,0.05);
            color: #e2e8f0;
        }}

        /* Finding card transitions */
        .finding-card {{
            transition: all 0.2s ease;
        }}

        /* Copy button toast */
        .copy-toast {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #0f172a;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            z-index: 1000;
            animation: fadeInUp 0.3s ease, fadeOut 0.3s ease 1.7s forwards;
        }}
        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes fadeOut {{
            from {{ opacity: 1; }}
            to {{ opacity: 0; }}
        }}

        /* Print styles */
        @media print {{
            @page {{ size: A4; margin: 1cm; }}

            * {{
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }}

            aside.sidebar {{
                display: none !important;
            }}

            main {{
                margin-left: 0 !important;
                padding: 0 !important;
                max-width: 100% !important;
            }}

            body {{
                background: white !important;
                color: #1a1a1a !important;
                font-size: 10pt;
            }}

            main::before {{
                content: "BugHound Security Assessment Report";
                display: block;
                font-size: 18pt;
                font-weight: bold;
                color: #1e40af;
                margin-bottom: 16pt;
                padding-bottom: 8pt;
                border-bottom: 2pt solid #1e40af;
            }}

            .finding-card {{
                page-break-inside: avoid;
                border: 1px solid #ddd !important;
                box-shadow: none !important;
                margin-bottom: 12pt;
            }}

            h2 {{
                page-break-after: avoid;
            }}

            .bg-slate-900 {{
                background: #f5f5f5 !important;
                border: 1px solid #ccc !important;
            }}
            .bg-slate-900 code {{
                color: #333 !important;
            }}
            .text-green-400 {{
                color: #006600 !important;
            }}
            .text-amber-400 {{
                color: #996600 !important;
            }}

            button {{
                display: none !important;
            }}

            #filter-bar {{
                display: none !important;
            }}

            canvas {{
                max-width: 300pt !important;
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body class="min-h-screen flex bg-slate-50 text-slate-800">

    <!-- ==================== SIDEBAR ==================== -->
    <aside class="sidebar w-72 bg-slate-900 text-white flex flex-col fixed h-screen overflow-y-auto z-50 shrink-0">
        <div class="p-6">
            <!-- Logo + Brand -->
            <div class="flex items-center gap-3 mb-8">
                {logo_html}
                <div>
                    <h1 class="text-lg font-bold tracking-tight">Bug<span class="text-blue-400">Hound</span></h1>
                    <div class="text-[10px] text-slate-500 uppercase tracking-widest">Security Assessment</div>
                </div>
            </div>

            <!-- Scan Metadata -->
            <div class="space-y-3 mb-8">
                <div class="text-[10px] uppercase text-slate-500 font-bold tracking-widest mb-3">Assessment Context</div>
                <div>
                    <div class="text-xs text-slate-400 mb-0.5">Target</div>
                    <div class="font-mono text-sm text-blue-400 break-all">{_e(target)}</div>
                </div>
                <div>
                    <div class="text-xs text-slate-400 mb-0.5">Scan Date</div>
                    <div class="text-sm">{_e(date)}</div>
                </div>
                <div>
                    <div class="text-xs text-slate-400 mb-0.5">Workspace</div>
                    <div class="text-sm font-mono text-slate-300">{_e(workspace_id)}</div>
                </div>
                <div>
                    <div class="text-xs text-slate-400 mb-0.5">Overall Risk</div>
                    <span class="inline-block px-2.5 py-1 rounded text-xs font-bold uppercase {risk_bg} {risk_text}">{_e(risk_level)}</span>
                </div>
            </div>

            <!-- Navigation -->
            <nav class="space-y-1 mb-8">
                <div class="text-[10px] uppercase text-slate-500 font-bold tracking-widest mb-3">Navigation</div>
                <a href="#executive-summary" class="nav-link">Executive Summary</a>
                <a href="#findings" class="nav-link">Findings</a>
                <a href="#technologies" class="nav-link">Technologies</a>
                <a href="#coverage" class="nav-link">Coverage</a>
                <a href="#about" class="nav-link">About</a>
            </nav>

            <!-- Severity Counts -->
            <div class="space-y-2">
                <div class="text-[10px] uppercase text-slate-500 font-bold tracking-widest mb-3">Finding Summary</div>
                <div class="flex justify-between items-center bg-red-900/20 p-2 rounded text-sm">
                    <span class="text-xs font-bold text-red-400">CRITICAL</span>
                    <span class="font-bold">{sidebar_counts['critical']}</span>
                </div>
                <div class="flex justify-between items-center bg-red-600/20 p-2 rounded text-sm">
                    <span class="text-xs font-bold text-red-300">HIGH</span>
                    <span class="font-bold">{sidebar_counts['high']}</span>
                </div>
                <div class="flex justify-between items-center bg-amber-500/20 p-2 rounded text-sm">
                    <span class="text-xs font-bold text-amber-400">MEDIUM</span>
                    <span class="font-bold">{sidebar_counts['medium']}</span>
                </div>
                <div class="flex justify-between items-center bg-blue-600/20 p-2 rounded text-sm">
                    <span class="text-xs font-bold text-blue-400">LOW</span>
                    <span class="font-bold">{sidebar_counts['low']}</span>
                </div>
                <div class="flex justify-between items-center bg-emerald-600/20 p-2 rounded text-sm">
                    <span class="text-xs font-bold text-emerald-400">INFO</span>
                    <span class="font-bold">{sidebar_counts['info']}</span>
                </div>
            </div>

            <!-- Export Button -->
            <div class="mt-8">
                <button onclick="window.print()" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2.5 px-4 rounded-lg transition-colors text-sm">
                    Export PDF
                </button>
            </div>
        </div>

        <!-- Sidebar Footer -->
        <div class="mt-auto p-6 border-t border-slate-800">
            <div class="text-[10px] text-slate-600 leading-relaxed uppercase tracking-wider">
                Confidential security assessment. Unauthorized distribution prohibited.
            </div>
        </div>
    </aside>

    <!-- ==================== MAIN CONTENT ==================== -->
    <main class="flex-1 ml-72 p-8 lg:p-12">
        <div class="max-w-5xl mx-auto">

            <!-- ===== EXECUTIVE SUMMARY ===== -->
            <section id="executive-summary" class="mb-12">
                <!-- Risk Banner -->
                <div class="{risk_bg} {risk_text} rounded-lg px-6 py-4 mb-8 shadow-sm">
                    <div class="text-sm font-bold uppercase tracking-wider opacity-80">Overall Risk Level</div>
                    <div class="text-2xl font-bold">{_e(risk_level)}</div>
                </div>

                <!-- Auto Summary -->
                <p class="text-base text-slate-600 leading-relaxed mb-8">{_e(summary_text)}</p>

                <!-- Stats Grid + Chart -->
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                    <!-- Donut Chart -->
                    <div class="lg:col-span-2 bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">Severity Distribution</h3>
                        <div class="flex items-center justify-center" style="max-height:300px">
                            <div class="w-full max-w-xs">
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Stats Cards -->
                    <div class="space-y-4">
                        <div class="bg-white border border-slate-200 rounded-lg p-5 shadow-sm text-center">
                            <div class="text-3xl font-bold text-slate-800">{total}</div>
                            <div class="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Total Findings</div>
                        </div>
                        <div class="bg-white border border-slate-200 rounded-lg p-5 shadow-sm text-center border-l-4 border-l-emerald-500">
                            <div class="text-3xl font-bold text-emerald-600">{confirmed_count}</div>
                            <div class="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Confirmed</div>
                        </div>
                        <div class="bg-white border border-slate-200 rounded-lg p-5 shadow-sm text-center border-l-4 border-l-amber-500">
                            <div class="text-3xl font-bold text-amber-600">{pending_count}</div>
                            <div class="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Pending Review</div>
                        </div>
                        <div class="bg-white border border-slate-200 rounded-lg p-5 shadow-sm text-center">
                            <div class="text-3xl font-bold text-slate-400">{fp_count}</div>
                            <div class="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">False Positives</div>
                        </div>
                    </div>
                </div>

                <!-- Severity Bars -->
                <div class="bg-white border border-slate-200 rounded-lg p-6 shadow-sm">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">Severity Breakdown</h3>
                    {severity_bars_html}
                </div>
            </section>

            <!-- ===== FINDINGS ===== -->
            <section id="findings" class="mb-12">
                <h2 class="text-2xl font-bold text-slate-800 mb-6 pb-3 border-b border-slate-200">Detailed Findings</h2>

                <!-- Filter Buttons -->
                <div id="filter-bar" class="flex flex-wrap gap-2 mb-6">
                    <button onclick="filterFindings('all')" class="filter-btn px-4 py-2 rounded-lg text-sm font-bold border border-slate-300 bg-slate-800 text-white" data-filter="all">All ({total})</button>
                    <button onclick="filterFindings('critical')" class="filter-btn px-4 py-2 rounded-lg text-sm font-bold border border-red-200 bg-white text-red-900 hover:bg-red-50" data-filter="critical">Critical ({sidebar_counts['critical']})</button>
                    <button onclick="filterFindings('high')" class="filter-btn px-4 py-2 rounded-lg text-sm font-bold border border-red-200 bg-white text-red-600 hover:bg-red-50" data-filter="high">High ({sidebar_counts['high']})</button>
                    <button onclick="filterFindings('medium')" class="filter-btn px-4 py-2 rounded-lg text-sm font-bold border border-amber-200 bg-white text-amber-700 hover:bg-amber-50" data-filter="medium">Medium ({sidebar_counts['medium']})</button>
                    <button onclick="filterFindings('low')" class="filter-btn px-4 py-2 rounded-lg text-sm font-bold border border-blue-200 bg-white text-blue-700 hover:bg-blue-50" data-filter="low">Low ({sidebar_counts['low']})</button>
                    <button onclick="filterFindings('info')" class="filter-btn px-4 py-2 rounded-lg text-sm font-bold border border-emerald-200 bg-white text-emerald-700 hover:bg-emerald-50" data-filter="info">Info ({sidebar_counts['info']})</button>
                </div>

                <!-- Finding Cards -->
                <div id="findingsContainer">
                    {findings_html}
                </div>
            </section>

            <!-- ===== TECHNOLOGIES ===== -->
            {tech_section_html}

            <!-- ===== COVERAGE ===== -->
            {coverage_section_html}

            <!-- ===== ABOUT / FOOTER ===== -->
            <footer id="about" class="mt-16 pt-8 border-t border-slate-200 text-center text-slate-400 text-sm space-y-2">
                <div class="font-bold text-slate-500">Generated by BugHound &mdash; AI-Powered Bug Bounty MCP Server</div>
                <div>{_e(now)}</div>
                <div class="text-xs">Workspace: {_e(workspace_id)}</div>
            </footer>
        </div>
    </main>

    <!-- ==================== JAVASCRIPT ==================== -->
    <script>
        // --- Severity Donut Chart ---
        (function() {{
            const ctx = document.getElementById('severityChart');
            if (!ctx) return;
            const counts = {chart_data};
            // Only render chart if there are findings
            if (counts.reduce((a,b) => a+b, 0) === 0) return;
            new Chart(ctx.getContext('2d'), {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        data: counts,
                        backgroundColor: ['#991b1b', '#dc2626', '#d97706', '#2563eb', '#059669'],
                        borderColor: '#ffffff',
                        borderWidth: 3,
                        hoverOffset: 8
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    cutout: '60%',
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                usePointStyle: true,
                                pointStyle: 'circle',
                                padding: 16,
                                font: {{ size: 12, weight: '600', family: 'Inter' }},
                                color: '#475569'
                            }}
                        }}
                    }}
                }}
            }});
        }})();

        // --- Finding Filter ---
        function filterFindings(severity) {{
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (severity === 'all' || card.dataset.severity === severity) {{
                    card.style.display = '';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                if (btn.dataset.filter === severity) {{
                    btn.classList.add('bg-slate-800', 'text-white', 'border-slate-800');
                    btn.classList.remove('bg-white');
                }} else {{
                    btn.classList.remove('bg-slate-800', 'text-white', 'border-slate-800');
                    btn.classList.add('bg-white');
                }}
            }});
        }}

        // --- Copy curl command ---
        function copyCmd(id) {{
            const el = document.getElementById(id);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText).then(() => {{
                const toast = document.createElement('div');
                toast.className = 'copy-toast';
                toast.textContent = 'Copied to clipboard';
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 2000);
            }});
        }}

        // --- Smooth scroll for sidebar nav ---
        document.querySelectorAll('.nav-link').forEach(link => {{
            link.addEventListener('click', function(e) {{
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {{
                    target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
                }}
            }});
        }});
    </script>
</body>
</html>'''


# ===================================================================
# BUG BOUNTY MARKDOWN REPORT
# ===================================================================


def _generate_bug_bounty_md(
    target: str,
    processed: dict[str, Any],
) -> str:
    """Generate per-finding markdown report for bug bounty platforms."""
    findings = processed["findings"]
    lines: list[str] = []

    lines.append(f"# Security Findings \u2014 {target}")
    lines.append("")
    lines.append(f"**Date:** {_date_str()}")
    lines.append(f"**Total Findings:** {processed['total']}")
    lines.append(f"**Risk Level:** {processed['risk_level']}")
    lines.append("")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        vc = f.get("vulnerability_class", "other")
        title = _display_name(vc)
        status = f.get("status", "PENDING")
        endpoint = f.get("endpoint", "")
        param = f.get("parameter", "")
        tool = f.get("tool", "")
        description = f.get("description", "")
        evidence = f.get("evidence", "")
        curl_cmd = _auto_curl(f)
        repro_steps = f.get("reproduction_steps", [])
        payload = f.get("payload_used", "")
        cvss = f.get("cvss_score", "")
        impact = f.get("impact", "") or _IMPACT.get(vc, "")
        remediation = _REMEDIATION.get(vc, "Review and remediate according to security best practices.")
        host = f.get("host", "")

        lines.append(f"## Finding {i}: {title}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Severity | {sev.title()} |")
        if endpoint:
            lines.append(f"| Endpoint | `{endpoint}` |")
        if param:
            lines.append(f"| Parameter | `{param}` |")
        if host:
            lines.append(f"| Host | {host} |")
        if tool:
            lines.append(f"| Tool | {tool} |")
        lines.append(f"| Status | {status} |")
        if cvss:
            lines.append(f"| CVSS 3.1 | {cvss} |")
        lines.append("")

        if description:
            lines.append("### Description")
            lines.append(description)
            lines.append("")

        if evidence:
            lines.append("### Evidence")
            lines.append("```")
            lines.append(evidence)
            lines.append("```")
            lines.append("")

        if payload:
            lines.append("### Payload")
            lines.append(f"`{payload}`")
            lines.append("")

        if curl_cmd or repro_steps:
            lines.append("### Steps to Reproduce")
            if curl_cmd:
                lines.append(f"1. Send: `{curl_cmd}`")
                step_num = 2
            else:
                step_num = 1
            for step in repro_steps:
                lines.append(f"{step_num}. {step}")
                step_num += 1
            if not repro_steps and curl_cmd:
                lines.append(f"2. Observe the response for signs of {vc.replace('_', ' ')}")
            lines.append("")

        if impact:
            lines.append("### Impact")
            lines.append(impact)
            lines.append("")

        if remediation:
            lines.append("### Remediation")
            lines.append(remediation)
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append(f"*Generated by BugHound \u2014 {_now_str()}*")
    lines.append("")

    return "\n".join(lines)


# ===================================================================
# EXECUTIVE MARKDOWN REPORT
# ===================================================================


def _generate_executive_md(
    target: str,
    processed: dict[str, Any],
) -> str:
    """Generate a one-page executive summary in markdown."""
    findings = processed["findings"]
    by_severity = processed["by_severity"]
    risk_level = processed["risk_level"]
    total = processed["total"]
    confirmed = processed["confirmed_count"]
    lines: list[str] = []

    lines.append(f"# Executive Security Summary \u2014 {target}")
    lines.append("")
    lines.append(f"**Date:** {_date_str()}")
    lines.append(f"**Risk Level:** {risk_level}")
    lines.append("")

    # Key findings
    lines.append("## Key Findings")
    lines.append("")
    sev_parts = []
    if by_severity.get("critical"):
        sev_parts.append(f"- {by_severity['critical']} Critical vulnerabilities requiring immediate attention")
    if by_severity.get("high"):
        sev_parts.append(f"- {by_severity['high']} High severity issues")
    if by_severity.get("medium"):
        sev_parts.append(f"- {by_severity['medium']} Medium severity issues")
    if by_severity.get("low"):
        sev_parts.append(f"- {by_severity['low']} Low severity issues")
    if by_severity.get("info"):
        sev_parts.append(f"- {by_severity['info']} Informational findings")
    lines.extend(sev_parts)
    lines.append(f"- {total} total findings, {confirmed} confirmed through validation")
    lines.append("")

    # Top critical/high findings
    top_findings = [
        f for f in findings
        if f.get("severity", "").lower() in ("critical", "high")
    ]
    if top_findings:
        count_label = min(len(top_findings), 5)
        lines.append(f"## Top {count_label} Critical/High Issues")
        lines.append("")
        for i, f in enumerate(top_findings[:5], 1):
            vc = f.get("vulnerability_class", "other")
            title = _display_name(vc)
            sev = f.get("severity", "info").title()
            endpoint = f.get("endpoint", "")
            impact = f.get("impact", "") or _IMPACT.get(vc, "")
            # Build concise line
            ep_short = ""
            if endpoint:
                try:
                    parsed = urlparse(endpoint)
                    ep_short = parsed.path or endpoint
                except Exception:
                    ep_short = endpoint
                if len(ep_short) > 40:
                    ep_short = ep_short[:37] + "..."
            impact_short = impact.split(".")[0] if impact else ""
            line = f"{i}. **{title}** [{sev}]"
            if ep_short:
                line += f" \u2014 `{ep_short}`"
            if impact_short:
                line += f" ({impact_short})"
            lines.append(line)
        lines.append("")

    # Vulnerability class distribution
    by_class = processed.get("by_class", {})
    if by_class:
        lines.append("## Vulnerability Distribution")
        lines.append("")
        lines.append("| Vulnerability Type | Count | Highest Severity |")
        lines.append("|-------------------|-------|-----------------|")
        # Sort classes by highest severity in each
        sorted_classes = sorted(
            by_class.items(),
            key=lambda kv: min(
                _SEV_ORDER.get(f.get("severity", "info").lower(), 5)
                for f in kv[1]
            ),
        )
        for vc, class_findings in sorted_classes:
            display = _display_name(vc)
            highest = min(
                class_findings,
                key=lambda f: _SEV_ORDER.get(f.get("severity", "info").lower(), 5),
            )
            highest_sev = highest.get("severity", "info").title()
            lines.append(f"| {display} | {len(class_findings)} | {highest_sev} |")
        lines.append("")

    # Recommendation
    lines.append("## Recommendation")
    lines.append("")
    if risk_level == "CRITICAL":
        lines.append(
            "Immediate remediation of critical findings is required before "
            "production deployment. Critical vulnerabilities may allow complete "
            "system compromise."
        )
    elif risk_level == "HIGH":
        lines.append(
            "High severity vulnerabilities should be remediated as a priority. "
            "These issues pose significant risk to data confidentiality and integrity."
        )
    elif risk_level == "MEDIUM":
        lines.append(
            "Medium severity findings should be addressed in the next development cycle. "
            "While not immediately exploitable in all cases, they may contribute to "
            "attack chains."
        )
    else:
        lines.append(
            "The overall risk posture is acceptable. Low and informational findings "
            "should be reviewed and addressed as part of ongoing security hardening."
        )
    lines.append("")

    lines.append(f"*Generated by BugHound \u2014 {_now_str()}*")
    lines.append("")

    return "\n".join(lines)


# ===================================================================
# ERROR HELPER
# ===================================================================


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
