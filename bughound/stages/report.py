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
    "info_leak": "Remove sensitive information from responses. Suppress version headers and error details.",
    "vulnerable_component": "Update to the latest supported version. Monitor CVE databases for new advisories.",
    "deserialization": "Never deserialize untrusted data. Enable ViewState MAC validation. Use signed serialization.",
    "prototype_pollution": "Freeze Object.prototype. Validate input object keys. Use Map instead of plain objects.",
    "csti": "Sanitize user input before template rendering. Use strict template escaping.",
    "header_injection": "Validate and sanitize all user input used in HTTP headers. Strip newline characters.",
    "xxe": "Disable external entity processing in XML parsers. Use defusedxml in Python, disable DTDs in Java/C#.",
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
    "info_leak": "Information Disclosure",
    "vulnerable_component": "Known Vulnerable Component",
    "deserialization": "Insecure Deserialization",
    "prototype_pollution": "Prototype Pollution",
    "csti": "Client-Side Template Injection",
    "header_injection": "HTTP Header Injection",
    "xxe": "XML External Entity Injection (XXE)",
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
    "info_leak": "Sensitive information disclosure, aids targeted attacks.",
    "vulnerable_component": "Known CVEs in component, potential remote code execution.",
    "deserialization": "Remote code execution via crafted serialized objects.",
    "prototype_pollution": "Client-side code execution, XSS, privilege escalation.",
    "csti": "Client-side code execution, XSS via template injection.",
    "header_injection": "HTTP response manipulation, session fixation, XSS.",
    "xxe": "Arbitrary file read, SSRF, denial of service, potential remote code execution.",
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
            continue  # Skip false positives (Stage 5)
        if f.get("validation_status") == "LIKELY_FALSE_POSITIVE":
            continue  # Skip AI-agent-marked false positives

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

    # Filter out nuclei "other" noise (unclassified templates)
    merged = [
        f for f in merged
        if f.get("vulnerability_class") not in ("other", None, "")
    ]

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
    # Keep URL-encoded — special chars like | must be encoded for curl to work
    if endpoint.startswith("http"):
        cmd = f"curl -sk '{endpoint}'"
        if payload and param:
            if payload not in endpoint:
                cmd = f"curl -sk '{endpoint}' --data-urlencode '{param}={payload}'"
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

    BugHound sidebar layout design:
    - Fixed sidebar (260px, #0f172a) with logo, context, risk summary, tech stack
    - Main content area (margin-left: 260px, #0a0f1a) with radar chart, stat cards, findings
    - Self-contained inline CSS (no Tailwind CDN)
    - Chart.js for radar chart, Google Fonts for Inter + JetBrains Mono
    - Sidebar severity rows are clickable filters
    - JavaScript for filtering, smooth scroll, copy-to-clipboard
    - Print-optimized CSS: hide sidebar, full width, white background
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

    # Build severity data for Chart.js radar
    chart_data = json.dumps([
        by_severity.get("critical", 0),
        by_severity.get("high", 0),
        by_severity.get("medium", 0),
        by_severity.get("low", 0),
        by_severity.get("info", 0),
    ])

    # Severity border color mapping
    _SEV_BORDER = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#6b7280",
    }

    summary_text = _auto_summary(target, processed)

    # --- Sidebar logo ---
    logo_60 = ""
    if _LOGO_B64:
        logo_60 = f'<img src="data:image/jpeg;base64,{_LOGO_B64}" alt="BugHound" style="width:60px;height:60px;border-radius:10px;object-fit:cover;">'
    else:
        logo_60 = '<div style="width:60px;height:60px;background:#14b8a6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:28px;color:#0a0f1a;">B</div>'

    # --- Sidebar severity rows ---
    sev_rows_html_parts: list[str] = []
    _SEV_ROW_COLORS = {
        "critical": ("#ef4444", "CRITICAL"),
        "high": ("#f97316", "HIGH"),
        "medium": ("#eab308", "MEDIUM"),
        "low": ("#3b82f6", "LOW"),
        "info": ("#6b7280", "INFO"),
    }
    for sev_key in ("critical", "high", "medium", "low", "info"):
        sev_color, sev_label = _SEV_ROW_COLORS[sev_key]
        sev_count = by_severity.get(sev_key, 0)
        sev_rows_html_parts.append(
            f'<div class="sev-row" data-severity="{sev_key}" onclick="sidebarFilter(\'{sev_key}\')">'
            f'<span class="sev-row-border" style="background:{sev_color};"></span>'
            f'<span class="sev-row-label" style="color:{sev_color};">{sev_label}</span>'
            f'<span class="sev-row-count">{sev_count}</span>'
            f'</div>'
        )
    sev_rows_html = "\n".join(sev_rows_html_parts)

    # --- Sidebar technology stack ---
    technologies = data.get("technologies", [])
    tech_names: list[str] = []
    for t in technologies[:20]:
        if not isinstance(t, dict):
            continue
        techs = t.get("technologies", t.get("tech", []))
        if isinstance(techs, list):
            for tn in techs:
                name_str = str(tn)
                if name_str and name_str not in tech_names:
                    tech_names.append(name_str)
        elif techs:
            name_str = str(techs)
            if name_str not in tech_names:
                tech_names.append(name_str)
    sidebar_tech_html = ""
    if tech_names:
        tech_items = "\n".join(
            f'<div class="tech-item">{_e(tn)}</div>'
            for tn in tech_names[:12]
        )
        sidebar_tech_html = f'''
            <div class="sidebar-section">
                <div class="sidebar-heading">Technology Stack</div>
                {tech_items}
            </div>'''

    # --- Probe-confirmed count for sidebar ---
    probe_findings = [
        f for f in findings
        if f.get("probe") or f.get("source") == "probe"
        or (f.get("description", "") and "probe" in f.get("description", "").lower())
        or (f.get("evidence", "") and "probe" in f.get("evidence", "").lower())
    ]
    probe_count = len(probe_findings)
    sidebar_probe_html = ""
    if probe_count > 0:
        sidebar_probe_html = f'''
            <div class="sidebar-section">
                <div class="sidebar-heading">Probe Confirmed</div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="font-size:24px;font-weight:700;color:#14b8a6;">{probe_count}</span>
                    <span style="font-size:12px;color:#9ca3af;">finding{"s" if probe_count != 1 else ""} confirmed by live probes</span>
                </div>
            </div>'''

    # --- Stat cards (right column in main) ---
    # Compute URLs tested from attack surface
    attack_surface = data.get("attack_surface", {})
    urls_tested = 0
    url_data = attack_surface.get("urls", [])
    if isinstance(url_data, list):
        urls_tested = len(url_data)
    if urls_tested == 0:
        urls_tested = len(set(f.get("endpoint", "") for f in findings if f.get("endpoint")))

    # Compute scan duration from metadata
    metadata = data.get("metadata", {})
    scan_duration = ""
    stage_history = metadata.get("stage_history", [])
    if stage_history and len(stage_history) >= 2:
        try:
            first_ts = stage_history[0].get("timestamp", "")
            last_ts = stage_history[-1].get("timestamp", "")
            if first_ts and last_ts:
                from datetime import datetime as _dt
                t1 = _dt.fromisoformat(first_ts.replace("Z", "+00:00"))
                t2 = _dt.fromisoformat(last_ts.replace("Z", "+00:00"))
                delta = (t2 - t1).total_seconds()
                if delta > 0:
                    mins = int(delta // 60)
                    secs = int(delta % 60)
                    scan_duration = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
        except Exception:
            pass
    if not scan_duration:
        scan_duration = "N/A"

    stat_cards_html = f'''
        <div class="stat-card">
            <div class="stat-card-label">Validation Status</div>
            <div class="stat-card-value">{confirmed_count}/{total}</div>
            <div class="stat-card-sub">{"confirmed" if confirmed_count > 0 else "pending validation"}</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-label">URLs Tested</div>
            <div class="stat-card-value">{urls_tested}</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-label">Scan Duration</div>
            <div class="stat-card-value">{_e(scan_duration)}</div>
        </div>
        <div class="stat-card stat-card-accent">
            <div class="stat-card-label">Total Findings</div>
            <div class="stat-card-value" style="color:#14b8a6;">{total}</div>
        </div>'''

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

        border_color = _SEV_BORDER.get(sev, "#6b7280")
        status_cls = "badge-confirmed" if status == "CONFIRMED" else "badge-pending"
        status_label = status

        # Meta rows
        meta_rows = []
        if endpoint:
            meta_rows.append(f'<tr><td class="meta-label">Endpoint</td><td class="meta-value" style="font-family:\'JetBrains Mono\',monospace;font-size:12px;word-break:break-all;">{_e(endpoint)}</td></tr>')
        if host:
            meta_rows.append(f'<tr><td class="meta-label">Host</td><td class="meta-value">{_e(host)}</td></tr>')
        if param:
            meta_rows.append(f'<tr><td class="meta-label">Parameter</td><td class="meta-value" style="font-family:\'JetBrains Mono\',monospace;">{_e(param)}</td></tr>')
        if tool:
            meta_rows.append(f'<tr><td class="meta-label">Tool</td><td class="meta-value">{_e(tool)}</td></tr>')
        if technique:
            meta_rows.append(f'<tr><td class="meta-label">Technique</td><td class="meta-value">{_e(technique)}</td></tr>')
        meta_rows.append(f'<tr><td class="meta-label">Status</td><td class="meta-value"><span class="badge {status_cls}">{_e(status_label)}</span></td></tr>')
        if cvss:
            meta_rows.append(f'<tr><td class="meta-label">CVSS 3.1</td><td class="meta-value" style="font-weight:700;color:#e5e7eb;">{_e(str(cvss))}</td></tr>')
        meta_html = "\n".join(meta_rows)

        # Description
        desc_html = ""
        if description:
            desc_html = f'<p style="color:#9ca3af;font-size:14px;line-height:1.6;margin-top:12px;">{_e(description)}</p>'

        # Evidence block
        evidence_html = ""
        if evidence:
            evidence_html = f'''
                <div style="margin-top:16px;">
                    <div class="section-label">Evidence</div>
                    <div class="code-block">{_e(evidence)}</div>
                </div>'''

        # Payload block
        payload_html = ""
        if payload:
            payload_html = f'''
                <div style="margin-top:16px;">
                    <div class="section-label">Payload Used</div>
                    <div class="code-block" style="color:#eab308;">{_e(payload)}</div>
                </div>'''

        # Curl reproduction block
        curl_html = ""
        if curl_cmd:
            curl_id = f"curl-{i}"
            curl_html = f'''
                <div style="margin-top:16px;">
                    <div class="section-label">Reproduction Command</div>
                    <div class="curl-block">
                        <code id="{curl_id}">{_e(curl_cmd)}</code>
                        <button class="copy-btn" onclick="copyCmd('{curl_id}')">COPY</button>
                    </div>
                </div>'''

        # Repro steps
        repro_html = ""
        if repro_steps:
            steps_li = "\n".join(f"<li style='color:#9ca3af;font-size:13px;margin-bottom:4px;'>{_e(s)}</li>" for s in repro_steps)
            repro_html = f'''
                <div style="margin-top:16px;">
                    <div class="section-label">Steps to Reproduce</div>
                    <ol style="padding-left:20px;margin:0;">{steps_li}</ol>
                </div>'''

        # Impact callout
        impact_html = ""
        if impact:
            impact_html = f'''
                <div class="callout callout-impact">
                    <div class="section-label" style="color:#f97316;margin-bottom:4px;">Impact</div>
                    <p style="color:#e5e7eb;font-size:13px;margin:0;">{_e(impact)}</p>
                </div>'''

        # Remediation callout
        remediation_html = f'''
                <div class="callout callout-fix">
                    <div class="section-label" style="color:#10b981;margin-bottom:4px;">Remediation</div>
                    <p style="color:#e5e7eb;font-size:13px;margin:0;">{_e(remediation)}</p>
                </div>'''

        # Instances badge
        instances_html = ""
        if instances and instances > 1:
            instances_html = f'<span style="margin-left:8px;font-size:11px;background:#1f2937;color:#9ca3af;padding:2px 8px;border-radius:10px;font-weight:600;">{instances} instances</span>'

        findings_html_parts.append(f'''
        <div class="finding {sev}" data-severity="{sev}" id="finding-{i}" style="border-left-color:{border_color};">
            <div style="display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:16px;">
                <span style="font-size:13px;font-weight:700;color:#4b5563;">#{i}</span>
                <span class="badge badge-{sev}">{_e(sev.upper())}</span>
                <h3 style="font-size:17px;font-weight:700;color:#e5e7eb;margin:0;">{_e(title)}</h3>
                {instances_html}
            </div>
            <table style="width:100%;border-collapse:collapse;margin-bottom:8px;">{meta_html}</table>
            {desc_html}
            {evidence_html}
            {payload_html}
            {curl_html}
            {repro_html}
            {impact_html}
            {remediation_html}
        </div>''')

    findings_html = "\n".join(findings_html_parts)

    # --- Build technologies table for main content ---
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
            flag_badge = '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.3);">OLD_TECH</span>'
        elif flags_str:
            flag_badge = f'<span style="font-size:12px;color:#9ca3af;">{_e(flags_str)}</span>'
        tech_rows.append(
            f'<tr>'
            f'<td style="font-family:\'JetBrains Mono\',monospace;font-size:13px;">{_e(t_host)}</td>'
            f'<td>{_e(tech_str)}</td>'
            f'<td>{flag_badge}</td>'
            f'</tr>'
        )
    tech_rows_html = "\n".join(tech_rows)
    tech_section_html = ""
    if tech_rows:
        tech_section_html = f'''
            <section id="tech">
                <h2><span class="accent">//</span> Technologies Detected</h2>
                <div class="card" style="padding:0;overflow:hidden;">
                    <table>
                        <thead>
                            <tr>
                                <th>Host</th>
                                <th>Technologies</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>{tech_rows_html}</tbody>
                    </table>
                </div>
            </section>'''

    # --- Build testing coverage HTML ---
    test_classes = attack_surface.get("suggested_test_classes", [])
    technique_counts: dict[str, int] = {}
    tools_used: set[str] = set()
    for f in findings:
        tid = f.get("technique_id", "")
        if tid:
            technique_counts[tid] = technique_counts.get(tid, 0) + 1
        t = f.get("tool", "")
        if t:
            tools_used.add(t)

    coverage_cards: list[str] = []
    for tc in test_classes:
        if isinstance(tc, dict):
            tc_name = tc.get("test_class", "")
            fc = technique_counts.get(tc_name, 0)
        elif isinstance(tc, str):
            tc_name = tc
            fc = technique_counts.get(tc, 0)
        else:
            continue
        count_color = "#10b981" if fc > 0 else "#4b5563"
        coverage_cards.append(
            f'<div class="coverage-card">'
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;color:#e5e7eb;margin-bottom:6px;">{_e(tc_name)}</div>'
            f'<div style="font-size:24px;font-weight:700;color:{count_color};">{fc}</div>'
            f'<div style="font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;">findings</div>'
            f'</div>'
        )
    coverage_cards_html = "\n".join(coverage_cards)
    tools_list_html = " ".join(
        f'<span style="display:inline-block;background:#1f2937;color:#9ca3af;font-size:11px;font-family:\'JetBrains Mono\',monospace;padding:3px 8px;border-radius:4px;margin:2px;">{_e(t)}</span>'
        for t in sorted(tools_used)
    )
    coverage_section_html = ""
    if coverage_cards:
        coverage_section_html = f'''
            <section id="coverage">
                <h2><span class="accent">//</span> Testing Coverage</h2>
                <div class="coverage-grid">
                    {coverage_cards_html}
                </div>
                {('<div style="margin-top:16px;"><span style="font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-right:8px;">Tools Used:</span>' + tools_list_html + '</div>') if tools_list_html else ''}
            </section>'''

    # --- Assemble the full HTML ---
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment &mdash; {_e(target)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html {{ scroll-behavior: smooth; }}
        body {{
            background: #0a0f1a;
            color: #e5e7eb;
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            line-height: 1.6;
        }}

        /* ===== SIDEBAR ===== */
        .sidebar {{
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            width: 260px;
            background: #0f172a;
            border-right: 1px solid #1e293b;
            overflow-y: auto;
            z-index: 100;
            display: flex;
            flex-direction: column;
            padding: 28px 20px;
        }}
        .sidebar-brand {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 32px;
        }}
        .sidebar-brand-text {{
            font-size: 20px;
            font-weight: 700;
            color: #e5e7eb;
            letter-spacing: -0.3px;
        }}
        .sidebar-brand-text span {{
            color: #14b8a6;
        }}
        .sidebar-section {{
            margin-bottom: 28px;
        }}
        .sidebar-heading {{
            font-size: 10px;
            font-weight: 700;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 12px;
        }}
        .sidebar-meta-label {{
            font-size: 12px;
            color: #64748b;
            margin-bottom: 2px;
        }}
        .sidebar-meta-value {{
            font-size: 13px;
            color: #e5e7eb;
            font-weight: 500;
            margin-bottom: 10px;
            word-break: break-all;
        }}
        .sidebar-meta-value.mono {{
            font-family: 'JetBrains Mono', monospace;
            color: #14b8a6;
            font-size: 12px;
        }}

        /* ===== SEVERITY ROWS ===== */
        .sev-row {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.15s;
            margin-bottom: 4px;
        }}
        .sev-row:hover {{
            background: rgba(255,255,255,0.05);
        }}
        .sev-row.active {{
            background: rgba(255,255,255,0.08);
            outline: 1px solid rgba(255,255,255,0.15);
        }}
        .sev-row-border {{
            width: 3px;
            height: 20px;
            border-radius: 2px;
            flex-shrink: 0;
        }}
        .sev-row-label {{
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            flex: 1;
        }}
        .sev-row-count {{
            font-size: 14px;
            font-weight: 700;
            color: #e5e7eb;
        }}
        .clear-filter {{
            display: block;
            margin-top: 8px;
            font-size: 11px;
            color: #64748b;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
            transition: color 0.15s;
            background: none;
            border: none;
            font-family: 'Inter', sans-serif;
        }}
        .clear-filter:hover {{
            color: #e5e7eb;
        }}

        /* ===== TECH ITEMS ===== */
        .tech-item {{
            font-size: 12px;
            color: #9ca3af;
            padding: 4px 0;
            padding-left: 14px;
            position: relative;
        }}
        .tech-item::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            width: 5px;
            height: 5px;
            background: #14b8a6;
            border-radius: 50%;
        }}

        /* ===== SIDEBAR FOOTER ===== */
        .sidebar-footer {{
            margin-top: auto;
            padding-top: 20px;
            border-top: 1px solid #1e293b;
        }}
        .sidebar-footer button {{
            width: 100%;
            background: #14b8a6;
            color: #0f172a;
            border: none;
            border-radius: 6px;
            padding: 10px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: background 0.15s;
        }}
        .sidebar-footer button:hover {{
            background: #0d9488;
        }}
        .sidebar-confidential {{
            font-size: 9px;
            color: #475569;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            line-height: 1.5;
            margin-top: 12px;
        }}

        /* ===== MAIN CONTENT ===== */
        .main {{
            margin-left: 260px;
            padding: 32px 40px 48px;
            min-height: 100vh;
        }}

        /* ===== DASHBOARD TOP ROW ===== */
        .dashboard-row {{
            display: grid;
            grid-template-columns: 3fr 2fr;
            gap: 20px;
            margin-bottom: 32px;
        }}

        /* ===== CARDS ===== */
        .card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 24px;
        }}

        /* ===== RADAR CHART CARD ===== */
        .chart-card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 24px;
            display: flex;
            flex-direction: column;
        }}
        .chart-card h2 {{
            font-size: 16px;
            font-weight: 700;
            color: #e5e7eb;
            margin: 0 0 16px 0;
            padding: 0;
            border: none;
        }}
        .chart-wrapper {{
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 280px;
        }}

        /* ===== STAT CARDS STACK ===== */
        .stat-stack {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .stat-card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 18px 20px;
        }}
        .stat-card-accent {{
            border-color: #14b8a6;
        }}
        .stat-card-label {{
            font-size: 10px;
            font-weight: 700;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }}
        .stat-card-value {{
            font-size: 28px;
            font-weight: 700;
            color: #e5e7eb;
            line-height: 1.2;
        }}
        .stat-card-sub {{
            font-size: 11px;
            color: #64748b;
            margin-top: 2px;
        }}

        /* ===== EXECUTIVE SUMMARY ===== */
        .summary-card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 32px;
        }}
        .summary-card p {{
            color: #9ca3af;
            font-size: 14px;
            line-height: 1.7;
        }}

        /* ===== FINDING CARDS ===== */
        .finding {{
            background: #111827;
            border: 1px solid #1e293b;
            border-left: 4px solid #ef4444;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 16px;
            transition: box-shadow 0.2s;
        }}
        .finding:hover {{
            box-shadow: 0 4px 24px rgba(0,0,0,0.3);
        }}
        .finding.high {{ border-left-color: #f97316; }}
        .finding.medium {{ border-left-color: #eab308; }}
        .finding.low {{ border-left-color: #3b82f6; }}
        .finding.info {{ border-left-color: #6b7280; }}

        .meta-label {{
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            padding: 5px 16px 5px 0;
            white-space: nowrap;
            vertical-align: top;
        }}
        .meta-value {{
            font-size: 13px;
            color: #e5e7eb;
            padding: 5px 0;
            word-break: break-word;
        }}

        .section-label {{
            font-size: 11px;
            font-weight: 700;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 8px;
        }}

        /* ===== CODE & CURL BLOCKS ===== */
        .code-block {{
            background: #0a0f1a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #14b8a6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .curl-block {{
            background: #0a0f1a;
            border: 1px solid #14b8a6;
            border-radius: 6px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #14b8a6;
            position: relative;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .copy-btn {{
            position: absolute;
            top: 8px; right: 8px;
            background: #1e293b;
            color: #9ca3af;
            border: 1px solid #374151;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 11px;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
            transition: color 0.2s, border-color 0.2s;
        }}
        .copy-btn:hover {{
            color: #14b8a6;
            border-color: #14b8a6;
        }}

        /* ===== BADGES ===== */
        .badge {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-critical {{ background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
        .badge-high {{ background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }}
        .badge-medium {{ background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3); }}
        .badge-low {{ background: rgba(59,130,246,0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3); }}
        .badge-info {{ background: rgba(107,114,128,0.15); color: #6b7280; border: 1px solid rgba(107,114,128,0.3); }}
        .badge-confirmed {{ background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }}
        .badge-pending {{ background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3); }}
        .badge-CONFIRMED {{ background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }}
        .badge-PENDING {{ background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3); }}

        /* ===== CALLOUTS ===== */
        .callout {{
            border-radius: 6px;
            padding: 12px 16px;
            margin: 12px 0;
            font-size: 14px;
        }}
        .callout-impact {{
            background: rgba(249,115,22,0.08);
            border-left: 3px solid #f97316;
        }}
        .callout-fix {{
            background: rgba(16,185,129,0.08);
            border-left: 3px solid #10b981;
        }}

        /* ===== SECTION HEADERS ===== */
        h2 {{
            font-size: 20px;
            font-weight: 700;
            color: #e5e7eb;
            margin: 40px 0 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid #1e293b;
        }}
        h2 .accent {{
            color: #14b8a6;
        }}

        /* ===== TABLES ===== */
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #0a0f1a;
            text-align: left;
            padding: 10px 12px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #9ca3af;
            border-bottom: 1px solid #1e293b;
            font-weight: 700;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #1e293b;
            font-size: 14px;
            color: #e5e7eb;
        }}
        tr:hover {{
            background: rgba(20,184,166,0.03);
        }}

        /* ===== COVERAGE GRID ===== */
        .coverage-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 12px;
            margin: 16px 0;
        }}
        .coverage-card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .coverage-card:hover {{
            border-color: #14b8a6;
        }}

        /* ===== FOOTER ===== */
        .report-footer {{
            margin-top: 48px;
            padding-top: 24px;
            border-top: 2px solid #14b8a6;
            text-align: center;
        }}
        .report-footer .footer-brand {{
            font-size: 14px;
            font-weight: 600;
            color: #9ca3af;
            margin-bottom: 8px;
        }}
        .report-footer .footer-brand span {{
            color: #14b8a6;
        }}
        .report-footer .footer-meta {{
            font-size: 12px;
            color: #6b7280;
        }}

        /* ===== COPY TOAST ===== */
        .copy-toast {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #14b8a6;
            color: #0a0f1a;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            z-index: 1000;
            animation: toastIn 0.3s ease, toastOut 0.3s ease 1.7s forwards;
        }}
        @keyframes toastIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes toastOut {{
            from {{ opacity: 1; }}
            to {{ opacity: 0; }}
        }}

        /* ===== PRINT ===== */
        @media print {{
            @page {{ size: A4; margin: 1cm; }}
            * {{ -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
            body {{ background: white; color: #1a1a1a; }}
            .sidebar {{ display: none; }}
            .main {{ margin-left: 0; padding: 0; }}
            .dashboard-row {{ grid-template-columns: 1fr; }}
            .card, .chart-card, .stat-card, .finding, .summary-card {{
                background: white; border-color: #dee2e6;
            }}
            .finding {{ page-break-inside: avoid; }}
            h2 {{ page-break-after: avoid; color: #1a1a1a; }}
            .code-block, .curl-block {{ background: #f5f5f5; color: #006666; border-color: #dee2e6; }}
            .copy-btn {{ display: none; }}
            .stat-card-value {{ color: #1a1a1a; }}
            .stat-card-label {{ color: #666; }}
            canvas {{ max-width: 300pt !important; page-break-inside: avoid; }}
            .badge-critical {{ background: #fdd; color: #c00; border-color: #faa; }}
            .badge-high {{ background: #fed; color: #d60; border-color: #fca; }}
            .meta-label {{ color: #666; }}
            .meta-value {{ color: #1a1a1a; }}
            .callout-impact {{ background: #fff8f0; }}
            .callout-fix {{ background: #f0fdf4; }}
            td, th {{ color: #1a1a1a; }}
            th {{ background: #f5f5f5; color: #666; }}
            .report-footer {{ border-top-color: #0d9488; }}
            .coverage-card {{ background: white; border-color: #dee2e6; }}
            .summary-card p {{ color: #333; }}
            /* Print header */
            .main::before {{
                content: 'BugHound Security Assessment Report';
                display: block;
                font-size: 18pt;
                font-weight: bold;
                color: #0d9488;
                margin-bottom: 16pt;
                padding-bottom: 8pt;
                border-bottom: 2pt solid #0d9488;
            }}
        }}

        /* ===== RESPONSIVE ===== */
        @media (max-width: 900px) {{
            .sidebar {{ display: none; }}
            .main {{ margin-left: 0; padding: 16px; }}
            .dashboard-row {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>

    <!-- ==================== SIDEBAR ==================== -->
    <aside class="sidebar">
        <div class="sidebar-brand">
            {logo_60}
            <div class="sidebar-brand-text">Bug<span>Hound</span></div>
        </div>

        <!-- Assessment Context -->
        <div class="sidebar-section">
            <div class="sidebar-heading">Assessment Context</div>
            <div class="sidebar-meta-label">Target</div>
            <div class="sidebar-meta-value mono">{_e(target)}</div>
            <div class="sidebar-meta-label">Date</div>
            <div class="sidebar-meta-value">{_e(date)}</div>
            <div class="sidebar-meta-label">Workspace</div>
            <div class="sidebar-meta-value">{_e(workspace_id)}</div>
        </div>

        <!-- Risk Summary -->
        <div class="sidebar-section">
            <div class="sidebar-heading">Risk Summary</div>
            {sev_rows_html}
            <button class="clear-filter" onclick="sidebarFilter('all')">Clear Filter</button>
        </div>

        <!-- Technology Stack -->
        {sidebar_tech_html}

        <!-- Probe Confirmed -->
        {sidebar_probe_html}

        <!-- Sidebar Footer -->
        <div class="sidebar-footer">
            <button onclick="exportAll()">Export All (PDF)</button>
            <button onclick="exportFiltered()" style="margin-top:6px;">Export Filtered</button>
            <div class="sidebar-confidential">
                Confidential security assessment. Unauthorized distribution prohibited.
            </div>
        </div>
    </aside>

    <!-- ==================== MAIN CONTENT ==================== -->
    <div class="main">

        <!-- ===== DASHBOARD: CHART + STAT CARDS ===== -->
        <div class="dashboard-row">
            <div class="chart-card">
                <h2 style="margin:0 0 16px 0;padding:0;border:none;">Vulnerability Distribution</h2>
                <div class="chart-wrapper">
                    <div style="width:100%;max-width:360px;">
                        <canvas id="radarChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="stat-stack">
                {stat_cards_html}
            </div>
        </div>

        <!-- ===== EXECUTIVE SUMMARY ===== -->
        <div class="summary-card">
            <p>{_e(summary_text)}</p>
        </div>

        <!-- ===== FINDINGS ===== -->
        <section id="findings-section">
            <h2><span class="accent">//</span> Detailed Findings</h2>

            <div id="findingsContainer">
                {findings_html}
            </div>
        </section>

        <!-- ===== TECHNOLOGIES ===== -->
        {tech_section_html}

        <!-- ===== COVERAGE ===== -->
        {coverage_section_html}

        <!-- ===== FOOTER ===== -->
        <footer class="report-footer">
            <div class="footer-brand">Generated by Bug<span>Hound</span> &mdash; AI-Powered Security Operations</div>
            <div class="footer-meta">{_e(now)} &middot; Workspace: {_e(workspace_id)}</div>
            <div style="font-size:10px;color:#4b5563;margin-top:8px;">Confidential security assessment. Unauthorized distribution prohibited.</div>
        </footer>

    </div>

    <!-- ==================== JAVASCRIPT ==================== -->
    <script>
        // --- Radar Chart ---
        (function() {{
            const ctx = document.getElementById('radarChart');
            if (!ctx) return;
            const counts = {chart_data};
            if (counts.reduce((a,b) => a+b, 0) === 0) return;
            new Chart(ctx.getContext('2d'), {{
                type: 'radar',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        label: 'Risk Vector',
                        data: counts,
                        backgroundColor: 'rgba(20, 184, 166, 0.25)',
                        borderColor: '#14b8a6',
                        borderWidth: 2,
                        pointBackgroundColor: '#14b8a6',
                        pointBorderColor: '#0f172a',
                        pointBorderWidth: 2,
                        pointRadius: 5,
                        fill: true
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {{
                        r: {{
                            beginAtZero: true,
                            ticks: {{ display: false, stepSize: 1 }},
                            grid: {{ color: '#1e293b' }},
                            angleLines: {{ color: '#1e293b' }},
                            pointLabels: {{
                                font: {{ size: 12, weight: '600', family: 'Inter' }},
                                color: '#9ca3af'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
        }})();

        // --- Sidebar severity filter ---
        function sidebarFilter(severity) {{
            const cards = document.querySelectorAll('.finding');
            cards.forEach(card => {{
                if (severity === 'all' || card.dataset.severity === severity) {{
                    card.style.display = '';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
            // Highlight active sidebar row
            document.querySelectorAll('.sev-row').forEach(row => {{
                if (row.dataset.severity === severity) {{
                    row.classList.add('active');
                }} else {{
                    row.classList.remove('active');
                }}
            }});
            // Scroll to findings
            if (severity !== 'all') {{
                const section = document.getElementById('findings-section');
                if (section) section.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }}
        }}

        // --- Export functions ---
        function exportAll() {{
            // Show all findings, print, then restore filter
            const cards = document.querySelectorAll('.finding');
            const hidden = [];
            cards.forEach(card => {{
                if (card.style.display === 'none') {{
                    hidden.push(card);
                    card.style.display = '';
                }}
            }});
            setTimeout(() => {{
                window.print();
                // Restore hidden state after print dialog
                setTimeout(() => {{
                    hidden.forEach(card => {{ card.style.display = 'none'; }});
                }}, 500);
            }}, 100);
        }}

        function exportFiltered() {{
            window.print();
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
