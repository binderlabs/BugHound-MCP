"""HTML report generator for BugHound Stage 2 and Stage 3 outputs.

Self-contained HTML with inline CSS. Dark cybersecurity theme.
No external dependencies, no JavaScript frameworks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiofiles
import structlog

from bughound.config.settings import WORKSPACE_BASE_DIR

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Shared CSS + HTML scaffolding
# ---------------------------------------------------------------------------

_CSS = """\
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    line-height: 1.6;
    padding: 0;
}
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
header {
    background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
    border-bottom: 2px solid #30363d;
    padding: 32px 0;
    margin-bottom: 24px;
}
header .container { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
.logo { font-size: 28px; font-weight: 700; color: #58a6ff; letter-spacing: -0.5px; }
.logo span { color: #3fb950; }
.header-meta { text-align: right; color: #8b949e; font-size: 13px; }
.header-meta .target { color: #c9d1d9; font-size: 16px; font-weight: 600; margin-bottom: 4px; }
h2 { color: #e6edf3; font-size: 20px; margin: 32px 0 16px 0; padding-bottom: 8px; border-bottom: 1px solid #21262d; }
h3 { color: #c9d1d9; font-size: 16px; margin: 16px 0 8px 0; }
.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px;
    margin: 8px 0;
}
.card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin: 16px 0;
}
.stat-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 16px;
    text-align: center;
}
.stat-card .value { font-size: 32px; font-weight: 700; color: #58a6ff; }
.stat-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}
.badge-critical { background: #da3633; color: #ffffff; }
.badge-high { background: #d29922; color: #000000; }
.badge-medium { background: #e3b341; color: #000000; }
.badge-low { background: #3fb950; color: #000000; }
.badge-info { background: #58a6ff; color: #000000; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
thead th {
    background: #21262d;
    text-align: left;
    padding: 10px 12px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #8b949e;
    border-bottom: 2px solid #30363d;
}
tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid #30363d;
    font-size: 14px;
    vertical-align: top;
}
tbody tr:hover { background: #1c2128; }
.probe-confirmed {
    border-left: 3px solid #da3633;
    padding-left: 12px;
    margin: 8px 0;
    background: rgba(218, 54, 51, 0.06);
    border-radius: 0 6px 6px 0;
    padding: 12px 16px 12px 16px;
}
.immediate-win {
    border-left: 3px solid #3fb950;
    padding-left: 12px;
    margin: 8px 0;
    background: rgba(63, 185, 80, 0.06);
    border-radius: 0 6px 6px 0;
    padding: 12px 16px 12px 16px;
}
.chain-card {
    border-left: 3px solid #d29922;
    background: rgba(210, 153, 34, 0.06);
    border-radius: 0 6px 6px 0;
    padding: 16px;
    margin: 12px 0;
}
.chain-card.chain-critical { border-left-color: #da3633; background: rgba(218, 54, 51, 0.06); }
.chain-card.chain-high { border-left-color: #d29922; background: rgba(210, 153, 34, 0.06); }
.chain-card.chain-medium { border-left-color: #e3b341; background: rgba(227, 179, 65, 0.06); }
.steps { margin: 8px 0; padding-left: 20px; }
.steps li { margin: 4px 0; color: #8b949e; font-size: 13px; }
.steps li code { background: #21262d; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #e6edf3; }
.url-text { color: #58a6ff; word-break: break-all; font-size: 13px; }
.mono { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 13px; }
.flag-tag {
    display: inline-block;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 2px 8px;
    margin: 2px 4px 2px 0;
    font-size: 12px;
    color: #e3b341;
}
.score-badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 16px;
    font-size: 14px;
    font-weight: 700;
}
.score-critical { background: #da3633; color: #fff; }
.score-high { background: #d29922; color: #000; }
.score-medium { background: #e3b341; color: #000; }
.score-low { background: #3fb950; color: #000; }
details { margin: 8px 0; }
summary {
    cursor: pointer;
    padding: 8px 12px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-weight: 600;
    font-size: 14px;
    user-select: none;
}
summary:hover { background: #1c2128; }
details[open] summary { border-radius: 6px 6px 0 0; border-bottom: none; }
details .detail-content {
    background: #161b22;
    border: 1px solid #30363d;
    border-top: none;
    border-radius: 0 0 6px 6px;
    padding: 12px 16px;
}
footer {
    text-align: center;
    padding: 32px 0;
    color: #484f58;
    font-size: 12px;
    border-top: 1px solid #21262d;
    margin-top: 48px;
}
.empty-state { color: #484f58; font-style: italic; padding: 12px; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 768px) {
    .two-col { grid-template-columns: 1fr; }
    .card-grid { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }
    header .container { flex-direction: column; text-align: center; }
    .header-meta { text-align: center; }
}
.reason-list { list-style: none; padding: 0; margin: 4px 0; }
.reason-list li { padding: 4px 0; font-size: 13px; color: #c9d1d9; }
.reason-list li::before { content: "\\25B6 "; color: #58a6ff; font-size: 10px; margin-right: 4px; }
.test-group { margin: 8px 0; }
.test-group-title { font-size: 14px; font-weight: 600; color: #e3b341; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
.test-tag {
    display: inline-block;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 3px 10px;
    margin: 3px 4px 3px 0;
    font-size: 12px;
    color: #c9d1d9;
}
.param-bar { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
.param-bar-label { min-width: 100px; font-size: 13px; color: #8b949e; }
.param-bar-fill { height: 8px; border-radius: 4px; }
"""


def _html_wrap(title: str, body: str) -> str:
    """Wrap body content in full HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)} - BugHound Report</title>
<style>{_CSS}</style>
</head>
<body>
{body}
<footer>
    Generated by BugHound &mdash; AI-Powered Bug Bounty Reconnaissance<br>
    {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
</footer>
</body>
</html>"""


def _esc(text: Any) -> str:
    """HTML-escape a string."""
    s = str(text) if text is not None else ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _severity_badge(severity: str) -> str:
    """Return an HTML badge span for a severity level."""
    sev = (severity or "INFO").upper()
    css_class = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "MEDIUM-HIGH": "badge-high",
        "LOW": "badge-low",
        "INFO": "badge-info",
    }.get(sev, "badge-info")
    return f'<span class="badge {css_class}">{_esc(sev)}</span>'


def _score_class(risk_level: str) -> str:
    """CSS class for a risk-level score badge."""
    return {
        "CRITICAL": "score-critical",
        "HIGH": "score-high",
        "MEDIUM": "score-medium",
        "LOW": "score-low",
    }.get(risk_level.upper(), "score-low")


def _truncate(text: str, max_len: int = 80) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# ---------------------------------------------------------------------------
# 1. Discovery HTML (Stage 2)
# ---------------------------------------------------------------------------


def generate_discovery_html(workspace_id: str, data: dict[str, Any]) -> str:
    """Generate a self-contained HTML report for Stage 2 Discovery results.

    Parameters
    ----------
    workspace_id : str
        The workspace identifier.
    data : dict
        Dictionary with keys like:
        - target: str
        - live_hosts: int
        - urls_discovered: int
        - js_files: int
        - technologies: list[list[str]] or list[dict]
        - flags: list[dict] (flagged hosts with flags)
        - probe_stats: dict  (parameter classification stats)
        - cors_results: list[dict]
        - sensitive_paths: dict[str, list[dict]]
        - auth_results: list[dict]
        - crawled_urls: list[dict]
        - parameters_harvested: int
    """
    target = data.get("target", workspace_id)
    live_hosts = data.get("live_hosts", 0)
    urls_discovered = data.get("urls_discovered", 0)
    js_files = data.get("js_files", 0)
    params_harvested = data.get("parameters_harvested", 0)
    flags = data.get("flags", [])
    technologies = data.get("technologies", [])
    probe_stats = data.get("probe_stats", {})
    cors_results = data.get("cors_results", [])
    sensitive_paths = data.get("sensitive_paths", {})
    auth_results = data.get("auth_results", [])
    crawled_urls = data.get("crawled_urls", [])

    # Count forms from data if available
    forms_count = data.get("forms_discovered", 0)
    secrets_count = data.get("secrets_found", 0)

    # Flatten technologies
    flat_techs: dict[str, int] = {}
    for entry in technologies:
        if isinstance(entry, list):
            for t in entry:
                flat_techs[t] = flat_techs.get(t, 0) + 1
        elif isinstance(entry, dict):
            tech = entry.get("technology", "")
            count = entry.get("host_count", 1)
            if tech:
                flat_techs[tech] = flat_techs.get(tech, 0) + count

    # --- Header ---
    parts: list[str] = []
    parts.append(f"""
<header>
<div class="container">
    <div class="logo">Bug<span>Hound</span></div>
    <div class="header-meta">
        <div class="target">{_esc(target)}</div>
        <div>Stage 2: Discovery Report</div>
        <div>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>
    </div>
</div>
</header>""")

    # --- Summary cards ---
    parts.append('<div class="container">')
    parts.append('<h2>Discovery Summary</h2>')
    parts.append('<div class="card-grid">')

    summary_items = [
        (live_hosts, "Live Hosts"),
        (urls_discovered, "URLs"),
        (js_files, "JS Files"),
        (params_harvested, "Parameters"),
        (forms_count, "Forms"),
        (secrets_count, "Secrets"),
    ]
    for val, label in summary_items:
        parts.append(f"""
<div class="stat-card">
    <div class="value">{val}</div>
    <div class="label">{label}</div>
</div>""")

    parts.append("</div>")  # card-grid

    # --- Technologies ---
    if flat_techs:
        parts.append("<h2>Technologies Detected</h2>")
        parts.append('<div class="card"><table>')
        parts.append("<thead><tr><th>Technology</th><th>Hosts</th></tr></thead>")
        parts.append("<tbody>")
        for tech, count in sorted(flat_techs.items(), key=lambda x: -x[1])[:30]:
            parts.append(
                f"<tr><td>{_esc(tech)}</td><td>{count}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    # --- Flags ---
    if flags:
        parts.append("<h2>Intelligence Flags</h2>")
        parts.append('<div class="card"><table>')
        parts.append("<thead><tr><th>Host</th><th>Flags</th></tr></thead>")
        parts.append("<tbody>")
        for fh in flags:
            host_label = fh.get("host", fh.get("url", "?"))
            flag_list = fh.get("flags", [])
            if not flag_list:
                continue
            flag_tags = " ".join(
                f'<span class="flag-tag">{_esc(f)}</span>'
                for f in flag_list
            )
            parts.append(
                f'<tr><td class="mono">{_esc(host_label)}</td><td>{flag_tags}</td></tr>'
            )
        parts.append("</tbody></table></div>")

    # --- Probe-confirmed findings ---
    probe_xss = probe_stats.get("xss_confirmed", 0) if isinstance(probe_stats, dict) else 0
    probe_sqli = probe_stats.get("sqli_confirmed", 0) if isinstance(probe_stats, dict) else 0
    probe_lfi = probe_stats.get("lfi_confirmed", 0) if isinstance(probe_stats, dict) else 0
    if probe_xss or probe_sqli or probe_lfi:
        parts.append("<h2>Probe-Confirmed Vulnerabilities</h2>")
        parts.append('<div class="probe-confirmed">')
        parts.append("<h3>Live vulnerability probes detected the following:</h3>")
        if probe_sqli:
            parts.append(
                f"<p>{_severity_badge('CRITICAL')} <strong>SQL Injection:</strong> "
                f"{probe_sqli} confirmed endpoint(s)</p>"
            )
        if probe_xss:
            parts.append(
                f"<p>{_severity_badge('HIGH')} <strong>Reflected XSS:</strong> "
                f"{probe_xss} confirmed endpoint(s)</p>"
            )
        if probe_lfi:
            parts.append(
                f"<p>{_severity_badge('CRITICAL')} <strong>Local File Inclusion:</strong> "
                f"{probe_lfi} confirmed endpoint(s)</p>"
            )
        parts.append("</div>")

    # --- Crawled URLs (categorized) ---
    if crawled_urls:
        api_urls: list[str] = []
        dynamic_urls: list[str] = []
        admin_urls: list[str] = []
        static_urls: list[str] = []

        for entry in crawled_urls:
            url_str = entry.get("url", "") if isinstance(entry, dict) else str(entry)
            if not url_str:
                continue
            try:
                parsed = urlparse(url_str)
                path = parsed.path.lower()
            except Exception:
                static_urls.append(url_str)
                continue

            if parsed.query:
                dynamic_urls.append(url_str)
            elif any(seg in path for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
                api_urls.append(url_str)
            elif any(seg in path for seg in ("/admin", "/debug", "/internal", "/manage", "/console")):
                admin_urls.append(url_str)
            else:
                static_urls.append(url_str)

        parts.append("<h2>Crawled URLs</h2>")
        parts.append('<div class="card-grid" style="grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));">')
        for count, label, color in [
            (len(dynamic_urls), "Dynamic", "#d29922"),
            (len(api_urls), "API", "#da3633"),
            (len(admin_urls), "Admin", "#f85149"),
            (len(static_urls), "Static", "#8b949e"),
        ]:
            parts.append(f"""
<div class="stat-card">
    <div class="value" style="color: {color};">{count}</div>
    <div class="label">{label}</div>
</div>""")
        parts.append("</div>")

        # Expandable URL lists
        _url_sections = [
            ("API Endpoints", api_urls),
            ("Dynamic URLs (with parameters)", dynamic_urls),
            ("Admin / Debug URLs", admin_urls),
        ]
        for section_name, url_list in _url_sections:
            if url_list:
                parts.append(f"<details><summary>{_esc(section_name)} ({len(url_list)})</summary>")
                parts.append('<div class="detail-content"><table>')
                parts.append("<thead><tr><th>URL</th></tr></thead><tbody>")
                for u in url_list[:100]:
                    parts.append(f'<tr><td class="url-text">{_esc(_truncate(u, 120))}</td></tr>')
                if len(url_list) > 100:
                    parts.append(f'<tr><td class="empty-state">... and {len(url_list) - 100} more</td></tr>')
                parts.append("</tbody></table></div></details>")

    # --- Sensitive Paths ---
    sp_flat: list[dict[str, Any]] = []
    if isinstance(sensitive_paths, dict):
        for host_url, findings in sensitive_paths.items():
            for f in findings:
                sp_flat.append({**f, "host_url": host_url})
    elif isinstance(sensitive_paths, list):
        sp_flat = sensitive_paths

    if sp_flat:
        parts.append("<h2>Sensitive Paths</h2>")
        parts.append('<div class="card"><table>')
        parts.append("<thead><tr><th>Host</th><th>Path</th><th>Category</th><th>Status</th></tr></thead>")
        parts.append("<tbody>")
        for sp in sp_flat[:50]:
            cat = sp.get("category", "")
            cat_sev = "HIGH" if cat in ("GIT_EXPOSED", "ENV_LEAKED", "CONFIG_LEAKED") else "MEDIUM"
            parts.append(
                f'<tr><td class="mono">{_esc(_truncate(sp.get("host_url", ""), 40))}</td>'
                f'<td class="mono">{_esc(sp.get("path", ""))}</td>'
                f"<td>{_severity_badge(cat_sev)} {_esc(cat)}</td>"
                f'<td>{sp.get("status_code", "?")}</td></tr>'
            )
        if len(sp_flat) > 50:
            parts.append(f'<tr><td colspan="4" class="empty-state">... and {len(sp_flat) - 50} more</td></tr>')
        parts.append("</tbody></table></div>")

    # --- CORS Results ---
    if cors_results:
        parts.append("<h2>CORS Misconfigurations</h2>")
        parts.append('<div class="card"><table>')
        parts.append("<thead><tr><th>URL</th><th>Severity</th><th>Origin Tested</th><th>Credentials</th></tr></thead>")
        parts.append("<tbody>")
        for cr in cors_results[:30]:
            creds = "Yes" if cr.get("credentials_allowed") else "No"
            parts.append(
                f'<tr><td class="url-text">{_esc(_truncate(cr.get("url", ""), 60))}</td>'
                f"<td>{_severity_badge(cr.get('severity', 'INFO'))}</td>"
                f'<td class="mono">{_esc(cr.get("origin_tested", ""))}</td>'
                f"<td>{creds}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    # --- Auth Discovery Summary ---
    if auth_results:
        parts.append("<h2>Authentication Discovery</h2>")
        jwt_count = sum(1 for a in auth_results if a.get("jwts"))
        cookie_issues = sum(len(a.get("insecure_cookie_flags", [])) for a in auth_results)
        injectable = sum(len(a.get("injectable_cookies", [])) for a in auth_results)
        auth_eps = sum(len(a.get("auth_endpoints", [])) for a in auth_results)

        parts.append('<div class="card-grid" style="grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));">')
        for val, label in [
            (auth_eps, "Auth Endpoints"),
            (jwt_count, "JWT Tokens"),
            (cookie_issues, "Cookie Issues"),
            (injectable, "Injectable Cookies"),
        ]:
            color = "#da3633" if val > 0 and label in ("Injectable Cookies",) else "#58a6ff"
            parts.append(f"""
<div class="stat-card">
    <div class="value" style="color: {color};">{val}</div>
    <div class="label">{label}</div>
</div>""")
        parts.append("</div>")

    parts.append("</div>")  # container

    return _html_wrap(f"Discovery - {target}", "\n".join(parts))


# ---------------------------------------------------------------------------
# 2. Attack Surface HTML (Stage 3)
# ---------------------------------------------------------------------------


def generate_attack_surface_html(workspace_id: str, result: dict[str, Any]) -> str:
    """Generate a self-contained HTML report for Stage 3 Attack Surface analysis.

    Parameters
    ----------
    workspace_id : str
        The workspace identifier.
    result : dict
        The full result dict from ``get_attack_surface()``.
    """
    target = result.get("target", workspace_id)
    total_hosts = result.get("total_live_hosts", 0)
    high_interest = result.get("high_interest_targets", [])
    chains = result.get("attack_chains", [])
    wins = result.get("immediate_wins", [])
    test_classes = result.get("suggested_test_classes", [])
    reasoning = result.get("reasoning_prompts", [])
    param_class = result.get("parameter_classification", {})
    stats = result.get("stats", {})
    tech_dist = result.get("technology_distribution", {})
    flags_summary = result.get("flags_summary", {})

    # Determine overall risk from top-scored host
    top_risk = "LOW"
    top_score = 0
    if high_interest:
        top_risk = high_interest[0].get("risk_level", "LOW")
        top_score = high_interest[0].get("score", 0)

    parts: list[str] = []

    # --- Header ---
    parts.append(f"""
<header>
<div class="container">
    <div class="logo">Bug<span>Hound</span></div>
    <div class="header-meta">
        <div class="target">{_esc(target)}</div>
        <div>Stage 3: Attack Surface Analysis</div>
        <div>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>
    </div>
</div>
</header>""")

    parts.append('<div class="container">')

    # --- Overall Score Card ---
    parts.append("<h2>Overall Assessment</h2>")
    parts.append('<div class="card" style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;">')
    parts.append(
        f'<span class="score-badge {_score_class(top_risk)}">{_esc(top_risk)}</span>'
    )
    parts.append(f'<span style="font-size:24px;font-weight:700;color:#e6edf3;">Score: {top_score}</span>')
    parts.append(f'<span style="color:#8b949e;">{total_hosts} live hosts analyzed</span>')

    # Quick stats
    parts.append("</div>")

    summary_cards = [
        (total_hosts, "Live Hosts"),
        (len(chains), "Attack Chains"),
        (len(wins), "Immediate Wins"),
        (len(high_interest), "High Interest"),
    ]
    parts.append('<div class="card-grid">')
    for val, label in summary_cards:
        color = "#da3633" if label == "Immediate Wins" and val > 0 else "#58a6ff"
        parts.append(f"""
<div class="stat-card">
    <div class="value" style="color: {color};">{val}</div>
    <div class="label">{label}</div>
</div>""")
    parts.append("</div>")

    # --- Immediate Wins (highlighted) ---
    if wins:
        parts.append(f'<h2>Immediate Wins ({len(wins)} report-ready findings)</h2>')
        for win in wins:
            parts.append('<div class="immediate-win">')
            parts.append(
                f"<p>{_severity_badge(win.get('severity', 'INFO'))} "
                f"<strong>{_esc(win.get('type', ''))}</strong> on "
                f'<span class="mono">{_esc(win.get("host", ""))}</span></p>'
            )
            parts.append(f'<p style="color:#8b949e;font-size:13px;">{_esc(win.get("evidence", ""))}</p>')
            if win.get("reproduction"):
                parts.append(
                    f'<p style="margin-top:4px;"><code class="mono">{_esc(win.get("reproduction", ""))}</code></p>'
                )
            if win.get("impact"):
                parts.append(f'<p style="font-size:13px;color:#c9d1d9;margin-top:4px;">{_esc(win.get("impact", ""))}</p>')
            if win.get("bounty_estimate"):
                parts.append(
                    f'<p style="font-size:13px;color:#3fb950;margin-top:4px;">Bounty estimate: {_esc(win.get("bounty_estimate", ""))}</p>'
                )
            parts.append("</div>")

    # --- Probe-Confirmed Vulnerabilities ---
    # Extract from high_interest targets
    probe_hosts = [
        h for h in high_interest
        if any("CONFIRMED" in r for r in h.get("reasons", []))
    ]
    if probe_hosts:
        parts.append("<h2>Probe-Confirmed Vulnerabilities</h2>")
        for ph in probe_hosts:
            parts.append('<div class="probe-confirmed">')
            parts.append(
                f'<p><strong>{_esc(ph.get("host", ""))}</strong> '
                f'<span class="score-badge {_score_class(ph.get("risk_level", "LOW"))}">'
                f'Score: {ph.get("score", 0)}</span></p>'
            )
            for reason in ph.get("reasons", []):
                if "CONFIRMED" in reason:
                    parts.append(f'<p style="color:#f85149;font-size:13px;">{_esc(reason)}</p>')
            parts.append("</div>")

    # --- Host Score Cards ---
    if high_interest:
        parts.append(f"<h2>High Interest Targets ({len(high_interest)})</h2>")
        for host_data in high_interest[:15]:
            host = host_data.get("host", "?")
            score = host_data.get("score", 0)
            risk = host_data.get("risk_level", "LOW")
            reasons = host_data.get("reasons", [])
            techs = host_data.get("technologies", [])
            sp = host_data.get("sensitive_paths_found", [])
            flags_set = host_data.get("flags", [])

            parts.append(f"""
<details>
<summary>
    <span class="score-badge {_score_class(risk)}" style="font-size:11px;margin-right:8px;">{_esc(risk)} ({score})</span>
    {_esc(host)}
    {' '.join(f'<span class="flag-tag" style="font-size:10px;">{_esc(f)}</span>' for f in sorted(flags_set)[:5])}
</summary>
<div class="detail-content">""")

            # Reasons
            if reasons:
                parts.append('<ul class="reason-list">')
                for r in reasons:
                    parts.append(f"<li>{_esc(r)}</li>")
                parts.append("</ul>")

            # Tech + sensitive paths on same line
            if techs:
                parts.append(f'<p style="font-size:12px;color:#8b949e;margin-top:8px;">Technologies: {_esc(", ".join(techs[:8]))}</p>')
            if sp:
                parts.append(f'<p style="font-size:12px;color:#d29922;margin-top:4px;">Sensitive paths: {_esc(", ".join(sp[:5]))}</p>')

            parts.append("</div></details>")

    # --- Attack Chains ---
    if chains:
        parts.append(f"<h2>Attack Chains ({len(chains)})</h2>")
        for chain in chains:
            sev = chain.get("severity", "MEDIUM").upper()
            css_sev = "chain-critical" if sev == "CRITICAL" else ("chain-high" if sev in ("HIGH", "MEDIUM-HIGH") else "chain-medium")
            parts.append(f'<div class="chain-card {css_sev}">')
            parts.append(
                f"<p>{_severity_badge(sev)} "
                f"<strong>{_esc(chain.get('name', ''))}</strong> "
                f'<span style="color:#8b949e;font-size:12px;margin-left:8px;">{_esc(chain.get("chain_id", ""))}</span>'
                f'</p>'
            )
            evidence = chain.get("evidence", {})
            if evidence.get("trigger"):
                parts.append(f'<p style="font-size:13px;color:#c9d1d9;margin-top:4px;">Trigger: {_esc(evidence["trigger"])}</p>')
            if evidence.get("supporting"):
                parts.append(f'<p style="font-size:13px;color:#8b949e;">Supporting: {_esc(evidence["supporting"])}</p>')

            affected = chain.get("affected_hosts", [])
            if affected:
                parts.append(
                    f'<p style="font-size:12px;color:#58a6ff;margin-top:4px;">Hosts: {_esc(", ".join(affected[:5]))}</p>'
                )

            steps = chain.get("exploitation_steps", [])
            if steps:
                parts.append('<ol class="steps">')
                for step in steps:
                    parts.append(f"<li><code>{_esc(step)}</code></li>")
                parts.append("</ol>")

            bounty = chain.get("bounty_estimate", "")
            ready = chain.get("report_ready", False)
            meta_parts = []
            if bounty:
                meta_parts.append(f'<span style="color:#3fb950;">Bounty: {_esc(bounty)}</span>')
            if ready:
                meta_parts.append(f'{_severity_badge("LOW")} Report Ready')
            if meta_parts:
                parts.append(f'<p style="font-size:12px;margin-top:8px;">{" &middot; ".join(meta_parts)}</p>')

            parts.append("</div>")

    # --- Reasoning Prompts ---
    if reasoning:
        parts.append("<h2>AI Reasoning Prompts</h2>")
        parts.append('<div class="card">')
        for idx, prompt in enumerate(reasoning[:10], 1):
            if isinstance(prompt, dict):
                prompt_text = prompt.get("prompt", prompt.get("question", str(prompt)))
            else:
                prompt_text = str(prompt)
            parts.append(
                f'<p style="margin:8px 0;font-size:13px;color:#c9d1d9;">'
                f'<span style="color:#58a6ff;font-weight:600;">{idx}.</span> {_esc(prompt_text)}</p>'
            )
        parts.append("</div>")

    # --- Suggested Test Classes ---
    if test_classes:
        parts.append("<h2>Suggested Test Classes</h2>")

        # Group by category
        groups: dict[str, list[dict[str, Any]]] = {}
        for tc in test_classes:
            if isinstance(tc, dict):
                cat = tc.get("category", tc.get("group", "other"))
                groups.setdefault(cat, []).append(tc)
            elif isinstance(tc, str):
                groups.setdefault("general", []).append({"name": tc})

        parts.append('<div class="card">')
        for group_name, items in sorted(groups.items()):
            parts.append(f'<div class="test-group"><div class="test-group-title">{_esc(group_name)}</div>')
            for item in items:
                name = item.get("name", item.get("technique", str(item)))
                reason = item.get("reason", "")
                parts.append(f'<span class="test-tag" title="{_esc(reason)}">{_esc(name)}</span>')
            parts.append("</div>")
        parts.append("</div>")

    # --- Parameter Classification Summary ---
    if param_class and isinstance(param_class, dict):
        parts.append("<h2>Parameter Classification</h2>")
        parts.append('<div class="card">')

        pc_stats = param_class.get("stats", param_class)
        if isinstance(pc_stats, dict):
            stat_items = [
                ("Total Params", pc_stats.get("total_params", pc_stats.get("unique_params_matched", 0))),
                ("SQLi Candidates", pc_stats.get("sqli_candidates", 0)),
                ("XSS Candidates", pc_stats.get("xss_candidates", 0)),
                ("SSRF Candidates", pc_stats.get("ssrf_candidates", 0)),
                ("LFI Candidates", pc_stats.get("lfi_candidates", 0)),
                ("IDOR Candidates", pc_stats.get("idor_candidates", 0)),
                ("Redirect Candidates", pc_stats.get("redirect_candidates", 0)),
            ]
            parts.append("<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>")
            for label, count in stat_items:
                if count:
                    color = '#da3633' if "SQLi" in label or "LFI" in label else ('#d29922' if count > 0 else '#c9d1d9')
                    parts.append(f'<tr><td>{_esc(label)}</td><td style="color:{color};font-weight:600;">{count}</td></tr>')
            parts.append("</tbody></table>")

        # Top candidates per vuln type
        for vuln_type in ("sqli_candidates", "xss_candidates", "ssrf_candidates", "lfi_candidates"):
            candidates = param_class.get(vuln_type, [])
            if candidates and isinstance(candidates, list):
                label = vuln_type.replace("_candidates", "").upper()
                parts.append(
                    f'<details><summary>Top {label} Candidates ({len(candidates)})</summary>'
                    '<div class="detail-content"><table>'
                    "<thead><tr><th>Parameter</th><th>URL</th></tr></thead><tbody>"
                )
                for c in candidates[:20]:
                    if isinstance(c, dict):
                        parts.append(
                            f'<tr><td class="mono">{_esc(c.get("param", ""))}</td>'
                            f'<td class="url-text">{_esc(_truncate(c.get("url", ""), 80))}</td></tr>'
                        )
                parts.append("</tbody></table></div></details>")

        parts.append("</div>")

    # --- Flags Summary ---
    if flags_summary and isinstance(flags_summary, dict):
        parts.append("<h2>Flags Distribution</h2>")
        parts.append('<div class="card"><table>')
        parts.append("<thead><tr><th>Flag Type</th><th>Count</th></tr></thead><tbody>")
        for flag_type, count in sorted(flags_summary.items(), key=lambda x: -(x[1] if isinstance(x[1], int) else 0)):
            if isinstance(count, int) and count > 0:
                parts.append(f"<tr><td>{_esc(flag_type)}</td><td>{count}</td></tr>")
        parts.append("</tbody></table></div>")

    # --- Technology Distribution ---
    if tech_dist and isinstance(tech_dist, dict):
        parts.append("<h2>Technology Distribution</h2>")
        parts.append('<div class="card"><table>')
        parts.append("<thead><tr><th>Technology</th><th>Count</th></tr></thead><tbody>")
        sorted_techs = sorted(tech_dist.items(), key=lambda x: -(x[1] if isinstance(x[1], int) else 0))
        for tech, count in sorted_techs[:20]:
            parts.append(f"<tr><td>{_esc(tech)}</td><td>{count}</td></tr>")
        parts.append("</tbody></table></div>")

    parts.append("</div>")  # container

    return _html_wrap(f"Attack Surface - {target}", "\n".join(parts))


# ---------------------------------------------------------------------------
# 3. Save helper
# ---------------------------------------------------------------------------


async def save_html_report(
    workspace_id: str,
    filename: str,
    html_content: str,
) -> Path:
    """Save HTML content to ``{workspace_dir}/reports/{filename}``.

    Returns the absolute path of the written file.
    """
    ws_dir = WORKSPACE_BASE_DIR / workspace_id
    reports_dir = ws_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    dest = reports_dir / filename
    async with aiofiles.open(dest, "w") as f:
        await f.write(html_content)

    logger.info("html_report.saved", workspace_id=workspace_id, path=str(dest))
    return dest
