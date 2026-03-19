"""HTML report generator for BugHound Stage 2 and Stage 3 outputs.

Self-contained HTML with inline CSS and minimal JS. Dark cybersecurity theme
with professional dashboard layout, sticky navigation, collapsible sections,
color-coded severity badges, and print-friendly styles.

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

# Logo as base64 data URI
_LOGO_B64_PATH = Path(__file__).parent / "logo_b64.txt"
try:
    _LOGO_B64 = _LOGO_B64_PATH.read_text().strip()
except Exception:
    _LOGO_B64 = ""


# ---------------------------------------------------------------------------
# Shared CSS
# ---------------------------------------------------------------------------

_CSS = """\
*{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{
    background:#0d1117;color:#c9d1d9;
    font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
    line-height:1.6;padding:0;
}
.container{max-width:1200px;margin:0 auto;padding:24px;}

/* Sticky top bar — header + nav combined */
.top-bar{
    position:sticky;top:0;z-index:200;
    background:#0d1117;
}
header{
    background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);
    border-bottom:1px solid #30363d;
    padding:10px 0;
}
header .container{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;padding-top:8px;padding-bottom:8px;}
.logo-group{display:flex;align-items:center;gap:12px;}
.logo-img{width:42px;height:42px;border-radius:50%;border:2px solid #30363d;object-fit:cover;}
.logo{font-size:24px;font-weight:700;color:#58a6ff;letter-spacing:-0.5px;}
.logo span{color:#3fb950;}
.header-meta{text-align:right;color:#8b949e;font-size:12px;}
.header-meta .target{color:#e6edf3;font-size:14px;font-weight:600;margin-bottom:2px;word-break:break-all;}
.header-meta .stage-label{color:#58a6ff;font-weight:600;font-size:12px;}

/* Nav inside top-bar */
.nav{
    background:#161b22;border-bottom:2px solid #30363d;
    padding:4px 0;overflow-x:auto;white-space:nowrap;
}
.nav .container{padding-top:0;padding-bottom:0;display:flex;gap:2px;flex-wrap:nowrap;}
.nav a{
    color:#8b949e;text-decoration:none;padding:6px 14px;font-size:13px;
    border-radius:4px;transition:all .15s;
}
.nav a:hover{color:#58a6ff;background:rgba(88,166,255,.08);}

/* Section anchors — offset for sticky header+nav */
h2{
    color:#e6edf3;font-size:20px;margin:36px 0 16px 0;
    padding-bottom:8px;border-bottom:1px solid #21262d;
    scroll-margin-top:110px;
}
h3{color:#c9d1d9;font-size:16px;margin:16px 0 8px 0;}

/* Cards */
.card{
    background:#161b22;border:1px solid #30363d;
    border-radius:6px;padding:16px;margin:8px 0;
}
.card-grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
    gap:12px;margin:16px 0;
}

/* Stat cards with top color bar */
.stat-card{
    background:#161b22;border:1px solid #30363d;
    border-radius:6px;padding:16px;text-align:center;
    border-top:3px solid #58a6ff;
    transition:transform .15s,box-shadow .15s;
}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.3);}
.stat-card.critical{border-top-color:#da3633;}
.stat-card.high{border-top-color:#d29922;}
.stat-card.warning{border-top-color:#e3b341;}
.stat-card.success{border-top-color:#3fb950;}
.stat-card.info{border-top-color:#58a6ff;}
.stat-card .icon{font-size:20px;margin-bottom:4px;}
.stat-card .value{font-size:32px;font-weight:700;color:#58a6ff;}
.stat-card .label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;}

/* Severity badges */
.badge{
    display:inline-block;padding:2px 10px;border-radius:12px;
    font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;
}
.badge-critical{background:#da3633;color:#fff;}
.badge-high{background:#d29922;color:#000;}
.badge-medium{background:#e3b341;color:#000;}
.badge-low{background:#3fb950;color:#000;}
.badge-info{background:#58a6ff;color:#000;}

/* Tables */
table{width:100%;border-collapse:collapse;margin:8px 0;}
thead th{
    background:#21262d;text-align:left;padding:10px 12px;
    font-size:12px;text-transform:uppercase;letter-spacing:.5px;
    color:#8b949e;border-bottom:2px solid #30363d;
    position:sticky;top:0;
}
tbody td{padding:10px 12px;border-bottom:1px solid #21262d;font-size:14px;vertical-align:top;}
tbody tr:nth-child(even){background:rgba(22,27,34,.6);}
tbody tr:hover{background:#1c2128;}

/* Probe-confirmed block */
.probe-confirmed{
    border-left:4px solid #da3633;
    margin:12px 0;background:rgba(218,54,51,.08);
    border-radius:0 8px 8px 0;padding:16px 20px;
}
.probe-confirmed h3{color:#f85149;margin-top:0;}

/* Immediate win block */
.immediate-win{
    border-left:4px solid #3fb950;
    margin:12px 0;background:rgba(63,185,80,.08);
    border-radius:0 8px 8px 0;padding:16px 20px;
}

/* Chain card */
.chain-card{
    border-left:4px solid #d29922;background:rgba(210,153,34,.06);
    border-radius:0 8px 8px 0;padding:16px 20px;margin:12px 0;
}
.chain-card.chain-critical{border-left-color:#da3633;background:rgba(218,54,51,.06);}
.chain-card.chain-high{border-left-color:#d29922;background:rgba(210,153,34,.06);}
.chain-card.chain-medium{border-left-color:#e3b341;background:rgba(227,179,65,.06);}

/* Collapsible details */
details{margin:8px 0;}
summary{
    cursor:pointer;padding:10px 14px;background:#161b22;
    border:1px solid #30363d;border-radius:6px;color:#c9d1d9;
    font-weight:600;font-size:14px;user-select:none;
    transition:background .15s;list-style:none;
}
summary::-webkit-details-marker{display:none;}
summary::before{content:"\\25B6";display:inline-block;margin-right:8px;font-size:10px;transition:transform .2s;color:#58a6ff;}
details[open] summary::before{transform:rotate(90deg);}
summary:hover{background:#1c2128;}
details[open] summary{border-radius:6px 6px 0 0;border-bottom:none;}
details .detail-content{
    background:#161b22;border:1px solid #30363d;border-top:none;
    border-radius:0 0 6px 6px;padding:12px 16px;
}

/* Score badges */
.score-badge{display:inline-block;padding:4px 14px;border-radius:16px;font-size:14px;font-weight:700;}
.score-critical{background:#da3633;color:#fff;}
.score-high{background:#d29922;color:#000;}
.score-medium{background:#e3b341;color:#000;}
.score-low{background:#3fb950;color:#000;}

/* Flag / test tags */
.flag-tag{
    display:inline-block;background:#21262d;border:1px solid #30363d;
    border-radius:4px;padding:2px 8px;margin:2px 4px 2px 0;font-size:12px;color:#e3b341;
}
.test-tag{
    display:inline-block;background:#21262d;border:1px solid #30363d;
    border-radius:4px;padding:3px 10px;margin:3px 4px 3px 0;font-size:12px;color:#c9d1d9;
}
.test-group{margin:8px 0;}
.test-group-title{font-size:14px;font-weight:600;color:#e3b341;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;}

/* Progress bars */
.bar{height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin:2px 0;}
.bar-fill{height:100%;border-radius:4px;transition:width .3s;}
.param-bar{display:flex;align-items:center;gap:8px;margin:4px 0;}
.param-bar-label{min-width:110px;font-size:13px;color:#8b949e;}
.param-bar-count{min-width:40px;font-size:13px;font-weight:600;text-align:right;}

/* Utility classes */
.url-text{color:#58a6ff;word-break:break-all;font-size:13px;}
.mono{font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:13px;}
.empty-state{color:#484f58;font-style:italic;padding:12px;}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.reason-list{list-style:none;padding:0;margin:4px 0;}
.reason-list li{padding:4px 0;font-size:13px;color:#c9d1d9;}
.reason-list li::before{content:"\\25B6 ";color:#58a6ff;font-size:10px;margin-right:4px;}
.steps{margin:8px 0;padding-left:20px;}
.steps li{margin:4px 0;color:#8b949e;font-size:13px;}
.steps li code{background:#21262d;padding:2px 6px;border-radius:3px;font-size:12px;color:#e6edf3;}

/* Risk-score big display */
.risk-display{
    display:flex;align-items:center;gap:24px;flex-wrap:wrap;
    padding:20px;margin:16px 0;
}

/* Intelligence briefing items */
.briefing-item{
    padding:12px 16px;margin:6px 0;
    background:#161b22;border:1px solid #30363d;border-radius:6px;
    border-left:3px solid #58a6ff;font-size:13px;color:#c9d1d9;
}
.briefing-item .idx{color:#58a6ff;font-weight:700;margin-right:8px;}

/* Executive summary box */
.exec-summary{
    background:linear-gradient(135deg,rgba(88,166,255,.05),rgba(63,185,80,.05));
    border:1px solid #30363d;border-radius:8px;padding:20px 24px;
    margin:16px 0;font-size:14px;line-height:1.7;color:#e6edf3;
}

/* Pulse animation for critical items */
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:.7;}}
.pulse{animation:pulse 2s infinite;}

/* Footer */
footer{
    text-align:center;padding:32px 0;color:#484f58;font-size:12px;
    border-top:1px solid #21262d;margin-top:48px;
}
footer .brand{color:#58a6ff;font-weight:600;}

/* Responsive */
@media(max-width:768px){
    .two-col{grid-template-columns:1fr;}
    .card-grid{grid-template-columns:repeat(auto-fit,minmax(120px,1fr));}
    header .container{flex-direction:column;text-align:center;}
    .header-meta{text-align:center;}
    .nav a{padding:6px 8px;font-size:12px;}
}

/* Print styles */
@media print{
    body{background:#fff;color:#1a1a1a;}
    .container{max-width:100%;}
    header{position:static;background:#fff;border-bottom:2px solid #ddd;padding:12px 0;}
    .nav{display:none;}
    .logo{color:#0a5cad;} .logo span{color:#1a7f37;}
    .header-meta,.header-meta .target{color:#1a1a1a;}
    .header-meta .stage-label{color:#0a5cad;}
    h2{color:#1a1a1a;border-bottom-color:#ddd;page-break-after:avoid;}
    .card,.stat-card{background:#fafafa;border-color:#ddd;box-shadow:none;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .stat-card:hover{transform:none;box-shadow:none;}
    .stat-card .value{color:#0a5cad;}
    .stat-card .label{color:#555;}
    table{page-break-inside:avoid;}
    thead th{background:#eee;color:#333;border-bottom-color:#ddd;}
    tbody td{border-bottom-color:#eee;color:#333;}
    tbody tr:nth-child(even){background:#f5f5f5;}
    tbody tr:hover{background:transparent;}
    .probe-confirmed{background:rgba(218,54,51,.1);border-left-color:#d00;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .immediate-win{background:rgba(63,185,80,.1);border-left-color:#1a7f37;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .chain-card{background:rgba(210,153,34,.1);-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .badge,.score-badge{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .url-text{color:#0a5cad;}
    summary{background:#fafafa;border-color:#ddd;color:#1a1a1a;}
    details .detail-content{background:#fafafa;border-color:#ddd;}
    footer{color:#999;border-top-color:#ddd;}
    footer .brand{color:#0a5cad;}
    .flag-tag{background:#eee;border-color:#ddd;color:#8a6b00;}
    .test-tag{background:#eee;border-color:#ddd;color:#333;}
    .briefing-item{background:#fafafa;border-color:#ddd;border-left-color:#0a5cad;color:#333;}
    .exec-summary{background:#f0f8ff;border-color:#ddd;color:#1a1a1a;}
    .reason-list li{color:#333;}
    .empty-state{color:#999;}
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _timestamp() -> str:
    """Current UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _header_html(target: str, stage_label: str) -> str:
    """Generate the sticky header with logo and target info."""
    logo_img = ""
    if _LOGO_B64:
        logo_img = f'<img src="data:image/jpeg;base64,{_LOGO_B64}" alt="BugHound" class="logo-img">'
    return f"""
<header>
<div class="container">
    <div class="logo-group">
        {logo_img}
        <div class="logo">Bug<span>Hound</span></div>
    </div>
    <div class="header-meta">
        <div class="target">{_esc(target)}</div>
        <div class="stage-label">{_esc(stage_label)}</div>
        <div>{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>
    </div>
</div>
</header>"""


def _footer_html() -> str:
    """Generate footer with branding and timestamp."""
    return f"""
<footer>
    <span class="brand">BugHound</span> &mdash; AI-Powered Bug Bounty Reconnaissance<br>
    Report generated {_timestamp()}
</footer>"""


def _nav_html(sections: list[tuple[str, str]]) -> str:
    """Generate sticky navigation bar. sections = [(anchor_id, label), ...]."""
    links = "".join(
        f'<a href="#{_esc(sid)}">{_esc(label)}</a>'
        for sid, label in sections
    )
    return f'<nav class="nav"><div class="container">{links}</div></nav>'


def _stat_card(value: int | str, label: str, css_class: str = "info", icon: str = "") -> str:
    """Single stat card with colored top border."""
    icon_html = f'<div class="icon">{icon}</div>' if icon else ""
    return f"""
<div class="stat-card {_esc(css_class)}">
    {icon_html}
    <div class="value">{_esc(str(value))}</div>
    <div class="label">{_esc(label)}</div>
</div>"""


def _progress_bar(count: int, total: int, color: str = "#58a6ff") -> str:
    """Inline progress bar HTML."""
    pct = min(100, int(count / total * 100)) if total > 0 else 0
    return (
        f'<div class="bar" style="flex:1;"><div class="bar-fill" '
        f'style="width:{pct}%;background:{color};"></div></div>'
    )


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
{_footer_html()}
</body>
</html>"""


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
        Dictionary with keys from discover.py call site:
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
        - parameters_harvested: int  (NOTE: from discover.py this is len(hidden_params))
        - forms_discovered: int
        - secrets_found: int
    """
    target = data.get("target", workspace_id)
    live_hosts = data.get("live_hosts", 0)
    urls_discovered = data.get("urls_discovered", 0)
    js_files = data.get("js_files", 0)
    flags = data.get("flags", [])
    technologies = data.get("technologies", [])
    probe_stats = data.get("probe_stats", {})
    cors_results = data.get("cors_results", [])
    sensitive_paths = data.get("sensitive_paths", {})
    auth_results = data.get("auth_results", [])
    crawled_urls = data.get("crawled_urls", [])

    forms_count = data.get("forms_discovered", 0)
    secrets_count = data.get("secrets_found", 0)

    # FIX: parameters_harvested from discover.py is len(hidden_params) which
    # is just arjun results. The probe_stats dict (from param_classifier)
    # has the real total_unique_params count from all URL parameter extraction.
    params_harvested = 0
    if isinstance(probe_stats, dict):
        params_harvested = probe_stats.get(
            "total_unique_params",
            probe_stats.get("unique_params_matched",
                            data.get("parameters_harvested", 0)),
        )
    else:
        params_harvested = data.get("parameters_harvested", 0)

    # FIX: Probe-confirmed counts use the correct key names from
    # param_classifier.probe_reflection(): probe_xss_found, probe_sqli_found, probe_lfi_found
    probe_xss = probe_stats.get("probe_xss_found", 0) if isinstance(probe_stats, dict) else 0
    probe_sqli = probe_stats.get("probe_sqli_found", 0) if isinstance(probe_stats, dict) else 0
    probe_lfi = probe_stats.get("probe_lfi_found", 0) if isinstance(probe_stats, dict) else 0

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

    # Build navigation sections
    nav_sections: list[tuple[str, str]] = [("summary", "Summary")]
    if probe_xss or probe_sqli or probe_lfi:
        nav_sections.append(("probes", "Probe Results"))
    if flat_techs:
        nav_sections.append(("technologies", "Technologies"))
    if flags:
        nav_sections.append(("flags", "Intelligence"))
    if crawled_urls:
        nav_sections.append(("urls", "URLs"))
    sp_flat = _flatten_sensitive_paths(sensitive_paths)
    if sp_flat:
        nav_sections.append(("sensitive", "Sensitive Paths"))
    if cors_results:
        nav_sections.append(("cors", "CORS"))
    if auth_results:
        nav_sections.append(("auth", "Auth Discovery"))

    parts: list[str] = []

    # --- Header + Nav ---
    parts.append('<div class="top-bar">')
    parts.append(_header_html(target, "Stage 2: Discovery Report"))
    parts.append(_nav_html(nav_sections))
    parts.append('</div>')

    # --- Summary Dashboard ---
    parts.append('<div class="container">')
    parts.append('<h2 id="summary">Discovery Summary</h2>')
    parts.append('<div class="card-grid">')

    summary_items = [
        (live_hosts, "Live Hosts", "success" if live_hosts > 0 else "info", ""),
        (urls_discovered, "URLs", "info", ""),
        (params_harvested, "Parameters", "warning" if params_harvested > 10 else "info", ""),
        (js_files, "JS Files", "info", ""),
        (forms_count, "Forms", "warning" if forms_count > 0 else "info", ""),
        (secrets_count, "Secrets", "critical" if secrets_count > 0 else "info", ""),
    ]
    for val, label, css_cls, icon in summary_items:
        parts.append(_stat_card(val, label, css_cls, icon))
    parts.append("</div>")  # card-grid

    # --- Probe-Confirmed Vulnerabilities (highlight section) ---
    if probe_xss or probe_sqli or probe_lfi:
        parts.append('<h2 id="probes">Probe-Confirmed Vulnerabilities</h2>')
        parts.append('<div class="probe-confirmed">')
        parts.append("<h3>Live vulnerability probes detected injectable parameters:</h3>")
        total_confirmed = probe_xss + probe_sqli + probe_lfi
        parts.append(
            f'<p style="font-size:15px;color:#f85149;margin-bottom:12px;">'
            f'<strong>{total_confirmed}</strong> confirmed injectable endpoint(s) '
            f'found during parameter probing.</p>'
        )
        if probe_sqli:
            parts.append(
                f'<p style="margin:6px 0;">{_severity_badge("CRITICAL")} '
                f'<strong>SQL Injection:</strong> {probe_sqli} confirmed endpoint(s) '
                f'&mdash; error-based detection triggered</p>'
            )
        if probe_xss:
            parts.append(
                f'<p style="margin:6px 0;">{_severity_badge("HIGH")} '
                f'<strong>Reflected XSS:</strong> {probe_xss} confirmed endpoint(s) '
                f'&mdash; reflection of injected payload detected</p>'
            )
        if probe_lfi:
            parts.append(
                f'<p style="margin:6px 0;">{_severity_badge("CRITICAL")} '
                f'<strong>Local File Inclusion:</strong> {probe_lfi} confirmed endpoint(s) '
                f'&mdash; file content indicators in response</p>'
            )
        parts.append(
            '<p style="font-size:12px;color:#8b949e;margin-top:10px;">'
            'These findings are from live probes during parameter classification. '
            'Proceed to Stage 4 (Testing) for full exploitation verification.</p>'
        )
        parts.append("</div>")

        # Show probe stats as small cards
        parts.append('<div class="card-grid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin-top:8px;">')
        probe_total = probe_stats.get("probe_total", 0) if isinstance(probe_stats, dict) else 0
        parts.append(_stat_card(probe_total, "Params Probed", "info"))
        if probe_sqli:
            parts.append(_stat_card(probe_sqli, "SQLi Confirmed", "critical"))
        if probe_xss:
            parts.append(_stat_card(probe_xss, "XSS Confirmed", "high"))
        if probe_lfi:
            parts.append(_stat_card(probe_lfi, "LFI Confirmed", "critical"))
        parts.append("</div>")

    # --- Technologies ---
    if flat_techs:
        parts.append('<h2 id="technologies">Technologies Detected</h2>')
        parts.append('<div class="card"><table>')
        parts.append(
            "<thead><tr><th>Technology</th><th>Hosts</th><th>Status</th></tr></thead>"
        )
        parts.append("<tbody>")
        # Check OLD_TECH patterns
        import re
        old_tech_patterns = [
            (re.compile(r"jquery[/: ]*[12]\.", re.I), "EOL"),
            (re.compile(r"php[/: ]*5\.", re.I), "EOL"),
            (re.compile(r"php[/: ]*7\.[0-3]\.", re.I), "EOL"),
            (re.compile(r"angular[/: ]*1\.", re.I), "EOL"),
            (re.compile(r"apache[/: ]*2\.2\.", re.I), "EOL"),
            (re.compile(r"openssl[/: ]*1\.0\.", re.I), "EOL"),
            (re.compile(r"asp\.net[/: ]*[123]\.", re.I), "EOL"),
            (re.compile(r"wordpress[/: ]*[1-5]\.", re.I), "OLD"),
            (re.compile(r"nginx[/: ]*1\.(1[0-8]|[0-9])\.", re.I), "OLD"),
            (re.compile(r"express[/: ]*[1-3]\.", re.I), "OLD"),
            (re.compile(r"django[/: ]*[12]\.", re.I), "EOL"),
            (re.compile(r"tomcat[/: ]*[1-8]\.", re.I), "OLD"),
        ]
        for tech, count in sorted(flat_techs.items(), key=lambda x: -x[1])[:30]:
            status_html = ""
            tech_lower = tech.lower()
            for pat, label in old_tech_patterns:
                if pat.search(tech_lower):
                    status_html = f'{_severity_badge("HIGH")} {label}'
                    break
            if not status_html:
                status_html = '<span style="color:#3fb950;font-size:12px;">OK</span>'
            parts.append(
                f"<tr><td class=\"mono\">{_esc(tech)}</td>"
                f"<td>{count}</td>"
                f"<td>{status_html}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    # --- Intelligence Flags ---
    if flags:
        # Count hosts with flags
        hosts_with_flags = [h for h in flags if h.get("flags")]
        if hosts_with_flags:
            parts.append(f'<h2 id="flags">Intelligence Flags ({len(hosts_with_flags)} hosts flagged)</h2>')
            parts.append('<div class="card"><table>')
            parts.append(
                "<thead><tr><th>Host</th><th>Flags</th><th>Count</th></tr></thead>"
            )
            parts.append("<tbody>")
            for fh in hosts_with_flags[:50]:
                host_label = fh.get("host", fh.get("url", "?"))
                flag_list = fh.get("flags", [])
                if not flag_list:
                    continue
                # Color-code certain flags
                flag_html_parts = []
                for f in flag_list:
                    f_upper = f.split(":")[0].upper()
                    if f_upper in ("NO_WAF", "NON_CDN_IP", "DEBUG_MODE"):
                        flag_html_parts.append(
                            f'<span class="flag-tag" style="color:#f85149;border-color:#da3633;">'
                            f'{_esc(f)}</span>'
                        )
                    elif f_upper in ("OLD_TECH", "CORS_MISCONFIGURED", "SOURCE_MAP_EXPOSED"):
                        flag_html_parts.append(
                            f'<span class="flag-tag" style="color:#d29922;border-color:#d29922;">'
                            f'{_esc(f)}</span>'
                        )
                    else:
                        flag_html_parts.append(f'<span class="flag-tag">{_esc(f)}</span>')
                flag_tags = " ".join(flag_html_parts)
                parts.append(
                    f'<tr><td class="mono">{_esc(_truncate(host_label, 50))}</td>'
                    f"<td>{flag_tags}</td>"
                    f"<td>{len(flag_list)}</td></tr>"
                )
            parts.append("</tbody></table></div>")

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

        parts.append(f'<h2 id="urls">Crawled URLs ({len(crawled_urls)} total)</h2>')

        # URL category cards
        parts.append('<div class="card-grid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));">')
        for count, label, css_cls in [
            (len(dynamic_urls), "Dynamic", "warning"),
            (len(api_urls), "API", "critical"),
            (len(admin_urls), "Admin", "critical"),
            (len(static_urls), "Static", "info"),
        ]:
            parts.append(_stat_card(count, label, css_cls))
        parts.append("</div>")

        # Expandable URL lists
        _url_sections = [
            ("API Endpoints", api_urls, "#da3633"),
            ("Dynamic URLs (with parameters)", dynamic_urls, "#d29922"),
            ("Admin / Debug URLs", admin_urls, "#f85149"),
        ]
        for section_name, url_list, _color in _url_sections:
            if url_list:
                parts.append(
                    f"<details><summary>{_esc(section_name)} ({len(url_list)})</summary>"
                )
                parts.append('<div class="detail-content"><table>')
                parts.append("<thead><tr><th>#</th><th>URL</th></tr></thead><tbody>")
                for idx, u in enumerate(url_list[:100], 1):
                    parts.append(
                        f'<tr><td style="color:#484f58;width:40px;">{idx}</td>'
                        f'<td class="url-text">{_esc(_truncate(u, 120))}</td></tr>'
                    )
                if len(url_list) > 100:
                    parts.append(
                        f'<tr><td colspan="2" class="empty-state">'
                        f'... and {len(url_list) - 100} more</td></tr>'
                    )
                parts.append("</tbody></table></div></details>")

    # --- Sensitive Paths ---
    if sp_flat:
        parts.append(f'<h2 id="sensitive">Sensitive Paths ({len(sp_flat)} found)</h2>')
        parts.append('<div class="card"><table>')
        parts.append(
            "<thead><tr><th>Host</th><th>Path</th><th>Category</th><th>Status</th></tr></thead>"
        )
        parts.append("<tbody>")
        for sp in sp_flat[:50]:
            cat = sp.get("category", "")
            cat_sev = "CRITICAL" if cat in ("GIT_EXPOSED", "ENV_LEAKED") else (
                "HIGH" if cat in ("CONFIG_LEAKED", "SWAGGER_EXPOSED", "DEBUG_ENDPOINT") else "MEDIUM"
            )
            parts.append(
                f'<tr><td class="mono">{_esc(_truncate(sp.get("host_url", ""), 40))}</td>'
                f'<td class="mono">{_esc(sp.get("path", ""))}</td>'
                f"<td>{_severity_badge(cat_sev)} {_esc(cat)}</td>"
                f'<td>{sp.get("status_code", "?")}</td></tr>'
            )
        if len(sp_flat) > 50:
            parts.append(
                f'<tr><td colspan="4" class="empty-state">'
                f'... and {len(sp_flat) - 50} more</td></tr>'
            )
        parts.append("</tbody></table></div>")

    # --- CORS Results ---
    if cors_results:
        # Count by severity
        cors_crit = sum(1 for c in cors_results if c.get("severity", "").upper() in ("CRITICAL", "HIGH"))
        parts.append(
            f'<h2 id="cors">CORS Misconfigurations ({len(cors_results)} found'
            f'{", " + str(cors_crit) + " critical/high" if cors_crit else ""})</h2>'
        )
        parts.append('<div class="card"><table>')
        parts.append(
            "<thead><tr><th>URL</th><th>Severity</th>"
            "<th>Origin Tested</th><th>Credentials</th></tr></thead>"
        )
        parts.append("<tbody>")
        for cr in cors_results[:30]:
            creds = "Yes" if cr.get("credentials_allowed") else "No"
            creds_style = ' style="color:#da3633;font-weight:600;"' if cr.get("credentials_allowed") else ""
            parts.append(
                f'<tr><td class="url-text">{_esc(_truncate(cr.get("url", ""), 60))}</td>'
                f"<td>{_severity_badge(cr.get('severity', 'INFO'))}</td>"
                f'<td class="mono">{_esc(cr.get("origin_tested", ""))}</td>'
                f"<td{creds_style}>{creds}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    # --- Auth Discovery Summary ---
    if auth_results:
        jwt_count = sum(1 for a in auth_results if a.get("jwts"))
        cookie_issues = sum(len(a.get("insecure_cookie_flags", [])) for a in auth_results)
        injectable = sum(len(a.get("injectable_cookies", [])) for a in auth_results)
        auth_eps = sum(len(a.get("auth_endpoints", [])) for a in auth_results)

        parts.append(f'<h2 id="auth">Authentication Discovery</h2>')
        parts.append(
            '<div class="card-grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr));">'
        )
        parts.append(_stat_card(auth_eps, "Auth Endpoints", "info"))
        parts.append(_stat_card(jwt_count, "JWT Tokens", "warning" if jwt_count > 0 else "info"))
        parts.append(_stat_card(cookie_issues, "Cookie Issues", "warning" if cookie_issues > 0 else "info"))
        parts.append(_stat_card(
            injectable, "Injectable Cookies",
            "critical" if injectable > 0 else "info",
        ))
        parts.append("</div>")

        # Detail: list auth endpoints found
        all_auth_eps: list[str] = []
        for a in auth_results:
            for ep in a.get("auth_endpoints", []):
                url = ep if isinstance(ep, str) else ep.get("url", "")
                if url:
                    all_auth_eps.append(url)
        if all_auth_eps:
            parts.append(
                f"<details><summary>Auth Endpoints Found ({len(all_auth_eps)})</summary>"
            )
            parts.append('<div class="detail-content"><table>')
            parts.append("<thead><tr><th>Endpoint</th></tr></thead><tbody>")
            for ep_url in all_auth_eps[:30]:
                parts.append(f'<tr><td class="url-text">{_esc(ep_url)}</td></tr>')
            parts.append("</tbody></table></div></details>")

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

    # Build navigation
    nav_sections: list[tuple[str, str]] = [("overview", "Overview")]
    if wins:
        nav_sections.append(("wins", "Immediate Wins"))
    # Check for probe-confirmed
    probe_hosts = [
        h for h in high_interest
        if any("CONFIRMED" in r for r in h.get("reasons", []))
    ]
    if probe_hosts:
        nav_sections.append(("probe-confirmed", "Probe Confirmed"))
    if high_interest:
        nav_sections.append(("hosts", "Host Scores"))
    if chains:
        nav_sections.append(("chains", "Attack Chains"))
    if reasoning:
        nav_sections.append(("reasoning", "AI Reasoning"))
    if test_classes:
        nav_sections.append(("tests", "Test Classes"))
    if param_class and isinstance(param_class, dict):
        nav_sections.append(("params", "Parameters"))

    parts: list[str] = []

    # --- Header + Nav ---
    parts.append('<div class="top-bar">')
    parts.append(_header_html(target, "Stage 3: Attack Surface Analysis"))
    parts.append(_nav_html(nav_sections))
    parts.append('</div>')
    parts.append('<div class="container">')

    # --- Overall Assessment ---
    parts.append('<h2 id="overview">Overall Assessment</h2>')
    parts.append(f'<div class="card risk-display">')
    pulse = " pulse" if top_risk in ("CRITICAL", "HIGH") else ""
    parts.append(
        f'<span class="score-badge {_score_class(top_risk)}{pulse}" '
        f'style="font-size:18px;padding:8px 24px;">{_esc(top_risk)}</span>'
    )
    parts.append(
        f'<span style="font-size:28px;font-weight:700;color:#e6edf3;">Score: {top_score}</span>'
    )
    parts.append(f'<span style="color:#8b949e;">{total_hosts} live hosts analyzed</span>')
    parts.append("</div>")

    # Executive summary auto-generated
    parts.append('<div class="exec-summary">')
    exec_parts: list[str] = [
        f"Analysis of <strong>{_esc(target)}</strong> identified "
        f"<strong>{total_hosts}</strong> live host(s)"
    ]
    if wins:
        exec_parts.append(
            f" with <strong style=\"color:#3fb950;\">{len(wins)} immediate win(s)</strong>"
            " that can be reported without further testing"
        )
    if chains:
        exec_parts.append(f", <strong>{len(chains)} attack chain(s)</strong>")
    if high_interest:
        crit_count = sum(1 for h in high_interest if h.get("risk_level", "").upper() in ("CRITICAL", "HIGH"))
        if crit_count:
            exec_parts.append(
                f", and <strong style=\"color:#da3633;\">{crit_count} critical/high-risk target(s)</strong>"
            )
    exec_parts.append(
        f". The highest-scoring host received a risk score of <strong>{top_score}</strong> "
        f"({_esc(top_risk)})."
    )
    parts.append("".join(exec_parts))
    parts.append("</div>")

    # Summary cards
    parts.append('<div class="card-grid">')
    parts.append(_stat_card(total_hosts, "Live Hosts", "info"))
    parts.append(_stat_card(len(chains), "Attack Chains", "high" if chains else "info"))
    parts.append(_stat_card(len(wins), "Immediate Wins", "success" if wins else "info"))
    parts.append(_stat_card(len(high_interest), "High Interest", "warning" if high_interest else "info"))
    parts.append("</div>")

    # --- Immediate Wins (GREEN highlighted) ---
    if wins:
        parts.append(f'<h2 id="wins">Immediate Wins ({len(wins)} report-ready findings)</h2>')
        parts.append(
            '<p style="color:#3fb950;font-size:13px;margin-bottom:12px;">'
            'These findings can be reported to bug bounty programs immediately '
            'without additional testing.</p>'
        )
        for win in wins:
            parts.append('<div class="immediate-win">')
            parts.append(
                f"<p>{_severity_badge(win.get('severity', 'INFO'))} "
                f"<strong>{_esc(win.get('type', ''))}</strong> on "
                f'<span class="mono">{_esc(win.get("host", ""))}</span></p>'
            )
            if win.get("evidence"):
                parts.append(
                    f'<p style="color:#8b949e;font-size:13px;margin-top:4px;">'
                    f'{_esc(win.get("evidence", ""))}</p>'
                )
            if win.get("reproduction"):
                parts.append(
                    f'<p style="margin-top:4px;">'
                    f'<code class="mono">{_esc(win.get("reproduction", ""))}</code></p>'
                )
            if win.get("impact"):
                parts.append(
                    f'<p style="font-size:13px;color:#c9d1d9;margin-top:4px;">'
                    f'{_esc(win.get("impact", ""))}</p>'
                )
            if win.get("bounty_estimate"):
                parts.append(
                    f'<p style="font-size:13px;color:#3fb950;margin-top:4px;">'
                    f'Bounty estimate: {_esc(win.get("bounty_estimate", ""))}</p>'
                )
            parts.append("</div>")

    # --- Probe-Confirmed Vulnerabilities (RED highlighted) ---
    if probe_hosts:
        parts.append(f'<h2 id="probe-confirmed">Probe-Confirmed Vulnerabilities ({len(probe_hosts)})</h2>')
        parts.append(
            '<p style="color:#f85149;font-size:13px;margin-bottom:12px;">'
            'These hosts have vulnerabilities confirmed by live parameter probing '
            'during discovery.</p>'
        )
        for ph in probe_hosts:
            parts.append('<div class="probe-confirmed">')
            parts.append(
                f'<p><strong>{_esc(ph.get("host", ""))}</strong> '
                f'<span class="score-badge {_score_class(ph.get("risk_level", "LOW"))}">'
                f'Score: {ph.get("score", 0)}</span></p>'
            )
            for reason in ph.get("reasons", []):
                if "CONFIRMED" in reason:
                    parts.append(
                        f'<p style="color:#f85149;font-size:13px;margin:4px 0;">'
                        f'{_esc(reason)}</p>'
                    )
            parts.append("</div>")

    # --- Host Score Cards ---
    if high_interest:
        parts.append(f'<h2 id="hosts">High Interest Targets ({len(high_interest)})</h2>')
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

            # Score bar visualization
            max_score = max(h.get("score", 1) for h in high_interest) or 1
            bar_pct = min(100, int(score / max_score * 100))
            bar_color = {"CRITICAL": "#da3633", "HIGH": "#d29922", "MEDIUM": "#e3b341", "LOW": "#3fb950"}.get(
                risk.upper(), "#58a6ff"
            )
            parts.append(
                f'<div style="margin:8px 0 12px 0;">'
                f'<div class="bar" style="height:10px;">'
                f'<div class="bar-fill" style="width:{bar_pct}%;background:{bar_color};"></div>'
                f'</div></div>'
            )

            if reasons:
                parts.append('<ul class="reason-list">')
                for r in reasons:
                    parts.append(f"<li>{_esc(r)}</li>")
                parts.append("</ul>")

            if techs:
                parts.append(
                    f'<p style="font-size:12px;color:#8b949e;margin-top:8px;">'
                    f'Technologies: {_esc(", ".join(techs[:8]))}</p>'
                )
            if sp:
                parts.append(
                    f'<p style="font-size:12px;color:#d29922;margin-top:4px;">'
                    f'Sensitive paths: {_esc(", ".join(str(s) for s in sp[:5]))}</p>'
                )

            parts.append("</div></details>")

    # --- Attack Chains ---
    if chains:
        parts.append(f'<h2 id="chains">Attack Chains ({len(chains)})</h2>')
        for chain in chains:
            sev = chain.get("severity", "MEDIUM").upper()
            css_sev = (
                "chain-critical" if sev == "CRITICAL"
                else ("chain-high" if sev in ("HIGH", "MEDIUM-HIGH") else "chain-medium")
            )
            parts.append(f'<div class="chain-card {css_sev}">')
            parts.append(
                f"<p>{_severity_badge(sev)} "
                f"<strong>{_esc(chain.get('name', ''))}</strong> "
                f'<span style="color:#8b949e;font-size:12px;margin-left:8px;">'
                f"{_esc(chain.get('chain_id', ''))}</span></p>"
            )
            evidence = chain.get("evidence", {})
            if evidence.get("trigger"):
                parts.append(
                    f'<p style="font-size:13px;color:#c9d1d9;margin-top:4px;">'
                    f'Trigger: {_esc(evidence["trigger"])}</p>'
                )
            if evidence.get("supporting"):
                parts.append(
                    f'<p style="font-size:13px;color:#8b949e;">'
                    f'Supporting: {_esc(evidence["supporting"])}</p>'
                )

            affected = chain.get("affected_hosts", [])
            if affected:
                parts.append(
                    f'<p style="font-size:12px;color:#58a6ff;margin-top:4px;">'
                    f'Hosts: {_esc(", ".join(affected[:5]))}'
                    f'{"..." if len(affected) > 5 else ""}</p>'
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
                meta_parts.append(
                    f'<span style="color:#3fb950;">Bounty: {_esc(bounty)}</span>'
                )
            if ready:
                meta_parts.append(f'{_severity_badge("LOW")} Report Ready')
            if meta_parts:
                parts.append(
                    f'<p style="font-size:12px;margin-top:8px;">'
                    f'{" &middot; ".join(meta_parts)}</p>'
                )

            parts.append("</div>")

    # --- AI Reasoning Prompts (intelligence briefing style) ---
    if reasoning:
        parts.append(f'<h2 id="reasoning">AI Reasoning Prompts ({len(reasoning[:15])})</h2>')
        parts.append(
            '<p style="color:#8b949e;font-size:13px;margin-bottom:12px;">'
            'Intelligence briefing items for AI-guided analysis and decision-making.</p>'
        )
        for idx, prompt in enumerate(reasoning[:15], 1):
            if isinstance(prompt, dict):
                prompt_text = prompt.get("prompt", prompt.get("question", str(prompt)))
            else:
                prompt_text = str(prompt)
            parts.append(
                f'<div class="briefing-item">'
                f'<span class="idx">{idx}.</span> {_esc(prompt_text)}'
                f'</div>'
            )

    # --- Suggested Test Classes ---
    if test_classes:
        parts.append(f'<h2 id="tests">Suggested Test Classes ({len(test_classes)})</h2>')

        # Group by category
        groups: dict[str, list[dict[str, Any]]] = {}
        for tc in test_classes:
            if isinstance(tc, dict):
                cat = tc.get("category", tc.get("group", "other"))
                groups.setdefault(cat, []).append(tc)
            elif isinstance(tc, str):
                groups.setdefault("general", []).append({"name": tc})

        # Color map for test categories
        cat_colors = {
            "injection": "#da3633", "auth": "#d29922", "infra": "#58a6ff",
            "api": "#bc8cff", "client": "#e3b341", "general": "#8b949e",
        }

        parts.append('<div class="card">')
        for group_name, items in sorted(groups.items()):
            color = cat_colors.get(group_name.lower(), "#8b949e")
            parts.append(
                f'<div class="test-group">'
                f'<div class="test-group-title" style="color:{color};">'
                f'{_esc(group_name)}</div>'
            )
            for item in items:
                name = item.get("name", item.get("technique", str(item)))
                reason = item.get("reason", "")
                parts.append(
                    f'<span class="test-tag" title="{_esc(reason)}"'
                    f' style="border-left:3px solid {color};">{_esc(name)}</span>'
                )
            parts.append("</div>")
        parts.append("</div>")

    # --- Parameter Classification Summary ---
    if param_class and isinstance(param_class, dict):
        parts.append('<h2 id="params">Parameter Classification</h2>')
        parts.append('<div class="card">')

        pc_stats = param_class.get("stats", param_class)
        if isinstance(pc_stats, dict):
            # Overview stats
            total_params = pc_stats.get(
                "total_params",
                pc_stats.get("total_unique_params",
                             pc_stats.get("unique_params_matched", 0)),
            )

            # Vuln type counts with visual bars
            vuln_types = [
                ("SQLi", pc_stats.get("sqli_count", pc_stats.get("sqli_candidates", 0)), "#da3633"),
                ("XSS", pc_stats.get("xss_count", pc_stats.get("xss_candidates", 0)), "#d29922"),
                ("SSRF", pc_stats.get("ssrf_count", pc_stats.get("ssrf_candidates", 0)), "#bc8cff"),
                ("LFI", pc_stats.get("lfi_count", pc_stats.get("lfi_candidates", 0)), "#f85149"),
                ("IDOR", pc_stats.get("idor_count", pc_stats.get("idor_candidates", 0)), "#e3b341"),
                ("Redirect", pc_stats.get("redirect_count", pc_stats.get("redirect_candidates", 0)), "#58a6ff"),
                ("RCE", pc_stats.get("rce_count", pc_stats.get("rce_candidates", 0)), "#da3633"),
                ("SSTI", pc_stats.get("ssti_count", pc_stats.get("ssti_candidates", 0)), "#f85149"),
            ]
            # Filter to non-zero
            vuln_types_nonzero = [(l, c, col) for l, c, col in vuln_types if c > 0]
            max_count = max((c for _, c, _ in vuln_types_nonzero), default=1)

            parts.append(
                f'<p style="font-size:14px;margin-bottom:12px;">'
                f'<strong>{total_params}</strong> unique parameters classified across '
                f'<strong>{pc_stats.get("total_urls_with_params", 0)}</strong> URL(s)</p>'
            )

            if vuln_types_nonzero:
                for label, count, color in vuln_types_nonzero:
                    pct = min(100, int(count / max_count * 100))
                    parts.append(
                        f'<div class="param-bar">'
                        f'<span class="param-bar-label">{_esc(label)}</span>'
                        f'<div class="bar" style="flex:1;">'
                        f'<div class="bar-fill" style="width:{pct}%;background:{color};"></div>'
                        f'</div>'
                        f'<span class="param-bar-count" style="color:{color};">{count}</span>'
                        f'</div>'
                    )

            # Probe results if available
            probe_xss = pc_stats.get("probe_xss_found", 0)
            probe_sqli = pc_stats.get("probe_sqli_found", 0)
            probe_lfi = pc_stats.get("probe_lfi_found", 0)
            if probe_xss or probe_sqli or probe_lfi:
                parts.append(
                    '<div style="margin-top:12px;padding-top:12px;border-top:1px solid #21262d;">'
                    '<p style="font-size:13px;color:#f85149;font-weight:600;">Probe-Confirmed:</p>'
                )
                if probe_sqli:
                    parts.append(f'<p style="font-size:13px;">{_severity_badge("CRITICAL")} SQLi: {probe_sqli}</p>')
                if probe_xss:
                    parts.append(f'<p style="font-size:13px;">{_severity_badge("HIGH")} XSS: {probe_xss}</p>')
                if probe_lfi:
                    parts.append(f'<p style="font-size:13px;">{_severity_badge("CRITICAL")} LFI: {probe_lfi}</p>')
                parts.append("</div>")

        # Probe-confirmed candidates detail
        probe_confirmed = param_class.get("probe_confirmed", [])
        if probe_confirmed:
            parts.append(
                f"<details><summary>Probe-Confirmed Parameters ({len(probe_confirmed)})</summary>"
            )
            parts.append('<div class="detail-content"><table>')
            parts.append(
                "<thead><tr><th>Vuln Type</th><th>Parameter</th>"
                "<th>URL</th><th>Priority</th></tr></thead><tbody>"
            )
            for pc_item in probe_confirmed[:20]:
                parts.append(
                    f"<tr><td>{_severity_badge(pc_item.get('vuln_type', 'info').upper())}</td>"
                    f'<td class="mono">{_esc(pc_item.get("param", ""))}</td>'
                    f'<td class="url-text">{_esc(_truncate(pc_item.get("url", ""), 70))}</td>'
                    f'<td style="color:#f85149;font-size:12px;">{_esc(pc_item.get("priority", ""))}</td></tr>'
                )
            parts.append("</tbody></table></div></details>")

        # Top candidates per vuln type
        top_by_type = param_class.get("top_candidates_by_type", {})
        if top_by_type:
            for vuln_type, candidates in sorted(top_by_type.items()):
                if candidates and isinstance(candidates, list):
                    label = vuln_type.upper()
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
        non_zero = {k: v for k, v in flags_summary.items() if isinstance(v, int) and v > 0}
        if non_zero:
            parts.append("<h2>Flags Distribution</h2>")
            parts.append('<div class="card"><table>')
            parts.append(
                "<thead><tr><th>Flag Type</th><th>Count</th><th>Distribution</th></tr></thead><tbody>"
            )
            max_flag = max(non_zero.values()) or 1
            for flag_type, count in sorted(non_zero.items(), key=lambda x: -x[1]):
                pct = min(100, int(count / max_flag * 100))
                # Color based on flag type
                flag_color = "#da3633" if flag_type in ("NO_WAF", "DEBUG_MODE") else (
                    "#d29922" if flag_type in ("OLD_TECH", "CORS_MISCONFIGURED") else "#58a6ff"
                )
                parts.append(
                    f"<tr><td>{_esc(flag_type)}</td><td>{count}</td>"
                    f'<td><div class="bar" style="width:200px;">'
                    f'<div class="bar-fill" style="width:{pct}%;background:{flag_color};"></div>'
                    f"</div></td></tr>"
                )
            parts.append("</tbody></table></div>")

    # --- Technology Distribution ---
    if tech_dist and isinstance(tech_dist, dict):
        parts.append("<h2>Technology Distribution</h2>")
        parts.append('<div class="card"><table>')
        parts.append(
            "<thead><tr><th>Technology</th><th>Count</th><th>Distribution</th></tr></thead><tbody>"
        )
        sorted_techs = sorted(
            tech_dist.items(),
            key=lambda x: -(x[1] if isinstance(x[1], int) else 0),
        )
        max_tech = max((v for _, v in sorted_techs if isinstance(v, int)), default=1) or 1
        for tech, count in sorted_techs[:20]:
            if not isinstance(count, int):
                continue
            pct = min(100, int(count / max_tech * 100))
            parts.append(
                f"<tr><td class=\"mono\">{_esc(tech)}</td><td>{count}</td>"
                f'<td><div class="bar" style="width:200px;">'
                f'<div class="bar-fill" style="width:{pct}%;background:#58a6ff;"></div>'
                f"</div></td></tr>"
            )
        parts.append("</tbody></table></div>")

    parts.append("</div>")  # container

    return _html_wrap(f"Attack Surface - {target}", "\n".join(parts))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flatten_sensitive_paths(
    sensitive_paths: dict[str, list[dict[str, Any]]] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flatten sensitive_paths dict into a flat list with host_url attached."""
    sp_flat: list[dict[str, Any]] = []
    if isinstance(sensitive_paths, dict):
        for host_url, findings in sensitive_paths.items():
            for f in findings:
                sp_flat.append({**f, "host_url": host_url})
    elif isinstance(sensitive_paths, list):
        sp_flat = list(sensitive_paths)
    return sp_flat


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
