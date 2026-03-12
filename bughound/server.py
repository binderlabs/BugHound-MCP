"""Single BugHound MCP server. All tools registered here."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging — ALL output must go to stderr. stdout is the JSON-RPC stdio pipe.
# Writing anything to stdout (including structlog's default ConsoleRenderer)
# corrupts the MCP transport and freezes the AI client (gemini-cli, etc.).
# ---------------------------------------------------------------------------
logging.basicConfig(format="%(message)s", level=logging.WARNING, stream=sys.stderr)
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)

from bughound.core import target_classifier, tool_runner, workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import WorkspaceState
from bughound.stages import analyze as stage_analyze
from bughound.stages import discover as stage_discover
from bughound.stages import enumerate as stage_enumerate
from bughound.stages import test as stage_test

# Shared job manager instance (lives for server lifetime)
_job_manager = JobManager()

mcp = FastMCP("bughound")


# ---------------------------------------------------------------------------
# Stage 0: Initialize + Workspace management
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_init",
    description=(
        "Initialize a new BugHound workspace for a target. Stage 0: classifies "
        "the target (broad domain, single host, endpoint, or URL list), creates "
        "a workspace, and returns which pipeline stages to run. Always call this "
        "first before any other bughound tool. Sync.\n\n"
        "depth parameter:\n"
        "- 'light' (default): fast passive recon only, good for quick assessments\n"
        "- 'deep': thorough recon with active tools, background jobs, brute-force — "
        "use when user says 'full recon', 'deep scan', 'thorough', or 'comprehensive'\n\n"
        "If the user just says 'scan X' or 'check X', use light. "
        "If they say 'full recon on X' or 'deep scan X', use deep."
    ),
)
async def bughound_init(target: str, depth: str = "light") -> str:
    """Classify target and create workspace."""
    try:
        classification = target_classifier.classify(target, depth)
    except ValueError as exc:
        return f"Error: {exc}"

    meta = await workspace.create_workspace(target, depth)

    await workspace.update_metadata(
        meta.workspace_id,
        target_type=classification.target_type,
        classification=classification.model_dump(mode="json"),
    )
    await workspace.add_stage_history(meta.workspace_id, 0, "completed")

    # Format stage list
    stage_names = {
        0: "Initialize", 1: "Enumerate", 2: "Discover",
        3: "Analyze", 4: "Test", 5: "Validate", 6: "Report",
    }
    stages_str = ", ".join(
        f"Stage {s} ({stage_names.get(s, '?')})"
        for s in classification.stages_to_run
    )

    skips = ""
    if classification.skip_reasons:
        skips = "\n**Skipped stages:**\n"
        for stage, reason in classification.skip_reasons.items():
            skips += f"  - Stage {stage}: {reason}\n"

    next_step = _suggest_next(classification.stages_to_run)

    ws_path = workspace.workspace_dir(meta.workspace_id)

    return (
        f"## Workspace Created Successfully\n\n"
        f"**Workspace ID:** `{meta.workspace_id}`\n"
        f"**Target:** {target}\n"
        f"**Target Type:** {classification.target_type.value}\n"
        f"**Depth:** {depth}\n"
        f"**Path:** `{ws_path}`\n"
        f"**Normalized Targets:** {', '.join(classification.normalized_targets)}\n\n"
        f"**Pipeline stages to run:** {stages_str}\n"
        f"{skips}\n"
        f"**Next step:** {next_step}\n"
    )


@mcp.tool(
    name="bughound_workspace_list",
    description=(
        "List all BugHound workspaces. Optionally filter by state "
        "(INITIALIZED, ENUMERATING, DISCOVERING, ANALYZING, TESTING, "
        "VALIDATING, COMPLETED, ARCHIVED). Sync."
    ),
)
async def bughound_workspace_list(state: str = "") -> str:
    """List workspaces with optional state filter."""
    state_filter = None
    if state:
        try:
            state_filter = WorkspaceState(state.upper())
        except ValueError:
            valid = ", ".join(s.value for s in WorkspaceState)
            return f"Error: Invalid state '{state}'. Valid states: {valid}"

    workspaces = await workspace.list_workspaces(state_filter)

    if not workspaces:
        return "No workspaces found. Use `bughound_init` to create one."

    lines = [f"## BugHound Workspaces ({len(workspaces)})\n"]
    for ws in workspaces:
        stats = ws.stats
        lines.append(
            f"- **`{ws.workspace_id}`** | {ws.target} | "
            f"{ws.state.value} | {ws.depth} | "
            f"subs: {stats.subdomains_found}, hosts: {stats.live_hosts}, "
            f"urls: {stats.urls_discovered}"
        )

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_workspace_get",
    description=(
        "Get full details of a BugHound workspace including metadata, "
        "config, current stage, and stats. Requires workspace_id from "
        "bughound_init or bughound_workspace_list. Sync."
    ),
)
async def bughound_workspace_get(workspace_id: str) -> str:
    """Get workspace metadata and config."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return f"Error: Workspace '{workspace_id}' not found. Run `bughound_init` first."

    cfg = await workspace.get_config(workspace_id)
    s = meta.stats

    stage_history = ""
    if meta.stage_history:
        stage_history = "\n**Stage History:**\n"
        for entry in meta.stage_history:
            stage_history += f"  - Stage {entry.stage}: {entry.status}\n"

    scope_str = ""
    if cfg:
        scope_str = (
            f"\n**Scope:**\n"
            f"  - Include: {', '.join(cfg.scope.include) or 'all'}\n"
            f"  - Exclude: {', '.join(cfg.scope.exclude) or 'none'}\n"
        )

    return (
        f"## Workspace: {meta.workspace_id}\n\n"
        f"**Target:** {meta.target}\n"
        f"**Target Type:** {meta.target_type.value if meta.target_type else 'not classified'}\n"
        f"**State:** {meta.state.value}\n"
        f"**Depth:** {meta.depth}\n"
        f"**Current Stage:** {meta.current_stage}\n"
        f"**Created:** {meta.created_at}\n"
        f"**Updated:** {meta.updated_at}\n\n"
        f"**Stats:**\n"
        f"  - Subdomains found: {s.subdomains_found}\n"
        f"  - Live hosts: {s.live_hosts}\n"
        f"  - URLs discovered: {s.urls_discovered}\n"
        f"  - Findings total: {s.findings_total}\n"
        f"  - Findings confirmed: {s.findings_confirmed}\n"
        f"{stage_history}"
        f"{scope_str}"
    )


@mcp.tool(
    name="bughound_workspace_delete",
    description=(
        "Delete a BugHound workspace and all its data. This is irreversible. "
        "Requires workspace_id. Sync."
    ),
)
async def bughound_workspace_delete(workspace_id: str) -> str:
    """Delete a workspace."""
    if not workspace.workspace_exists(workspace_id):
        return f"Error: Workspace '{workspace_id}' not found."

    deleted = await workspace.delete_workspace(workspace_id)
    if deleted:
        return f"Workspace `{workspace_id}` deleted successfully."
    return f"Error: Failed to delete workspace '{workspace_id}'."


@mcp.tool(
    name="bughound_workspace_results",
    description=(
        "View workspace results dashboard or drill into specific data categories. "
        "Without a category, returns an overview of all collected data with counts. "
        "With a category, returns the actual data. Categories: subdomains, dns, "
        "hosts, flags, technologies, urls, parameters, secrets, js_secrets_confirmed, "
        "hidden_endpoints, api_endpoints, sensitive_paths, cors, takeover, "
        "takeover_confirmed, vulnerabilities, waf, attack_surface. "
        "Use anytime to check recon progress or review findings. "
        "The attack_surface category returns the saved Stage 3 analysis "
        "(scored targets, chains, wins) without recomputing."
    ),
)
async def bughound_workspace_results(workspace_id: str, category: str = "") -> str:
    """View workspace data dashboard or drill into a specific category."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return f"Error: Workspace '{workspace_id}' not found."

    if not category:
        return await _results_dashboard(workspace_id, meta)
    return await _results_category(workspace_id, meta, category.strip().lower())


async def _results_dashboard(workspace_id: str, meta: Any) -> str:
    """Build a dashboard overview of all workspace data."""
    # Category definitions: (label, file_path)
    categories = [
        ("subdomains", "subdomains/all.txt"),
        ("dns_records", "dns/records.json"),
        ("live_hosts", "hosts/live_hosts.json"),
        ("technologies", "hosts/technologies.json"),
        ("waf", "hosts/waf.json"),
        ("flags", "hosts/flags.json"),
        ("urls", "urls/crawled.json"),
        ("parameters", "urls/parameters.json"),
        ("js_secrets", "secrets/js_secrets.json"),
        ("js_secrets_confirmed", "secrets/js_secrets_confirmed.json"),
        ("hidden_endpoints", "endpoints/hidden_endpoints.json"),
        ("api_endpoints", "endpoints/api_endpoints.json"),
        ("sensitive_paths", "hosts/sensitive_paths.json"),
        ("cors_results", "hosts/cors_results.json"),
        ("takeover_candidates", "cloud/takeover_candidates.json"),
        ("takeover_confirmed", "cloud/takeover_confirmed.json"),
        ("vulnerabilities", "vulnerabilities/scan_results.json"),
        ("attack_surface", "analysis/attack_surface.json"),
    ]

    lines = [
        f"## Workspace Dashboard: `{workspace_id}`\n",
        f"**Target:** {meta.target}",
        f"**State:** {meta.state.value}",
        f"**Current Stage:** {meta.current_stage}\n",
        "**Data Collected:**",
    ]

    for label, file_path in categories:
        data = await workspace.read_data(workspace_id, file_path)
        if data is None:
            lines.append(f"  - {label}: —")
        elif isinstance(data, list):
            lines.append(f"  - **{label}**: {len(data)} entries  (`{file_path}`)")
        elif isinstance(data, dict):
            count = data.get("count", len(data.get("data", [])))
            lines.append(f"  - **{label}**: {count} entries  (`{file_path}`)")

    # Stages
    completed = [e.stage for e in meta.stage_history if e.status == "completed"]
    all_stages = meta.classification.get("stages_to_run", []) if meta.classification else list(range(7))
    pending = [s for s in all_stages if s not in completed]

    stage_names = {
        0: "Initialize", 1: "Enumerate", 2: "Discover",
        3: "Analyze", 4: "Test", 5: "Validate", 6: "Report",
    }
    completed_str = ", ".join(f"{s} ({stage_names.get(s, '?')})" for s in completed)
    pending_str = ", ".join(f"{s} ({stage_names.get(s, '?')})" for s in pending)

    lines.append(f"\n**Stages completed:** {completed_str or 'none'}")
    lines.append(f"**Stages pending:** {pending_str or 'none'}")

    # Available drill-down categories
    lines.append(
        "\n**Drill down:** call with category = subdomains | dns | hosts | flags | "
        "technologies | urls | parameters | secrets | js_secrets_confirmed | "
        "hidden_endpoints | api_endpoints | sensitive_paths | cors | takeover | "
        "takeover_confirmed | vulnerabilities | waf | attack_surface"
    )

    return "\n".join(lines) + "\n"


# Category -> (file_path, truncate_limit or 0 for no truncation)
_CATEGORY_MAP: dict[str, tuple[str, int]] = {
    "subdomains": ("subdomains/all.txt", 100),
    "dns": ("dns/records.json", 0),
    "dns_records": ("dns/records.json", 0),
    "hosts": ("hosts/live_hosts.json", 0),
    "live_hosts": ("hosts/live_hosts.json", 0),
    "flags": ("hosts/flags.json", 0),
    "technologies": ("hosts/technologies.json", 0),
    "urls": ("urls/crawled.json", 100),
    "parameters": ("urls/parameters.json", 0),
    "secrets": ("secrets/js_secrets.json", 0),
    "js_secrets": ("secrets/js_secrets.json", 0),
    "js_secrets_confirmed": ("secrets/js_secrets_confirmed.json", 0),
    "hidden_endpoints": ("endpoints/hidden_endpoints.json", 0),
    "api_endpoints": ("endpoints/api_endpoints.json", 0),
    "sensitive_paths": ("hosts/sensitive_paths.json", 0),
    "cors": ("hosts/cors_results.json", 0),
    "cors_results": ("hosts/cors_results.json", 0),
    "takeover": ("cloud/takeover_candidates.json", 0),
    "takeover_candidates": ("cloud/takeover_candidates.json", 0),
    "takeover_confirmed": ("cloud/takeover_confirmed.json", 0),
    "vulnerabilities": ("vulnerabilities/scan_results.json", 0),
    "waf": ("hosts/waf.json", 0),
    "attack_surface": ("analysis/attack_surface.json", 0),
}


async def _results_category(workspace_id: str, meta: Any, category: str) -> str:
    """Return actual data for a specific category, human-formatted."""
    if category not in _CATEGORY_MAP:
        valid = ", ".join(sorted(_CATEGORY_MAP.keys()))
        return f"Error: Unknown category '{category}'. Valid categories: {valid}"

    file_path, truncate_limit = _CATEGORY_MAP[category]
    data = await workspace.read_data(workspace_id, file_path)

    if data is None:
        return (
            f"## {category} — No Data\n\n"
            f"File `{file_path}` does not exist yet. "
            f"This data is collected during a later pipeline stage."
        )

    # Special handling for attack_surface (full analysis result, not a list)
    if category == "attack_surface":
        if isinstance(data, dict) and "data" in data:
            # DataWrapper envelope — unwrap
            return _format_attack_surface(data["data"])
        return _format_attack_surface(data)

    # Extract items from DataWrapper envelope or plain list
    if isinstance(data, dict):
        items = data.get("data", [])
        total = data.get("count", len(items))
    elif isinstance(data, list):
        items = data
        total = len(data)
    else:
        items, total = [], 0

    lines = [f"## {category} — `{workspace_id}`\n"]
    lines.append(f"**Total:** {total}\n")

    # Use per-category formatter if available, else generic
    formatter = _CATEGORY_FORMATTERS.get(category)
    if formatter:
        show = items[:truncate_limit] if truncate_limit else items
        lines.extend(formatter(show))
        if truncate_limit and total > truncate_limit:
            lines.append(f"\n... and {total - truncate_limit} more (showing first {truncate_limit})")
    else:
        lines.append(f"```json\n{json.dumps(items[:20], indent=2)}\n```")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Per-category formatters — return list of markdown lines
# ---------------------------------------------------------------------------


def _fmt_subdomains(items: list) -> list[str]:
    lines: list[str] = []
    for item in items:
        lines.append(f"  - {item}")
    return lines


def _fmt_hosts(items: list) -> list[str]:
    lines: list[str] = []
    for h in items:
        status = h.get("status_code", "?")
        title = h.get("title", "—")[:60]
        server = h.get("web_server", "—")
        techs = ", ".join(h.get("technologies", [])[:5])
        cdn = h.get("cdn") or ""
        flags = h.get("flags", [])

        lines.append(f"### {h.get('host', h.get('url', '?'))}")
        lines.append(f"  - **URL:** {h.get('url', '?')}  |  **Status:** {status}")
        lines.append(f"  - **Title:** {title}")
        lines.append(f"  - **Server:** {server}  |  **Tech:** {techs or '—'}")
        if cdn:
            lines.append(f"  - **CDN:** {cdn}")
        if flags:
            lines.append(f"  - **Flags:** {', '.join(flags)}")
        lines.append("")
    return lines


def _fmt_flags(items: list) -> list[str]:
    lines: list[str] = []
    for h in items:
        host = h.get("host", h.get("url", "?"))
        flags = h.get("flags", [])
        if flags:
            lines.append(f"**{host}** ({len(flags)} flags)")
            for f in flags:
                lines.append(f"  - {f}")
            lines.append("")
    return lines


def _fmt_waf(items: list) -> list[str]:
    lines: list[str] = []
    for w in items:
        url = w.get("url", "?")
        detected = w.get("detected", False)
        waf_name = w.get("waf", "None")
        if detected:
            lines.append(f"  - **{url}**: {waf_name} ({w.get('manufacturer', '?')})")
        else:
            lines.append(f"  - {url}: No WAF detected")
    return lines


def _fmt_technologies(items: list) -> list[str]:
    lines: list[str] = []
    for t in items:
        tech = t.get("technology", "?")
        count = t.get("host_count", 0)
        lines.append(f"  - **{tech}**: {count} host{'s' if count != 1 else ''}")
    return lines


def _fmt_urls(items: list) -> list[str]:
    lines: list[str] = []
    # Group by source
    by_source: dict[str, int] = {}
    for u in items:
        src = u.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

    if by_source:
        lines.append("**By source:**")
        for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
            lines.append(f"  - {src}: {cnt}")
        lines.append("")

    lines.append("**URLs:**")
    for u in items:
        lines.append(f"  - {u.get('url', '?')}  ({u.get('source', '?')})")
    return lines


def _fmt_parameters(items: list) -> list[str]:
    lines: list[str] = []
    for p in items:
        path = p.get("path", "?")
        params = p.get("params", [])
        param_names = [pr.get("name", "?") for pr in params]
        high_freq = [pr.get("name", "?") for pr in params if pr.get("high_frequency")]
        lines.append(f"  - **{path}**: {', '.join(param_names)}")
        if high_freq:
            lines.append(f"    High frequency: {', '.join(high_freq)}")
    return lines


def _fmt_secrets(items: list) -> list[str]:
    lines: list[str] = []
    for s in items:
        conf = s.get("confidence", "?")
        stype = s.get("type", "?")
        value = s.get("value", "?")
        src = s.get("source_file", "?").split("/")[-1]
        lines.append(f"  - **[{conf}]** {stype}: `{value}`")
        lines.append(f"    Source: {src}")
    return lines


def _fmt_hidden_endpoints(items: list) -> list[str]:
    lines: list[str] = []
    for ep in items:
        method = ep.get("method", "GET")
        path = ep.get("path", "?")
        etype = ep.get("endpoint_type", "?")
        src = ep.get("source_file", "?").split("/")[-1]
        lines.append(f"  - **{method}** `{path}`  [{etype}]  (from {src})")
    return lines


def _fmt_sensitive_paths(items: list) -> list[str]:
    lines: list[str] = []
    # Group by host
    by_host: dict[str, list] = {}
    for sp in items:
        host = sp.get("host_url", "?")
        by_host.setdefault(host, []).append(sp)

    for host, paths in by_host.items():
        lines.append(f"**{host}** ({len(paths)} paths)")
        for sp in paths:
            cat = sp.get("category", "?")
            path = sp.get("path", "?")
            status = sp.get("status_code", "?")
            lines.append(f"  - [{cat}] `{path}` (status {status})")
        lines.append("")
    return lines


def _fmt_cors(items: list) -> list[str]:
    lines: list[str] = []
    for c in items:
        url = c.get("url", "?")
        severity = c.get("severity", "?")
        origin = c.get("origin_tested", "?")
        acao = c.get("acao", "?")
        creds = c.get("credentials_allowed", False)
        lines.append(
            f"  - **[{severity}]** {url}\n"
            f"    Origin: {origin} | ACAO: {acao} | Credentials: {'Yes' if creds else 'No'}"
        )
    return lines


def _fmt_takeover(items: list) -> list[str]:
    lines: list[str] = []
    for t in items:
        sub = t.get("subdomain", t.get("host", "?"))
        cname = t.get("cname", "?")
        service = t.get("service", t.get("provider", "?"))
        lines.append(f"  - **{sub}** → `{cname}` ({service})")
    return lines


def _fmt_vulnerabilities(items: list) -> list[str]:
    lines: list[str] = []
    for v in items:
        severity = v.get("severity", "?").upper()
        name = v.get("template_id", v.get("vulnerability_class", "?"))
        host = v.get("host", "?")
        endpoint = v.get("endpoint", "")
        tool = v.get("tool", "?")
        lines.append(f"  - **[{severity}]** {name}")
        lines.append(f"    Host: {host}{endpoint}  |  Tool: {tool}")
    return lines


def _fmt_api_endpoints(items: list) -> list[str]:
    lines: list[str] = []
    for ep in items:
        method = ep.get("method", "GET")
        path = ep.get("path", ep.get("endpoint", "?"))
        source = ep.get("source", ep.get("from", ""))
        host = ep.get("host", "")
        prefix = f"{host}" if host else ""
        lines.append(f"  - **{method}** `{path}`  {f'({source})' if source else ''} {prefix}")
    return lines


def _fmt_dns(items: list) -> list[str]:
    lines: list[str] = []
    for rec in items:
        domain = rec.get("domain", "?")
        a_records = rec.get("A", [])
        cname = rec.get("CNAME", [])
        resolved = rec.get("resolved", False)
        status = "resolved" if resolved else "unresolved"
        ips = ", ".join(a_records[:3]) if a_records else ""
        cnames = ", ".join(cname[:2]) if cname else ""
        detail = ips or cnames or status
        lines.append(f"  - **{domain}** → {detail}")
    return lines


_CATEGORY_FORMATTERS: dict[str, Any] = {
    "subdomains": _fmt_subdomains,
    "hosts": _fmt_hosts,
    "live_hosts": _fmt_hosts,
    "flags": _fmt_flags,
    "waf": _fmt_waf,
    "technologies": _fmt_technologies,
    "urls": _fmt_urls,
    "parameters": _fmt_parameters,
    "secrets": _fmt_secrets,
    "js_secrets": _fmt_secrets,
    "js_secrets_confirmed": _fmt_secrets,
    "hidden_endpoints": _fmt_hidden_endpoints,
    "api_endpoints": _fmt_api_endpoints,
    "sensitive_paths": _fmt_sensitive_paths,
    "cors": _fmt_cors,
    "cors_results": _fmt_cors,
    "takeover": _fmt_takeover,
    "takeover_candidates": _fmt_takeover,
    "takeover_confirmed": _fmt_takeover,
    "vulnerabilities": _fmt_vulnerabilities,
    "dns": _fmt_dns,
    "dns_records": _fmt_dns,
}


# ---------------------------------------------------------------------------
# Stage 1: Enumerate
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_enumerate",
    description=(
        "Discover subdomains for a broad domain target. Stage 1: runs passive "
        "subdomain sources (subfinder, assetfinder, findomain, crt.sh) in parallel, "
        "resolves DNS, detects wildcards, and analyzes naming patterns. Requires "
        "bughound_init first. Auto-skips for non-domain targets. Sync, ~30-60s."
    ),
)
async def bughound_enumerate(workspace_id: str) -> str:
    """Run light subdomain enumeration."""
    result = await stage_enumerate.enumerate_light(workspace_id)
    return _format_enumerate(result)


@mcp.tool(
    name="bughound_enumerate_deep",
    description=(
        "Deep subdomain enumeration as a background job. Stage 1 deep mode: "
        "runs all passive sources plus active bruteforce and permutation fuzzing "
        "if tools are available. Requires bughound_init first. Returns job_id — "
        "poll with bughound_job_status. Async, 5-15 minutes."
    ),
)
async def bughound_enumerate_deep(workspace_id: str) -> str:
    """Start deep enumeration as a background job."""
    result = await stage_enumerate.enumerate_deep(workspace_id, _job_manager)
    return _format_job_started(result)


# ---------------------------------------------------------------------------
# Stage 2: Discover
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_discover",
    description=(
        "Full attack surface discovery: probe live hosts, fingerprint technologies, "
        "detect WAF/CDN, crawl URLs, analyze JavaScript for secrets and hidden "
        "endpoints, check 70+ sensitive paths, detect subdomain takeovers, test "
        "CORS misconfigurations, harvest parameters. Returns intelligence flags per "
        "host for AI reasoning. Sync for single hosts, async for broad domains."
    ),
)
async def bughound_discover(workspace_id: str) -> str:
    """Run Stage 2 discovery."""
    result = await stage_discover.discover(workspace_id, _job_manager)
    return _format_discover(result)


# ---------------------------------------------------------------------------
# Stage 3: Analyze
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_get_attack_surface",
    description=(
        "Get comprehensive attack surface analysis with exploitability-scored targets, "
        "attack chain detection, immediate reportable wins, technology-specific playbooks, "
        "and cross-stage correlations. This is the intelligence brain of BugHound. "
        "Use after discovery to plan testing or generate reports for immediate wins. "
        "Stage 3, read-only, sync."
    ),
)
async def bughound_get_attack_surface(workspace_id: str) -> str:
    """Analyze full attack surface from Stage 2 data."""
    result = await stage_analyze.get_attack_surface(workspace_id)
    return _format_attack_surface(result)


@mcp.tool(
    name="bughound_submit_scan_plan",
    description=(
        "Submit testing strategy after reviewing attack surface. Validates targets "
        "against scope and checks tool availability. Required before "
        "bughound_execute_tests. The scan_plan parameter is a JSON string with "
        "'targets' array and optional 'global_settings'. Stage 3, sync."
    ),
)
async def bughound_submit_scan_plan(workspace_id: str, scan_plan: str) -> str:
    """Validate and store scan plan."""
    try:
        parsed = json.loads(scan_plan)
    except (json.JSONDecodeError, TypeError) as exc:
        return f"Error: Invalid JSON in scan_plan: {exc}"
    result = await stage_analyze.submit_scan_plan(workspace_id, parsed)
    return _format_scan_plan_result(result)


@mcp.tool(
    name="bughound_enrich_target",
    description=(
        "Get complete intelligence dossier on a single host. All fingerprint data, "
        "flags, URLs, parameters, secrets, sensitive paths, CORS results, attack "
        "chains. Use when drilling into a high-interest target from the attack "
        "surface analysis. Stage 3, sync."
    ),
)
async def bughound_enrich_target(workspace_id: str, host: str) -> str:
    """Get all workspace intelligence for one host."""
    result = await stage_analyze.enrich_target(workspace_id, host)
    return _format_enrich_target(result)


@mcp.tool(
    name="bughound_scope_check",
    description=(
        "Verify if a target is within workspace scope before testing. Returns "
        "in_scope boolean. Use to confirm targets before manual testing. Sync."
    ),
)
async def bughound_scope_check(workspace_id: str, target: str) -> str:
    """Check scope for a target."""
    if not workspace.workspace_exists(workspace_id):
        return f"Error: Workspace '{workspace_id}' not found."
    in_scope = await workspace.is_in_scope(workspace_id, target)
    cfg = await workspace.get_config(workspace_id)
    scope_rules = ""
    if cfg:
        scope_rules = (
            f"\n**Scope rules:**\n"
            f"  - Include: {', '.join(cfg.scope.include) or 'all'}\n"
            f"  - Exclude: {', '.join(cfg.scope.exclude) or 'none'}"
        )
    status = "IN SCOPE" if in_scope else "OUT OF SCOPE"
    return f"## Scope Check\n\n**Target:** {target}\n**Result:** {status}{scope_rules}\n"


@mcp.tool(
    name="bughound_check_tool_coverage",
    description=(
        "Check which security tools are installed on this system. Returns available "
        "and missing tools with install commands. Use to understand testing "
        "capabilities before submitting a scan plan. Sync."
    ),
)
async def bughound_check_tool_coverage() -> str:
    """Check installed security tools."""
    tools_info = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
        "sqlmap": "pip install sqlmap",
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
        "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "gospider": "go install github.com/jaeles-project/gospider@latest",
        "wafw00f": "pip install wafw00f",
        "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "puredns": "go install github.com/d3mondev/puredns/v2@latest",
        "gotator": "go install github.com/Josue87/gotator@latest",
        "subjack": "go install github.com/haccer/subjack@latest",
        "arjun": "pip install arjun",
        "interactsh-client": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "trufflehog": "pip install trufflehog",
        "findomain": "apt install findomain",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    }

    available: list[str] = []
    missing: list[tuple[str, str]] = []
    for tool_name, install_cmd in sorted(tools_info.items()):
        if tool_runner.is_available(tool_name):
            available.append(tool_name)
        else:
            missing.append((tool_name, install_cmd))

    lines = [
        "## Tool Coverage\n",
        f"**Available:** {len(available)}/{len(tools_info)}\n",
    ]

    if available:
        lines.append("**Installed:**")
        for t in available:
            lines.append(f"  - {t}")
        lines.append("")

    if missing:
        lines.append("**Missing (with install commands):**")
        for t, cmd in missing:
            lines.append(f"  - **{t}**: `{cmd}`")
        lines.append("")

    # Coverage by category
    recon_tools = {"subfinder", "assetfinder", "findomain", "amass", "httpx", "wafw00f"}
    discovery_tools = {"gau", "waybackurls", "katana", "gospider"}
    scanning_tools = {"nuclei", "ffuf", "sqlmap", "dalfox"}
    recon_avail = len(recon_tools & set(available))
    disc_avail = len(discovery_tools & set(available))
    scan_avail = len(scanning_tools & set(available))
    lines.append("**Coverage by category:**")
    lines.append(f"  - Recon: {recon_avail}/{len(recon_tools)}")
    lines.append(f"  - Discovery: {disc_avail}/{len(discovery_tools)}")
    lines.append(f"  - Scanning: {scan_avail}/{len(scanning_tools)}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Stage 4: Test
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_execute_tests",
    description=(
        "Execute vulnerability scan plan created in Stage 3. Runs nuclei with "
        "targeted template tags per host based on the scan plan. Sync for single "
        "targets (<=2 hosts, <=6 test classes), async for larger plans. "
        "Requires bughound_submit_scan_plan first. Stage 4."
    ),
)
async def bughound_execute_tests(workspace_id: str) -> str:
    """Run the scan plan."""
    result = await stage_test.execute_tests(workspace_id, _job_manager)
    if result.get("status") == "job_started":
        return _format_job_started(result)
    return _format_test_results(result)


@mcp.tool(
    name="bughound_test_single",
    description=(
        "Surgical vulnerability test on a specific endpoint. Use for targeted "
        "follow-up when the AI identifies an interesting target from analysis. "
        "Always synchronous. Scope-checked. Stage 4."
    ),
)
async def bughound_test_single(
    workspace_id: str,
    target_url: str,
    tool: str = "nuclei",
    tags: str = "",
    severity: str = "",
) -> str:
    """Test one specific endpoint."""
    result = await stage_test.test_single(
        workspace_id, target_url, tool,
        tags=tags or None,
        severity=severity or None,
    )
    return _format_test_results(result)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@mcp.tool(
    name="bughound_job_status",
    description=(
        "Check the status of an async background job. Returns progress percentage, "
        "current module, status, and result summary if completed. Sync."
    ),
)
async def bughound_job_status(job_id: str) -> str:
    """Poll job status."""
    status = await _job_manager.get_status(job_id)
    if status is None:
        return f"Error: Job '{job_id}' not found."

    lines = [
        f"## Job Status: `{job_id}`\n",
        f"**Status:** {status['status']}",
        f"**Progress:** {status['progress_pct']}%",
        f"**Message:** {status['message']}",
    ]
    if status.get("current_module"):
        lines.append(f"**Current Module:** {status['current_module']}")
    if status.get("result_summary"):
        lines.append(f"\n**Result Summary:**")
        for k, v in status["result_summary"].items():
            lines.append(f"  - {k}: {v}")
    if status.get("error"):
        lines.append(f"\n**Error:** {status['error']}")

    if status["status"] in ("RUNNING", "PENDING"):
        lines.append(f"\n**Wait at least 30 seconds before checking again.**")

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_job_results",
    description=(
        "Get results of a completed async job. Returns the workspace data "
        "written by the job. Requires a completed job_id. Sync."
    ),
)
async def bughound_job_results(job_id: str) -> str:
    """Get completed job results."""
    status = await _job_manager.get_status(job_id)
    if status is None:
        return f"Error: Job '{job_id}' not found."

    if status["status"] not in ("COMPLETED", "FAILED", "TIMED_OUT"):
        return (
            f"Job `{job_id}` is still **{status['status']}** "
            f"({status['progress_pct']}%). Poll again with `bughound_job_status`."
        )

    lines = [f"## Job Results: `{job_id}`\n"]
    lines.append(f"**Status:** {status['status']}")
    lines.append(f"**Workspace:** `{status.get('workspace_id', 'unknown')}`")

    if status.get("result_summary"):
        lines.append(f"\n**Results:**")
        for k, v in status["result_summary"].items():
            lines.append(f"  - {k}: {v}")

    if status.get("error"):
        lines.append(f"\n**Error:** {status['error']}")

    return "\n".join(lines) + "\n"


@mcp.tool(
    name="bughound_job_cancel",
    description="Cancel a running async job. Returns confirmation. Sync.",
)
async def bughound_job_cancel(job_id: str) -> str:
    """Cancel a background job."""
    try:
        cancelled = await _job_manager.cancel_job(job_id)
    except KeyError:
        return f"Error: Job '{job_id}' not found."

    if cancelled:
        return f"Job `{job_id}` cancelled successfully."
    return f"Job `{job_id}` is not running (cannot cancel)."


# ---------------------------------------------------------------------------
# Formatters — convert stage result dicts to human-friendly text
# ---------------------------------------------------------------------------


def _format_enumerate(result: dict[str, Any]) -> str:
    """Format enumerate result as readable text."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    data = result.get("data", {})

    if data.get("skipped"):
        return result["message"]

    lines = [f"## Enumeration Results\n"]
    lines.append(f"**{result['message']}**\n")

    # Tools used
    tools = data.get("tools_used", {})
    if tools:
        lines.append("**Tools Used:**")
        for tool, time in tools.items():
            lines.append(f"  - {tool}: {time}")
        lines.append("")

    # Patterns
    patterns = data.get("patterns", {})
    interesting = patterns.get("interesting_targets", [])
    if interesting:
        lines.append(f"**Interesting Targets ({len(interesting)}):**")
        for t in interesting[:15]:
            lines.append(f"  - {t}")
        if len(interesting) > 15:
            lines.append(f"  - ... and {len(interesting) - 15} more")
        lines.append("")

    prefixes = patterns.get("common_prefixes", [])
    if prefixes:
        lines.append("**Common Naming Patterns:**")
        for p in prefixes[:10]:
            lines.append(f"  - `{p['prefix']}*` ({p['count']} subdomains)")
        lines.append("")

    subnets = patterns.get("top_subnets", [])
    if subnets:
        lines.append("**IP Subnet Clusters:**")
        for s in subnets[:5]:
            lines.append(f"  - {s['subnet']}: {s['host_count']} hosts")
        lines.append("")

    # Wildcards
    wildcards = data.get("wildcard_domains", 0)
    if wildcards:
        lines.append(f"**Warning:** {wildcards} wildcard DNS domain(s) detected\n")

    # Warnings
    warnings = result.get("warnings", [])
    if warnings:
        lines.append("**Warnings:**")
        for w in warnings:
            lines.append(f"  - {w}")
        lines.append("")

    # Files
    files = result.get("files_written", [])
    if files:
        lines.append("**Files written to workspace:**")
        for f in files:
            lines.append(f"  - `{f}`")
        lines.append("")

    lines.append(f"**Next step:** {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _format_discover(result: dict[str, Any]) -> str:
    """Format discover result as readable text."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    # Job started (async)
    if result.get("status") == "job_started":
        return _format_job_started(result)

    data = result.get("data", {})
    lines = [f"## Discovery Results\n"]
    lines.append(f"**{result['message']}**\n")

    # Live hosts
    lines.append(f"**Live Hosts:** {data.get('live_hosts', 0)}")
    lines.append(f"**Hosts with Flags:** {data.get('hosts_with_flags', 0)}")

    # WAF
    waf = data.get("waf_detected", 0)
    lines.append(f"**WAF Detected:** {waf} hosts")

    # Technologies
    techs = data.get("top_technologies", [])
    if techs:
        lines.append(f"\n**Top Technologies:**")
        for tech, count in techs[:10]:
            lines.append(f"  - {tech} ({count} hosts)")

    # Intelligence flags
    flags = data.get("flag_distribution", {})
    if flags:
        lines.append(f"\n**Intelligence Flags:**")
        for flag, count in flags.items():
            lines.append(f"  - **{flag}**: {count} hosts")

    # URLs with per-tool breakdown
    urls = data.get("urls_discovered", 0)
    lines.append(f"\n**URLs Discovered:** {urls}")
    url_sources = data.get("url_sources", {})
    if url_sources:
        lines.append("**URL Sources:**")
        for tool, count in url_sources.items():
            if count == -1:
                lines.append(f"  - {tool}: not installed (skipped)")
            else:
                lines.append(f"  - {tool}: {count} URLs")
    lines.append(f"**JS Files Found:** {data.get('js_files_found', 0)}")

    # Secrets with confidence breakdown
    secrets = data.get("secrets_found", 0)
    if secrets:
        conf = data.get("secrets_by_confidence", {})
        high = conf.get("HIGH", 0)
        med = conf.get("MEDIUM", 0)
        low = conf.get("LOW", 0)
        lines.append(
            f"\n**Secrets Found:** {secrets} "
            f"(HIGH: {high}, MEDIUM: {med}, LOW: {low})"
        )
        stypes = data.get("secret_types", {})
        if stypes:
            for stype, count in stypes.items():
                lines.append(f"  - {stype}: {count}")

    # Hidden endpoints
    hidden = data.get("hidden_endpoints", 0)
    if hidden:
        lines.append(f"\n**Hidden Endpoints (in JS, not crawled):** {hidden}")

    # Parameters
    params = data.get("parameters_harvested", 0)
    if params:
        lines.append(f"**Parameters Harvested:** {params}")

    # Sensitive paths
    sp = data.get("sensitive_paths_found", 0)
    if sp:
        lines.append(f"\n**Sensitive Paths Found:** {sp}")
        sp_cats = data.get("sensitive_path_categories", {})
        if sp_cats:
            for cat, count in sp_cats.items():
                lines.append(f"  - {cat}: {count}")

    # Takeover
    takeover = data.get("takeover_candidates", 0)
    if takeover:
        lines.append(f"\n**Subdomain Takeover Candidates:** {takeover}")
    takeover_conf = data.get("takeover_confirmed", 0)
    if takeover_conf:
        lines.append(f"**Takeover Confirmed (nuclei):** {takeover_conf}")

    # CORS
    cors = data.get("cors_vulnerable", 0)
    if cors:
        lines.append(f"\n**CORS Misconfiguration:** {cors} hosts")
        cors_sev = data.get("cors_severities", {})
        if cors_sev:
            for sev, count in cors_sev.items():
                lines.append(f"  - {sev}: {count}")

    # CDN
    cdn = data.get("majority_cdn")
    if cdn:
        lines.append(f"\n**Majority CDN:** {cdn}")

    lines.append(f"\n**httpx execution time:** {data.get('httpx_time', '?')}")

    # Warnings
    warnings = result.get("warnings", [])
    if warnings:
        lines.append(f"\n**Warnings:**")
        for w in warnings:
            lines.append(f"  - {w}")

    # Files
    files = result.get("files_written", [])
    if files:
        lines.append(f"\n**Files written to workspace:**")
        for f in files:
            lines.append(f"  - `{f}`")

    lines.append(f"\n**Next step:** {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _format_job_started(result: dict[str, Any]) -> str:
    """Format async job-started response."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    return (
        f"## Background Job Started\n\n"
        f"**Job ID:** `{result.get('job_id', '?')}`\n"
        f"**Message:** {result.get('message', '')}\n"
        f"**Estimated Time:** {result.get('estimated_time', 'unknown')}\n\n"
        f"**IMPORTANT:** Do NOT poll in a loop. Continue with the next pipeline stage now. "
        f"Check this job once later with `bughound_job_status`.\n"
    )


def _format_attack_surface(result: dict[str, Any]) -> str:
    """Format attack surface analysis as readable markdown."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    stats = result.get("stats", {})
    lines = [
        f"## Attack Surface Analysis\n",
        f"**Target:** {result.get('target', '?')} ({result.get('target_type', '?')})\n",
        "### Stats Overview",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Subdomains | {stats.get('total_subdomains', 0)} |",
        f"| Live Hosts | {stats.get('live_hosts', 0)} |",
        f"| URLs | {stats.get('total_urls', 0)} |",
        f"| Parameters | {stats.get('total_parameters', 0)} |",
        f"| JS Files | {stats.get('js_files', 0)} |",
        f"| Secrets | {stats.get('secrets_found', 0)} |",
        f"| Hidden Endpoints | {stats.get('hidden_endpoints', 0)} |",
        f"| Sensitive Paths | {stats.get('sensitive_paths', 0)} |",
        f"| CORS Issues | {stats.get('cors_issues', 0)} |",
        f"| Takeover Candidates | {stats.get('takeover_candidates', 0)} |",
        "",
    ]

    # Secrets by confidence
    sbc = stats.get("secrets_by_confidence", {})
    if any(sbc.values()):
        lines.append(f"**Secrets:** HIGH: {sbc.get('HIGH', 0)}, MEDIUM: {sbc.get('MEDIUM', 0)}, LOW: {sbc.get('LOW', 0)}\n")

    # Immediate wins (most important — show first)
    wins = result.get("immediate_wins", [])
    if wins:
        lines.append(f"### Immediate Wins ({len(wins)}) — Report NOW\n")
        for w in wins:
            lines.append(f"**[{w.get('severity', '?')}] {w.get('type', '?')}** on `{w.get('host', '?')}`")
            lines.append(f"  - Path: `{w.get('path', '?')}`")
            lines.append(f"  - Bounty: {w.get('bounty_estimate', '?')}")
            lines.append(f"  - Evidence: {w.get('evidence', '?')}")
            lines.append(f"  - Reproduce: `{w.get('reproduction', '?')}`")
            lines.append(f"  - Impact: {w.get('impact', '?')}")
            lines.append("")

    # Attack chains
    chains = result.get("attack_chains", [])
    if chains:
        lines.append(f"### Attack Chains ({len(chains)})\n")
        for c in chains:
            lines.append(f"**[{c.get('severity', '?')}] {c.get('name', '?')}** (est. {c.get('bounty_estimate', '?')})")
            lines.append(f"  - Hosts: {', '.join(c.get('affected_hosts', []))}")
            ev = c.get("evidence", {})
            lines.append(f"  - Trigger: {ev.get('trigger', '?')}")
            lines.append(f"  - Supporting: {ev.get('supporting', '?')}")
            steps = c.get("exploitation_steps", [])
            if steps:
                lines.append(f"  - Steps:")
                for i, s in enumerate(steps, 1):
                    lines.append(f"    {i}. {s}")
            lines.append("")

    # High-interest targets
    targets = result.get("high_interest_targets", [])
    if targets:
        lines.append(f"### High-Interest Targets (top {len(targets)})\n")
        for t in targets:
            risk = t.get("risk_level", "?")
            emoji_map = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": ""}
            indicator = emoji_map.get(risk, "")
            lines.append(f"**{t.get('host', '?')}** — Score: {t.get('score', 0)} [{risk}] {indicator}")
            lines.append(f"  - URL: {t.get('url', '?')}")
            if t.get("technologies"):
                lines.append(f"  - Tech: {', '.join(t['technologies'][:5])}")
            if t.get("flags"):
                lines.append(f"  - Flags: {', '.join(t['flags'])}")
            if t.get("secrets_on_host"):
                for s in t["secrets_on_host"][:3]:
                    lines.append(f"  - Secret: [{s.get('confidence')}] {s.get('type')} in {s.get('file')}")
            if t.get("cors_issue"):
                ci = t["cors_issue"]
                lines.append(f"  - CORS: [{ci.get('severity')}] {ci.get('detail')}")
            if t.get("sensitive_paths_found"):
                lines.append(f"  - Sensitive: {', '.join(t['sensitive_paths_found'][:5])}")
            lines.append(f"  - Endpoints: {t.get('hidden_endpoints_count', 0)} hidden, {t.get('api_endpoints_count', 0)} API")
            lines.append(f"  - Params: {t.get('parameters_count', 0)} | URLs: {t.get('urls_count', 0)}")
            if t.get("reasons"):
                lines.append(f"  - Why:")
                for r in t["reasons"]:
                    lines.append(f"    - {r}")
            lines.append("")

    # Correlations
    corrs = result.get("correlations", [])
    if corrs:
        lines.append(f"### Cross-Stage Correlations ({len(corrs)})\n")
        for c in corrs:
            lines.append(f"**[{c.get('priority', '?')}] {c.get('type', '?')}**")
            lines.append(f"  - {c.get('description', '?')}")
            lines.append(f"  - Significance: {c.get('significance', '?')}")
            lines.append("")

    # Technology playbooks
    pbs = result.get("technology_playbooks", [])
    if pbs:
        lines.append(f"### Technology Playbooks\n")
        for pb in pbs:
            lines.append(f"**{pb.get('technology', '?')}:**")
            for check in pb.get("checks", []):
                if "path" in check:
                    lines.append(f"  - `{check['path']}` — {check.get('purpose', '')}")
                elif "query" in check:
                    lines.append(f"  - Query: `{check['query'][:60]}...` — {check.get('purpose', '')}")
                elif "test" in check:
                    lines.append(f"  - Test: {check['test']} — {check.get('purpose', '')}")
                elif "tool" in check:
                    lines.append(f"  - Tool: `{check['tool']} {check.get('args', '')}` — {check.get('purpose', '')}")
            lines.append("")

    # Suggested test classes
    tc = result.get("suggested_test_classes", [])
    if tc:
        lines.append(f"**Suggested test classes:** {', '.join(tc)}\n")

    # Flags summary
    flags_sum = result.get("flags_summary", {})
    if flags_sum:
        lines.append("**Flags distribution:**")
        for flag, count in flags_sum.items():
            lines.append(f"  - {flag}: {count}")
        lines.append("")

    lines.append(f"**Next step:** {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _format_scan_plan_result(result: dict[str, Any]) -> str:
    """Format scan plan submission result."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    if result.get("status") == "rejected":
        lines = [
            "## Scan Plan Rejected\n",
            f"**{result.get('message', '')}**\n",
            "**Reasons:**",
        ]
        for r in result.get("rejected_reasons", []):
            lines.append(f"  - {r}")
        lines.append("\nFix the issues and resubmit.")
        return "\n".join(lines) + "\n"

    # Approved
    lines = [
        "## Scan Plan Approved\n",
        f"**{result.get('message', '')}**\n",
        f"**Targets:** {result.get('targets_count', 0)}",
        f"**Test Classes:** {result.get('test_classes_total', 0)}",
    ]

    tools_req = result.get("tools_required", [])
    if tools_req:
        lines.append(f"**Tools Required:** {', '.join(tools_req)}")

    avail = result.get("tools_available", [])
    if avail:
        lines.append(f"**Tools Available:** {', '.join(avail)}")

    missing = result.get("tools_missing", [])
    if missing:
        lines.append(f"**Tools Missing:** {', '.join(missing)} (install for full coverage)")

    lines.append(f"\n**Next step:** {result.get('next_step', 'Continue.')}")
    return "\n".join(lines) + "\n"


def _format_enrich_target(result: dict[str, Any]) -> str:
    """Format target enrichment dossier."""
    if result.get("status") == "error":
        return f"Error: {result['message']}"

    fp = result.get("fingerprint", {})
    lines = [
        f"## Target Dossier: `{result.get('host', '?')}`\n",
        f"**Score:** {result.get('score', 0)} [{result.get('risk_level', '?')}]\n",
        "### Fingerprint",
        f"  - URL: {fp.get('url', '?')}",
        f"  - Status: {fp.get('status_code', '?')}",
        f"  - Title: {fp.get('title', '?')}",
        f"  - Server: {fp.get('web_server', '?')}",
        f"  - IP: {fp.get('ip', '?')}",
        f"  - CDN: {fp.get('cdn') or 'None'}",
        "",
    ]

    if result.get("flags"):
        lines.append("### Flags")
        for f in result["flags"]:
            lines.append(f"  - {f}")
        lines.append("")

    if result.get("technologies"):
        lines.append(f"### Technologies: {', '.join(result['technologies'])}\n")

    waf = result.get("waf")
    if waf:
        lines.append(f"### WAF: {waf.get('waf', 'None')} ({'detected' if waf.get('detected') else 'not detected'})\n")

    if result.get("reasons"):
        lines.append("### Risk Factors")
        for r in result["reasons"]:
            lines.append(f"  - {r}")
        lines.append("")

    if result.get("secrets"):
        lines.append(f"### Secrets ({len(result['secrets'])})")
        for s in result["secrets"][:10]:
            lines.append(f"  - [{s.get('confidence')}] {s.get('type')}: `{s.get('value', '?')}`")
        lines.append("")

    if result.get("sensitive_paths"):
        lines.append(f"### Sensitive Paths ({len(result['sensitive_paths'])})")
        for sp in result["sensitive_paths"][:10]:
            lines.append(f"  - [{sp.get('category')}] `{sp.get('path')}` (status {sp.get('status_code', '?')})")
        lines.append("")

    if result.get("cors_results"):
        lines.append(f"### CORS Issues ({len(result['cors_results'])})")
        for c in result["cors_results"]:
            lines.append(f"  - [{c.get('severity')}] origin {c.get('origin_tested', '?')} reflected")
        lines.append("")

    if result.get("hidden_endpoints"):
        lines.append(f"### Hidden Endpoints ({len(result['hidden_endpoints'])})")
        for ep in result["hidden_endpoints"][:15]:
            lines.append(f"  - {ep.get('method', 'GET')} `{ep.get('path', '?')}`")
        lines.append("")

    if result.get("api_endpoints"):
        lines.append(f"### API Endpoints ({len(result['api_endpoints'])})")
        for ep in result["api_endpoints"][:15]:
            lines.append(f"  - {ep.get('method', 'GET')} `{ep.get('path', '?')}`")
        lines.append("")

    if result.get("parameters"):
        lines.append(f"### Parameters ({len(result['parameters'])} paths)")
        for p in result["parameters"][:10]:
            param_names = [pr.get("name", "?") for pr in p.get("params", [])]
            lines.append(f"  - `{p.get('path', '?')}`: {', '.join(param_names)}")
        lines.append("")

    urls_total = result.get("urls_total", 0)
    if urls_total:
        lines.append(f"### URLs: {urls_total} total (showing first {len(result.get('urls', []))})")
        for u in result.get("urls", [])[:20]:
            lines.append(f"  - {u}")
        lines.append("")

    if result.get("attack_chains"):
        lines.append(f"### Attack Chains Involving This Host")
        for c in result["attack_chains"]:
            lines.append(f"  - [{c.get('severity')}] {c.get('name')} (est. {c.get('bounty_estimate', '?')})")
        lines.append("")

    if result.get("dns_records"):
        lines.append(f"### DNS Records")
        for rec in result["dns_records"][:5]:
            lines.append(f"  - {json.dumps(rec)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def _format_test_results(result: dict[str, Any]) -> str:
    """Format test execution results as readable text."""
    if result.get("status") == "error":
        return f"Error [{result.get('error_type', '?')}]: {result['message']}"

    lines = [f"## Test Results\n"]

    # Single-target mode
    if result.get("tool"):
        lines.append(f"**Tool:** {result['tool']}")
        lines.append(f"**Target:** {result.get('target', '?')}")
    else:
        lines.append(f"**Targets Tested:** {result.get('targets_tested', 0)}")

    lines.append(f"**Findings Total:** {result.get('findings_total', 0)}\n")

    # Severity breakdown
    sev = result.get("findings_by_severity", {})
    if any(sev.values()):
        lines.append("**Findings by Severity:**")
        for level in ("critical", "high", "medium", "low", "info"):
            count = sev.get(level, 0)
            if count:
                lines.append(f"  - **{level.upper()}**: {count}")
        lines.append("")

    # Validation breakdown
    needs_val = result.get("findings_needing_validation")
    definitive = result.get("findings_definitive")
    if needs_val is not None:
        lines.append(f"**Definitive (report now):** {definitive}")
        lines.append(f"**Needs Validation (Stage 5):** {needs_val}\n")

    # Show findings
    findings = result.get("findings", [])
    if findings:
        lines.append("### Findings\n")
        for f in findings[:15]:
            sev_tag = f.get("severity", "?").upper()
            val_tag = " [needs validation]" if f.get("needs_validation") else " [definitive]"
            lines.append(
                f"**[{sev_tag}]** `{f.get('template_id', '?')}`{val_tag}"
            )
            lines.append(f"  - Host: {f.get('host', '?')}")
            lines.append(f"  - Endpoint: `{f.get('endpoint', '?')}`")
            lines.append(f"  - Class: {f.get('vulnerability_class', '?')}")
            name = f.get("template_name", "")
            if name:
                lines.append(f"  - Name: {name}")
            curl = f.get("curl_command", "")
            if curl:
                lines.append(f"  - Curl: `{curl[:120]}{'...' if len(curl) > 120 else ''}`")
            lines.append("")

        if len(findings) > 15:
            lines.append(f"... and {len(findings) - 15} more findings.\n")

    # Warnings
    warnings = result.get("warnings", [])
    if warnings:
        lines.append("**Warnings:**")
        for w in warnings:
            lines.append(f"  - {w}")
        lines.append("")

    # Files
    files = result.get("files_written", [])
    if files:
        lines.append("**Files written:**")
        for f in files:
            lines.append(f"  - `{f}`")
        lines.append("")

    lines.append(f"**Next step:** {result.get('next_step', 'Continue to next stage.')}")
    return "\n".join(lines) + "\n"


def _suggest_next(stages: list[int]) -> str:
    """Suggest the next tool to call based on stages_to_run."""
    if 1 in stages:
        return "Call `bughound_enumerate` to discover subdomains."
    if 2 in stages:
        return "Call `bughound_discover` to probe and discover the attack surface."
    if 3 in stages:
        return "Call `bughound_get_attack_surface` to analyze the attack surface."
    if 4 in stages:
        return "Call `bughound_execute_tests` to run the scan plan."
    return "Call the next stage tool in the pipeline."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the BugHound MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
