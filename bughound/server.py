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

from bughound.core import target_classifier, workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import WorkspaceState
from bughound.stages import discover as stage_discover
from bughound.stages import enumerate as stage_enumerate

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
        "first before any other bughound tool. Sync."
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
        "With a category (subdomains, hosts, flags, technologies, urls, parameters, "
        "secrets, hidden_endpoints, sensitive_paths, cors, takeover, vulnerabilities, "
        "waf), returns the actual data. Use anytime to check recon progress or "
        "review findings."
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
        "\n**Drill down:** call with category = subdomains | hosts | flags | "
        "technologies | urls | parameters | secrets | hidden_endpoints | "
        "sensitive_paths | cors | takeover | vulnerabilities | waf"
    )

    return "\n".join(lines) + "\n"


# Category -> (file_path, truncate_limit or 0 for no truncation)
_CATEGORY_MAP: dict[str, tuple[str, int]] = {
    "subdomains": ("subdomains/all.txt", 100),
    "hosts": ("hosts/live_hosts.json", 0),
    "flags": ("hosts/flags.json", 0),
    "technologies": ("hosts/technologies.json", 0),
    "urls": ("urls/crawled.json", 100),
    "parameters": ("urls/parameters.json", 0),
    "secrets": ("secrets/js_secrets.json", 0),
    "hidden_endpoints": ("endpoints/hidden_endpoints.json", 0),
    "sensitive_paths": ("hosts/sensitive_paths.json", 0),
    "cors": ("hosts/cors_results.json", 0),
    "takeover": ("cloud/takeover_candidates.json", 0),
    "vulnerabilities": ("vulnerabilities/scan_results.json", 0),
    "waf": ("hosts/waf.json", 0),
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


_CATEGORY_FORMATTERS: dict[str, Any] = {
    "subdomains": _fmt_subdomains,
    "hosts": _fmt_hosts,
    "flags": _fmt_flags,
    "waf": _fmt_waf,
    "technologies": _fmt_technologies,
    "urls": _fmt_urls,
    "parameters": _fmt_parameters,
    "secrets": _fmt_secrets,
    "hidden_endpoints": _fmt_hidden_endpoints,
    "sensitive_paths": _fmt_sensitive_paths,
    "cors": _fmt_cors,
    "takeover": _fmt_takeover,
    "vulnerabilities": _fmt_vulnerabilities,
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
        f"Use `bughound_job_status` with job_id `{result.get('job_id', '')}` to check progress.\n"
    )


def _suggest_next(stages: list[int]) -> str:
    """Suggest the next tool to call based on stages_to_run."""
    if 1 in stages:
        return "Call `bughound_enumerate` to discover subdomains."
    if 2 in stages:
        return "Call `bughound_discover` to probe and discover the attack surface."
    return "Call the next stage tool in the pipeline."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the BugHound MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
