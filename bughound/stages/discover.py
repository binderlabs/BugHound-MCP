"""Stage 2: Probe, crawl, dirfuzz, JS analysis, secrets, cloud assets.

Day 5 implements Phase 2A: probing + fingerprinting + intelligence flags.
Day 6 adds Phase 2B-2F: URL discovery, JS analysis, secrets, etc.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from typing import Any

import structlog

from bughound.core import workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import TargetType, WorkspaceState
from bughound.tools.recon import httpx, wafw00f

logger = structlog.get_logger()

# Default page title patterns indicating uninteresting/default installs
_DEFAULT_TITLES = {
    "welcome to nginx",
    "apache2 default page",
    "apache2 debian default page",
    "apache2 ubuntu default page",
    "iis windows server",
    "microsoft internet information services",
    "test page for the apache",
    "it works!",
    "default web site page",
    "web server's default page",
    "congratulations",
    "404 not found",
    "403 forbidden",
    "page not found",
    "under construction",
    "coming soon",
    "parked domain",
    "domain for sale",
}

# Old tech patterns: (regex on tech string, flag message)
_OLD_TECH_PATTERNS = [
    (re.compile(r"wordpress\s*[1-5]\.", re.I), "WordPress < 6.x"),
    (re.compile(r"jquery[/ ]1\.", re.I), "jQuery 1.x (EOL)"),
    (re.compile(r"jquery[/ ]2\.", re.I), "jQuery 2.x (EOL)"),
    (re.compile(r"jquery[/ ]3\.[0-4]\.", re.I), "jQuery < 3.5 (prototype pollution)"),
    (re.compile(r"php[/ ]5\.", re.I), "PHP 5.x (EOL)"),
    (re.compile(r"php[/ ]7\.[0-3]\.", re.I), "PHP 7.0-7.3 (EOL)"),
    (re.compile(r"angular[/ ]1\.", re.I), "AngularJS 1.x (EOL, XSS-prone)"),
    (re.compile(r"apache[/ ]2\.2\.", re.I), "Apache 2.2 (EOL)"),
    (re.compile(r"nginx[/ ]1\.(1[0-8]|[0-9])\.", re.I), "nginx < 1.19 (old branch)"),
    (re.compile(r"openssl[/ ]1\.0\.", re.I), "OpenSSL 1.0 (EOL)"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover(
    workspace_id: str,
    job_manager: JobManager | None = None,
) -> dict[str, Any]:
    """Run Stage 2 discovery on a workspace.

    For SINGLE_HOST / SINGLE_ENDPOINT: synchronous, returns results directly.
    For BROAD_DOMAIN / URL_LIST with many targets: starts async job if job_manager given.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    targets = await _resolve_targets(meta)
    if not targets:
        return _error(
            "invalid_input",
            "No targets to discover. Run bughound_enumerate first for broad domains.",
        )

    is_broad = meta.target_type in (TargetType.BROAD_DOMAIN, TargetType.URL_LIST)
    many_targets = len(targets) > 10

    if is_broad and many_targets and job_manager is not None:
        return await _start_discover_job(workspace_id, targets, meta, job_manager)

    return await _run_discover(workspace_id, targets, meta)


# ---------------------------------------------------------------------------
# Synchronous discovery (Phase 2A)
# ---------------------------------------------------------------------------


async def _run_discover(
    workspace_id: str,
    targets: list[str],
    meta: Any,
) -> dict[str, Any]:
    """Run Phase 2A synchronously and return structured results."""
    await workspace.update_metadata(
        workspace_id, state=WorkspaceState.DISCOVERING, current_stage=2,
    )
    await workspace.add_stage_history(workspace_id, 2, "running")

    target_label = meta.target
    warnings: list[str] = []

    # --- Phase 2A: Probe with httpx ---
    if not httpx.is_available():
        await workspace.add_stage_history(workspace_id, 2, "failed")
        return _error(
            "tool_not_found",
            "httpx is required for discovery but not installed. "
            "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        )

    httpx_result = await httpx.execute(targets if len(targets) > 1 else targets[0])
    if not httpx_result.success:
        warnings.append(f"httpx: {httpx_result.error.message if httpx_result.error else 'failed'}")

    live_hosts: list[dict[str, Any]] = httpx_result.results if httpx_result.success else []

    if not live_hosts:
        await workspace.add_stage_history(workspace_id, 2, "completed")
        return {
            "status": "success",
            "message": f"No live hosts found for {target_label}. All targets may be down or blocked.",
            "workspace_id": workspace_id,
            "data": {"live_hosts": 0},
            "warnings": warnings,
        }

    # --- Phase 2A: WAF detection ---
    waf_results: list[dict[str, Any]] = []
    if wafw00f.is_available():
        live_urls = [h["url"] for h in live_hosts if h.get("url")]
        sample = live_urls[:20]  # Sample to avoid slowness
        waf_tasks = [wafw00f.execute(url) for url in sample]

        waf_raw = await asyncio.gather(*waf_tasks, return_exceptions=True)
        for r in waf_raw:
            if isinstance(r, Exception):
                continue
            if r.success:
                waf_results.extend(r.results)
    else:
        warnings.append("wafw00f not installed — WAF detection skipped.")

    # Build WAF lookup: url -> waf name (None means scanned but no WAF found)
    waf_by_url: dict[str, str | None] = {}
    for wr in waf_results:
        waf_by_url[wr.get("url", "")] = wr.get("waf")

    # --- Generate intelligence flags ---
    cdn_counter: Counter[str] = Counter()
    for h in live_hosts:
        cdn = h.get("cdn", "")
        if cdn:
            cdn_counter[cdn] += 1
    majority_cdn = cdn_counter.most_common(1)[0][0] if cdn_counter else None

    flagged_hosts: list[dict[str, Any]] = []
    tech_counter: Counter[str] = Counter()

    for host in live_hosts:
        flags = _generate_flags(host, waf_by_url, majority_cdn)
        flagged_hosts.append({**host, "flags": flags})
        for tech in host.get("technologies") or []:
            tech_counter[tech] += 1

    # --- Write to workspace ---
    await workspace.write_data(
        workspace_id, "hosts/live_hosts.json", flagged_hosts,
        generated_by="httpx", target=target_label,
    )

    tech_list = [
        {"technology": tech, "host_count": count}
        for tech, count in tech_counter.most_common(30)
    ]
    await workspace.write_data(
        workspace_id, "hosts/technologies.json", tech_list,
        generated_by="httpx", target=target_label,
    )

    if waf_results:
        await workspace.write_data(
            workspace_id, "hosts/waf.json", waf_results,
            generated_by="wafw00f", target=target_label,
        )

    hosts_with_flags = [h for h in flagged_hosts if h.get("flags")]
    if hosts_with_flags:
        flags_summary = [
            {"host": h["host"], "url": h["url"], "flags": h["flags"]}
            for h in hosts_with_flags
        ]
        await workspace.write_data(
            workspace_id, "hosts/flags.json", flags_summary,
            generated_by="discover", target=target_label,
        )

    # --- Update metadata ---
    await workspace.update_stats(workspace_id, live_hosts=len(live_hosts))
    await workspace.add_stage_history(workspace_id, 2, "completed")

    files_written = ["hosts/live_hosts.json", "hosts/technologies.json"]
    if waf_results:
        files_written.append("hosts/waf.json")
    if hosts_with_flags:
        files_written.append("hosts/flags.json")

    # --- Build summary for AI ---
    flag_dist: Counter[str] = Counter()
    for h in flagged_hosts:
        for f in h.get("flags", []):
            flag_dist[f.split(":")[0]] += 1

    return {
        "status": "success",
        "message": (
            f"Discovered {len(live_hosts)} live hosts for {target_label}. "
            f"{len(hosts_with_flags)} hosts have intelligence flags."
        ),
        "workspace_id": workspace_id,
        "files_written": files_written,
        "data": {
            "live_hosts": len(live_hosts),
            "hosts_with_flags": len(hosts_with_flags),
            "waf_detected": sum(1 for w in waf_results if w.get("detected")),
            "waf_skipped": len(live_hosts) - len(waf_results),
            "top_technologies": tech_counter.most_common(10),
            "flag_distribution": dict(flag_dist.most_common(10)),
            "majority_cdn": majority_cdn,
            "httpx_time": f"{httpx_result.execution_time_seconds}s",
        },
        "warnings": warnings,
        "next_step": "Call bughound_get_attack_surface to review the full attack surface with AI analysis.",
    }


# ---------------------------------------------------------------------------
# Async discovery job
# ---------------------------------------------------------------------------


async def _start_discover_job(
    workspace_id: str,
    targets: list[str],
    meta: Any,
    job_manager: JobManager,
) -> dict[str, Any]:
    """Start discovery as a background job for broad targets."""
    try:
        job_id = await job_manager.create_job(workspace_id, "discover", meta.target)
    except RuntimeError as exc:
        return _error("execution_failed", str(exc))

    async def _run_job(jid: str) -> None:
        await job_manager.update_progress(jid, 10, "Probing live hosts", "httpx")
        result = await _run_discover(workspace_id, targets, meta)
        if result.get("status") == "success":
            await job_manager.complete_job(jid, result.get("data"))
        else:
            await job_manager.fail_job(jid, result.get("message", "Discovery failed"))

    await job_manager.start_job(job_id, _run_job(job_id))

    return {
        "status": "job_started",
        "job_id": job_id,
        "message": (
            f"Discovery started for {len(targets)} targets. "
            "Poll with bughound_job_status."
        ),
        "workspace_id": workspace_id,
        "estimated_time": "2-5 minutes",
    }


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


async def _resolve_targets(meta: Any) -> list[str]:
    """Determine which targets to probe based on workspace metadata."""
    target_type = meta.target_type
    classification = meta.classification or {}

    if target_type == TargetType.BROAD_DOMAIN:
        subs = await workspace.read_data(meta.workspace_id, "subdomains/all.txt")
        if isinstance(subs, list) and subs:
            return subs
        return classification.get("normalized_targets", [meta.target])

    if target_type in (TargetType.SINGLE_HOST, TargetType.SINGLE_ENDPOINT):
        return classification.get("normalized_targets", [meta.target])

    if target_type == TargetType.URL_LIST:
        return classification.get("normalized_targets", [])

    return [meta.target]


# ---------------------------------------------------------------------------
# Intelligence flags
# ---------------------------------------------------------------------------


def _generate_flags(
    host: dict[str, Any],
    waf_by_url: dict[str, str | None],
    majority_cdn: str | None,
) -> list[str]:
    """Generate intelligence flags for a single host."""
    flags: list[str] = []
    url = host.get("url", "")
    title = (host.get("title") or "").lower()
    techs = host.get("technologies") or []
    techs_lower = " ".join(techs).lower()
    cdn = host.get("cdn", "")
    server = (host.get("web_server") or "").lower()

    # NO_WAF: url was scanned by wafw00f and no WAF was found
    if url in waf_by_url and waf_by_url[url] is None:
        flags.append("NO_WAF: No WAF detected — direct exposure")

    # NON_CDN_IP: this host isn't behind the CDN that most siblings use
    if majority_cdn and not cdn:
        flags.append(f"NON_CDN_IP: Not behind {majority_cdn} while siblings are")

    # DEFAULT_PAGE
    if any(default in title for default in _DEFAULT_TITLES):
        flags.append(f"DEFAULT_PAGE: Default/placeholder page ({title[:60]})")

    # GRAPHQL
    graphql_indicators = ("graphql", "graphiql", "playground", "apollo")
    if any(g in title for g in graphql_indicators) or any(g in url.lower() for g in graphql_indicators):
        flags.append("GRAPHQL: GraphQL detected — check introspection")

    # OLD_TECH
    for pattern, label in _OLD_TECH_PATTERNS:
        if pattern.search(techs_lower) or pattern.search(server):
            flags.append(f"OLD_TECH: {label}")
            break

    # DEBUG_MODE
    status = host.get("status_code", 0)
    if status == 500 or "debug" in title or "stack trace" in title or "traceback" in title:
        flags.append("DEBUG_MODE: Error/debug information exposed")

    return flags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
