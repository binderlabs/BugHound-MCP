"""Stage 1: Subdomain discovery + DNS. Skipped for non-BROAD_DOMAIN targets.

Light mode: passive sources in parallel + DNS resolution (~30-60s)
Deep mode:  same + permutation/bruteforce if tools available (async job, 5-15min)
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any

import structlog

from bughound.core import workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import TargetType, ToolResult, WorkspaceState
from bughound.tools.recon import amass, assetfinder, crtsh, dns_resolver, findomain, subfinder

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Light enumeration (synchronous)
# ---------------------------------------------------------------------------


async def enumerate_light(workspace_id: str) -> dict[str, Any]:
    """Run passive subdomain discovery + DNS resolution.

    Returns a structured result dict matching the MCP output pattern.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Check target type — skip if not broad domain
    if meta.target_type != TargetType.BROAD_DOMAIN:
        await workspace.add_stage_history(workspace_id, 1, "skipped")
        return {
            "status": "success",
            "message": (
                f"Enumeration skipped for {meta.target_type.value} target. "
                "Proceed to bughound_discover."
            ),
            "workspace_id": workspace_id,
            "data": {"subdomains_found": 0, "skipped": True},
        }

    # Mark stage as running
    await workspace.update_metadata(
        workspace_id, state=WorkspaceState.ENUMERATING, current_stage=1
    )
    await workspace.add_stage_history(workspace_id, 1, "running")

    target = meta.classification["normalized_targets"][0] if meta.classification else meta.target

    # --- Run passive tools in parallel ---
    tools = _get_available_tools()
    warnings: list[str] = []

    if not tools:
        return _error(
            "execution_failed",
            "No subdomain enumeration tools available. Install subfinder, assetfinder, or findomain.",
        )

    tool_tasks: dict[str, asyncio.Task] = {}
    for name, exec_fn in tools.items():
        tool_tasks[name] = asyncio.create_task(exec_fn(target))

    tool_results: dict[str, ToolResult] = {}
    for name, task in tool_tasks.items():
        try:
            tool_results[name] = await task
        except Exception as exc:
            warnings.append(f"{name} failed: {exc}")

    # --- Merge and deduplicate ---
    all_subs: set[str] = set()
    sources: dict[str, list[str]] = {}  # subdomain -> [tool_names]

    for name, result in tool_results.items():
        if not result.success:
            warnings.append(
                f"{name}: {result.error.message if result.error else 'failed'}"
            )
            continue
        for sub in result.results:
            sub = sub.strip().lower()
            if sub:
                all_subs.add(sub)
                sources.setdefault(sub, []).append(name)

    deduped = sorted(all_subs)

    if not deduped:
        await workspace.add_stage_history(workspace_id, 1, "completed")
        return {
            "status": "success",
            "message": (
                f"No subdomains found for {target} via passive sources. "
                "Consider running bughound_enumerate_deep for active bruteforce."
            ),
            "workspace_id": workspace_id,
            "data": {"subdomains_found": 0, "tools_used": list(tools.keys())},
            "warnings": warnings,
        }

    # --- DNS resolution ---
    dns_records = await dns_resolver.resolve_domains(deduped)
    resolved = [d for d, r in dns_records.items() if r.get("resolved")]

    # --- Wildcard detection ---
    wildcards = await dns_resolver.detect_wildcards([target])

    # --- Pattern analysis ---
    patterns = _analyze_patterns(deduped, dns_records)

    # --- Write to workspace ---
    await workspace.write_data(
        workspace_id, "subdomains/all.txt", deduped,
        generated_by="enumerate", target=target,
    )

    sources_list = [
        {"subdomain": sub, "sources": srcs}
        for sub, srcs in sorted(sources.items())
    ]
    await workspace.write_data(
        workspace_id, "subdomains/sources.json", sources_list,
        generated_by="enumerate", target=target,
    )

    dns_list = [
        {"domain": domain, **records}
        for domain, records in sorted(dns_records.items())
    ]
    await workspace.write_data(
        workspace_id, "dns/records.json", dns_list,
        generated_by="dns_resolver", target=target,
    )

    if wildcards:
        await workspace.write_data(
            workspace_id, "dns/wildcards.json", wildcards,
            generated_by="dns_resolver", target=target,
        )

    # --- Update metadata ---
    await workspace.update_stats(
        workspace_id,
        subdomains_found=len(deduped),
    )
    await workspace.add_stage_history(workspace_id, 1, "completed")

    files_written = ["subdomains/all.txt", "subdomains/sources.json", "dns/records.json"]
    if wildcards:
        files_written.append("dns/wildcards.json")

    # --- Tool timing summary ---
    tool_timing = {
        name: f"{r.execution_time_seconds}s"
        for name, r in tool_results.items()
    }

    return {
        "status": "success",
        "message": (
            f"Enumerated {len(deduped)} subdomains for {target}. "
            f"{len(resolved)} resolve to IP addresses."
        ),
        "workspace_id": workspace_id,
        "files_written": files_written,
        "data": {
            "subdomains_found": len(deduped),
            "resolved_count": len(resolved),
            "wildcard_domains": len(wildcards),
            "tools_used": tool_timing,
            "patterns": patterns,
        },
        "warnings": warnings,
        "next_step": "Call bughound_discover to probe live hosts and map the attack surface.",
    }


# ---------------------------------------------------------------------------
# Deep enumeration (async job)
# ---------------------------------------------------------------------------


async def enumerate_deep(
    workspace_id: str,
    job_manager: JobManager,
) -> dict[str, Any]:
    """Start deep enumeration as a background job.

    Returns immediately with a job_id.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    if meta.target_type != TargetType.BROAD_DOMAIN:
        return {
            "status": "success",
            "message": "Deep enumeration skipped for non-broad-domain target.",
            "workspace_id": workspace_id,
            "data": {"skipped": True},
        }

    target = meta.classification["normalized_targets"][0] if meta.classification else meta.target

    try:
        job_id = await job_manager.create_job(workspace_id, "enumerate_deep", target)
    except RuntimeError as exc:
        return _error("execution_failed", str(exc))

    async def _run_deep(jid: str) -> None:
        # Phase 1: same passive enum as light
        await job_manager.update_progress(jid, 10, "Running passive enumeration", "passive")
        light_result = await enumerate_light(workspace_id)

        await job_manager.update_progress(jid, 60, "Passive enumeration complete", "passive")

        # Phase 2: active tools (puredns, gotator) if available
        extra_warnings: list[str] = []
        from bughound.core import tool_runner

        has_puredns = tool_runner.is_available("puredns")
        has_gotator = tool_runner.is_available("gotator")

        if not has_puredns and not has_gotator:
            extra_warnings.append(
                "No active enumeration tools (puredns, gotator) available. "
                "Deep mode ran passive sources only."
            )
            await job_manager.update_progress(jid, 90, "No active tools available", "passive")
        else:
            await job_manager.update_progress(jid, 70, "Active tools not yet integrated", "active")
            extra_warnings.append(
                "Active enumeration tools (puredns, gotator) not yet integrated. "
                "Deep mode ran passive sources only in this version."
            )

        summary = {
            "subdomains_found": light_result.get("data", {}).get("subdomains_found", 0),
            "resolved_count": light_result.get("data", {}).get("resolved_count", 0),
            "extra_warnings": extra_warnings,
        }
        await job_manager.complete_job(jid, summary)

    await job_manager.start_job(job_id, _run_deep(job_id))

    return {
        "status": "job_started",
        "job_id": job_id,
        "message": f"Deep enumeration started for {target}. Poll with bughound_job_status.",
        "workspace_id": workspace_id,
        "estimated_time": "5-15 minutes",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_available_tools() -> dict[str, Any]:
    """Return dict of available enumeration tool names to their execute functions."""
    tools: dict[str, Any] = {}
    # Always include crtsh (API-based)
    tools["crtsh"] = crtsh.execute

    if subfinder.is_available():
        tools["subfinder"] = subfinder.execute
    if assetfinder.is_available():
        tools["assetfinder"] = assetfinder.execute
    if findomain.is_available():
        tools["findomain"] = findomain.execute
    if amass.is_available():
        tools["amass"] = amass.execute

    return tools


def _analyze_patterns(
    subdomains: list[str],
    dns_records: dict[str, Any],
) -> dict[str, Any]:
    """Extract naming patterns, IP groupings, and anomalies."""
    # Naming pattern prefixes
    prefix_counter: Counter[str] = Counter()
    for sub in subdomains:
        parts = sub.split(".")
        if len(parts) >= 3:
            prefix_counter[parts[0]] += 1

    # Group by common prefixes
    common_prefixes = [
        {"prefix": p, "count": c}
        for p, c in prefix_counter.most_common(15)
        if c >= 2
    ]

    # IP subnet grouping (/24)
    subnet_counter: Counter[str] = Counter()
    for domain, records in dns_records.items():
        for ip in records.get("A", []):
            parts = ip.split(".")
            if len(parts) == 4:
                subnet_counter[f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"] += 1

    top_subnets = [
        {"subnet": s, "host_count": c}
        for s, c in subnet_counter.most_common(10)
    ]

    # Interesting naming patterns
    interesting_keywords = {"admin", "api", "dev", "staging", "test", "internal",
                           "vpn", "mail", "portal", "dashboard", "jenkins", "git",
                           "jira", "confluence", "grafana", "kibana", "elastic"}
    interesting_found = sorted(
        sub for sub in subdomains
        if any(kw in sub.split(".")[0] for kw in interesting_keywords)
    )

    return {
        "common_prefixes": common_prefixes,
        "top_subnets": top_subnets,
        "interesting_targets": interesting_found[:20],
        "total_resolved": sum(
            1 for r in dns_records.values() if r.get("resolved")
        ),
    }


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
