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
        "next_step": (
            "STOP here and present results to the user. "
            "Do NOT proceed to the next stage unless the user explicitly asks."
        ),
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
        extra_warnings: list[str] = []

        # Phase 1: run fast passive tools (same as light, excludes amass)
        await job_manager.update_progress(jid, 5, "Running fast passive enumeration", "passive")
        light_result = await enumerate_light(workspace_id)
        fast_count = light_result.get("data", {}).get("subdomains_found", 0)
        await job_manager.update_progress(jid, 30, f"Fast passive done: {fast_count} subdomains", "passive")

        # Phase 2: run amass (slow, thorough) with generous timeout
        amass_subs: set[str] = set()
        if amass.is_available():
            await job_manager.update_progress(jid, 35, "Running amass (slow, thorough)", "amass")
            try:
                amass_result = await amass.execute(target, timeout=660)
                if amass_result.success and amass_result.results:
                    amass_subs = {s.strip().lower() for s in amass_result.results if s.strip()}
                    await job_manager.update_progress(
                        jid, 60, f"Amass found {len(amass_subs)} subdomains", "amass"
                    )
                else:
                    msg = amass_result.error.message if amass_result.error else "no results"
                    extra_warnings.append(f"amass: {msg}")
                    await job_manager.update_progress(jid, 60, "Amass finished (no results)", "amass")
            except Exception as exc:
                extra_warnings.append(f"amass failed: {exc}")
                await job_manager.update_progress(jid, 60, "Amass failed", "amass")
        else:
            extra_warnings.append("amass not installed, skipped.")
            await job_manager.update_progress(jid, 60, "Amass not available", "amass")

        # Phase 3: merge amass results with existing subdomains
        existing_subs: set[str] = set()
        existing_data = await workspace.read_data(workspace_id, "subdomains/all.txt")
        if isinstance(existing_data, list):
            existing_subs = {s.strip().lower() for s in existing_data if s.strip()}

        new_from_amass = amass_subs - existing_subs
        if new_from_amass:
            merged = sorted(existing_subs | amass_subs)
            await workspace.write_data(
                workspace_id, "subdomains/all.txt", merged,
                generated_by="enumerate_deep", target=target,
            )
            # Resolve DNS for new subdomains only
            await job_manager.update_progress(
                jid, 70, f"Resolving {len(new_from_amass)} new subdomains from amass", "dns"
            )
            new_dns = await dns_resolver.resolve_domains(sorted(new_from_amass))
            # Merge with existing DNS records
            existing_dns = await workspace.read_data(workspace_id, "dns/records.json")
            dns_map: dict[str, Any] = {}
            if isinstance(existing_dns, list):
                for rec in existing_dns:
                    if isinstance(rec, dict) and "domain" in rec:
                        domain = rec.pop("domain")
                        dns_map[domain] = rec
            dns_map.update(new_dns)
            dns_list = [{"domain": d, **r} for d, r in sorted(dns_map.items())]
            await workspace.write_data(
                workspace_id, "dns/records.json", dns_list,
                generated_by="dns_resolver", target=target,
            )
            await workspace.update_stats(workspace_id, subdomains_found=len(merged))

        await job_manager.update_progress(jid, 80, "Slow passive merge complete", "merge")

        # Phase 4: active tools (puredns, gotator) if available
        from bughound.core import tool_runner

        has_puredns = tool_runner.is_available("puredns")
        has_gotator = tool_runner.is_available("gotator")

        if not has_puredns and not has_gotator:
            extra_warnings.append(
                "No active enumeration tools (puredns, gotator) available. "
                "Deep mode ran passive sources + amass only."
            )
            await job_manager.update_progress(jid, 95, "No active tools available", "active")
        else:
            await job_manager.update_progress(jid, 85, "Active tools not yet integrated", "active")
            extra_warnings.append(
                "Active enumeration tools (puredns, gotator) not yet integrated."
            )

        final_subs = await workspace.read_data(workspace_id, "subdomains/all.txt")
        final_count = len(final_subs) if isinstance(final_subs, list) else fast_count

        summary = {
            "subdomains_found": final_count,
            "fast_passive_count": fast_count,
            "amass_new_count": len(new_from_amass),
            "resolved_count": light_result.get("data", {}).get("resolved_count", 0),
            "extra_warnings": extra_warnings,
        }
        await job_manager.complete_job(jid, summary)

    await job_manager.start_job(job_id, _run_deep(job_id))

    return {
        "status": "job_started",
        "job_id": job_id,
        "message": (
            f"Deep enumeration started for {target}. "
            "DO NOT wait or poll in a loop. Proceed to bughound_discover now — "
            "it will use the subdomains already found by light enumeration. "
            "After discovery completes, check this job once with bughound_job_status. "
            "If deep enum found new subdomains, run bughound_discover again on the updated list."
        ),
        "workspace_id": workspace_id,
        "estimated_time": "5-15 minutes",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_available_tools(include_slow: bool = False) -> dict[str, Any]:
    """Return dict of available enumeration tool names to their execute functions.

    include_slow: if True, include amass (slow but thorough, for deep mode only).
    """
    tools: dict[str, Any] = {}
    # Always include crtsh (API-based)
    tools["crtsh"] = crtsh.execute

    if subfinder.is_available():
        tools["subfinder"] = subfinder.execute
    if assetfinder.is_available():
        tools["assetfinder"] = assetfinder.execute
    if findomain.is_available():
        tools["findomain"] = findomain.execute
    if include_slow and amass.is_available():
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
