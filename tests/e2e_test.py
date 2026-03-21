#!/usr/bin/env python3
"""End-to-end test: Stages 0→5, same code path as MCP tools.

Usage:
    python tests/e2e_test.py <target> [--depth light|deep]

Example:
    python tests/e2e_test.py https://pro.odaha.io
    python tests/e2e_test.py bugstore.bugtraceai.com --depth deep
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bughound.core.target_classifier import classify
from bughound.core import workspace
from bughound.core.job_manager import JobManager
from bughound.stages import enumerate as stage_enumerate
from bughound.stages import discover as stage_discover
from bughound.stages import analyze as stage_analyze
from bughound.stages import test as stage_test
from bughound.stages import validate as stage_validate
from bughound.stages import report as stage_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sev_icon(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev.lower(), "❓")


def _progress_bar(pct: int) -> str:
    filled = int(pct / 5)
    return f"[{'█' * filled}{'░' * (20 - filled)}] {pct}%"


def _print_header(stage: int, name: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  Stage {stage}: {name}")
    print(f"{'=' * 70}\n")


def _print_result(key: str, value, indent: int = 0) -> None:
    prefix = "  " * indent
    if isinstance(value, dict):
        print(f"{prefix}{key}:")
        for k, v in value.items():
            _print_result(k, v, indent + 1)
    elif isinstance(value, list) and len(value) > 5:
        print(f"{prefix}{key}: {len(value)} items")
    elif isinstance(value, list):
        print(f"{prefix}{key}: {value}")
    else:
        print(f"{prefix}{key}: {value}")


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

async def run_stage_0(target: str, depth: str) -> str:
    """Stage 0: Initialize workspace."""
    _print_header(0, "Initialize")

    classification = classify(target, depth)
    meta = await workspace.create_workspace(target, depth)
    await workspace.update_metadata(
        meta.workspace_id,
        target_type=classification.target_type,
        classification=classification.model_dump(mode="json"),
    )
    await workspace.add_stage_history(meta.workspace_id, 0, "completed")

    print(f"  Workspace ID: {meta.workspace_id}")
    print(f"  Target: {target}")
    print(f"  Target Type: {classification.target_type.value}")
    print(f"  Depth: {depth}")
    print(f"  Stages to run: {classification.stages_to_run}")
    print(f"  Normalized: {classification.normalized_targets}")

    if classification.skip_reasons:
        for stage, reason in classification.skip_reasons.items():
            print(f"  Skip Stage {stage}: {reason}")

    return meta.workspace_id


async def run_stage_1(workspace_id: str) -> dict:
    """Stage 1: Enumerate subdomains (skipped for single hosts)."""
    _print_header(1, "Enumerate")

    result = await stage_enumerate.enumerate_light(workspace_id)
    if result.get("data", {}).get("skipped"):
        print("  Skipped (single host target)")
    else:
        data = result.get("data", {})
        print(f"  Subdomains found: {data.get('subdomains_found', 0)}")
        print(f"  Resolved: {data.get('resolved_count', 0)}")

    return result


async def run_stage_2(workspace_id: str, job_manager: JobManager) -> dict:
    """Stage 2: Discovery — crawl, probe, classify params."""
    _print_header(2, "Discover")

    # Run discover (async job)
    result = await stage_discover.discover(workspace_id, job_manager)

    if result.get("status") == "job_started":
        job_id = result["job_id"]
        print(f"  Job started: {job_id}")

        # Poll until complete
        while True:
            await asyncio.sleep(3)
            status = await job_manager.get_status(job_id)
            if status is None:
                print("  Error: job not found")
                break

            pct = status.get("progress_pct", 0)
            msg = status.get("message", "")
            module = status.get("current_module", "")
            print(f"  {_progress_bar(pct)} {msg[:60]}")

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                if status["status"] != "COMPLETED":
                    print(f"  ❌ Job {status['status']}: {status.get('error', '?')}")
                else:
                    rs = status.get("result_summary", {})
                    print(f"\n  ✅ Discovery complete:")
                    for k, v in rs.items():
                        if isinstance(v, dict):
                            flat = ", ".join(f"{sk}: {sv}" for sk, sv in v.items() if sv)
                            if flat:
                                print(f"    {k}: {flat}")
                        elif v or v == 0:
                            print(f"    {k}: {v}")
                break
    else:
        # Synchronous result
        data = result.get("data", {})
        print(f"  Live hosts: {data.get('live_hosts', 0)}")
        print(f"  URLs discovered: {data.get('urls_discovered', 0)}")

    return result


async def run_stage_3(workspace_id: str) -> dict:
    """Stage 3: Analyze attack surface."""
    _print_header(3, "Analyze Attack Surface")

    result = await stage_analyze.get_attack_surface(workspace_id)

    if result.get("status") == "error":
        print(f"  ❌ Error: {result.get('message', '?')}")
        return result

    stats = result.get("stats", {})
    print(f"  Target: {result.get('target', '?')}")
    print(f"  Target Type: {result.get('target_type', '?')}")
    print()

    # Key stats
    print("  Stats:")
    for key in ("live_hosts", "total_urls", "total_parameters", "js_files",
                "secrets_found", "hidden_endpoints", "sensitive_paths",
                "cors_issues", "takeover_candidates"):
        val = stats.get(key, 0)
        if val:
            print(f"    {key}: {val}")

    # Probe-confirmed
    pc = result.get("parameter_classification", {})
    probe_confirmed = pc.get("probe_confirmed", [])
    if probe_confirmed:
        print(f"\n  🎯 Probe-Confirmed Vulnerabilities ({len(probe_confirmed)}):")
        for p in probe_confirmed:
            print(f"    [{p['vuln_type'].upper()}] {p['url'][:60]} param={p['param']} ({p['probe_result']})")

    # Reasoning prompts
    prompts = result.get("reasoning_prompts", [])
    if prompts:
        print(f"\n  💡 Reasoning Prompts ({len(prompts)}):")
        for p in prompts[:5]:
            print(f"    - {p[:100]}...")

    # Attack chains
    chains = result.get("attack_chains", [])
    if chains:
        print(f"\n  ⛓ Attack Chains ({len(chains)}):")
        for c in chains[:5]:
            print(f"    [{c.get('severity','?')}] {c.get('name','?')} (est. {c.get('bounty_estimate','?')})")

    # Immediate wins
    wins = result.get("immediate_wins", [])
    if wins:
        print(f"\n  🏆 Immediate Wins ({len(wins)}):")
        for w in wins:
            print(f"    [{w.get('severity','?')}] {w.get('type','?')} on {w.get('host','?')}")

    # Suggested test classes
    tc = result.get("suggested_test_classes", [])
    if tc:
        print(f"\n  Test classes: {', '.join(tc)}")

    return result


async def run_stage_4(
    workspace_id: str, job_manager: JobManager, attack_surface: dict,
) -> dict:
    """Stage 4: Execute tests — auto-generate scan plan then run."""
    _print_header(4, "Test (Execute)")

    # Auto-generate scan plan from attack surface
    meta = await workspace.get_workspace(workspace_id)
    target_host = meta.target
    if "://" in target_host:
        from urllib.parse import urlparse
        target_host = urlparse(target_host).hostname or target_host

    # Build scan plan
    suggested_classes = attack_surface.get("suggested_test_classes", [])
    if not suggested_classes:
        suggested_classes = [
            "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect",
            "crlf", "idor", "header_injection", "rce",
            "graphql", "jwt", "misconfig", "default_creds",
            "cors", "bac", "rate_limiting", "csti", "cve_specific",
        ]

    scan_plan = {
        "targets": [{
            "host": target_host,
            "priority": 1,
            "test_classes": suggested_classes,
        }],
        "global_settings": {
            "nuclei_severity": "critical,high,medium,low,info",
            "nuclei_rate_limit": 100,
            "nuclei_concurrency": 25,
            "timeout_per_target": 300,
        },
    }

    # Submit scan plan
    print("  Submitting scan plan...")
    plan_result = await stage_analyze.submit_scan_plan(workspace_id, scan_plan)
    if plan_result.get("status") == "error":
        print(f"  ❌ Scan plan error: {plan_result.get('message', '?')}")
        return plan_result
    if plan_result.get("status") == "rejected":
        print(f"  ❌ Scan plan rejected: {plan_result.get('rejected_reasons', [])}")
        return plan_result

    print(f"  ✅ Scan plan approved: {plan_result.get('targets_count', 0)} targets, "
          f"{plan_result.get('test_classes_total', 0)} test classes")

    # Execute tests
    print("  Starting test execution...")
    result = await stage_test.execute_tests(workspace_id, job_manager)

    if result.get("status") == "job_started":
        job_id = result["job_id"]
        print(f"  Job started: {job_id}")

        while True:
            await asyncio.sleep(5)
            status = await job_manager.get_status(job_id)
            if status is None:
                print("  Error: job not found")
                break

            pct = status.get("progress_pct", 0)
            msg = status.get("message", "")
            print(f"  {_progress_bar(pct)} {msg[:60]}")

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                if status["status"] != "COMPLETED":
                    print(f"  ❌ Job {status['status']}: {status.get('error', '?')}")
                else:
                    rs = status.get("result_summary", {})
                    print(f"\n  ✅ Testing complete:")
                    for k, v in rs.items():
                        if isinstance(v, dict):
                            flat = ", ".join(f"{sk}: {sv}" for sk, sv in v.items() if sv)
                            if flat:
                                print(f"    {k}: {flat}")
                        elif v or v == 0:
                            print(f"    {k}: {v}")
                break

        # Read full results
        raw = await workspace.read_data(workspace_id, "vulnerabilities/scan_results.json")
        findings = raw.get("data", raw) if isinstance(raw, dict) else (raw or [])
        return {"findings": findings, "status": "success"}
    else:
        return result


async def run_stage_5(workspace_id: str, job_manager: JobManager) -> dict:
    """Stage 5: Validate findings."""
    _print_header(5, "Validate")

    # Run as background job
    try:
        job_id = await job_manager.create_job(workspace_id, "validate_all", "batch validation")
    except RuntimeError as exc:
        print(f"  ❌ Error: {exc}")
        return {"status": "error", "message": str(exc)}

    async def _run_job(jid: str) -> None:
        result = await stage_validate.validate_all(workspace_id)
        summary = {
            "total_validated": result.get("total_validated", 0),
            "confirmed": result.get("confirmed", 0),
            "false_positives": result.get("false_positives", 0),
            "manual_review": result.get("manual_review", 0),
        }
        await job_manager.complete_job(jid, summary)

    await job_manager.start_job(job_id, _run_job(job_id))
    print(f"  Job started: {job_id}")

    while True:
        await asyncio.sleep(5)
        status = await job_manager.get_status(job_id)
        if status is None:
            print("  Error: job not found")
            break

        pct = status.get("progress_pct", 0)
        msg = status.get("message", "")
        print(f"  {_progress_bar(pct)} {msg[:60]}")

        if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
            if status["status"] != "COMPLETED":
                print(f"  ❌ Job {status['status']}: {status.get('error', '?')}")
            else:
                rs = status.get("result_summary", {})
                print(f"\n  ✅ Validation complete:")
                for k, v in rs.items():
                    print(f"    {k}: {v}")
            break

    return status.get("result_summary", {}) if status else {}


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------

def print_final_report(findings: list[dict]) -> None:
    """Print a clean summary of all findings."""
    print(f"\n{'=' * 70}")
    print(f"  FINAL REPORT")
    print(f"{'=' * 70}\n")

    if not findings:
        print("  No findings.")
        return

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get("vulnerability_class", ""),
            f.get("endpoint", ""),
            f.get("param", f.get("description", "")),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Stats
    sev_counts = Counter(f.get("severity", "?") for f in unique)
    class_counts = Counter(f.get("vulnerability_class", "?") for f in unique)
    tool_counts = Counter(f.get("tool", "?") for f in unique)
    tech_counts = Counter(f.get("technique_id", "?") for f in unique)
    needs_val = sum(1 for f in unique if f.get("needs_validation"))
    definitive = len(unique) - needs_val

    print(f"  Total Findings: {len(unique)} (from {len(findings)} raw)")
    print(f"  Definitive: {definitive}  |  Needs Validation: {needs_val}")
    print()

    # Severity table
    print("  By Severity:")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        if count:
            print(f"    {_sev_icon(sev)} {sev.upper():10s} {count}")

    # Class table
    print(f"\n  By Vulnerability Class:")
    for cls, count in class_counts.most_common():
        print(f"    {cls:25s} {count}")

    # Tool table
    print(f"\n  By Tool:")
    for tool, count in tool_counts.most_common():
        print(f"    {tool:25s} {count}")

    # Technique table
    print(f"\n  By Technique:")
    for tech, count in tech_counts.most_common():
        if count > 0:
            print(f"    {tech:30s} {count}")

    # Finding details (sorted by severity)
    print(f"\n  {'─' * 66}")
    print(f"  Findings Detail (top 30):")
    print(f"  {'─' * 66}")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(unique, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    for i, f in enumerate(sorted_findings[:30], 1):
        sev = f.get("severity", "info")
        icon = _sev_icon(sev)
        desc = f.get("description", f.get("template_name", f.get("template_id", "?")))
        endpoint = f.get("endpoint", "?")
        tool = f.get("tool", "?")
        val = "✅" if not f.get("needs_validation") else "⏳"

        print(f"\n  {i:2d}. {icon} [{sev.upper():8s}] {desc[:65]}")
        print(f"      Endpoint: {endpoint[:70]}")
        print(f"      Tool: {tool}  |  {val}")
        if f.get("payload_used"):
            print(f"      Payload: {f['payload_used'][:60]}")
        if f.get("evidence"):
            ev = f["evidence"]
            if isinstance(ev, str):
                print(f"      Evidence: {ev[:80]}")

    if len(sorted_findings) > 30:
        print(f"\n  ... and {len(sorted_findings) - 30} more findings.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    parser = argparse.ArgumentParser(description="BugHound E2E Test")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--depth", default="light", choices=["light", "deep"])
    parser.add_argument("--skip-validate", action="store_true", help="Skip Stage 5")
    args = parser.parse_args()

    start = time.time()
    job_manager = JobManager()

    print(f"\n{'#' * 70}")
    print(f"  BugHound End-to-End Test")
    print(f"  Target: {args.target}")
    print(f"  Depth: {args.depth}")
    print(f"{'#' * 70}")

    # Stage 0: Init
    workspace_id = await run_stage_0(args.target, args.depth)

    # Stage 1: Enumerate
    await run_stage_1(workspace_id)

    # Stage 2: Discover
    await run_stage_2(workspace_id, job_manager)

    # Stage 3: Analyze
    attack_surface = await run_stage_3(workspace_id)

    # Stage 4: Test
    test_result = await run_stage_4(workspace_id, job_manager, attack_surface)
    findings = test_result.get("findings", [])

    # Stage 5: Validate
    if not args.skip_validate and findings:
        await run_stage_5(workspace_id, job_manager)

    # Stage 6: Report
    _print_header(6, "Report")
    try:
        report_result = await stage_report.generate_report(workspace_id, "all")
        if report_result.get("status") == "success":
            print(f"  Reports generated:")
            for rt, path in report_result.get("reports", {}).items():
                print(f"    {rt}: {path}")
            print(f"  Findings: {report_result.get('total_findings', 0)}")
            print(f"  Confirmed: {report_result.get('confirmed', 0)}")
        else:
            print(f"  Error: {report_result.get('message', '?')}")
    except Exception as exc:
        print(f"  Report generation failed: {exc}")

    # Final report
    print_final_report(findings)

    elapsed = time.time() - start
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    print(f"\n  ⏱ Total time: {minutes}m {seconds}s")
    print(f"  📁 Workspace: {workspace_id}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
