#!/usr/bin/env python3
"""BugHound CLI — automated bug bounty scanning from the command line.

Usage:
    bughound scan <target>
    bughound scan <target> --depth deep
    bughound scan <target> --skip-nuclei --skip-validate
    bughound scan targets.txt
    bughound report <workspace_id>
    bughound list
    bughound serve

Same pipeline as the MCP server — same stages, same techniques, same code.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Add project root to path if running directly
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)


# ---------------------------------------------------------------------------
# Terminal colors (no external dependency)
# ---------------------------------------------------------------------------

class _C:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"


def _sev_color(sev: str) -> str:
    return {
        "critical": _C.RED,
        "high": _C.MAGENTA,
        "medium": _C.YELLOW,
        "low": _C.BLUE,
        "info": _C.GRAY,
    }.get(sev.lower(), _C.WHITE)


def _sev_bg(sev: str) -> str:
    return {
        "critical": _C.BG_RED,
        "high": _C.BG_MAGENTA,
        "medium": _C.BG_YELLOW,
        "low": _C.BG_BLUE,
        "info": _C.GRAY,
    }.get(sev.lower(), "")


def _progress_bar(pct: int, width: int = 30) -> str:
    filled = int(pct * width / 100)
    bar = f"{_C.CYAN}{'#' * filled}{_C.DIM}{'-' * (width - filled)}{_C.RESET}"
    return f"[{bar}] {pct}%"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = f"""{_C.CYAN}{_C.BOLD}
  ____              _   _                       _
 | __ ) _   _  __ _| | | | ___  _   _ _ __   __| |
 |  _ \\| | | |/ _` | |_| |/ _ \\| | | | '_ \\ / _` |
 | |_) | |_| | (_| |  _  | (_) | |_| | | | | (_| |
 |____/ \\__,_|\\__, |_| |_|\\___/ \\__,_|_| |_|\\__,_|
              |___/
{_C.RESET}{_C.DIM}  AI-Powered Bug Bounty Reconnaissance{_C.RESET}
"""


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

def _print_stage(stage: int, name: str) -> None:
    print(f"\n{_C.CYAN}{_C.BOLD}{'=' * 60}{_C.RESET}")
    print(f"  {_C.BOLD}Stage {stage}: {name}{_C.RESET}")
    print(f"{_C.CYAN}{'=' * 60}{_C.RESET}\n")


async def _run_init(target: str, depth: str) -> str:
    """Stage 0: Initialize workspace."""
    from bughound.core.target_classifier import classify
    from bughound.core import workspace

    _print_stage(0, "Initialize")

    classification = classify(target, depth)
    meta = await workspace.create_workspace(target, depth)
    await workspace.update_metadata(
        meta.workspace_id,
        target_type=classification.target_type,
        classification=classification.model_dump(mode="json"),
    )
    await workspace.add_stage_history(meta.workspace_id, 0, "completed")

    print(f"  {_C.DIM}Workspace:{_C.RESET}   {meta.workspace_id}")
    print(f"  {_C.DIM}Target:{_C.RESET}      {target}")
    print(f"  {_C.DIM}Type:{_C.RESET}        {classification.target_type.value}")
    print(f"  {_C.DIM}Depth:{_C.RESET}       {depth}")
    print(f"  {_C.DIM}Stages:{_C.RESET}      {classification.stages_to_run}")

    return meta.workspace_id


async def _run_enumerate(workspace_id: str) -> None:
    """Stage 1: Enumerate subdomains."""
    from bughound.stages import enumerate as stage_enumerate

    _print_stage(1, "Enumerate")

    result = await stage_enumerate.enumerate_light(workspace_id)
    if result.get("data", {}).get("skipped"):
        print(f"  {_C.DIM}Skipped (single host){_C.RESET}")
    else:
        data = result.get("data", {})
        print(f"  Subdomains: {data.get('subdomains_found', 0)}")
        print(f"  Resolved:   {data.get('resolved_count', 0)}")


async def _run_discover(workspace_id: str, job_manager: Any) -> None:
    """Stage 2: Discovery."""
    from bughound.stages import discover as stage_discover

    _print_stage(2, "Discover")

    result = await stage_discover.discover(workspace_id, job_manager)

    if result.get("status") == "job_started":
        job_id = result["job_id"]
        while True:
            await asyncio.sleep(3)
            status = await job_manager.get_status(job_id)
            if status is None:
                break

            pct = status.get("progress_pct", 0)
            msg = status.get("message", "")
            sys.stdout.write(f"\r  {_progress_bar(pct)} {_C.DIM}{msg[:45]}{_C.RESET}    ")
            sys.stdout.flush()

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                print()
                if status["status"] == "COMPLETED":
                    rs = status.get("result_summary", {})
                    _print_summary_dict(rs)
                else:
                    print(f"  {_C.RED}Job {status['status']}{_C.RESET}")
                break


async def _run_analyze(workspace_id: str) -> dict:
    """Stage 3: Analyze attack surface."""
    from bughound.stages import analyze as stage_analyze

    _print_stage(3, "Analyze")

    result = await stage_analyze.get_attack_surface(workspace_id)

    if result.get("status") == "error":
        print(f"  {_C.RED}Error: {result.get('message', '?')}{_C.RESET}")
        return result

    stats = result.get("stats", {})
    for key in ("live_hosts", "total_urls", "total_parameters", "secrets_found",
                "hidden_endpoints", "sensitive_paths", "cors_issues"):
        val = stats.get(key, 0)
        if val:
            print(f"  {_C.DIM}{key}:{_C.RESET} {val}")

    # Probe confirmed
    pc = result.get("parameter_classification", {})
    confirmed = pc.get("probe_confirmed", [])
    if confirmed:
        print(f"\n  {_C.GREEN}Probe confirmed: {len(confirmed)}{_C.RESET}")
        for p in confirmed[:5]:
            print(f"    [{p['vuln_type'].upper()}] {p['url'][:50]} ({p['probe_result']})")

    # Attack chains
    chains = result.get("attack_chains", [])
    if chains:
        print(f"\n  {_C.BOLD}Attack chains: {len(chains)}{_C.RESET}")
        for c in chains[:5]:
            sev = c.get("severity", "?").lower()
            print(f"    {_sev_color(sev)}[{sev.upper()}]{_C.RESET} {c.get('name', '?')}")

    # Immediate wins
    wins = result.get("immediate_wins", [])
    if wins:
        print(f"\n  {_C.BOLD}Immediate wins: {len(wins)}{_C.RESET}")

    tc = result.get("suggested_test_classes", [])
    print(f"\n  {_C.DIM}Test classes: {len(tc)}{_C.RESET}")

    return result


async def _run_test(
    workspace_id: str, job_manager: Any, attack_surface: dict,
) -> list[dict]:
    """Stage 4: Execute tests."""
    from bughound.stages import analyze as stage_analyze
    from bughound.stages import test as stage_test
    from bughound.core import workspace

    _print_stage(4, "Test")

    # Build scan plan
    meta = await workspace.get_workspace(workspace_id)
    target_host = meta.target
    if "://" in target_host:
        target_host = urlparse(target_host).hostname or target_host

    suggested = attack_surface.get("suggested_test_classes", [])
    if not suggested:
        suggested = [
            "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect",
            "crlf", "idor", "rce", "xxe", "header_injection",
            "graphql", "jwt", "misconfig", "default_creds",
            "cors", "bac", "csti", "cve_specific",
        ]

    scan_plan = {
        "targets": [{"host": target_host, "priority": 1, "test_classes": suggested}],
        "global_settings": {
            "nuclei_severity": "critical,high,medium,low,info",
            "nuclei_rate_limit": 100,
            "nuclei_concurrency": 25,
        },
    }

    await stage_analyze.submit_scan_plan(workspace_id, scan_plan)
    print(f"  {_C.DIM}Scan plan: {len(suggested)} test classes{_C.RESET}")

    result = await stage_test.execute_tests(workspace_id, job_manager)

    if result.get("status") == "job_started":
        job_id = result["job_id"]
        while True:
            await asyncio.sleep(5)
            status = await job_manager.get_status(job_id)
            if status is None:
                break

            pct = status.get("progress_pct", 0)
            msg = status.get("message", "")
            sys.stdout.write(f"\r  {_progress_bar(pct)} {_C.DIM}{msg[:45]}{_C.RESET}    ")
            sys.stdout.flush()

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                print()
                if status["status"] != "COMPLETED":
                    print(f"  {_C.RED}Job {status['status']}{_C.RESET}")
                break

    # Load findings
    raw = await workspace.read_data(workspace_id, "vulnerabilities/scan_results.json")
    findings = raw.get("data", raw) if isinstance(raw, dict) else (raw or [])
    return findings if isinstance(findings, list) else []


async def _run_validate(workspace_id: str, job_manager: Any) -> None:
    """Stage 5: Validate."""
    from bughound.stages import validate as stage_validate

    _print_stage(5, "Validate")

    try:
        job_id = await job_manager.create_job(workspace_id, "validate_all", "validation")
    except RuntimeError as exc:
        print(f"  {_C.RED}Error: {exc}{_C.RESET}")
        return

    async def _progress(pct: int, msg: str) -> None:
        await job_manager.update_progress(job_id, pct, msg, "validate")

    async def _run_job(jid: str) -> None:
        result = await stage_validate.validate_all(workspace_id, progress_cb=_progress)
        await job_manager.complete_job(jid, {
            "confirmed": result.get("confirmed", 0),
            "false_positives": result.get("false_positives", 0),
            "manual_review": result.get("needs_manual_review", 0),
        })

    await job_manager.start_job(job_id, _run_job(job_id))

    while True:
        await asyncio.sleep(3)
        status = await job_manager.get_status(job_id)
        if status is None:
            break

        pct = status.get("progress_pct", 0)
        msg = status.get("message", "")
        sys.stdout.write(f"\r  {_progress_bar(pct)} {_C.DIM}{msg[:45]}{_C.RESET}    ")
        sys.stdout.flush()

        if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
            print()
            if status["status"] == "COMPLETED":
                rs = status.get("result_summary", {})
                for k, v in rs.items():
                    print(f"  {k}: {v}")
            else:
                print(f"  {_C.RED}Job {status['status']}{_C.RESET}")
            break


async def _run_report(workspace_id: str) -> None:
    """Stage 6: Generate reports."""
    from bughound.stages import report as stage_report

    _print_stage(6, "Report")

    result = await stage_report.generate_report(workspace_id, "all")

    if result.get("status") == "success":
        for rt, path in result.get("reports", {}).items():
            print(f"  {_C.GREEN}{rt}{_C.RESET}: {path}")
        print(f"\n  Findings: {result.get('total_findings', 0)}")
        print(f"  Confirmed: {result.get('confirmed', 0)}")
    else:
        print(f"  {_C.RED}Error: {result.get('message', '?')}{_C.RESET}")


# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------

def _print_findings_summary(findings: list[dict]) -> None:
    """Print colored findings summary."""
    print(f"\n{_C.CYAN}{_C.BOLD}{'=' * 60}{_C.RESET}")
    print(f"  {_C.BOLD}Results{_C.RESET}")
    print(f"{_C.CYAN}{'=' * 60}{_C.RESET}\n")

    if not findings:
        print(f"  {_C.DIM}No findings.{_C.RESET}")
        return

    # Deduplicate
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in findings:
        key = (f.get("vulnerability_class", ""), f.get("endpoint", ""),
               f.get("param", f.get("description", "")))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    sev_counts = Counter(f.get("severity", "?") for f in unique)
    cls_counts = Counter(f.get("vulnerability_class", "?") for f in unique)
    needs_val = sum(1 for f in unique if f.get("needs_validation"))

    print(f"  {_C.BOLD}Total: {len(unique)}{_C.RESET}  "
          f"Definitive: {len(unique) - needs_val}  "
          f"Needs Review: {needs_val}")
    print()

    # Severity bars
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        if count:
            color = _sev_color(sev)
            bar = "#" * min(count, 40)
            print(f"  {color}{sev.upper():10s}{_C.RESET} {bar} {count}")

    # Top classes
    print(f"\n  {_C.BOLD}Vulnerability Classes:{_C.RESET}")
    for cls, count in cls_counts.most_common(15):
        print(f"    {cls:25s} {count}")

    # Finding details
    print(f"\n  {_C.DIM}{'─' * 56}{_C.RESET}")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(unique, key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    for i, f in enumerate(sorted_findings[:30], 1):
        sev = f.get("severity", "info")
        color = _sev_color(sev)
        cls = f.get("vulnerability_class", "?")
        ep = f.get("endpoint", "?")[:65]
        ev = f.get("evidence", "")
        if isinstance(ev, str) and len(ev) > 80:
            ev = ev[:80] + "..."

        val_status = f.get("validation_status", "")
        if val_status in ("CONFIRMED", "confirmed"):
            val_mark = f"{_C.GREEN}CONFIRMED{_C.RESET}"
        elif val_status == "LIKELY_FALSE_POSITIVE":
            val_mark = f"{_C.RED}FALSE POS{_C.RESET}"
        elif f.get("needs_validation"):
            val_mark = f"{_C.YELLOW}REVIEW{_C.RESET}"
        else:
            val_mark = f"{_C.GREEN}DEFINITIVE{_C.RESET}"

        print(f"\n  {i:2d}. {color}[{sev.upper():8s}]{_C.RESET} [{val_mark}] {cls}")
        print(f"      {_C.DIM}{ep}{_C.RESET}")
        if ev:
            print(f"      {ev}")

    if len(sorted_findings) > 30:
        print(f"\n  {_C.DIM}... and {len(sorted_findings) - 30} more findings{_C.RESET}")


def _print_summary_dict(d: dict) -> None:
    """Print a dict as a clean summary."""
    for k, v in d.items():
        if isinstance(v, dict):
            flat = ", ".join(f"{sk}: {sv}" for sk, sv in v.items() if sv)
            if flat:
                print(f"  {_C.DIM}{k}:{_C.RESET} {flat}")
        elif v or v == 0:
            print(f"  {_C.DIM}{k}:{_C.RESET} {v}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

async def cmd_scan(args: argparse.Namespace) -> None:
    """Run full scan pipeline."""
    from bughound.core.job_manager import JobManager

    print(_BANNER)
    print(f"  {_C.BOLD}Target:{_C.RESET} {args.target}")
    print(f"  {_C.BOLD}Depth:{_C.RESET}  {args.depth}")
    if args.skip_nuclei:
        print(f"  {_C.YELLOW}Nuclei: skipped{_C.RESET}")
    if args.skip_validate:
        print(f"  {_C.YELLOW}Validation: skipped{_C.RESET}")
    print()

    start = time.time()
    job_manager = JobManager()

    # Stage 0
    workspace_id = await _run_init(args.target, args.depth)

    # Stage 1
    await _run_enumerate(workspace_id)

    # Stage 2
    await _run_discover(workspace_id, job_manager)

    # Stage 3
    attack_surface = await _run_analyze(workspace_id)

    # Stage 4
    findings = await _run_test(workspace_id, job_manager, attack_surface)

    # Stage 5
    if not args.skip_validate and findings:
        await _run_validate(workspace_id, job_manager)

    # Stage 6
    await _run_report(workspace_id)

    # Summary
    _print_findings_summary(findings)

    elapsed = time.time() - start
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    print(f"\n  {_C.DIM}Time: {minutes}m {seconds}s{_C.RESET}")
    print(f"  {_C.DIM}Workspace: {workspace_id}{_C.RESET}")
    print()


async def cmd_report(args: argparse.Namespace) -> None:
    """Generate report for existing workspace."""
    print(_BANNER)
    await _run_report(args.workspace_id)


async def cmd_list(args: argparse.Namespace) -> None:
    """List workspaces."""
    from bughound.core import workspace

    print(_BANNER)
    workspaces = await workspace.list_workspaces()

    if not workspaces:
        print(f"  {_C.DIM}No workspaces found.{_C.RESET}")
        return

    print(f"  {_C.BOLD}{len(workspaces)} workspace(s){_C.RESET}\n")
    for ws in workspaces:
        # WorkspaceSummary is a Pydantic model, not a dict
        state_raw = getattr(ws, "state", "?")
        state = state_raw.value if hasattr(state_raw, "value") else str(state_raw)
        target = str(getattr(ws, "target", "?"))
        ws_id = str(getattr(ws, "workspace_id", "?"))
        state_color = _C.GREEN if "completed" in state.lower() else _C.YELLOW
        print(f"  {state_color}{state:12s}{_C.RESET} {target[:40]:40s} {_C.DIM}{ws_id}{_C.RESET}")


async def cmd_serve(args: argparse.Namespace) -> None:
    """Start MCP server."""
    from bughound.server import mcp
    await mcp.run_async()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bughound",
        description="BugHound - AI-Powered Bug Bounty Reconnaissance",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Run full scan pipeline")
    scan_parser.add_argument("target", help="Target URL, domain, or file with targets")
    scan_parser.add_argument("--depth", default="light", choices=["light", "deep"],
                             help="Scan depth (default: light)")
    scan_parser.add_argument("--skip-nuclei", action="store_true",
                             help="Skip nuclei template scanning")
    scan_parser.add_argument("--skip-validate", action="store_true",
                             help="Skip Stage 5 validation")

    # report
    report_parser = subparsers.add_parser("report", help="Generate report for workspace")
    report_parser.add_argument("workspace_id", help="Workspace ID")

    # list
    subparsers.add_parser("list", help="List workspaces")

    # serve
    subparsers.add_parser("serve", help="Start MCP server")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    cmd_map = {
        "scan": cmd_scan,
        "report": cmd_report,
        "list": cmd_list,
        "serve": cmd_serve,
    }

    try:
        asyncio.run(cmd_map[args.command](args))
    except KeyboardInterrupt:
        print(f"\n{_C.YELLOW}Interrupted.{_C.RESET}")
        sys.exit(130)


if __name__ == "__main__":
    main()
