#!/usr/bin/env python3
"""BugHound CLI -- automated bug bounty scanning from the command line.

Usage:
    bughound scan <target>                   # Full pipeline (Stages 0-6)
    bughound scan <target> --depth deep
    bughound scan <target> --skip-nuclei --skip-validate
    bughound scan targets.txt
    bughound recon <target>                  # Stages 0-2 only
    bughound analyze <workspace_id>          # Stage 3 only
    bughound test <workspace_id>             # Stage 4 only
    bughound validate <workspace_id>         # Stage 5 only
    bughound report <workspace_id>           # Stage 6 only
    bughound list                            # List workspaces
    bughound serve                           # MCP server

Same pipeline as the MCP server -- same stages, same techniques, same code.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
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


def _strip_colors() -> None:
    """Replace all color codes with empty strings (--no-color)."""
    for attr in dir(_C):
        if not attr.startswith('_'):
            setattr(_C, attr, '')


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
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    """Configure structlog for CLI output."""
    import structlog

    if verbose:
        # Show all debug/info logs to stderr in colored format
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stderr,
            level=logging.DEBUG,
            force=True,
        )
        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.dev.ConsoleRenderer(colors=True),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
        )
    else:
        # Suppress all logs
        logging.basicConfig(level=logging.CRITICAL, force=True)
        structlog.configure(
            processors=[structlog.dev.ConsoleRenderer()],
            wrapper_class=structlog.stdlib.BoundLogger,
            logger_factory=structlog.stdlib.LoggerFactory(),
        )


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
{_C.RESET}{_C.DIM}  MCP-Based Security Automation Framework{_C.RESET}
"""


def _get_banner() -> str:
    """Return the banner string (respects current color state)."""
    return f"""{_C.CYAN}{_C.BOLD}
  ____              _   _                       _
 | __ ) _   _  __ _| | | | ___  _   _ _ __   __| |
 |  _ \\| | | |/ _` | |_| |/ _ \\| | | | '_ \\ / _` |
 | |_) | |_| | (_| |  _  | (_) | |_| | | | | (_| |
 |____/ \\__,_|\\__, |_| |_|\\___/ \\__,_|_| |_|\\__,_|
              |___/
{_C.RESET}{_C.DIM}  MCP-Based Security Automation Framework{_C.RESET}
"""


# ---------------------------------------------------------------------------
# Workspace validation helper
# ---------------------------------------------------------------------------

async def _require_workspace(workspace_id: str) -> Any:
    """Validate that a workspace exists, exit with error if not."""
    from bughound.core import workspace

    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        print(f"{_C.RED}Error: workspace '{workspace_id}' not found.{_C.RESET}",
              file=sys.stderr)
        sys.exit(1)
    return meta


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

def _print_stage(stage: int, name: str) -> None:
    print(f"\n{_C.CYAN}{_C.BOLD}{'=' * 60}{_C.RESET}")
    print(f"  {_C.BOLD}Stage {stage}: {name}{_C.RESET}")
    print(f"{_C.CYAN}{'=' * 60}{_C.RESET}\n")


async def _run_init(target: str, depth: str, verbose: bool = False) -> str:
    """Stage 0: Initialize workspace."""
    from bughound.core.target_classifier import classify
    from bughound.core import workspace

    _print_stage(0, "Initialize")

    if verbose:
        print(f"  {_C.DIM}[*] Classifying target...{_C.RESET}", file=sys.stderr)

    classification = classify(target, depth)

    if classification.target_type.value == "broad_domain":
        print(f"\n  {_C.YELLOW}Warning: '{target}' is a broad domain.{_C.RESET}")
        print(f"  {_C.YELLOW}This will enumerate and probe all subdomains.{_C.RESET}")
        try:
            confirm = input(f"  {_C.BOLD}Continue? [Y/n]: {_C.RESET}").strip().lower()
            if confirm == "n":
                print(f"  {_C.DIM}Aborted.{_C.RESET}")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)

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

    if verbose:
        print(f"  {_C.DIM}[*] Workspace created at {meta.workspace_id}{_C.RESET}",
              file=sys.stderr)

    return meta.workspace_id


async def _run_enumerate(workspace_id: str, verbose: bool = False) -> None:
    """Stage 1: Enumerate subdomains."""
    from bughound.stages import enumerate as stage_enumerate

    _print_stage(1, "Enumerate")

    if verbose:
        print(f"  {_C.DIM}[*] Running subdomain enumeration (subfinder, crtsh)...{_C.RESET}",
              file=sys.stderr)

    result = await stage_enumerate.enumerate_light(workspace_id)
    if result.get("data", {}).get("skipped"):
        print(f"  {_C.DIM}Skipped (single host){_C.RESET}")
    else:
        data = result.get("data", {})
        print(f"  Subdomains: {data.get('subdomains_found', 0)}")
        print(f"  Resolved:   {data.get('resolved_count', 0)}")

        if verbose:
            sources = data.get("sources", {})
            if sources:
                for src, count in sources.items():
                    print(f"  {_C.DIM}[*] {src}: {count} subdomains{_C.RESET}",
                          file=sys.stderr)


def _make_host_filter(max_hosts: int):
    """Create a host filter callback for discover stage.

    Returns an async function that shows live hosts after httpx probing
    and lets the user select which to continue scanning.
    """

    async def _filter(live_hosts: list[dict]) -> list[dict] | None:
        if len(live_hosts) <= 5:
            return None  # Small enough, scan all

        if max_hosts > 0:
            selected = live_hosts[:max_hosts]
            print(f"\n  {_C.GREEN}Auto-selected {len(selected)} of {len(live_hosts)} live hosts (--max-hosts {max_hosts}){_C.RESET}")
            return selected

        # Interactive selection
        print(f"\n  {_C.BOLD}Found {len(live_hosts)} live hosts:{_C.RESET}\n")

        for i, h in enumerate(live_hosts[:30], 1):
            url = h.get("url", "?")
            status = h.get("status_code", "?")
            title = h.get("title", "")
            techs = h.get("technologies", [])
            tech_str = f" [{', '.join(techs[:3])}]" if techs else ""

            status_color = _C.GREEN if status == 200 else _C.YELLOW if status in (301, 302) else _C.RED
            title_str = f" {title[:30]}" if title else ""

            print(
                f"  {_C.CYAN}{i:3d}{_C.RESET}. "
                f"{status_color}[{status}]{_C.RESET} "
                f"{url[:50]}"
                f"{_C.DIM}{title_str}{tech_str}{_C.RESET}"
            )

        if len(live_hosts) > 30:
            print(f"  {_C.DIM}... and {len(live_hosts) - 30} more{_C.RESET}")

        print(f"\n  Options:")
        print(f"    {_C.BOLD}3{_C.RESET}      — scan only host #3")
        print(f"    {_C.BOLD}1,3,5{_C.RESET}  — scan specific hosts")
        print(f"    {_C.BOLD}1-10{_C.RESET}   — scan hosts 1 through 10")
        print(f"    {_C.BOLD}all{_C.RESET}    — scan all {len(live_hosts)} hosts")

        try:
            choice = input(f"\n  {_C.BOLD}Select [{_C.GREEN}all{_C.RESET}{_C.BOLD}]: {_C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            return None  # Scan all on interrupt

        if not choice or choice.lower() == "all":
            return None  # Scan all

        if "-" in choice and not choice.startswith("-"):
            parts = choice.split("-")
            try:
                start = int(parts[0]) - 1
                end = int(parts[1])
                selected = live_hosts[start:end]
            except (ValueError, IndexError):
                return None
        elif "," in choice:
            try:
                indices = [int(x.strip()) - 1 for x in choice.split(",")]
                selected = [live_hosts[i] for i in indices if 0 <= i < len(live_hosts)]
            except (ValueError, IndexError):
                return None
        else:
            try:
                n = int(choice)
                if 1 <= n <= len(live_hosts):
                    selected = [live_hosts[n - 1]]
                else:
                    return None
            except ValueError:
                return None

        print(f"  {_C.GREEN}Selected {len(selected)} host(s) — continuing scan{_C.RESET}\n")
        return selected

    return _filter


async def _run_discover(workspace_id: str, job_manager: Any,
                        verbose: bool = False, max_hosts: int = 0,
                        timeout_mins: int = 60) -> None:
    """Stage 2: Discovery."""
    from bughound.stages import discover as stage_discover

    _print_stage(2, "Discover")

    if verbose:
        print(f"  {_C.DIM}[*] Probing live hosts with httpx...{_C.RESET}",
              file=sys.stderr)

    # Create host filter callback for interactive selection
    host_filter = _make_host_filter(max_hosts)

    # Run discover synchronously (not as background job) because input()
    # for interactive host selection requires stdin access.
    # Pass job_manager=None to force synchronous execution.
    _spinner_task: asyncio.Task | None = None

    async def _spin():
        """Print dots while waiting."""
        chars = ["|", "/", "-", "\\"]
        i = 0
        while True:
            sys.stdout.write(f"\r  {_C.DIM}[{chars[i % 4]}] Discovery running...{_C.RESET}  ")
            sys.stdout.flush()
            i += 1
            await asyncio.sleep(1)

    # Wrap host_filter to pause spinner during interactive prompt
    _original_filter = host_filter

    async def _filter_with_spinner_pause(live_hosts: list) -> list | None:
        nonlocal _spinner_task
        # Stop spinner so input() prompt is visible
        if _spinner_task and not _spinner_task.done():
            _spinner_task.cancel()
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()
        result = await _original_filter(live_hosts)
        # Restart spinner for remaining discovery
        _spinner_task = asyncio.create_task(_spin())
        return result

    _spinner_task = asyncio.create_task(_spin())
    try:
        result = await asyncio.wait_for(
            stage_discover.discover(
                workspace_id, job_manager=None,
                host_filter_cb=_filter_with_spinner_pause,
            ),
            timeout=timeout_mins * 60,
        )
    except asyncio.TimeoutError:
        print(f"\n  {_C.RED}Discovery timed out after {timeout_mins} minutes{_C.RESET}")
        result = {"status": "error", "message": "Discovery timed out"}
    finally:
        if _spinner_task and not _spinner_task.done():
            _spinner_task.cancel()
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

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

            if verbose and msg:
                print(f"  {_C.DIM}[*] {msg}{_C.RESET}", file=sys.stderr)

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                print()
                if status["status"] == "COMPLETED":
                    rs = status.get("result_summary", {})
                    _print_summary_dict(rs)
                else:
                    print(f"  {_C.RED}Job {status['status']}{_C.RESET}")
                break
    elif result.get("status") == "success":
        # Synchronous result
        data = result.get("data", {})
        if isinstance(data, dict):
            _print_summary_dict(data)


async def _run_analyze(workspace_id: str, verbose: bool = False) -> dict:
    """Stage 3: Analyze attack surface."""
    from bughound.stages import analyze as stage_analyze

    _print_stage(3, "Analyze")

    if verbose:
        print(f"  {_C.DIM}[*] Building attack surface model...{_C.RESET}",
              file=sys.stderr)
        print(f"  {_C.DIM}[*] Classifying parameters, detecting patterns...{_C.RESET}",
              file=sys.stderr)

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

    if verbose:
        for cls in tc:
            print(f"  {_C.DIM}[*] Suggested test class: {cls}{_C.RESET}",
                  file=sys.stderr)

    return result


async def _run_test(
    workspace_id: str, job_manager: Any, attack_surface: dict,
    verbose: bool = False,
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

    if verbose:
        print(f"  {_C.DIM}[*] Running {len(suggested)} techniques in parallel...{_C.RESET}",
              file=sys.stderr)
        for cls in suggested:
            print(f"  {_C.DIM}[*] Queued: {cls}{_C.RESET}", file=sys.stderr)

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

            if verbose and msg:
                print(f"  {_C.DIM}[*] {msg}{_C.RESET}", file=sys.stderr)

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                print()
                if status["status"] != "COMPLETED":
                    print(f"  {_C.RED}Job {status['status']}{_C.RESET}")
                else:
                    rs = status.get("result_summary", {})
                    if verbose and rs:
                        for k, v in rs.items():
                            print(f"  {_C.DIM}[*] {k}: {v}{_C.RESET}",
                                  file=sys.stderr)
                break

    # Load findings
    raw = await workspace.read_data(workspace_id, "vulnerabilities/scan_results.json")
    findings = raw.get("data", raw) if isinstance(raw, dict) else (raw or [])
    return findings if isinstance(findings, list) else []


async def _run_validate(workspace_id: str, job_manager: Any,
                        verbose: bool = False) -> None:
    """Stage 5: Validate."""
    from bughound.stages import validate as stage_validate

    _print_stage(5, "Validate")

    if verbose:
        print(f"  {_C.DIM}[*] Validating findings with surgical probes...{_C.RESET}",
              file=sys.stderr)

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

        if verbose and msg:
            print(f"  {_C.DIM}[*] {msg}{_C.RESET}", file=sys.stderr)

        if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
            print()
            if status["status"] == "COMPLETED":
                rs = status.get("result_summary", {})
                for k, v in rs.items():
                    print(f"  {k}: {v}")
            else:
                print(f"  {_C.RED}Job {status['status']}{_C.RESET}")
            break


async def _run_report(workspace_id: str, verbose: bool = False) -> None:
    """Stage 6: Generate reports."""
    from bughound.stages import report as stage_report

    _print_stage(6, "Report")

    if verbose:
        print(f"  {_C.DIM}[*] Generating HTML, JSON, and Markdown reports...{_C.RESET}",
              file=sys.stderr)

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

def _quiet_summary(findings: list[dict], target: str, workspace_id: str) -> str:
    """Build a single-line quiet summary."""
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
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sev_counts.get(sev, 0)
        if count:
            parts.append(f"{count} {sev}")

    severity_str = f" ({', '.join(parts)})" if parts else ""
    return f"BugHound: {len(unique)} findings{severity_str} on {target} -- workspace: {workspace_id}"


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
    print(f"\n  {_C.DIM}{'---' * 19}{_C.RESET}")
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
    """Run full scan pipeline (Stages 0-6)."""
    from bughound.core.job_manager import JobManager

    verbose = args.verbose
    quiet = args.quiet

    if not args.resume and not args.target:
        print(f"  {_C.RED}Error: target is required (or use --resume){_C.RESET}")
        sys.exit(1)

    # JSON output mode suppresses terminal output
    if args.output == "json":
        quiet = True

    # Set proxy if specified
    proxy = getattr(args, "proxy", None)
    if proxy:
        from bughound.tools.testing.injection_tester import set_proxy
        set_proxy(proxy)
        if not quiet:
            print(f"  {_C.YELLOW}Proxy: {proxy}{_C.RESET}")

    resume_stage = 0
    workspace_id = None

    if args.resume:
        workspace_id = args.resume
        # Check workspace exists
        from bughound.core import workspace
        meta = await workspace.get_workspace(workspace_id)
        if meta is None:
            print(f"  {_C.RED}Error: Workspace '{workspace_id}' not found{_C.RESET}")
            sys.exit(1)

        import os
        from bughound.config.settings import WORKSPACE_BASE_DIR
        ws_path = WORKSPACE_BASE_DIR / workspace_id

        # Determine resume point
        has_scan_results = (ws_path / "vulnerabilities" / "scan_results.json").exists()
        has_attack_surface = (ws_path / "analysis" / "attack_surface.json").exists()
        has_crawled = (ws_path / "urls" / "crawled.json").exists()
        has_hosts = (ws_path / "hosts" / "live_hosts.json").exists()

        if has_scan_results:
            resume_stage = 5
        elif has_attack_surface:
            resume_stage = 4
        elif has_crawled:
            resume_stage = 3
        elif has_hosts:
            resume_stage = 2
        else:
            resume_stage = 1

        if not quiet:
            print(_get_banner())
            print(f"  {_C.GREEN}Resuming from Stage {resume_stage}{_C.RESET}")
            print(f"  {_C.DIM}Workspace:{_C.RESET} {workspace_id}")
            print()
    elif not quiet:
        print(_get_banner())
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
    if resume_stage <= 0 and workspace_id is None:
        try:
            workspace_id = await _run_init(args.target, args.depth, verbose=verbose)
        except ValueError as exc:
            print(f"  {_C.RED}Error: {exc}{_C.RESET}")
            sys.exit(1)

    # Stage 1
    if resume_stage <= 1:
        await _run_enumerate(workspace_id, verbose=verbose)

    # Stage 2 (host selection happens inside discover after httpx)
    if resume_stage <= 2:
        await _run_discover(workspace_id, job_manager, verbose=verbose,
                            max_hosts=getattr(args, "max_hosts", 0),
                            timeout_mins=getattr(args, "timeout", 60))

    # Stage 3
    if resume_stage <= 3:
        attack_surface = await _run_analyze(workspace_id, verbose=verbose)
    else:
        # Load existing attack surface for later stages
        from bughound.stages import analyze as stage_analyze
        attack_surface = await stage_analyze.get_attack_surface(workspace_id)

    # Stage 4
    if resume_stage <= 4:
        findings = await _run_test(workspace_id, job_manager, attack_surface,
                                   verbose=verbose)
    else:
        # Load existing findings
        from bughound.core import workspace as ws_mod
        raw = await ws_mod.read_data(workspace_id, "vulnerabilities/scan_results.json")
        findings = raw.get("data", raw) if isinstance(raw, dict) else (raw or [])
        findings = findings if isinstance(findings, list) else []

    # Stage 5
    if resume_stage <= 5:
        if not args.skip_validate and findings:
            await _run_validate(workspace_id, job_manager, verbose=verbose)

    # Stage 6
    await _run_report(workspace_id, verbose=verbose)

    # JSON output mode: dump findings as JSON and return
    if args.output == "json":
        import json
        from bughound.core import workspace as ws_mod2
        raw = await ws_mod2.read_data(workspace_id, "vulnerabilities/scan_results.json")
        json_findings = raw.get("data", raw) if isinstance(raw, dict) else (raw or [])
        print(json.dumps(json_findings, indent=2))
        return

    # Summary
    if quiet:
        print(_quiet_summary(findings, args.target, workspace_id))
    else:
        _print_findings_summary(findings)

        elapsed = time.time() - start
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        print(f"\n  {_C.DIM}Time: {minutes}m {seconds}s{_C.RESET}")
        print(f"  {_C.DIM}Workspace: {workspace_id}{_C.RESET}")
        print()


async def cmd_recon(args: argparse.Namespace) -> None:
    """Run reconnaissance only (Stages 0-2)."""
    from bughound.core.job_manager import JobManager

    verbose = args.verbose
    quiet = args.quiet

    if not quiet:
        print(_get_banner())
        print(f"  {_C.BOLD}Target:{_C.RESET} {args.target}")
        print(f"  {_C.BOLD}Depth:{_C.RESET}  {args.depth}")
        print(f"  {_C.BOLD}Mode:{_C.RESET}   recon only (Stages 0-2)")
        print()

    start = time.time()
    job_manager = JobManager()

    # Stage 0
    try:
        workspace_id = await _run_init(args.target, args.depth, verbose=verbose)
    except ValueError as exc:
        print(f"  {_C.RED}Error: {exc}{_C.RESET}")
        sys.exit(1)

    # Stage 1
    await _run_enumerate(workspace_id, verbose=verbose)

    # Host selection for broad domains
    # Stage 2 (host selection happens inside discover after httpx)
    await _run_discover(workspace_id, job_manager, verbose=verbose,
                        max_hosts=getattr(args, "max_hosts", 0),
                        timeout_mins=60)

    if quiet:
        print(f"BugHound recon complete on {args.target} -- workspace: {workspace_id}")
    else:
        # Print recon summary
        from bughound.core import workspace
        print(f"\n{_C.CYAN}{_C.BOLD}{'=' * 60}{_C.RESET}")
        print(f"  {_C.BOLD}Recon Summary{_C.RESET}")
        print(f"{_C.CYAN}{'=' * 60}{_C.RESET}\n")

        # Try to load discovered data for summary
        hosts_data = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
        urls_data = await workspace.read_data(workspace_id, "urls/crawled_urls.json")
        subs_data = await workspace.read_data(workspace_id, "subdomains/all_subdomains.json")

        hosts_list = hosts_data if isinstance(hosts_data, list) else (
            hosts_data.get("data", []) if isinstance(hosts_data, dict) else [])
        urls_list = urls_data if isinstance(urls_data, list) else (
            urls_data.get("data", []) if isinstance(urls_data, dict) else [])
        subs_list = subs_data if isinstance(subs_data, list) else (
            subs_data.get("data", []) if isinstance(subs_data, dict) else [])

        print(f"  Subdomains found:  {len(subs_list)}")
        print(f"  Live hosts:        {len(hosts_list)}")
        print(f"  URLs discovered:   {len(urls_list)}")

        elapsed = time.time() - start
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        print(f"\n  {_C.DIM}Time: {minutes}m {seconds}s{_C.RESET}")
        print(f"  {_C.DIM}Workspace: {workspace_id}{_C.RESET}")
        print(f"\n  {_C.DIM}Next: bughound analyze {workspace_id}{_C.RESET}")
        print()


async def cmd_analyze(args: argparse.Namespace) -> None:
    """Run Stage 3 (analyze attack surface) on existing workspace."""
    verbose = args.verbose
    quiet = args.quiet

    await _require_workspace(args.workspace_id)

    if not quiet:
        print(_get_banner())
        print(f"  {_C.BOLD}Workspace:{_C.RESET} {args.workspace_id}")
        print(f"  {_C.BOLD}Mode:{_C.RESET}      analyze only (Stage 3)")
        print()

    result = await _run_analyze(args.workspace_id, verbose=verbose)

    if quiet:
        tc = result.get("suggested_test_classes", [])
        stats = result.get("stats", {})
        print(f"BugHound analyze: {stats.get('total_urls', 0)} urls, "
              f"{stats.get('total_parameters', 0)} params, "
              f"{len(tc)} test classes -- workspace: {args.workspace_id}")
    else:
        print(f"\n  {_C.DIM}Next: bughound test {args.workspace_id}{_C.RESET}")
        print()


async def cmd_test(args: argparse.Namespace) -> None:
    """Run Stage 4 (execute tests) on existing workspace."""
    from bughound.core.job_manager import JobManager

    verbose = args.verbose
    quiet = args.quiet

    await _require_workspace(args.workspace_id)

    if not quiet:
        print(_get_banner())
        print(f"  {_C.BOLD}Workspace:{_C.RESET} {args.workspace_id}")
        print(f"  {_C.BOLD}Mode:{_C.RESET}      test only (Stage 4)")
        print()

    job_manager = JobManager()

    # Get attack surface (must have been generated by analyze stage)
    from bughound.stages import analyze as stage_analyze
    attack_surface = await stage_analyze.get_attack_surface(args.workspace_id)

    if attack_surface.get("status") == "error":
        print(f"  {_C.RED}Error: No attack surface found. Run 'bughound analyze {args.workspace_id}' first.{_C.RESET}")
        sys.exit(1)

    findings = await _run_test(args.workspace_id, job_manager, attack_surface,
                               verbose=verbose)

    if quiet:
        sev_counts = Counter(f.get("severity", "?") for f in findings)
        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count:
                parts.append(f"{count} {sev}")
        severity_str = f" ({', '.join(parts)})" if parts else ""
        print(f"BugHound test: {len(findings)} findings{severity_str} -- workspace: {args.workspace_id}")
    else:
        _print_findings_summary(findings)
        print(f"\n  {_C.DIM}Next: bughound validate {args.workspace_id}{_C.RESET}")
        print()


async def cmd_validate(args: argparse.Namespace) -> None:
    """Run Stage 5 (validate findings) on existing workspace."""
    from bughound.core.job_manager import JobManager

    verbose = args.verbose
    quiet = args.quiet

    await _require_workspace(args.workspace_id)

    if not quiet:
        print(_get_banner())
        print(f"  {_C.BOLD}Workspace:{_C.RESET} {args.workspace_id}")
        print(f"  {_C.BOLD}Mode:{_C.RESET}      validate only (Stage 5)")
        print()

    job_manager = JobManager()
    await _run_validate(args.workspace_id, job_manager, verbose=verbose)

    if quiet:
        print(f"BugHound validate complete -- workspace: {args.workspace_id}")
    else:
        print(f"\n  {_C.DIM}Next: bughound report {args.workspace_id}{_C.RESET}")
        print()


async def cmd_report(args: argparse.Namespace) -> None:
    """Generate report for existing workspace."""
    verbose = args.verbose
    quiet = args.quiet

    await _require_workspace(args.workspace_id)

    if not quiet:
        print(_get_banner())
    await _run_report(args.workspace_id, verbose=verbose)


async def cmd_list(args: argparse.Namespace) -> None:
    """List workspaces."""
    from bughound.core import workspace

    quiet = args.quiet

    if not quiet:
        print(_get_banner())

    workspaces = await workspace.list_workspaces()

    if not workspaces:
        if quiet:
            print("BugHound: 0 workspaces")
        else:
            print(f"  {_C.DIM}No workspaces found.{_C.RESET}")
        return

    if quiet:
        print(f"BugHound: {len(workspaces)} workspace(s)")
        for ws in workspaces:
            ws_id = str(getattr(ws, "workspace_id", "?"))
            target = str(getattr(ws, "target", "?"))
            print(f"  {ws_id} {target}")
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


async def cmd_agent(args: argparse.Namespace) -> None:
    """Run AI-powered autonomous scanning."""
    import os
    from pathlib import Path

    # Validate: need either target or --resume
    if not args.target and not getattr(args, "resume", None):
        print(f"  {_C.RED}Error: target is required (or use --resume){_C.RESET}")
        sys.exit(1)

    # Load .env file if it exists (project root or current dir)
    for env_path in [Path(".env"), Path(__file__).resolve().parent.parent / ".env"]:
        if env_path.is_file():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
            break

    # Auto-detect provider from API keys if not explicitly set
    if not args.provider:
        env_to_provider = {
            "ANTHROPIC_API_KEY": "anthropic",
            "OPENAI_API_KEY": "openai",
            "XAI_API_KEY": "grok",
            "OPENROUTER_API_KEY": "openrouter",
        }
        for env_var, provider_name in env_to_provider.items():
            if os.environ.get(env_var):
                args.provider = provider_name
                break
        if not args.provider:
            print(f"  {_C.RED}Error: --provider required, or set API key in .env{_C.RESET}")
            sys.exit(1)

    # Resolve API key: --api-key flag > env var > .env
    api_key = args.api_key
    if not api_key:
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "grok": "XAI_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        env_var = env_map.get(args.provider, "")
        api_key = os.environ.get(env_var, "")
        if not api_key:
            print(f"  {_C.RED}Error: No API key. Use --api-key or set {env_var} in .env{_C.RESET}")
            sys.exit(1)

    resume_workspace_id = None
    if getattr(args, "resume", None):
        resume_workspace_id = args.resume
        from bughound.core import workspace
        meta = await workspace.get_workspace(resume_workspace_id)
        if meta is None:
            print(f"  {_C.RED}Error: Workspace '{resume_workspace_id}' not found{_C.RESET}")
            sys.exit(1)

        import os as _os
        from bughound.config.settings import WORKSPACE_BASE_DIR
        ws_path = WORKSPACE_BASE_DIR / resume_workspace_id

        has_scan_results = (ws_path / "vulnerabilities" / "scan_results.json").exists()
        has_attack_surface = (ws_path / "analysis" / "attack_surface.json").exists()
        has_crawled = (ws_path / "urls" / "crawled.json").exists()
        has_hosts = (ws_path / "hosts" / "live_hosts.json").exists()

        if has_scan_results:
            resume_stage = 5
        elif has_attack_surface:
            resume_stage = 4
        elif has_crawled:
            resume_stage = 3
        elif has_hosts:
            resume_stage = 2
        else:
            resume_stage = 1

        print(f"  {_C.GREEN}Resuming from Stage {resume_stage}{_C.RESET}")
        print(f"  {_C.DIM}Workspace:{_C.RESET} {resume_workspace_id}")
        print()

    from bughound.agent import run_agent

    # Determine from_phase
    from_phase = getattr(args, "from_phase", None)
    if from_phase and not resume_workspace_id:
        print(f"  {_C.RED}Error: --from-phase requires --resume{_C.RESET}")
        sys.exit(1)

    await run_agent(
        target=args.target,
        provider_name=args.provider,
        api_key=api_key,
        model=args.model,
        depth=args.depth,
        max_iterations=args.max_iterations,
        verbose=getattr(args, "verbose", False),
        resume_workspace_id=resume_workspace_id,
        from_phase=from_phase,
    )


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
        description="BugHound - MCP-Based Security Automation Framework",
    )
    parser.add_argument("--version", action="version", version="BugHound 1.0.0")

    # Shared flags (available on every subcommand in any position)
    _common = argparse.ArgumentParser(add_help=False)
    _common.add_argument("-v", "--verbose", action="store_true",
                         help="Show detailed activity logs")
    _common.add_argument("-q", "--quiet", action="store_true",
                         help="Minimal output (just findings count)")
    _common.add_argument("--no-color", action="store_true",
                         help="Disable ANSI colors")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    scan_parser = subparsers.add_parser("scan", parents=[_common],
                                        help="Run full scan pipeline (Stages 0-6)")
    scan_parser.add_argument("target", nargs="?", default=None,
                             help="Target URL, domain, or file with targets")
    scan_parser.add_argument("--depth", default="light", choices=["light", "deep"],
                             help="Scan depth (default: light)")
    scan_parser.add_argument("--skip-nuclei", action="store_true",
                             help="Skip nuclei template scanning")
    scan_parser.add_argument("--skip-validate", action="store_true",
                             help="Skip Stage 5 validation")
    scan_parser.add_argument("--resume", metavar="WORKSPACE_ID",
                             help="Resume scan from existing workspace")
    scan_parser.add_argument("--output", choices=["text", "json"], default="text",
                             help="Output format (default: text)")
    scan_parser.add_argument("--max-hosts", type=int, default=0, metavar="N",
                             help="Max hosts to scan for broad domains (0=ask interactively)")
    scan_parser.add_argument("--proxy", default=None, metavar="URL",
                             help="HTTP proxy for all requests (e.g., http://127.0.0.1:8080)")
    scan_parser.add_argument("--timeout", type=int, default=60, metavar="MINS",
                             help="Max time per stage in minutes (default: 60)")

    # recon
    recon_parser = subparsers.add_parser("recon", parents=[_common],
                                         help="Stages 0-2 only (init + enumerate + discover)")
    recon_parser.add_argument("target", help="Target URL, domain, or file with targets")
    recon_parser.add_argument("--depth", default="light", choices=["light", "deep"],
                              help="Scan depth (default: light)")
    recon_parser.add_argument("--max-hosts", type=int, default=0, metavar="N",
                             help="Max hosts to scan for broad domains (0=ask interactively)")
    recon_parser.add_argument("--proxy", default=None, metavar="URL",
                             help="HTTP proxy for all requests (e.g., http://127.0.0.1:8080)")

    # analyze
    analyze_parser = subparsers.add_parser("analyze", parents=[_common],
                                           help="Stage 3 only (attack surface analysis)")
    analyze_parser.add_argument("workspace_id", help="Workspace ID")

    # test
    test_parser = subparsers.add_parser("test", parents=[_common],
                                        help="Stage 4 only (execute tests)")
    test_parser.add_argument("workspace_id", help="Workspace ID")

    # validate
    validate_parser = subparsers.add_parser("validate", parents=[_common],
                                            help="Stage 5 only (validate findings)")
    validate_parser.add_argument("workspace_id", help="Workspace ID")

    # report
    report_parser = subparsers.add_parser("report", parents=[_common],
                                          help="Stage 6 only (generate reports)")
    report_parser.add_argument("workspace_id", help="Workspace ID")

    # list
    subparsers.add_parser("list", parents=[_common], help="List workspaces")

    # agent
    agent_parser = subparsers.add_parser("agent", parents=[_common],
                                         help="AI-powered autonomous scanning")
    agent_parser.add_argument("target", nargs="?", default=None,
                              help="Target URL or domain (not needed with --resume)")
    agent_parser.add_argument("--provider", default=None,
                              choices=["anthropic", "openai", "grok", "openrouter"],
                              help="AI provider (auto-detected from .env if not set)")
    agent_parser.add_argument("--api-key", default=None,
                              help="API key (or set in .env / environment)")
    agent_parser.add_argument("--model", default=None,
                              help="Model name (default: provider's best)")
    agent_parser.add_argument("--depth", default="light", choices=["light", "deep"],
                              help="Scan depth (default: light)")
    agent_parser.add_argument("--max-iterations", type=int, default=50,
                              help="Max AI reasoning steps (default: 50)")
    agent_parser.add_argument("--resume", metavar="WORKSPACE_ID",
                              help="Resume scan from existing workspace")
    agent_parser.add_argument("--from-phase", type=int, default=None, choices=[1, 2, 3, 4],
                              help="Start from specific phase (1=recon, 2=test, 3=AI validation, 4=report). Requires --resume")

    # serve
    subparsers.add_parser("serve", parents=[_common], help="Start MCP server")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Handle --no-color
    if args.no_color:
        _strip_colors()

    # Handle conflicting flags
    if getattr(args, 'verbose', False) and getattr(args, 'quiet', False):
        print("Error: --verbose and --quiet cannot be used together.",
              file=sys.stderr)
        sys.exit(1)

    # Setup logging based on verbose flag
    _setup_logging(getattr(args, 'verbose', False))

    cmd_map = {
        "scan": cmd_scan,
        "recon": cmd_recon,
        "analyze": cmd_analyze,
        "test": cmd_test,
        "validate": cmd_validate,
        "report": cmd_report,
        "list": cmd_list,
        "agent": cmd_agent,
        "serve": cmd_serve,
    }

    try:
        asyncio.run(cmd_map[args.command](args))
    except KeyboardInterrupt:
        print(f"\n{_C.YELLOW}Interrupted.{_C.RESET}")
        sys.exit(130)


if __name__ == "__main__":
    main()
