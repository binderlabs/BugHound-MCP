"""BugHound Agent Mode -- AI-powered autonomous bug bounty scanning.

Runs the full BugHound pipeline with an AI reasoning between stages:
  Phase 1: Automated recon (Stages 0-3)
  Phase 2: AI-driven targeted testing (Stage 4 techniques)
  Phase 3: AI-driven exploitation (http_request, SQLi extraction, LFI)
  Phase 4: Report generation (Stage 6)

The AI decides which techniques to run, how to exploit findings, and how
to chain vulnerabilities -- just like a skilled bug bounty hunter.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Terminal colors (same as cli.py)
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


def _sev_color(sev: str) -> str:
    return {
        "critical": _C.RED,
        "high": _C.MAGENTA,
        "medium": _C.YELLOW,
        "low": _C.BLUE,
        "info": _C.GRAY,
    }.get(sev.lower(), _C.WHITE)


def _progress_bar(pct: int, width: int = 30) -> str:
    filled = int(pct * width / 100)
    bar = f"{_C.CYAN}{'#' * filled}{_C.DIM}{'-' * (width - filled)}{_C.RESET}"
    return f"[{bar}] {pct}%"


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def create_provider(
    provider_name: str,
    api_key: str,
    model: str | None,
) -> Any:
    """Create an AI provider instance."""
    if provider_name == "anthropic":
        from bughound.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(api_key=api_key, model=model)
    elif provider_name in ("openai", "grok", "openrouter"):
        from bughound.providers.openai_compat import OpenAICompatProvider
        return OpenAICompatProvider(provider_name, api_key=api_key, model=model)
    else:
        raise ValueError(f"Unknown provider: {provider_name}")


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------

_COST_PER_M: dict[str, tuple[float, float]] = {
    # (input $/M, output $/M)
    "anthropic": (3.0, 15.0),
    "openai": (2.5, 10.0),
    "grok": (5.0, 15.0),
    "openrouter": (3.0, 15.0),
}


def _estimate_cost(
    provider_name: str,
    input_tokens: int,
    output_tokens: int,
) -> float:
    """Estimate cost in USD."""
    rates = _COST_PER_M.get(provider_name, (5.0, 15.0))
    return (input_tokens * rates[0] + output_tokens * rates[1]) / 1_000_000


# ---------------------------------------------------------------------------
# Attack surface formatter (condense for AI context)
# ---------------------------------------------------------------------------


def format_attack_surface(attack_surface: dict[str, Any]) -> str:
    """Condense attack surface JSON into a readable summary for the AI."""
    lines: list[str] = []

    # Target info
    lines.append(f"Target: {attack_surface.get('target', '?')}")
    lines.append(f"Type: {attack_surface.get('target_type', '?')}")

    # Stats
    stats = attack_surface.get("stats", {})
    if stats:
        lines.append(f"Live hosts: {stats.get('live_hosts', 0)}")
        lines.append(f"URLs: {stats.get('total_urls', 0)}")
        lines.append(f"Parameters: {stats.get('total_parameters', 0)}")
        lines.append(f"Secrets found: {stats.get('secrets_found', 0)}")
        lines.append(f"Hidden endpoints: {stats.get('hidden_endpoints', 0)}")

    # Tech stack
    tech = attack_surface.get("technology_profile", {})
    if tech:
        lines.append(f"\nTech stack: {json.dumps(tech, default=str)[:500]}")

    # Parameter classification
    pc = attack_surface.get("parameter_classification", {})
    if pc:
        lines.append("\nParameter classification:")
        for category in (
            "sqli_candidates", "xss_candidates", "lfi_candidates",
            "ssrf_candidates", "redirect_candidates", "idor_candidates",
            "rce_candidates", "ssti_candidates",
        ):
            items = pc.get(category, [])
            if items:
                lines.append(f"  {category}: {len(items)}")
                for item in items[:5]:
                    if isinstance(item, dict):
                        url = item.get("url", "?")[:80]
                        param = item.get("param", "?")
                        lines.append(f"    {param} @ {url}")

        # Probe confirmed
        confirmed = pc.get("probe_confirmed", [])
        if confirmed:
            lines.append(f"\n  PROBE CONFIRMED ({len(confirmed)}):")
            for p in confirmed[:10]:
                lines.append(
                    f"    [{p.get('vuln_type', '?').upper()}] "
                    f"{p.get('url', '?')[:70]} ({p.get('probe_result', '')})"
                )

    # Attack chains
    chains = attack_surface.get("attack_chains", [])
    if chains:
        lines.append(f"\nAttack chains ({len(chains)}):")
        for c in chains[:10]:
            sev = c.get("severity", "?")
            lines.append(f"  [{sev.upper()}] {c.get('name', '?')}")
            steps = c.get("steps", [])
            for s in steps[:4]:
                lines.append(f"    -> {s}")

    # Immediate wins
    wins = attack_surface.get("immediate_wins", [])
    if wins:
        lines.append(f"\nImmediate wins ({len(wins)}):")
        for w in wins[:10]:
            lines.append(
                f"  [{w.get('severity', '?').upper()}] "
                f"{w.get('type', '?')}: {w.get('url', '?')[:70]}"
            )

    # Suggested test classes
    tc = attack_surface.get("suggested_test_classes", [])
    if tc:
        lines.append(f"\nSuggested test classes: {', '.join(tc)}")

    # URLs with params (top 20)
    urls_with_params = attack_surface.get("urls_with_params", [])
    if urls_with_params:
        lines.append(f"\nTop URLs with params ({len(urls_with_params)} total):")
        for u in urls_with_params[:20]:
            if isinstance(u, dict):
                lines.append(f"  {u.get('url', '?')[:80]}")
            elif isinstance(u, str):
                lines.append(f"  {u[:80]}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Findings formatter (condense for AI context)
# ---------------------------------------------------------------------------


def format_findings(findings: list[dict[str, Any]]) -> str:
    """Condense findings into readable summary for the AI."""
    if not findings:
        return "No findings."

    from collections import Counter

    # Count by class and severity
    class_counts: Counter[str] = Counter()
    sev_counts: Counter[str] = Counter()
    for f in findings:
        if isinstance(f, dict):
            class_counts[f.get("vulnerability_class", "other")] += 1
            sev_counts[f.get("severity", "info")] += 1

    lines: list[str] = []
    lines.append(f"Total findings: {len(findings)}")
    lines.append(f"By severity: {dict(sev_counts.most_common())}")
    lines.append(f"By class: {dict(class_counts.most_common())}")

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_order.get(f.get("severity", "info"), 5),
    )

    lines.append("\nTop findings:")
    for f in sorted_findings[:15]:
        if not isinstance(f, dict):
            continue
        sev = f.get("severity", "info")
        cls = f.get("vulnerability_class", "?")
        ep = f.get("endpoint", "?")[:70]
        desc = f.get("description", "")[:80]
        evidence = f.get("evidence", "")[:60]
        validated = f.get("validation_status", "")

        status = ""
        if validated:
            status = f" [{validated}]"

        lines.append(f"  [{sev.upper()}] {cls}: {ep}")
        if desc:
            lines.append(f"    {desc}")
        if evidence:
            lines.append(f"    Evidence: {evidence}")
        if status:
            lines.append(f"    Status: {status}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool call display helpers
# ---------------------------------------------------------------------------


def _describe_action(tool_name: str, arguments: dict[str, Any]) -> str:
    """Human-readable one-line description of what the AI is doing."""
    url = arguments.get("url", arguments.get("command", ""))
    if isinstance(url, str) and len(url) > 60:
        url = url[:57] + "..."
    param = arguments.get("param", "")
    fid = arguments.get("finding_id", "")
    fstatus = arguments.get("status", "")
    descriptions = {
        "read_page": f"Reading page: {url}",
        "browse_page": f"Opening in browser: {url}",
        "http_request": f"Sending {arguments.get('method', 'GET')} to {url}",
        "run_tool": f"Running: {url[:60]}",
        "extract_sqli_data": f"Extracting SQL data from {url}",
        "read_file_via_lfi": f"Reading {arguments.get('file_path', '?')} via LFI",
        "update_finding_status": f"Marking {fid[:30]} -> {fstatus}",
        "add_finding": f"Recording {arguments.get('vulnerability_class', '?')} ({arguments.get('severity', '?')})",
        "get_findings": "Reviewing current findings",
        "get_attack_surface": "Analyzing attack surface",
        "validate_findings": "Validating findings",
        "generate_report": "Generating reports",
    }
    return descriptions.get(tool_name, f"{tool_name}()")


def _short_result(tool_name: str, result_json: str) -> str:
    """Short one-line result for non-verbose mode."""
    try:
        r = json.loads(result_json)
    except Exception:
        return ""
    if not isinstance(r, dict):
        return ""
    status = r.get("status_code", r.get("status", ""))
    if tool_name == "read_page":
        title = r.get("title", "")
        forms = len(r.get("forms", []))
        links = len(r.get("links", []))
        return f"title=\"{title[:30]}\" forms={forms} links={links}"
    elif tool_name == "http_request":
        size = r.get("content_length", len(r.get("body", "")))
        return f"status={status} size={size}"
    elif tool_name == "browse_page":
        return f"rendered {r.get('rendered_length', '?')} chars"
    elif tool_name == "update_finding_status":
        return r.get("message", "")[:60]
    elif tool_name == "add_finding":
        return r.get("message", "finding added")[:60]
    elif tool_name == "extract_sqli_data":
        return r.get("status", "")[:60]
    elif tool_name == "read_file_via_lfi":
        return r.get("status", "")[:60]
    elif tool_name == "get_findings":
        return f"{r.get('findings_count', '?')} findings"
    elif tool_name == "run_tool":
        out = r.get("stdout", "")[:60]
        return f"exit={r.get('exit_code', '?')} {out}"
    return ""


def _summarize_args(arguments: dict[str, Any]) -> str:
    """Short summary of tool call arguments for terminal display."""
    parts = []
    for key, val in arguments.items():
        if key == "workspace_id":
            continue  # Skip noise
        if isinstance(val, str) and len(val) > 50:
            parts.append(f"{key}='{val[:47]}...'")
        elif isinstance(val, str):
            parts.append(f"{key}='{val}'")
        else:
            parts.append(f"{key}={val}")
    return ", ".join(parts)


def _summarize_result(result_json: str) -> str:
    """Short summary of tool result for terminal display."""
    try:
        result = json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        return result_json[:100]

    if not isinstance(result, dict):
        return str(result)[:100]

    status = result.get("status", "")
    if status == "error":
        return f"Error: {result.get('message', '?')[:80]}"

    # For findings results
    count = result.get("findings_count", result.get("findings_total", None))
    if count is not None:
        by_sev = result.get("by_severity", result.get("findings_by_severity", {}))
        sev_str = ", ".join(
            f"{k}: {v}" for k, v in by_sev.items() if v
        ) if by_sev else ""
        if sev_str:
            return f"{count} findings ({sev_str})"
        return f"{count} findings"

    # For HTTP request results
    status_code = result.get("status_code")
    if status_code is not None:
        redirect = result.get("redirect_url", "")
        body_len = result.get("body_length", 0)
        parts = [f"{status_code}"]
        if redirect:
            parts.append(f"-> {redirect[:50]}")
        parts.append(f"({body_len} bytes)")
        return " ".join(parts)

    # For extraction results
    if "extracted_data" in result:
        data = result["extracted_data"][:100]
        return f"Extracted: {data}"

    if "content" in result:
        content = result["content"][:100]
        return f"File read: {content[:80]}"

    # For report results
    if "reports" in result:
        reps = result["reports"]
        return f"Reports generated: {', '.join(reps.keys())}"

    # Generic
    return json.dumps(result, default=str)[:100]


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------


async def run_agent(
    target: str,
    provider_name: str,
    api_key: str,
    model: str | None = None,
    depth: str = "light",
    max_iterations: int = 50,
    verbose: bool = False,
    resume_workspace_id: str | None = None,
    from_phase: int | None = None,
) -> None:
    """Run the full BugHound agent pipeline.

    Parameters
    ----------
    target : str
        Target URL or domain.
    provider_name : str
        AI provider name (anthropic, openai, grok, openrouter).
    api_key : str
        API key for the provider.
    model : str or None
        Model name override. None uses provider default.
    depth : str
        Scan depth (light or deep).
    max_iterations : int
        Maximum AI reasoning steps across all phases.
    verbose : bool
        Show detailed debug output.
    """
    # Pre-flight tool check
    import shutil
    httpx_path = shutil.which("httpx")
    if not httpx_path:
        print(f"  {_C.RED}ERROR: 'httpx' not found. Install ProjectDiscovery httpx:{_C.RESET}")
        print(f"  {_C.DIM}go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest{_C.RESET}")
        return
    # Check it's not Python httpx
    import subprocess as _sp
    try:
        _vr = _sp.run(["file", httpx_path], capture_output=True, text=True, timeout=5)
        if "python" in _vr.stdout.lower() or "script" in _vr.stdout.lower():
            print(f"  {_C.RED}ERROR: Wrong 'httpx' — found Python httpx (pip) instead of ProjectDiscovery httpx (Go).{_C.RESET}")
            print(f"  {_C.DIM}Fix: pip uninstall httpx && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest{_C.RESET}")
            return
    except Exception:
        pass

    from bughound.agent_tools import AGENT_TOOLS, execute_tool
    from bughound.agent_prompts import (
        SYSTEM_PROMPT, RECON_COMPLETE_PROMPT, REPORT_PROMPT,
    )
    from bughound.agent_experts import (
        SQLI_EXPERT, XSS_EXPERT, LFI_EXPERT, SSRF_EXPERT,
        RCE_EXPERT, AUTH_EXPERT, ORCHESTRATOR_DELEGATION,
    )

    # Build the full system prompt with all expert knowledge
    full_system_prompt = (
        SYSTEM_PROMPT + "\n\n"
        "# SPECIALIST KNOWLEDGE\n\n"
        "You have the following expert-level knowledge for each vulnerability class. "
        "Apply the right specialist's methodology when you encounter that type.\n\n"
        f"## SQL Injection Specialist\n{SQLI_EXPERT}\n\n"
        f"## XSS Specialist\n{XSS_EXPERT}\n\n"
        f"## LFI Specialist\n{LFI_EXPERT}\n\n"
        f"## SSRF Specialist\n{SSRF_EXPERT}\n\n"
        f"## RCE Specialist\n{RCE_EXPERT}\n\n"
        f"## Auth Specialist\n{AUTH_EXPERT}\n\n"
        f"## Orchestration\n{ORCHESTRATOR_DELEGATION}"
    )

    total_input_tokens = 0
    total_output_tokens = 0
    start_time = time.time()

    # --- Create AI provider ------------------------------------------------
    print(f"\n{_C.CYAN}{_C.BOLD}{'=' * 60}{_C.RESET}")
    print(f"  {_C.BOLD}BugHound Agent Mode{_C.RESET}")
    print(f"{_C.CYAN}{'=' * 60}{_C.RESET}")
    print(f"  {_C.DIM}Target:{_C.RESET}   {target}")
    print(f"  {_C.DIM}Provider:{_C.RESET} {provider_name}")
    print(f"  {_C.DIM}Model:{_C.RESET}    {model or 'default'}")
    print(f"  {_C.DIM}Depth:{_C.RESET}    {depth}")
    print()

    try:
        ai = create_provider(provider_name, api_key, model)
    except Exception as exc:
        print(f"  {_C.RED}Failed to initialize AI provider: {exc}{_C.RESET}")
        sys.exit(1)

    # --- Connection test ---------------------------------------------------
    print(f"  {_C.DIM}Testing API connection...{_C.RESET}", end="", flush=True)
    try:
        test_resp = await asyncio.wait_for(
            ai.chat([{"role": "user", "content": "Respond with only: OK"}]),
            timeout=30,
        )
        if test_resp.content:
            print(f" {_C.GREEN}connected{_C.RESET}")
        else:
            print(f" {_C.RED}no response{_C.RESET}")
            sys.exit(1)
    except asyncio.TimeoutError:
        print(f" {_C.RED}timeout — check API key and network{_C.RESET}")
        sys.exit(1)
    except Exception as exc:
        err_msg = str(exc)
        if "401" in err_msg or "auth" in err_msg.lower() or "invalid" in err_msg.lower():
            print(f" {_C.RED}invalid API key{_C.RESET}")
        elif "403" in err_msg or "forbidden" in err_msg.lower():
            print(f" {_C.RED}access denied — check API key permissions{_C.RESET}")
        else:
            print(f" {_C.RED}failed: {err_msg[:80]}{_C.RESET}")
        sys.exit(1)

    # Determine starting phase
    _start_phase = from_phase or 1
    workspace_id = resume_workspace_id or ""
    target_scope = target

    if resume_workspace_id:
        workspace_id = resume_workspace_id
        from bughound.core import workspace as _ws
        _meta = await _ws.get_workspace(workspace_id)
        if _meta is None:
            print(f"  {_C.RED}Workspace '{workspace_id}' not found{_C.RESET}")
            sys.exit(1)
        target_scope = _meta.target or target
        print(f"  {_C.GREEN}Resuming workspace: {workspace_id}{_C.RESET}")
        if _start_phase > 1:
            print(f"  {_C.GREEN}Starting from Phase {_start_phase}{_C.RESET}")

    # --- Phase 1: Automated Recon (Stages 0-3) -----------------------------
    if _start_phase <= 1:
        print(f"\n{_C.CYAN}{_C.BOLD}[*] Phase 1: Reconnaissance{_C.RESET}")

        # Stage 0: Init
        if not workspace_id:
            print(f"  {_C.DIM}[init]{_C.RESET} Classifying target and creating workspace...")
            workspace_id = await _run_stage0(target, depth)
            # Show target type
            from bughound.core import workspace as _ws
            _meta = await _ws.get_workspace(workspace_id)
            _ttype = getattr(_meta, "target_type", None) or "unknown"
            _ttype_str = _ttype.value if hasattr(_ttype, "value") else str(_ttype)
            print(f"  {_C.DIM}[init]{_C.RESET} Workspace: {workspace_id}")
            print(f"  {_C.DIM}[init]{_C.RESET} Target type: {_ttype_str}")

        # Stage 1: Enumerate
        print(f"  {_C.DIM}[enumerate]{_C.RESET} Running subdomain enumeration...")
        await _run_stage1(workspace_id, verbose)

        # Stage 2: Discover
        print(f"  {_C.DIM}[discover]{_C.RESET} Running discovery (probe, crawl, JS analysis)...")
        await _run_stage2(workspace_id, verbose)
    else:
        print(f"\n{_C.DIM}[*] Phase 1: Skipped (resuming){_C.RESET}")

    # Stage 3: Analyze
    print(f"  {_C.DIM}[analyze]{_C.RESET} Building attack surface model...")
    attack_surface = await _run_stage3(workspace_id)
    attack_surface_summary = format_attack_surface(attack_surface)

    # Print stats
    stats = attack_surface.get("stats", {})
    print(
        f"  {_C.DIM}[analyze]{_C.RESET} Complete: "
        f"{stats.get('live_hosts', 0)} hosts, "
        f"{stats.get('total_urls', 0)} URLs, "
        f"{stats.get('total_parameters', 0)} params"
    )
    confirmed = attack_surface.get("parameter_classification", {}).get(
        "probe_confirmed", [],
    )
    if confirmed:
        print(
            f"  {_C.GREEN}[analyze]{_C.RESET} "
            f"{len(confirmed)} probe-confirmed vulnerabilities"
        )
    chains = attack_surface.get("attack_chains", [])
    if chains:
        print(
            f"  {_C.YELLOW}[analyze]{_C.RESET} "
            f"{len(chains)} attack chains detected"
        )

    # --- Phase 2: Automated Testing (CLI speed) --------------------------------
    if _start_phase <= 2:
        print(f"\n{_C.CYAN}{_C.BOLD}[*] Phase 2: Automated Testing{_C.RESET}")
        print(f"  {_C.DIM}[test]{_C.RESET} Running all 45 techniques (same as CLI)...")

        from bughound.core.job_manager import JobManager as _JM
        from bughound.stages import test as stage_test
        from bughound.stages import analyze as stage_analyze

        _target_host = target
        if "://" in _target_host:
            _target_host = urlparse(_target_host).hostname or _target_host

        _suggested = attack_surface.get("suggested_test_classes", [])
        if not _suggested:
            _suggested = [
                "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect",
                "crlf", "idor", "rce", "xxe", "header_injection",
                "graphql", "jwt", "misconfig", "default_creds",
                "cors", "bac", "csti", "cve_specific",
            ]

        _scan_plan = {
            "targets": [{"host": _target_host, "priority": 1, "test_classes": _suggested}],
            "global_settings": {
                "nuclei_severity": "critical,high,medium,low,info",
                "nuclei_rate_limit": 100,
                "nuclei_concurrency": 25,
            },
        }
        await stage_analyze.submit_scan_plan(workspace_id, _scan_plan)

        _jm = _JM()
        _test_result = await stage_test.execute_tests(workspace_id, _jm)

        if _test_result.get("status") == "job_started":
            _job_id = _test_result["job_id"]
            while True:
                await asyncio.sleep(5)
                _status = await _jm.get_status(_job_id)
                if _status is None:
                    break
                _pct = _status.get("progress_pct", 0)
                _msg = _status.get("message", "")
                sys.stdout.write(
                    f"\r  {_progress_bar(_pct)} {_C.DIM}{_msg[:45]}{_C.RESET}    "
                )
                sys.stdout.flush()
                if _status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                    print()
                    break
    else:
        print(f"\n{_C.DIM}[*] Phase 2: Skipped (resuming){_C.RESET}")

    # Load automated findings
    automated_findings = await _load_findings(workspace_id)
    auto_summary = format_findings(automated_findings)

    from collections import Counter as _Counter
    _sev = _Counter(f.get("severity", "?") for f in automated_findings)
    print(
        f"  {_C.GREEN}[test]{_C.RESET} "
        f"{len(automated_findings)} findings from automated testing"
    )
    for s in ("critical", "high", "medium", "low"):
        if _sev.get(s):
            print(f"    {s}: {_sev[s]}")

    # --- Phase 3: AI Validation + Discovery ------------------------------------
    # AI IS the validator. No sqlmap/dalfox — AI is smarter and faster.
    # AI reads pages, sends targeted payloads, confirms or rejects each finding.
    # AI also discovers new vulns by reading page source.

    # Filter nuclei "other" noise
    automated_findings = [
        f for f in automated_findings
        if f.get("vulnerability_class") not in ("other", None, "")
    ]

    print(f"\n{_C.CYAN}{_C.BOLD}[*] Phase 3: AI Validation + Discovery{_C.RESET}")
    print(
        f"  {_C.DIM}[AI]{_C.RESET} "
        f"Validating {len(automated_findings)} findings + hunting for missed vulns..."
    )

    # Build detailed finding list for AI to validate
    finding_details = ""
    for idx, f in enumerate(automated_findings[:30], 1):
        cls = f.get("vulnerability_class", "?")
        sev = f.get("severity", "?")
        ep = f.get("endpoint", "?")[:70]
        ev = str(f.get("evidence", ""))[:80]
        fid = f.get("finding_id", f"unknown_{idx}")
        finding_details += (
            f"\n  #{idx} [id={fid}] [{sev}] {cls} — {ep}\n"
            f"    Evidence: {ev}\n"
        )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": full_system_prompt},
        {
            "role": "user",
            "content": RECON_COMPLETE_PROMPT.format(
                attack_surface_summary=attack_surface_summary,
            )
            + "\n\n--- AUTOMATED SCANNER FINDINGS (need validation) ---\n"
            + finding_details
            + "\n\n--- YOUR MISSION ---\n"
            "You are the validator. The automated scanner found the above findings.\n"
            "You MUST manually verify each finding by sending your OWN test request.\n"
            "Do NOT just trust the scanner evidence — test it yourself.\n\n"
            "CRITICAL RULE: You MUST call http_request() or read_page() to test the\n"
            "endpoint BEFORE calling update_finding_status(). Never bulk-confirm\n"
            "findings without testing them individually. Each finding needs its own\n"
            "verification request.\n\n"
            "IMPORTANT: Use the finding_id (e.g. 'finding_high_a1b2c3d4'), NOT a number.\n\n"
            "WORKFLOW — repeat for each finding:\n"
            "  1. Send a test request with http_request() to the vulnerable endpoint\n"
            "  2. Analyze the response — does it prove the vulnerability?\n"
            "  3. Call update_finding_status() with evidence from YOUR test\n\n"
            "HOW TO VALIDATE EACH TYPE:\n\n"
            "SQLi: http_request(GET, url_with_single_quote) → look for SQL error in response\n"
            "  - CONFIRMED if: SQL error string visible (e.g. 'Unclosed quotation mark')\n"
            "  - CONFIRMED if: boolean test OR 1=1 returns different content than AND 1=2\n"
            "  - FALSE_POSITIVE if: no SQL error, no behavior change\n\n"
            "XSS: http_request(GET, url_with_script_tag) → check if <script> unescaped in response\n"
            "  - CONFIRMED if: your payload appears unescaped in HTML body\n"
            "  - FALSE_POSITIVE if: payload is HTML-encoded or stripped\n\n"
            "LFI: http_request(GET, url_with_etc_passwd) → look for root:x:0:0 in body\n"
            "  - CONFIRMED if: /etc/passwd content visible\n"
            "  - FALSE_POSITIVE if: file content not in response\n\n"
            "IDOR: http_request(GET, url_with_different_id) → compare with original\n"
            "  - CONFIRMED if: different user's data visible without auth\n"
            "  - FALSE_POSITIVE if: same generic content or error page\n\n"
            "Prototype Pollution: read_page(url_with_proto_payload) → check for canary in response\n"
            "  - CONFIRMED if: injected property visible in response\n"
            "  - FALSE_POSITIVE if: payload just reflected in URL\n\n"
            "ALSO: Look for vulns the scanner missed using read_page() on interesting endpoints.\n"
            "For new discoveries → add_finding() with full evidence.\n\n"
            "IMPORTANT: Use update_finding_status() with finding_id for EXISTING findings.\n"
            "Use add_finding() only for NEW discoveries.\n"
            "You MUST validate EVERY finding — do NOT stop after the first batch.\n"
            "START with critical/high severity, then work through medium/low.\n"
            "Do NOT call generate_report() until ALL findings have been validated.\n"
            "Process 3-5 findings per iteration, not all at once.\n",
        },
    ]

    iterations_used = 0

    for i in range(max_iterations):
        iterations_used += 1

        try:
            response = await asyncio.wait_for(
                ai.chat(messages, tools=AGENT_TOOLS), timeout=120,
            )
        except asyncio.TimeoutError:
            print(f"  {_C.RED}[AI] API call timed out (120s){_C.RESET}")
            break
        except Exception as exc:
            print(f"  {_C.RED}[AI] API error: {exc}{_C.RESET}")
            break

        # Track tokens
        total_input_tokens += response.usage.get("input_tokens", 0)
        total_output_tokens += response.usage.get("output_tokens", 0)

        if response.has_tool_calls:
            messages.append(ai.format_assistant_tool_calls(response))

            # AI reasoning — only show in verbose
            if verbose and response.content:
                text = response.content.strip()
                if text:
                    display = text[:300] + "..." if len(text) > 300 else text
                    print(f"  {_C.CYAN}[AI]{_C.RESET} \"{display}\"")

            for tc in response.tool_calls:
                # Normal mode: short action description
                # Verbose mode: full tool call with args
                if verbose:
                    print(
                        f"  {_C.CYAN}[AI]{_C.RESET} "
                        f"{tc.name}({_summarize_args(tc.arguments)})"
                    )
                else:
                    # Clean one-line description
                    action = _describe_action(tc.name, tc.arguments)
                    print(f"  {_C.DIM}[{iterations_used}/{max_iterations}]{_C.RESET} {action}")

                try:
                    result = await asyncio.wait_for(
                        execute_tool(tc.name, tc.arguments, workspace_id, target_scope),
                        timeout=600,
                    )
                except asyncio.TimeoutError:
                    result = json.dumps({"status": "error", "message": "Tool timed out"})
                    print(f"  {_C.RED}  -> timed out{_C.RESET}")
                    messages.append(ai.format_tool_result(tc.id, result))
                    continue

                summary = _summarize_result(result)
                if verbose:
                    print(f"  {_C.GREEN}[->]{_C.RESET} {summary}")
                else:
                    # Short result
                    short = _short_result(tc.name, result)
                    if short:
                        print(f"  {_C.GREEN}  -> {short}{_C.RESET}")

                messages.append(ai.format_tool_result(tc.id, result))
        else:
            if response.content:
                # Show AI's final assessment (always, not just verbose)
                text = response.content.strip()
                if verbose:
                    print(f"\n  {_C.CYAN}[AI]{_C.RESET} {text[:500]}")
                else:
                    # Just show first 2 lines
                    lines = text.split("\n")[:2]
                    print(f"  {_C.CYAN}[AI]{_C.RESET} {' '.join(l.strip() for l in lines)[:150]}")

            # Check if there are still unvalidated findings before stopping
            try:
                from bughound.core import workspace as _ws
                _raw = await _ws.read_data(workspace_id, "vulnerabilities/scan_results.json")
                _items = _raw.get("data", _raw) if isinstance(_raw, dict) else (_raw or [])
                if not isinstance(_items, list): _items = []
                _pending = [
                    f for f in _items
                    if isinstance(f, dict)
                    and not f.get("validation_status")
                    and f.get("vulnerability_class") not in ("other", None, "")
                ]
                if _pending and iterations_used < max_iterations - 1:
                    # Push AI to keep validating — include FULL finding_ids
                    pending_lines = "\n".join(
                        f"  - {f.get('finding_id','?')} [{f.get('severity','?')}] "
                        f"{f.get('vulnerability_class','?')} — {f.get('endpoint','?')[:60]}"
                        for f in _pending[:15]
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            f"You still have {len(_pending)} PENDING findings. "
                            f"Do NOT stop yet. Validate these next:\n{pending_lines}\n\n"
                            "Use the EXACT finding_id shown above (copy it fully). "
                            "For each: call update_finding_status(finding_id, status)."
                        ),
                    })
                    print(f"  {_C.DIM}[AI]{_C.RESET} {len(_pending)} findings still pending, continuing...")
                    continue
            except Exception:
                pass  # If we can't check, just stop

            break

    # --- Phase 4: Report ---------------------------------------------------
    print(f"\n{_C.CYAN}{_C.BOLD}[*] Phase 4: Report{_C.RESET}")

    # Reload findings (may have been updated during exploitation)
    final_findings = await _load_findings(workspace_id)
    final_summary = format_findings(final_findings)

    if final_findings:
        messages.append({
            "role": "user",
            "content": REPORT_PROMPT.format(final_summary=final_summary),
        })

        report_limit = min(5, max_iterations - iterations_used)

        for i in range(report_limit):
            iterations_used += 1

            try:
                response = await ai.chat(messages, tools=AGENT_TOOLS)
            except Exception as exc:
                print(f"  {_C.RED}[AI] API error: {exc}{_C.RESET}")
                break

            total_input_tokens += response.usage.get("input_tokens", 0)
            total_output_tokens += response.usage.get("output_tokens", 0)

            if response.has_tool_calls:
                messages.append(ai.format_assistant_tool_calls(response))

                if response.content:
                    text = response.content.strip()
                    if text:
                        print(f"\n  {_C.CYAN}[AI]{_C.RESET} {text[:500]}")

                for tc in response.tool_calls:
                    print(
                        f"  {_C.CYAN}[AI]{_C.RESET} "
                        f"{tc.name}({_summarize_args(tc.arguments)})"
                    )

                    result = await execute_tool(
                        tc.name, tc.arguments, workspace_id, target_scope,
                    )

                    summary = _summarize_result(result)
                    print(f"  {_C.GREEN}[->]{_C.RESET} {summary}")

                    messages.append(ai.format_tool_result(tc.id, result))
            else:
                if response.content:
                    print(f"\n  {_C.CYAN}[AI]{_C.RESET} {response.content[:500]}")
                break
    else:
        print(f"  {_C.DIM}No findings to report.{_C.RESET}")

    # --- Final Summary -----------------------------------------------------
    elapsed = time.time() - start_time
    elapsed_str = (
        f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
        if elapsed >= 60
        else f"{elapsed:.1f}s"
    )
    cost = _estimate_cost(provider_name, total_input_tokens, total_output_tokens)

    print(f"\n{_C.CYAN}{_C.BOLD}{'=' * 60}{_C.RESET}")
    print(f"  {_C.BOLD}Agent Complete{_C.RESET}")
    print(f"{_C.CYAN}{'=' * 60}{_C.RESET}")
    print(f"  {_C.DIM}Workspace:{_C.RESET}  {workspace_id}")
    print(f"  {_C.DIM}Duration:{_C.RESET}   {elapsed_str}")
    print(f"  {_C.DIM}Iterations:{_C.RESET} {iterations_used}")

    # Print findings summary
    if final_findings:
        from collections import Counter
        sev_counts: Counter[str] = Counter()
        for f in final_findings:
            if isinstance(f, dict):
                sev_counts[f.get("severity", "info")] += 1

        findings_line = ", ".join(
            f"{_sev_color(k)}{v} {k}{_C.RESET}"
            for k, v in sorted(
                sev_counts.items(),
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x[0], 5),
            )
            if v
        )
        print(f"  {_C.DIM}Findings:{_C.RESET}   {len(final_findings)} ({findings_line})")
    else:
        print(f"  {_C.DIM}Findings:{_C.RESET}   0")

    # Token usage
    print(
        f"  {_C.DIM}Tokens:{_C.RESET}     "
        f"{total_input_tokens + total_output_tokens:,} "
        f"(input: {total_input_tokens:,}, output: {total_output_tokens:,})"
    )
    print(f"  {_C.DIM}Est. cost:{_C.RESET}  ${cost:.2f}")
    print()


# ---------------------------------------------------------------------------
# Stage runners (lightweight wrappers, no heavy imports at module level)
# ---------------------------------------------------------------------------


async def _run_stage0(target: str, depth: str) -> str:
    """Stage 0: Initialize workspace. Returns workspace_id."""
    from bughound.core.target_classifier import classify
    from bughound.core import workspace

    classification = classify(target, depth)
    meta = await workspace.create_workspace(target, depth)
    await workspace.update_metadata(
        meta.workspace_id,
        target_type=classification.target_type,
        classification=classification.model_dump(mode="json"),
    )
    await workspace.add_stage_history(meta.workspace_id, 0, "completed")
    return meta.workspace_id


async def _run_stage1(workspace_id: str, verbose: bool = False) -> None:
    """Stage 1: Enumerate subdomains."""
    from bughound.stages import enumerate as stage_enumerate

    result = await stage_enumerate.enumerate_light(workspace_id)
    data = result.get("data", {})
    if data.get("skipped"):
        print(f"  {_C.DIM}[enumerate]{_C.RESET} Skipped (single host)")
    else:
        print(
            f"  {_C.DIM}[enumerate]{_C.RESET} "
            f"{data.get('subdomains_found', 0)} subdomains, "
            f"{data.get('resolved_count', 0)} resolved"
        )


async def _run_stage2(
    workspace_id: str, verbose: bool = False, max_hosts: int = 10,
) -> None:
    """Stage 2: Discovery (probe, crawl, JS analysis)."""
    from bughound.stages import discover as stage_discover

    # Interactive host selection — same as CLI mode
    async def _auto_filter(live_hosts: list) -> list | None:
        if len(live_hosts) <= 1:
            return None  # Only 1 host, scan it

        # Show live hosts list
        print(f"\n  {_C.BOLD}Found {len(live_hosts)} live hosts:{_C.RESET}\n")
        for i, h in enumerate(live_hosts[:30], 1):
            if isinstance(h, dict):
                url = h.get("url", "?")
                status = h.get("status_code", "?")
                title = h.get("title", "")
                techs = h.get("technologies", [])
                tech_str = f" [{', '.join(techs[:3])}]" if techs else ""
            else:
                url, status, title, tech_str = str(h), "?", "", ""

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
            return None

        if not choice or choice.lower() == "all":
            return None

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

    # Run synchronously with host filter + timeout
    try:
        result = await asyncio.wait_for(
            stage_discover.discover(
                workspace_id, job_manager=None, host_filter_cb=_auto_filter,
            ),
            timeout=1800,  # 30 min max
        )
    except asyncio.TimeoutError:
        print(f"  {_C.RED}[discover]{_C.RESET} Timed out after 30 minutes")
        result = {"status": "error"}

    if result.get("status") == "job_started":
        from bughound.core.job_manager import JobManager
        job_manager = JobManager()
        job_id = result["job_id"]
        while True:
            await asyncio.sleep(3)
            status = await job_manager.get_status(job_id)
            if status is None:
                break

            pct = status.get("progress_pct", 0)
            msg = status.get("message", "")
            sys.stdout.write(
                f"\r  {_progress_bar(pct)} {_C.DIM}{msg[:45]}{_C.RESET}    "
            )
            sys.stdout.flush()

            if status["status"] in ("COMPLETED", "FAILED", "TIMED_OUT"):
                print()
                if status["status"] == "COMPLETED":
                    rs = status.get("result_summary", {})
                    if rs:
                        for k, v in rs.items():
                            if verbose:
                                print(f"  {_C.DIM}[discover] {k}: {v}{_C.RESET}")
                elif status["status"] != "COMPLETED":
                    print(f"  {_C.RED}[discover] {status['status']}{_C.RESET}")
                break


async def _run_stage3(workspace_id: str) -> dict[str, Any]:
    """Stage 3: Analyze attack surface. Returns attack surface dict."""
    from bughound.stages import analyze as stage_analyze

    result = await stage_analyze.get_attack_surface(workspace_id)
    if result.get("status") == "error":
        print(f"  {_C.RED}[analyze] Error: {result.get('message', '?')}{_C.RESET}")
        return {}
    return result


async def _load_findings(workspace_id: str) -> list[dict[str, Any]]:
    """Load findings from workspace."""
    from bughound.core import workspace

    raw = await workspace.read_data(
        workspace_id, "vulnerabilities/scan_results.json",
    )
    if raw is None:
        return []
    items = raw.get("data", raw) if isinstance(raw, dict) else raw
    return items if isinstance(items, list) else []
