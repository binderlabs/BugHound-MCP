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

    # --- Phase 1: Automated Recon (Stages 0-3) -----------------------------
    print(f"\n{_C.CYAN}{_C.BOLD}[*] Phase 1: Reconnaissance{_C.RESET}")

    # Stage 0: Init
    print(f"  {_C.DIM}[init]{_C.RESET} Classifying target and creating workspace...")
    workspace_id = await _run_stage0(target, depth)
    print(f"  {_C.DIM}[init]{_C.RESET} Workspace: {workspace_id}")

    # Extract target scope for scope validation
    target_scope = target

    # Stage 1: Enumerate
    print(f"  {_C.DIM}[enumerate]{_C.RESET} Running subdomain enumeration...")
    await _run_stage1(workspace_id, verbose)

    # Stage 2: Discover
    print(f"  {_C.DIM}[discover]{_C.RESET} Running discovery (probe, crawl, JS analysis)...")
    await _run_stage2(workspace_id, verbose)

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

    # --- Phase 2: AI-Driven Manual Testing -----------------------------------
    # NO automated scanner. The AI reads pages, crafts payloads, and tests
    # manually — like a human pentester, not a scanner wrapper.
    print(f"\n{_C.CYAN}{_C.BOLD}[*] Phase 2: AI Manual Testing{_C.RESET}")
    print(
        f"  {_C.DIM}[AI]{_C.RESET} "
        f"Starting manual assessment (read pages, craft payloads, test)..."
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": full_system_prompt},
        {
            "role": "user",
            "content": RECON_COMPLETE_PROMPT.format(
                attack_surface_summary=attack_surface_summary,
            ),
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
            # Add assistant message with tool calls
            messages.append(ai.format_assistant_tool_calls(response))

            # Print AI's reasoning if it included text
            if response.content:
                # Truncate long AI reasoning for display
                text = response.content.strip()
                if text:
                    display_text = text[:200] + "..." if len(text) > 200 else text
                    print(f"  {_C.CYAN}[AI]{_C.RESET} \"{display_text}\"")

            # Execute each tool call
            for tc in response.tool_calls:
                print(
                    f"  {_C.CYAN}[AI]{_C.RESET} "
                    f"{tc.name}({_summarize_args(tc.arguments)})"
                )

                try:
                    result = await asyncio.wait_for(
                        execute_tool(tc.name, tc.arguments, workspace_id, target_scope),
                        timeout=600,  # 10 min max per tool
                    )
                except asyncio.TimeoutError:
                    result = json.dumps({"status": "error", "message": "Tool timed out (10 min)"})
                    print(f"  {_C.RED}[->]{_C.RESET} Tool timed out")
                    messages.append(ai.format_tool_result(tc.id, result))
                    continue

                summary = _summarize_result(result)
                print(f"  {_C.GREEN}[->]{_C.RESET} {summary}")

                # Add tool result to conversation
                messages.append(ai.format_tool_result(tc.id, result))
        else:
            # AI finished this phase -- print analysis
            if response.content:
                print(f"\n  {_C.CYAN}[AI]{_C.RESET} {response.content[:500]}")
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

    # Agent auto-selects top N hosts (no interactive prompt)
    async def _auto_filter(live_hosts: list) -> list | None:
        if len(live_hosts) <= max_hosts:
            return None  # Scan all
        selected = live_hosts[:max_hosts]
        print(
            f"  {_C.GREEN}[discover]{_C.RESET} "
            f"Auto-selected {len(selected)} of {len(live_hosts)} live hosts"
        )
        for h in selected:
            url = h.get("url", "?") if isinstance(h, dict) else str(h)
            print(f"    {_C.DIM}{url}{_C.RESET}")
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
