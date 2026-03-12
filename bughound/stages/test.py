"""Stage 4: Execute scan plan from Stage 3. Nuclei + tech-specific checks.

No decision-making happens here. Tools run exactly what the scan plan says.
The AI client handles the feedback loop (find → re-recon → test more).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import aiofiles
import structlog

from bughound.config.settings import WORKSPACE_BASE_DIR
from bughound.core import tool_runner, workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import ToolResult, WorkspaceState

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Test class → nuclei tag mapping
# ---------------------------------------------------------------------------

_TEST_CLASS_TAGS: dict[str, list[str]] = {
    "sqli": ["sqli"],
    "xss": ["xss"],
    "ssrf": ["ssrf"],
    "graphql": ["graphql"],
    "wordpress": ["wordpress"],
    "lfi": ["lfi"],
    "rfi": ["rfi"],
    "open_redirect": ["redirect"],
    "subdomain_takeover": ["takeover"],
    "cve_specific": [],  # uses severity filter instead
    "misconfig": ["misconfig", "cors"],
    "default_creds": ["default-login"],
    "file_exposure": ["exposure"],
    "idor": ["idor"],
    "auth_bypass": ["auth-bypass"],
    "api_abuse": ["api"],
}

# Findings from these classes are definitive (nuclei is authoritative)
_DEFINITIVE_CLASSES = {
    "subdomain_takeover", "file_exposure", "misconfig", "default_creds",
}

# Findings from these need Stage 5 validation (sqlmap, dalfox, etc.)
_NEEDS_VALIDATION_CLASSES = {
    "sqli", "xss", "ssrf", "lfi", "rfi", "idor", "auth_bypass",
}


# ---------------------------------------------------------------------------
# PUBLIC API: execute_tests
# ---------------------------------------------------------------------------


async def execute_tests(
    workspace_id: str,
    job_manager: JobManager | None = None,
) -> dict[str, Any]:
    """Execute the scan plan from Stage 3.

    - Single target with few test classes → synchronous
    - Multiple targets or many test classes → async job with progress
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Read scan plan
    scan_plan = await _read_scan_plan(workspace_id)
    if scan_plan is None:
        return _error(
            "no_scan_plan",
            "No scan plan found. Run bughound_submit_scan_plan first.",
        )

    targets = scan_plan.get("targets", [])
    if not targets:
        return _error("empty_plan", "Scan plan has no targets.")

    # Check nuclei availability
    from bughound.tools.scanning import nuclei

    if not nuclei.is_available():
        return _error(
            "tool_not_found",
            "nuclei is not installed. Install: go install -v "
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        )

    global_settings = scan_plan.get("global_settings", {})

    # Decide sync vs async
    total_classes = sum(len(t.get("test_classes", [])) for t in targets)
    is_small = len(targets) <= 2 and total_classes <= 6

    if is_small or job_manager is None:
        # Synchronous execution
        return await _run_tests(workspace_id, meta, targets, global_settings)
    else:
        # Async execution
        target_label = meta.target
        try:
            job_id = await job_manager.create_job(
                workspace_id, "execute_tests", target_label,
            )
        except RuntimeError as exc:
            return _error("execution_failed", str(exc))

        async def _run_async(jid: str) -> None:
            result = await _run_tests(
                workspace_id, meta, targets, global_settings, jid, job_manager,
            )
            summary = {
                "targets_tested": result.get("targets_tested", 0),
                "findings_total": result.get("findings_total", 0),
                "findings_by_severity": result.get("findings_by_severity", {}),
            }
            await job_manager.complete_job(jid, summary)

        await job_manager.start_job(job_id, _run_async(job_id))

        return {
            "status": "job_started",
            "job_id": job_id,
            "message": (
                f"Testing started for {len(targets)} targets. "
                "Do NOT poll in a loop. Continue reasoning about findings from "
                "previous stages. Check this job once with bughound_job_status "
                "after a few minutes."
            ),
            "workspace_id": workspace_id,
            "estimated_time": f"{len(targets) * 2}-{len(targets) * 5} minutes",
        }


# ---------------------------------------------------------------------------
# PUBLIC API: test_single
# ---------------------------------------------------------------------------


async def test_single(
    workspace_id: str,
    target_url: str,
    tool: str = "nuclei",
    tags: str | None = None,
    severity: str | None = None,
    template: str | None = None,
) -> dict[str, Any]:
    """Surgical test of one specific endpoint. Always synchronous."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Scope check
    in_scope = await workspace.is_in_scope(workspace_id, target_url)
    if not in_scope:
        return _error("out_of_scope", f"Target '{target_url}' is out of scope.")

    if tool == "nuclei":
        from bughound.tools.scanning import nuclei

        if not nuclei.is_available():
            return _error(
                "tool_not_found",
                "nuclei is not installed.",
            )

        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
        result = await nuclei.execute(
            target_url,
            tags=tag_list,
            severity=severity or "critical,high,medium",
            template_path=template,
            timeout=300,
        )

        if not result.success:
            err_msg = result.error.message if result.error else "nuclei execution failed"
            return _error("execution_failed", err_msg)

        raw_findings = result.results if isinstance(result.results, list) else []

    elif tool == "ffuf":
        if not tool_runner.is_available("ffuf"):
            return _error("tool_not_found", "ffuf is not installed.")
        # ffuf integration placeholder
        return _error(
            "not_implemented",
            "ffuf integration not yet implemented. Use nuclei for now.",
        )
    else:
        return _error("unknown_tool", f"Unknown tool: {tool}. Supported: nuclei, ffuf.")

    # Process findings
    findings = _process_findings(raw_findings, workspace_id)

    # Append to workspace (don't overwrite)
    if findings:
        await _append_findings(workspace_id, findings)
        await workspace.update_stats(
            workspace_id, findings_total=len(findings),
        )

    severity_counts = _count_by_severity(findings)

    return {
        "status": "success",
        "workspace_id": workspace_id,
        "tool": tool,
        "target": target_url,
        "findings_total": len(findings),
        "findings_by_severity": severity_counts,
        "findings": findings[:20],  # cap output for large results
        "next_step": (
            "Use bughound_validate_finding for findings that need confirmation, "
            "or bughound_generate_report for definitive findings."
            if findings
            else "No findings. Try different tags or a broader severity filter."
        ),
    }


# ---------------------------------------------------------------------------
# Internal: run tests
# ---------------------------------------------------------------------------


async def _run_tests(
    workspace_id: str,
    meta: Any,
    targets: list[dict[str, Any]],
    global_settings: dict[str, Any],
    job_id: str | None = None,
    job_manager: JobManager | None = None,
) -> dict[str, Any]:
    """Core test execution logic for both sync and async paths."""
    from bughound.tools.scanning import nuclei

    # Update state
    await workspace.update_metadata(
        workspace_id, state=WorkspaceState.TESTING, current_stage=4,
    )
    await workspace.add_stage_history(workspace_id, 4, "running")

    # Read live hosts for URL mapping
    live_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    host_url_map = _build_host_url_map(live_hosts)

    nuclei_severity = global_settings.get("nuclei_severity", "critical,high,medium")
    timeout_per_target = global_settings.get("timeout_per_target", 300)

    # Sort targets by priority
    sorted_targets = sorted(targets, key=lambda t: t.get("priority", 99))

    all_findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    targets_tested = 0

    for idx, plan_target in enumerate(sorted_targets):
        host = plan_target.get("host", "")
        test_classes = plan_target.get("test_classes", [])
        specific_endpoints = plan_target.get("specific_endpoints", [])

        if not host or not test_classes:
            warnings.append(f"Skipping target with missing host or test_classes: {host}")
            continue

        # Progress update
        if job_manager and job_id:
            pct = int(10 + (idx / len(sorted_targets)) * 85)
            await job_manager.update_progress(
                job_id, pct,
                f"Testing {host} ({idx + 1}/{len(sorted_targets)})",
                "nuclei",
            )

        # Build nuclei tags from test classes
        all_tags: list[str] = []
        has_cve_specific = False
        for tc in test_classes:
            mapped = _TEST_CLASS_TAGS.get(tc, [])
            all_tags.extend(mapped)
            if tc == "cve_specific":
                has_cve_specific = True

        # Deduplicate tags
        all_tags = sorted(set(all_tags)) if all_tags else []

        # Determine target URLs
        if specific_endpoints:
            scan_targets: str | list[str] = specific_endpoints
        else:
            # Use host URL from live_hosts mapping
            host_url = host_url_map.get(host)
            if host_url:
                scan_targets = host_url
            elif host.startswith(("http://", "https://")):
                scan_targets = host
            else:
                scan_targets = f"https://{host}"

        # Build severity — for cve_specific, use critical,high only
        effective_severity = nuclei_severity
        if has_cve_specific and not all_tags:
            effective_severity = "critical,high"

        # Run nuclei
        try:
            result = await nuclei.execute(
                scan_targets,
                tags=all_tags if all_tags else None,
                severity=effective_severity,
                timeout=timeout_per_target,
            )

            if result.success and result.results:
                raw_findings = result.results if isinstance(result.results, list) else []
                processed = _process_findings(raw_findings, workspace_id, test_classes)
                all_findings.extend(processed)
            elif not result.success:
                err = result.error.message if result.error else "unknown error"
                warnings.append(f"nuclei failed for {host}: {err}")

        except Exception as exc:
            warnings.append(f"Error testing {host}: {exc}")

        targets_tested += 1

    # Write findings to workspace
    if all_findings:
        await _write_findings(workspace_id, all_findings)

    # Update stats
    await workspace.update_stats(
        workspace_id, findings_total=len(all_findings),
    )
    await workspace.add_stage_history(workspace_id, 4, "completed")

    severity_counts = _count_by_severity(all_findings)
    needs_validation = sum(1 for f in all_findings if f.get("needs_validation"))
    definitive = len(all_findings) - needs_validation

    return {
        "status": "success",
        "workspace_id": workspace_id,
        "targets_tested": targets_tested,
        "findings_total": len(all_findings),
        "findings_by_severity": severity_counts,
        "findings_needing_validation": needs_validation,
        "findings_definitive": definitive,
        "warnings": warnings,
        "files_written": ["vulnerabilities/scan_results.json"] if all_findings else [],
        "next_step": (
            "Use bughound_validate_finding for findings that need confirmation "
            "(sqli, xss, ssrf). Use bughound_generate_report for definitive findings."
            if all_findings
            else "No findings from nuclei. Consider adjusting the scan plan or "
            "running bughound_test_single with broader tags."
        ),
    }


# ---------------------------------------------------------------------------
# Finding processing
# ---------------------------------------------------------------------------


def _process_findings(
    raw_findings: list[dict[str, Any]],
    workspace_id: str,
    test_classes: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert raw nuclei output to standardized finding dicts."""
    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue

        template_id = raw.get("template_id", "unknown")
        host = raw.get("host", "")
        matched_at = raw.get("matched_at", "")
        severity = raw.get("severity", "info").lower()

        # Generate unique finding_id
        hash_input = f"{template_id}:{host}:{matched_at}"
        hash8 = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        finding_id = f"finding_{severity}_{hash8}"

        # Skip duplicates
        if finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)

        # Classify vulnerability
        vuln_class = _classify_vuln(template_id, raw.get("matcher_name", ""))
        needs_val = vuln_class in _NEEDS_VALIDATION_CLASSES

        # Determine confidence
        if vuln_class in _DEFINITIVE_CLASSES:
            confidence = "high"
        elif severity in ("critical", "high"):
            confidence = "medium"
        else:
            confidence = "low"

        finding = {
            "finding_id": finding_id,
            "host": host,
            "endpoint": matched_at or host,
            "vulnerability_class": vuln_class,
            "severity": severity,
            "tool": "nuclei",
            "template_id": template_id,
            "template_name": raw.get("template_name", "Unknown"),
            "description": raw.get("description", ""),
            "evidence": raw.get("curl_command") or raw.get("matcher_name", ""),
            "curl_command": raw.get("curl_command", ""),
            "extracted_results": raw.get("extracted_results", []),
            "confidence": confidence,
            "needs_validation": needs_val,
            "validated": False,
            "validation_status": None,
        }
        findings.append(finding)

    return findings


def _classify_vuln(template_id: str, matcher_name: str) -> str:
    """Map nuclei template_id to a vulnerability class."""
    tid = template_id.lower()
    # Check template ID patterns
    patterns = {
        "sqli": ["sqli", "sql-injection", "sql_injection"],
        "xss": ["xss", "cross-site-scripting"],
        "ssrf": ["ssrf", "server-side-request"],
        "lfi": ["lfi", "local-file-inclusion", "path-traversal"],
        "rfi": ["rfi", "remote-file-inclusion"],
        "open_redirect": ["redirect", "open-redirect"],
        "subdomain_takeover": ["takeover"],
        "file_exposure": ["exposure", "git-config", "env-file", "backup"],
        "misconfig": ["misconfig", "cors", "header"],
        "default_creds": ["default-login", "default-credential"],
        "idor": ["idor", "insecure-direct"],
        "auth_bypass": ["auth-bypass", "authentication-bypass"],
        "wordpress": ["wordpress", "wp-"],
        "graphql": ["graphql"],
        "api_abuse": ["api-"],
    }

    for vuln_class, keywords in patterns.items():
        if any(kw in tid for kw in keywords):
            return vuln_class

    # Fallback: check severity-based classification
    if "cve-" in tid:
        return "cve_specific"

    return "other"


# ---------------------------------------------------------------------------
# Workspace I/O
# ---------------------------------------------------------------------------


async def _read_scan_plan(workspace_id: str) -> dict[str, Any] | None:
    """Read scan_plan.json from workspace."""
    fpath = WORKSPACE_BASE_DIR / workspace_id / "scan_plan.json"
    if not fpath.exists():
        return None
    try:
        async with aiofiles.open(fpath) as f:
            return json.loads(await f.read())
    except (json.JSONDecodeError, OSError):
        return None


async def _write_findings(
    workspace_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Write findings to vulnerabilities/scan_results.json."""
    await workspace.write_data(
        workspace_id, "vulnerabilities/scan_results.json", findings,
        generated_by="nuclei", target="multiple",
    )


async def _append_findings(
    workspace_id: str,
    new_findings: list[dict[str, Any]],
) -> None:
    """Append findings to existing scan_results.json (for test_single)."""
    existing = await workspace.read_data(
        workspace_id, "vulnerabilities/scan_results.json",
    )

    if isinstance(existing, dict) and "data" in existing:
        existing_items = existing["data"]
    elif isinstance(existing, list):
        existing_items = existing
    else:
        existing_items = []

    # Deduplicate by finding_id
    existing_ids = {f.get("finding_id") for f in existing_items if isinstance(f, dict)}
    merged = list(existing_items)
    for f in new_findings:
        if f.get("finding_id") not in existing_ids:
            merged.append(f)

    await workspace.write_data(
        workspace_id, "vulnerabilities/scan_results.json", merged,
        generated_by="nuclei", target="multiple",
    )


def _build_host_url_map(live_hosts: Any) -> dict[str, str]:
    """Build hostname → full URL map from live_hosts data."""
    url_map: dict[str, str] = {}
    if not live_hosts:
        return url_map

    items = live_hosts
    if isinstance(live_hosts, dict):
        items = live_hosts.get("data", [])

    for host_data in items:
        if not isinstance(host_data, dict):
            continue
        hostname = host_data.get("host", "")
        url = host_data.get("url", "")
        if hostname and url:
            url_map[hostname] = url

    return url_map


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
