"""Stage 4: Execute scan plan — 5-phase testing with technique library.

Phase 4A: Nuclei template scan
Phase 4B: Deep directory fuzzing (ffuf)
Phase 4C: Deep parameter discovery (arjun)
Phase 4D: Value fuzzing / injection testing (sqlmap, dalfox, injection_tester)
Phase 4E: Technology-specific tests (GraphQL, JWT, WordPress, Spring Boot)

No decision-making happens here. Tools run exactly what the scan plan says.
The AI client handles the feedback loop (find → re-recon → test more).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

import aiofiles
import structlog

from bughound.config.settings import WORKSPACE_BASE_DIR
from bughound.core import tool_runner, workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import ToolResult, WorkspaceState
from bughound.stages import techniques

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

# Tool → needs_validation override (some tools are definitive)
_TOOL_DEFINITIVE = {"sqlmap", "dalfox", "graphql_tester"}


# ---------------------------------------------------------------------------
# PUBLIC API: execute_tests
# ---------------------------------------------------------------------------


async def execute_tests(
    workspace_id: str,
    job_manager: JobManager | None = None,
) -> dict[str, Any]:
    """Execute the scan plan from Stage 3 using 5-phase technique library.

    - Single target with few test classes → synchronous
    - Multiple targets or many test classes → async job with progress
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    scan_plan = await _read_scan_plan(workspace_id)
    if scan_plan is None:
        return _error(
            "no_scan_plan",
            "No scan plan found. Run bughound_submit_scan_plan first.",
        )

    targets = scan_plan.get("targets", [])
    if not targets:
        return _error("empty_plan", "Scan plan has no targets.")

    global_settings = scan_plan.get("global_settings", {})

    # Decide sync vs async
    total_classes = sum(len(t.get("test_classes", [])) for t in targets)
    is_small = len(targets) <= 2 and total_classes <= 5

    if is_small or job_manager is None:
        return await _run_tests(workspace_id, meta, targets, global_settings)
    else:
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
                f"Testing started for {len(targets)} targets with {total_classes} "
                "test classes across 5 phases. Do NOT poll in a loop. Check once "
                "with bughound_job_status after a few minutes."
            ),
            "workspace_id": workspace_id,
            "estimated_time": f"{len(targets) * 3}-{len(targets) * 8} minutes",
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
    technique: str | None = None,
) -> dict[str, Any]:
    """Surgical test of one specific endpoint. Always synchronous.

    Specify either tool (nuclei, sqlmap, dalfox, ffuf) or technique
    (ssrf_test, graphql_test, jwt_test, etc.).
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Scope check
    in_scope = await workspace.is_in_scope(workspace_id, target_url)
    if not in_scope:
        return _error("out_of_scope", f"Target '{target_url}' is out of scope.")

    findings: list[dict[str, Any]] = []

    # Route by technique (pure-python testers)
    if technique:
        tech_targets = [{"host": _host_from_url(target_url)}]
        try:
            raw = await techniques.execute_technique(
                technique, workspace_id, tech_targets,
            )
            for r in raw:
                r["finding_id"] = _make_finding_id(r)
                r.setdefault("validated", False)
                r.setdefault("validation_status", None)
            findings.extend(raw)
        except Exception as exc:
            return _error("execution_failed", f"Technique '{technique}' failed: {exc}")

    # Route by tool
    elif tool == "nuclei":
        from bughound.tools.scanning import nuclei

        if not nuclei.is_available():
            return _error("tool_not_found", "nuclei is not installed.")

        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
        result = await nuclei.execute(
            target_url,
            tags=tag_list,
            severity=severity or "critical,high,medium",
            template_path=template,
            timeout=300,
        )
        if not result.success:
            err_msg = result.error.message if result.error else "nuclei failed"
            return _error("execution_failed", err_msg)

        raw_findings = result.results if isinstance(result.results, list) else []
        findings = _process_nuclei_findings(raw_findings, workspace_id)

    elif tool == "sqlmap":
        from bughound.tools.scanning import sqlmap

        if not sqlmap.is_available():
            return _error("tool_not_found", "sqlmap is not installed.")

        result = await sqlmap.execute(target_url, timeout=120)
        if result.success and result.results:
            for r in result.results:
                if isinstance(r, dict) and r.get("vulnerable"):
                    findings.append({
                        "finding_id": _make_finding_id({"host": target_url, "tool": "sqlmap"}),
                        "host": _host_from_url(target_url),
                        "endpoint": target_url,
                        "vulnerability_class": "sqli",
                        "severity": "critical",
                        "tool": "sqlmap",
                        "technique_id": "sqli_param_fuzz",
                        "description": f"SQL injection confirmed: {r.get('db_type', 'unknown')}",
                        "evidence": str(r.get("payloads", []))[:500],
                        "payload_used": r.get("payloads", [""])[0] if r.get("payloads") else "",
                        "confidence": "high",
                        "needs_validation": False,
                        "validated": True,
                        "validation_status": "confirmed",
                    })

    elif tool == "dalfox":
        from bughound.tools.scanning import dalfox

        if not dalfox.is_available():
            return _error("tool_not_found", "dalfox is not installed.")

        result = await dalfox.execute(target_url, timeout=120)
        if result.success and result.results:
            for r in result.results:
                if not isinstance(r, dict):
                    continue
                findings.append({
                    "finding_id": _make_finding_id({"host": target_url, "tool": "dalfox", "payload": r.get("payload", "")}),
                    "host": _host_from_url(target_url),
                    "endpoint": r.get("url", target_url),
                    "vulnerability_class": "xss",
                    "severity": "high",
                    "tool": "dalfox",
                    "technique_id": "xss_param_fuzz",
                    "description": f"{r.get('xss_type', 'reflected')} XSS confirmed",
                    "evidence": r.get("evidence", ""),
                    "payload_used": r.get("payload", ""),
                    "confidence": "high",
                    "needs_validation": False,
                    "validated": True,
                    "validation_status": "confirmed",
                })

    elif tool == "ffuf":
        from bughound.tools.scanning import ffuf

        if not ffuf.is_available():
            return _error("tool_not_found", "ffuf is not installed.")

        result = await ffuf.execute(target_url, timeout=300)
        if result.success and result.results:
            for r in result.results:
                if not isinstance(r, dict):
                    continue
                findings.append({
                    "finding_id": _make_finding_id({"host": target_url, "path": r.get("path", "")}),
                    "host": _host_from_url(target_url),
                    "endpoint": r.get("url", ""),
                    "vulnerability_class": "content_discovery",
                    "severity": "info",
                    "tool": "ffuf",
                    "technique_id": "deep_dirfuzz",
                    "description": f"Directory found: {r.get('path', '')} ({r.get('status_code', '?')})",
                    "evidence": f"Size: {r.get('content_length', 0)} bytes",
                    "confidence": "high",
                    "needs_validation": False,
                    "validated": False,
                    "validation_status": None,
                })

    else:
        return _error(
            "unknown_tool",
            f"Unknown tool: {tool}. Supported: nuclei, sqlmap, dalfox, ffuf. "
            "Or use technique= for injection_tester techniques.",
        )

    # Append to workspace
    if findings:
        await _append_findings(workspace_id, findings)
        await workspace.update_stats(workspace_id, findings_total=len(findings))

    return {
        "status": "success",
        "workspace_id": workspace_id,
        "tool": technique or tool,
        "target": target_url,
        "findings_total": len(findings),
        "findings_by_severity": _count_by_severity(findings),
        "findings": findings[:20],
        "next_step": (
            "Use bughound_validate_finding for findings that need confirmation, "
            "or bughound_generate_report for definitive findings."
            if findings
            else "No findings. Try different tool/technique or broader parameters."
        ),
    }


# ---------------------------------------------------------------------------
# Internal: 5-phase test execution
# ---------------------------------------------------------------------------


async def _run_tests(
    workspace_id: str,
    meta: Any,
    targets: list[dict[str, Any]],
    global_settings: dict[str, Any],
    job_id: str | None = None,
    job_manager: JobManager | None = None,
) -> dict[str, Any]:
    """Core 5-phase test execution."""
    from bughound.tools.scanning import nuclei

    await workspace.update_metadata(
        workspace_id, state=WorkspaceState.TESTING, current_stage=4,
    )
    await workspace.add_stage_history(workspace_id, 4, "running")

    live_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    host_url_map = _build_host_url_map(live_hosts)

    nuclei_severity = global_settings.get("nuclei_severity", "critical,high,medium")
    timeout_per_target = global_settings.get("timeout_per_target", 300)
    sorted_targets = sorted(targets, key=lambda t: t.get("priority", 99))

    all_findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    phase_stats: dict[str, int] = {}

    # Collect all test classes from plan
    all_test_classes: set[str] = set()
    for t in sorted_targets:
        all_test_classes.update(t.get("test_classes", []))

    async def _progress(pct: int, msg: str, module: str) -> None:
        if job_manager and job_id:
            await job_manager.update_progress(job_id, pct, msg, module)

    # =================================================================
    # Phase 4A: Nuclei Template Scan (0-30%)
    # =================================================================
    await _progress(1, "Phase 4A: Nuclei template scanning", "nuclei")

    nuclei_available = nuclei.is_available()
    nuclei_findings: list[dict[str, Any]] = []

    if nuclei_available:
        for idx, plan_target in enumerate(sorted_targets):
            host = plan_target.get("host", "")
            test_classes = plan_target.get("test_classes", [])
            specific_endpoints = plan_target.get("specific_endpoints", [])

            if not host or not test_classes:
                continue

            pct = int(1 + (idx / max(len(sorted_targets), 1)) * 28)
            await _progress(pct, f"Nuclei: testing {host}", "nuclei")

            all_tags: list[str] = []
            has_cve_specific = False
            for tc in test_classes:
                mapped = _TEST_CLASS_TAGS.get(tc, [])
                all_tags.extend(mapped)
                if tc == "cve_specific":
                    has_cve_specific = True

            all_tags = sorted(set(all_tags)) if all_tags else []

            if specific_endpoints:
                scan_targets: str | list[str] = specific_endpoints
            else:
                host_url = host_url_map.get(host)
                if host_url:
                    scan_targets = host_url
                elif host.startswith(("http://", "https://")):
                    scan_targets = host
                else:
                    scan_targets = f"https://{host}"

            effective_severity = nuclei_severity
            if has_cve_specific and not all_tags:
                effective_severity = "critical,high"

            try:
                result = await nuclei.execute(
                    scan_targets,
                    tags=all_tags if all_tags else None,
                    severity=effective_severity,
                    timeout=timeout_per_target,
                )
                if result.success and result.results:
                    raw = result.results if isinstance(result.results, list) else []
                    processed = _process_nuclei_findings(raw, workspace_id, test_classes)
                    nuclei_findings.extend(processed)
                elif not result.success:
                    err = result.error.message if result.error else "unknown"
                    warnings.append(f"nuclei failed for {host}: {err}")
            except Exception as exc:
                warnings.append(f"nuclei error for {host}: {exc}")

        all_findings.extend(nuclei_findings)
        phase_stats["4A_nuclei"] = len(nuclei_findings)
    else:
        warnings.append("nuclei not installed — skipping Phase 4A template scan.")
        phase_stats["4A_nuclei"] = 0

    # =================================================================
    # Phase 4B: Deep Directory Fuzzing (30-40%)
    # =================================================================
    if "content_discovery" in all_test_classes:
        await _progress(30, "Phase 4B: Deep directory fuzzing", "ffuf")
        try:
            dirfuzz_findings = await techniques.execute_technique(
                "deep_dirfuzz", workspace_id, sorted_targets,
            )
            for f in dirfuzz_findings:
                f["finding_id"] = _make_finding_id(f)
                f.setdefault("validated", False)
                f.setdefault("validation_status", None)
            all_findings.extend(dirfuzz_findings)
            phase_stats["4B_dirfuzz"] = len(dirfuzz_findings)
        except Exception as exc:
            warnings.append(f"Phase 4B dirfuzz error: {exc}")
            phase_stats["4B_dirfuzz"] = 0
    else:
        phase_stats["4B_dirfuzz"] = 0

    # =================================================================
    # Phase 4C: Deep Parameter Discovery (40-45%)
    # =================================================================
    if "param_discovery" in all_test_classes:
        await _progress(40, "Phase 4C: Deep parameter discovery", "arjun")
        # arjun integration deferred — runs in Stage 2 already
        phase_stats["4C_param_discovery"] = 0
    else:
        phase_stats["4C_param_discovery"] = 0

    # =================================================================
    # Phase 4D: Value Fuzzing / Injection Testing (45-88%)
    # =================================================================
    await _progress(45, "Phase 4D: Injection testing", "injection_tester")

    injection_techniques = [
        ("sqli", "sqli_param_fuzz", 45, 55),
        ("xss", "xss_param_fuzz", 55, 65),
        ("ssrf", "ssrf_test", 65, 70),
        ("open_redirect", "open_redirect_test", 70, 73),
        ("lfi", "lfi_test", 73, 76),
        ("idor", "idor_test", 76, 79),
        ("crlf", "crlf_test", 79, 82),
        ("ssti", "ssti_test", 82, 85),
        ("header_injection", "header_injection_test", 85, 88),
    ]

    for test_class, technique_id, pct_start, pct_end in injection_techniques:
        if test_class not in all_test_classes:
            phase_stats[f"4D_{technique_id}"] = 0
            continue

        avail = techniques.check_technique_availability(
            next((t for t in techniques.TECHNIQUE_REGISTRY if t["id"] == technique_id), {}),
        )
        if not avail.get("available", True):
            warnings.append(f"{technique_id}: missing {avail.get('missing_tools', [])}")
            phase_stats[f"4D_{technique_id}"] = 0
            continue

        await _progress(pct_start, f"Phase 4D: {technique_id}", technique_id)

        try:
            tech_findings = await techniques.execute_technique(
                technique_id, workspace_id, sorted_targets,
            )
            for f in tech_findings:
                f["finding_id"] = _make_finding_id(f)
                f.setdefault("validated", False)
                f.setdefault("validation_status", None)
                # Override needs_validation for definitive tools
                if f.get("tool") in _TOOL_DEFINITIVE:
                    f["needs_validation"] = False
            all_findings.extend(tech_findings)
            phase_stats[f"4D_{technique_id}"] = len(tech_findings)
        except Exception as exc:
            warnings.append(f"{technique_id} error: {exc}")
            phase_stats[f"4D_{technique_id}"] = 0

    # =================================================================
    # Phase 4E: Technology-Specific Tests (88-99%)
    # =================================================================
    tech_specific = [
        ("graphql", "graphql_test", 88, 92),
        ("jwt", "jwt_test", 92, 95),
        ("wordpress", "wordpress_test", 95, 97),
        ("spring", "spring_actuator_test", 97, 99),
    ]

    for test_class, technique_id, pct_start, pct_end in tech_specific:
        if test_class not in all_test_classes:
            phase_stats[f"4E_{technique_id}"] = 0
            continue

        await _progress(pct_start, f"Phase 4E: {technique_id}", technique_id)

        try:
            tech_findings = await techniques.execute_technique(
                technique_id, workspace_id, sorted_targets,
            )
            for f in tech_findings:
                f["finding_id"] = _make_finding_id(f)
                f.setdefault("validated", False)
                f.setdefault("validation_status", None)
            all_findings.extend(tech_findings)
            phase_stats[f"4E_{technique_id}"] = len(tech_findings)
        except Exception as exc:
            warnings.append(f"{technique_id} error: {exc}")
            phase_stats[f"4E_{technique_id}"] = 0

    # =================================================================
    # Finalize
    # =================================================================
    await _progress(99, "Finalizing results", "finalize")

    if all_findings:
        await _write_findings(workspace_id, all_findings)

    await workspace.update_stats(workspace_id, findings_total=len(all_findings))
    await workspace.add_stage_history(workspace_id, 4, "completed")

    severity_counts = _count_by_severity(all_findings)
    needs_validation = sum(1 for f in all_findings if f.get("needs_validation"))
    definitive = len(all_findings) - needs_validation

    # Count by tool
    tool_counts: Counter[str] = Counter()
    for f in all_findings:
        tool_counts[f.get("tool", "unknown")] += 1

    # Count by vuln class
    class_counts: Counter[str] = Counter()
    for f in all_findings:
        class_counts[f.get("vulnerability_class", "other")] += 1

    await _progress(100, "Testing complete", "done")

    return {
        "status": "success",
        "workspace_id": workspace_id,
        "targets_tested": len(sorted_targets),
        "findings_total": len(all_findings),
        "findings_by_severity": severity_counts,
        "findings_by_tool": dict(tool_counts.most_common()),
        "findings_by_class": dict(class_counts.most_common()),
        "findings_needing_validation": needs_validation,
        "findings_definitive": definitive,
        "phase_stats": phase_stats,
        "findings": all_findings[:30],
        "warnings": warnings,
        "files_written": ["vulnerabilities/scan_results.json"] if all_findings else [],
        "next_step": (
            "Review findings. Use bughound_validate_finding for findings that need "
            "confirmation (sqli, xss, ssrf). Use bughound_generate_report for "
            "definitive findings."
            if all_findings
            else "No findings. Consider broadening the scan plan or running "
            "bughound_test_single with specific techniques."
        ),
    }


# ---------------------------------------------------------------------------
# Finding processing
# ---------------------------------------------------------------------------


def _process_nuclei_findings(
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

        hash_input = f"{template_id}:{host}:{matched_at}"
        hash8 = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        finding_id = f"finding_{severity}_{hash8}"

        if finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)

        vuln_class = _classify_vuln(template_id, raw.get("matcher_name", ""))
        needs_val = vuln_class in _NEEDS_VALIDATION_CLASSES

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
            "technique_id": "nuclei_scan",
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

    if "cve-" in tid:
        return "cve_specific"

    return "other"


def _make_finding_id(finding: dict[str, Any]) -> str:
    """Generate a unique finding_id from finding data."""
    severity = finding.get("severity", "info").lower()
    hash_input = (
        f"{finding.get('tool', '')}:{finding.get('host', '')}:"
        f"{finding.get('endpoint', '')}:{finding.get('payload_used', '')}:"
        f"{finding.get('description', '')}"
    )
    hash8 = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    return f"finding_{severity}_{hash8}"


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
        generated_by="stage4", target="multiple",
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

    existing_ids = {f.get("finding_id") for f in existing_items if isinstance(f, dict)}
    merged = list(existing_items)
    for f in new_findings:
        if f.get("finding_id") not in existing_ids:
            merged.append(f)

    await workspace.write_data(
        workspace_id, "vulnerabilities/scan_results.json", merged,
        generated_by="stage4", target="multiple",
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


def _host_from_url(url: str) -> str:
    """Extract hostname from URL."""
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


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
