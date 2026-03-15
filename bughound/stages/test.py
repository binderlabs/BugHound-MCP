"""Stage 4: Execute scan plan — multi-phase testing with technique library.

Phase 4A-1: URL-level nuclei scan (all discovered URLs with params)
Phase 4A-2: Host-level misconfig scan (root URLs, exposure/misconfig/CVE templates)
Phase 4A-3: Technology-specific nuclei scan (WP, nginx, apache, spring, etc.)
Phase 4A-4: CVE-specific scan (version-detected hosts only)
Phase 4B: Deep directory fuzzing (ffuf)
Phase 4C: Deep parameter discovery (arjun)
Phase 4D: Value fuzzing / injection testing (sqlmap, dalfox, injection_tester)
Phase 4E: Technology-specific tests (GraphQL, JWT, WordPress, Spring Boot)
Phase 4F: Insecure cookie configuration findings

No decision-making happens here. Tools run exactly what the scan plan says.
The AI client handles the feedback loop (find → re-recon → test more).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from typing import Any
from urllib.parse import urlparse

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

# Technology keyword → nuclei tag groups for Phase 4A-3
_TECH_NUCLEI_TAGS: dict[str, list[str]] = {
    # CMS / Frameworks
    "wordpress": ["wordpress"],
    "wp-": ["wordpress"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "magento": ["magento"],
    # Web servers
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "aspnet"],
    "openresty": ["nginx"],
    "caddy": ["caddy"],
    # Java ecosystem
    "spring": ["spring", "java"],
    "java": ["java"],
    "tomcat": ["tomcat", "java"],
    "jetty": ["java"],
    "wildfly": ["java"],
    "jboss": ["java"],
    # Node.js ecosystem
    "node": ["nodejs"],
    "express": ["nodejs"],
    "next.js": ["nodejs"],
    "nuxt": ["nodejs"],
    "koa": ["nodejs"],
    # PHP ecosystem
    "php": ["php"],
    "laravel": ["php"],
    "symfony": ["php"],
    "codeigniter": ["php"],
    # Python ecosystem — httpx reports "Python", "Uvicorn", "Gunicorn", etc.
    "python": ["python"],
    "django": ["python"],
    "flask": ["python"],
    "uvicorn": ["python"],
    "gunicorn": ["python"],
    "fastapi": ["python"],
    "tornado": ["python"],
    # .NET ecosystem
    "asp.net": ["iis", "aspnet"],
    ".net": ["aspnet"],
    # Ruby ecosystem
    "ruby": ["ruby"],
    "rails": ["ruby"],
    "puma": ["ruby"],
    # GraphQL
    "graphql": ["graphql"],
    # CDN / WAF — useful for bypass templates
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai"],
    # Other
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "kibana": ["kibana"],
    "elasticsearch": ["elasticsearch"],
    "minio": ["minio"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes"],
}

# URL-level scan tags (templates that test URL params for vulns)
_URL_LEVEL_TAGS = [
    "sqli", "xss", "ssrf", "lfi", "redirect", "rce", "ssti", "crlf", "idor",
]

# Host-level misconfig tags (templates for root-URL scanning)
_HOST_MISCONFIG_TAGS = [
    "exposure", "misconfig", "cve", "default-login", "security-headers",
]


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

    # Always run as background job to avoid MCP client timeouts
    total_classes = sum(len(t.get("test_classes", [])) for t in targets)

    if job_manager is None:
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
                f"test classes across 5 phases."
            ),
            "workspace_id": workspace_id,
            "estimated_time": f"{len(targets) * 3}-{len(targets) * 8} minutes",
            "next_step": (
                "Testing job is running in the background. "
                "Present the job ID and estimated time to the user. "
                "Wait for the user to ask you to check status."
            ),
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
    # Normalize: AI clients may send list ["critical","high"] instead of string
    if isinstance(nuclei_severity, list):
        nuclei_severity = ",".join(str(s) for s in nuclei_severity)
    timeout_per_target = global_settings.get("timeout_per_target", 300)
    sorted_targets = sorted(targets, key=lambda t: t.get("priority", 99))

    all_findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    phase_stats: dict[str, int] = {}

    # Collect all test classes from plan
    all_test_classes: set[str] = set()
    for t in sorted_targets:
        all_test_classes.update(t.get("test_classes", []))

    # Auto-populate test_classes if empty (AI client forgot to include them)
    if not all_test_classes:
        logger.warning("scan_plan.test_classes_empty", msg="Auto-populating from attack surface")
        attack_surface = await _read_attack_surface(workspace_id)
        if attack_surface:
            suggested = attack_surface.get("suggested_test_classes", [])
            all_test_classes.update(suggested)
        all_test_classes.update([
            "sqli", "xss", "ssrf", "lfi", "ssti", "open_redirect",
            "crlf", "idor", "header_injection", "rce",
            "graphql", "jwt", "misconfig", "default_creds",
        ])

    # Always merge in low-cost, high-value classes that AI clients often omit
    all_test_classes.update([
        "cors", "bac", "rate_limiting", "cve_specific",
        "ssti", "csti", "crlf", "header_injection", "jwt", "graphql",
    ])

    async def _progress(pct: int, msg: str, module: str) -> None:
        if job_manager and job_id:
            await job_manager.update_progress(job_id, pct, msg, module)

    # Nuclei settings from scan plan
    nuclei_rate = global_settings.get("nuclei_rate_limit", 100)
    nuclei_concurrency = global_settings.get("nuclei_concurrency", 25)
    nuclei_timeout = global_settings.get("nuclei_timeout", 600)
    stealth_mode = global_settings.get("stealth", False)
    if stealth_mode:
        nuclei_rate = min(nuclei_rate, 10)
        nuclei_concurrency = min(nuclei_concurrency, 5)

    # Check if interactsh is available (for OOB templates)
    no_interactsh = not tool_runner.is_available("interactsh-client")

    # Collect test class tags from scan plan (includes any auto-populated classes)
    plan_tags: set[str] = set()
    has_cve_specific = False
    for tc in all_test_classes:
        plan_tags.update(_TEST_CLASS_TAGS.get(tc, []))
        if tc == "cve_specific":
            has_cve_specific = True

    # =================================================================
    # Phase 4A-1: URL-level Nuclei Scan (0-15%)
    # =================================================================
    await _progress(1, "Phase 4A-1: URL-level nuclei scan", "nuclei")

    nuclei_available = nuclei.is_available()
    nuclei_findings: list[dict[str, Any]] = []

    if nuclei_available:
        # Gather ALL discovered URLs from workspace
        all_urls = await _collect_all_urls(workspace_id)
        url_level_tags = [t for t in _URL_LEVEL_TAGS if t in plan_tags or not plan_tags]

        if all_urls and url_level_tags:
            # Deduplicate URLs with urldedupe if available
            deduped_urls = await _dedupe_urls(all_urls)
            phase_stats["4A1_urls_total"] = len(all_urls)
            phase_stats["4A1_urls_deduped"] = len(deduped_urls)

            await _progress(
                3, f"Phase 4A-1: Scanning {len(deduped_urls)} URLs "
                f"(from {len(all_urls)} total)", "nuclei",
            )

            # Batch large URL sets to avoid timeouts
            _BATCH_SIZE = 50
            url_batches = [
                deduped_urls[i:i + _BATCH_SIZE]
                for i in range(0, len(deduped_urls), _BATCH_SIZE)
            ] if len(deduped_urls) > _BATCH_SIZE else [deduped_urls]

            for batch_idx, url_batch in enumerate(url_batches):
                if len(url_batches) > 1:
                    await _progress(
                        3 + (12 * batch_idx // len(url_batches)),
                        f"Phase 4A-1: Batch {batch_idx + 1}/{len(url_batches)} "
                        f"({len(url_batch)} URLs)", "nuclei",
                    )
                try:
                    result = await nuclei.execute(
                        url_batch,
                        tags=url_level_tags,
                        severity=nuclei_severity,
                        rate_limit=nuclei_rate,
                        concurrency=nuclei_concurrency,
                        no_interactsh=no_interactsh,
                        timeout=nuclei_timeout,
                    )
                    if result.success and result.results:
                        raw = result.results if isinstance(result.results, list) else []
                        processed = _process_nuclei_findings(raw, workspace_id)
                        processed = _deduplicate_nuclei_findings(processed)
                        nuclei_findings.extend(processed)
                    elif not result.success:
                        err = result.error.message if result.error else "unknown"
                        warnings.append(f"nuclei URL-level batch {batch_idx + 1} failed: {err}")
                except Exception as exc:
                    warnings.append(f"nuclei URL-level batch {batch_idx + 1} error: {exc}")

            phase_stats["4A1_url_scan"] = len(nuclei_findings)
        else:
            if not all_urls:
                warnings.append("No URLs found for URL-level nuclei scan (run bughound_discover first).")
            phase_stats["4A1_url_scan"] = 0
            phase_stats["4A1_urls_total"] = 0
            phase_stats["4A1_urls_deduped"] = 0

        # =================================================================
        # Phase 4A-2: Host-level Misconfig Scan (15-22%)
        # =================================================================
        await _progress(15, "Phase 4A-2: Host misconfig scan", "nuclei")

        host_urls = list(host_url_map.values())
        # Also add hosts from scan plan that aren't in the map
        for plan_target in sorted_targets:
            h = plan_target.get("host", "")
            if h and h not in host_url_map:
                if h.startswith(("http://", "https://")):
                    host_urls.append(h)
                else:
                    host_urls.append(f"https://{h}")

        host_urls = sorted(set(host_urls))
        misconfig_findings_before = len(nuclei_findings)

        if host_urls:
            try:
                result = await nuclei.execute(
                    host_urls,
                    tags=_HOST_MISCONFIG_TAGS,
                    severity="critical,high,medium,low,info",
                    rate_limit=nuclei_rate,
                    concurrency=nuclei_concurrency,
                    no_interactsh=no_interactsh,
                    timeout=nuclei_timeout,
                )
                if result.success and result.results:
                    raw = result.results if isinstance(result.results, list) else []
                    processed = _process_nuclei_findings(raw, workspace_id)
                    processed = _deduplicate_nuclei_findings(processed)
                    nuclei_findings.extend(processed)
                elif not result.success:
                    err = result.error.message if result.error else "unknown"
                    warnings.append(f"nuclei host-misconfig scan failed: {err}")
            except Exception as exc:
                warnings.append(f"nuclei host-misconfig error: {exc}")

        phase_stats["4A2_host_misconfig"] = len(nuclei_findings) - misconfig_findings_before

        # =================================================================
        # Phase 4A-3: Technology-specific Nuclei Scan (22-30%)
        # =================================================================
        await _progress(22, "Phase 4A-3: Tech-specific nuclei scan", "nuclei")

        tech_findings_before = len(nuclei_findings)
        tech_groups = await _group_hosts_by_technology(workspace_id, host_url_map)

        for tech_tag_group, tech_hosts in tech_groups.items():
            if not tech_hosts:
                continue
            tech_tags = tech_tag_group.split(",")
            await _progress(
                25, f"Phase 4A-3: {tech_tags[0]} templates ({len(tech_hosts)} hosts)",
                "nuclei",
            )
            try:
                result = await nuclei.execute(
                    tech_hosts,
                    tags=tech_tags,
                    severity="critical,high,medium,low",
                    rate_limit=nuclei_rate,
                    concurrency=nuclei_concurrency,
                    no_interactsh=no_interactsh,
                    timeout=nuclei_timeout,
                )
                if result.success and result.results:
                    raw = result.results if isinstance(result.results, list) else []
                    processed = _process_nuclei_findings(raw, workspace_id)
                    processed = _deduplicate_nuclei_findings(processed)
                    nuclei_findings.extend(processed)
            except Exception as exc:
                warnings.append(f"nuclei tech-specific ({tech_tags[0]}) error: {exc}")

        phase_stats["4A3_tech_specific"] = len(nuclei_findings) - tech_findings_before

        # =================================================================
        # Phase 4A-4: CVE-specific Scan (30-35%)
        # =================================================================
        if has_cve_specific:
            await _progress(30, "Phase 4A-4: CVE scan (versioned hosts)", "nuclei")

            cve_findings_before = len(nuclei_findings)
            versioned_hosts = await _get_versioned_hosts(workspace_id, host_url_map)

            if versioned_hosts:
                try:
                    result = await nuclei.execute(
                        versioned_hosts,
                        tags=["cve"],
                        severity="critical,high",
                        rate_limit=nuclei_rate,
                        concurrency=nuclei_concurrency,
                        no_interactsh=no_interactsh,
                        timeout=nuclei_timeout,
                    )
                    if result.success and result.results:
                        raw = result.results if isinstance(result.results, list) else []
                        processed = _process_nuclei_findings(raw, workspace_id)
                        processed = _deduplicate_nuclei_findings(processed)
                        nuclei_findings.extend(processed)
                except Exception as exc:
                    warnings.append(f"nuclei CVE scan error: {exc}")

            phase_stats["4A4_cve_scan"] = len(nuclei_findings) - cve_findings_before
        else:
            phase_stats["4A4_cve_scan"] = 0

        # Final deduplication across all 4A sub-phases
        nuclei_findings = _deduplicate_nuclei_findings(nuclei_findings)

        # Mark path traversal findings for validation
        for f in nuclei_findings:
            ep = f.get("endpoint", "")
            tid = f.get("template_id", "")
            if _is_path_traversal_candidate(tid, ep):
                f["_traversal_check"] = True

        # Validate path traversal findings (re-fetch to check for real content)
        nuclei_findings = await _validate_traversal_findings(nuclei_findings)
        all_findings.extend(nuclei_findings)
        phase_stats["4A_nuclei_total"] = len(nuclei_findings)
    else:
        warnings.append("nuclei not installed — skipping Phase 4A template scans.")
        phase_stats["4A_nuclei_total"] = 0
        phase_stats["4A1_url_scan"] = 0
        phase_stats["4A2_host_misconfig"] = 0
        phase_stats["4A3_tech_specific"] = 0
        phase_stats["4A4_cve_scan"] = 0

    # =================================================================
    # Phase 4B: Deep Directory Fuzzing (35-40%)
    # =================================================================
    if "content_discovery" in all_test_classes:
        await _progress(35, "Phase 4B: Deep directory fuzzing", "ffuf")
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
    # Phase 4D-pre: One-liner Pipeline Pre-filtering (45-48%)
    # =================================================================
    await _progress(45, "Phase 4D-pre: One-liner pre-filtering", "pipeline")

    injection_classes = {
        "sqli", "xss", "ssrf", "open_redirect", "lfi", "crlf", "ssti",
    }
    active_injection_classes = [c for c in injection_classes if c in all_test_classes]

    pipeline_candidates: dict[str, list] = {}
    pipeline_findings: list[dict[str, Any]] = []
    if active_injection_classes:
        try:
            from bughound.tools.oneliners.pipeline import run_prefilter

            prefilter_result = await run_prefilter(workspace_id, active_injection_classes)
            pipeline_candidates = prefilter_result.get("candidates_by_class", {})
            total_prefiltered = prefilter_result.get("total_candidates", 0)
            phase_stats["4D_pre_pipeline"] = total_prefiltered
            phase_stats["4D_pre_urls_before_dedupe"] = prefilter_result.get("urls_before_dedupe", 0)
            phase_stats["4D_pre_urls_after_dedupe"] = prefilter_result.get("urls_after_dedupe", 0)

            # Smart pipelines that do HTTP verification produce confirmed findings
            for vc, candidates in pipeline_candidates.items():
                for c in candidates:
                    if not isinstance(c, dict):
                        continue
                    # mass_* pipelines return hits with severity set
                    if c.get("severity") and c.get("matched"):
                        pipeline_findings.append({
                            "host": _host_from_url(c.get("url", "")),
                            "endpoint": c.get("url", ""),
                            "vulnerability_class": vc,
                            "severity": c.get("severity", "medium"),
                            "tool": "pipeline",
                            "technique_id": f"pipeline_{vc}",
                            "description": c.get("description", f"Pipeline {vc} hit"),
                            "evidence": f"Match: {c.get('matched_strings', c.get('match_type', ''))}",
                            "confidence": "medium",
                            "needs_validation": True,
                            "finding_id": _make_finding_id(c),
                            "validated": False,
                            "validation_status": None,
                        })

            if pipeline_findings:
                all_findings.extend(pipeline_findings)
                phase_stats["4D_pre_findings"] = len(pipeline_findings)

            if total_prefiltered > 0:
                await _progress(
                    47, f"Pre-filter: {total_prefiltered} candidates across "
                    f"{len(pipeline_candidates)} classes "
                    f"({len(pipeline_findings)} verified hits)",
                    "pipeline",
                )
        except Exception as exc:
            warnings.append(f"Pipeline pre-filter error: {exc}")
            phase_stats["4D_pre_pipeline"] = 0
    else:
        phase_stats["4D_pre_pipeline"] = 0

    # =================================================================
    # Phase 4D+4E: Parallel Injection + Tech-Specific Testing (48-95%)
    # =================================================================
    await _progress(48, "Phase 4D+4E: Parallel injection & tech testing", "parallel")

    # -- Technique definitions -----------------------------------------
    injection_techniques = [
        ("sqli", "sqli_param_fuzz"),
        ("sqli", "sqli_error_test"),
        ("sqli", "cookie_sqli"),
        ("sqli", "post_sqli"),
        ("xss", "xss_param_fuzz"),
        ("xss", "reflected_xss_test"),
        ("xss", "stored_xss"),
        ("xss", "dom_xss"),
        ("xss", "cookie_xss"),
        ("ssrf", "ssrf_test"),
        ("open_redirect", "open_redirect_test"),
        ("lfi", "lfi_test"),
        ("rce", "rce_test"),
        ("rce", "post_rce"),
        ("idor", "idor_test"),
        ("idor", "path_idor_test"),
        ("crlf", "crlf_test"),
        ("ssti", "ssti_test"),
        ("ssti", "post_ssti"),
        ("csti", "csti_test"),
        ("deserialization", "cookie_deserialization"),
        ("header_injection", "header_injection_test"),
    ]

    tech_specific = [
        ("graphql", "graphql_test"),
        ("jwt", "jwt_test"),
        ("wordpress", "wordpress_test"),
        ("spring", "spring_actuator_test"),
        ("bac", "broken_access_control"),
        ("rate_limiting", "rate_limit_test"),
        ("mass_assignment", "mass_assignment_test"),
        ("cors", "cors_misconfig"),
    ]

    # -- Build runnable task list (filter by test_class + availability) -
    # Heavy tools that spawn subprocesses — limit concurrency
    _HEAVY_TECHNIQUES = {"sqli_param_fuzz", "xss_param_fuzz", "deep_dirfuzz"}
    heavy_sem = asyncio.Semaphore(2)   # max 2 external-tool techniques
    light_sem = asyncio.Semaphore(6)   # max 6 pure-Python techniques

    async def _run_technique(
        technique_id: str, phase_prefix: str,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Run a single technique with semaphore control. Returns (id, findings)."""
        sem = heavy_sem if technique_id in _HEAVY_TECHNIQUES else light_sem
        async with sem:
            logger.info(
                "technique.parallel_start", technique_id=technique_id,
            )
            try:
                tech_findings = await techniques.execute_technique(
                    technique_id, workspace_id, sorted_targets,
                )
                for f in tech_findings:
                    f["finding_id"] = _make_finding_id(f)
                    f.setdefault("validated", False)
                    f.setdefault("validation_status", None)
                    if f.get("tool") in _TOOL_DEFINITIVE:
                        f["needs_validation"] = False
                return technique_id, tech_findings
            except Exception as exc:
                logger.warning(
                    "technique.parallel_error",
                    technique_id=technique_id, error=str(exc),
                )
                return technique_id, []

    # -- Collect tasks --------------------------------------------------
    parallel_tasks: list[asyncio.Task] = []
    task_meta: dict[str, str] = {}  # technique_id -> phase_prefix

    for test_class, technique_id in injection_techniques:
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
        task = asyncio.create_task(
            _run_technique(technique_id, "4D"),
            name=f"4D_{technique_id}",
        )
        parallel_tasks.append(task)
        task_meta[technique_id] = "4D"

    for test_class, technique_id in tech_specific:
        if test_class not in all_test_classes:
            phase_stats[f"4E_{technique_id}"] = 0
            continue
        task = asyncio.create_task(
            _run_technique(technique_id, "4E"),
            name=f"4E_{technique_id}",
        )
        parallel_tasks.append(task)
        task_meta[technique_id] = "4E"

    # -- Execute all in parallel with progress updates ------------------
    total_tasks = len(parallel_tasks)
    if total_tasks > 0:
        await _progress(
            50,
            f"Phase 4D+4E: Running {total_tasks} techniques in parallel "
            f"(heavy={heavy_sem._value} slots, light={light_sem._value} slots)",
            "parallel",
        )

        completed = 0
        for coro in asyncio.as_completed(parallel_tasks):
            technique_id, tech_findings = await coro
            completed += 1
            prefix = task_meta.get(technique_id, "4D")
            phase_stats[f"{prefix}_{technique_id}"] = len(tech_findings)
            if tech_findings:
                all_findings.extend(tech_findings)

            # Progress: 50% → 95% spread across tasks
            pct = 50 + int(45 * completed / total_tasks)
            await _progress(
                pct,
                f"Completed {technique_id} ({len(tech_findings)} findings) "
                f"[{completed}/{total_tasks}]",
                technique_id,
            )

    # =================================================================
    # Phase 4F: Insecure Cookie Configuration Findings
    # =================================================================
    auth_raw = await workspace.read_data(workspace_id, "hosts/auth_discovery.json")
    auth_items = auth_raw.get("data", []) if isinstance(auth_raw, dict) else (auth_raw or [])
    cookie_findings: list[dict[str, Any]] = []

    for auth in auth_items:
        if not isinstance(auth, dict):
            continue
        target_url = auth.get("target_url", "")
        host = _host_from_url(target_url)
        if host not in {t.get("host", "").lower() for t in sorted_targets}:
            continue

        for flag in auth.get("insecure_cookie_flags", []):
            issue = flag.get("issue", "")
            cookie_name = flag.get("cookie_name", "")
            classification = flag.get("classification", "other")

            # Session cookies without HttpOnly are more severe
            if issue == "missing_httponly" and classification == "session":
                severity = "medium"
            elif issue == "missing_secure":
                severity = "low"
            elif issue == "missing_httponly":
                severity = "info"
            elif issue == "missing_samesite":
                severity = "low"
            else:
                severity = "info"

            cookie_findings.append({
                "finding_id": _make_finding_id({
                    "host": host, "tool": "auth_analyzer",
                    "description": f"{issue}:{cookie_name}",
                }),
                "host": host,
                "endpoint": target_url,
                "vulnerability_class": "insecure_cookie",
                "severity": severity,
                "tool": "auth_analyzer",
                "technique_id": "auth_discovery",
                "description": f"Insecure cookie '{cookie_name}': {issue.replace('_', ' ')}",
                "evidence": f"Cookie classification: {classification}",
                "confidence": "high",
                "needs_validation": False,
                "validated": True,
                "validation_status": "confirmed",
            })

    if cookie_findings:
        all_findings.extend(cookie_findings)
        phase_stats["4F_cookie_config"] = len(cookie_findings)
    else:
        phase_stats["4F_cookie_config"] = 0

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
            "Testing complete. Present findings to user and await further instructions."
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
        matcher_name = raw.get("matcher_name", "")
        severity = raw.get("severity", "info").lower()
        # Include matcher_name in hash so multi-matcher templates
        # (e.g. http-missing-security-headers) produce separate findings
        hash_input = f"{template_id}:{host}:{matched_at}:{matcher_name}"
        hash8 = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        finding_id = f"finding_{severity}_{hash8}"

        if finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)

        vuln_class = _classify_vuln(template_id, raw.get("matcher_name", ""))
        needs_val = vuln_class in _NEEDS_VALIDATION_CLASSES

        # CVE-specific findings should always need validation
        if vuln_class == "cve_specific":
            needs_val = True

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


# Indicators that a path traversal response is real (not a soft 404)
_PASSWD_INDICATORS = ("root:", "/bin/bash", "/bin/sh", "nobody:", "daemon:")
_WINDOWS_INDICATORS = ("[boot loader]", "[operating systems]", "[fonts]")


def _is_path_traversal_candidate(template_id: str, matched_at: str) -> bool:
    """Return True if the finding looks like a path traversal that needs validation."""
    matched_lower = (matched_at or "").lower()
    tid_lower = template_id.lower()
    return (
        "/etc/passwd" in matched_lower
        or "/etc/shadow" in matched_lower
        or "win.ini" in matched_lower
        or "boot.ini" in matched_lower
        or "traversal" in tid_lower
        or (".." in matched_lower and ("etc" in matched_lower or "win" in matched_lower))
    )


async def _validate_traversal_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Re-fetch path traversal URLs and filter false positives.

    Many apps return 200 for any path (soft 404). We verify the response
    actually contains expected file content like root:/bin/bash.
    """
    import aiohttp

    validated: list[dict[str, Any]] = []
    to_check: list[dict[str, Any]] = []

    for f in findings:
        if f.get("_traversal_check"):
            to_check.append(f)
        else:
            validated.append(f)

    if not to_check:
        return findings

    timeout = aiohttp.ClientTimeout(total=10)
    headers = {"User-Agent": "Mozilla/5.0 (BugHound Scanner)"}

    async with aiohttp.ClientSession(headers=headers) as session:
        for f in to_check:
            url = f.get("endpoint", "")
            if not url:
                continue
            try:
                async with session.get(url, ssl=False, timeout=timeout) as resp:
                    body = await resp.text(errors="replace")
                    matched_lower = url.lower()

                    is_real = False
                    if "/etc/passwd" in matched_lower or "/etc/shadow" in matched_lower:
                        is_real = any(ind in body for ind in _PASSWD_INDICATORS)
                    elif "win.ini" in matched_lower or "boot.ini" in matched_lower:
                        is_real = any(ind in body for ind in _WINDOWS_INDICATORS)

                    if is_real:
                        f["confidence"] = "high"
                        f["evidence"] = body[:500]
                        validated.append(f)
                    # else: drop the finding (false positive)
            except Exception:
                # Network error — keep finding but mark needs_validation
                f["needs_validation"] = True
                f["confidence"] = "low"
                validated.append(f)

    # Clean up internal marker
    for f in validated:
        f.pop("_traversal_check", None)

    return validated


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
# Nuclei URL collection + deduplication
# ---------------------------------------------------------------------------


async def _collect_all_urls(workspace_id: str) -> list[str]:
    """Collect all discovered URLs from workspace for URL-level nuclei scanning.

    Sources: crawled URLs, form action URLs (GET forms), hidden endpoints.
    """
    urls: set[str] = set()

    # 1. Crawled URLs (main source)
    crawled = await workspace.read_data(workspace_id, "urls/crawled.json")
    if isinstance(crawled, dict):
        crawled_data = crawled.get("data", [])
    elif isinstance(crawled, list):
        crawled_data = crawled
    else:
        crawled_data = []

    for item in crawled_data:
        if isinstance(item, str) and item.startswith("http"):
            urls.add(item)
        elif isinstance(item, dict):
            url = item.get("url", item.get("endpoint", ""))
            if url and url.startswith("http"):
                urls.add(url)

    # 2. Form action URLs (GET forms are directly testable)
    forms = await workspace.read_data(workspace_id, "urls/forms.json")
    if isinstance(forms, dict):
        forms_data = forms.get("data", [])
    elif isinstance(forms, list):
        forms_data = forms
    else:
        forms_data = []

    for form in forms_data:
        if not isinstance(form, dict):
            continue
        testable = form.get("testable_url", "")
        if testable and testable.startswith("http"):
            urls.add(testable)
        # Also add the action URL for POST forms
        action = form.get("action", "")
        if action and action.startswith("http"):
            urls.add(action)

    # 3. Hidden endpoints from JS analysis
    hidden = await workspace.read_data(workspace_id, "endpoints/hidden_endpoints.json")
    if isinstance(hidden, dict):
        hidden_data = hidden.get("data", [])
    elif isinstance(hidden, list):
        hidden_data = hidden
    else:
        hidden_data = []

    for ep in hidden_data:
        if isinstance(ep, str) and ep.startswith("http"):
            urls.add(ep)
        elif isinstance(ep, dict):
            url = ep.get("url", ep.get("endpoint", ""))
            if url and url.startswith("http"):
                urls.add(url)

    # 4. OpenAPI spec endpoints — generate parameterized URLs
    import re
    oas_data = await workspace.read_data(workspace_id, "endpoints/openapi_specs.json")
    oas_items = oas_data.get("data", []) if isinstance(oas_data, dict) else (oas_data or [])
    for spec in oas_items:
        if not isinstance(spec, dict):
            continue
        host_url = spec.get("host_url", "")
        for ep in spec.get("endpoints", []):
            if not isinstance(ep, dict):
                continue
            method = (ep.get("method") or "GET").upper()
            if method != "GET":
                continue  # nuclei only tests GET URLs
            # Prefer the pre-built url field; fall back to host_url + path
            raw_url = ep.get("url", "")
            if not raw_url:
                path = ep.get("path", "")
                if not path:
                    continue
                raw_url = f"{host_url}{path}"
            if not raw_url.startswith("http"):
                continue
            # Replace path params {id}, {order_id} etc. with example value
            url_resolved = re.sub(r"\{[^}]+\}", "1", raw_url)
            # Build query string from query parameters
            query_params = []
            for p in ep.get("parameters", []):
                if isinstance(p, dict) and p.get("in") == "query":
                    query_params.append(f"{p['name']}=FUZZ")
            if query_params:
                full_url = f"{url_resolved}?{'&'.join(query_params)}"
            else:
                full_url = url_resolved
            urls.add(full_url)

    return sorted(urls)


async def _dedupe_urls(urls: list[str]) -> list[str]:
    """Deduplicate URLs using urldedupe if available, otherwise basic dedup.

    urldedupe removes URLs that differ only by parameter values,
    keeping one representative URL per unique path+param-set.
    """
    if len(urls) <= 1:
        return urls

    if tool_runner.is_available("urldedupe"):
        import tempfile
        from pathlib import Path

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="bughound_urls_",
        )
        for u in urls:
            tmp.write(f"{u}\n")
        tmp.close()
        tmp_path = Path(tmp.name)

        try:
            result = await tool_runner.run(
                "urldedupe", ["-u", tmp.name, "-s"], target="url_dedupe", timeout=30,
            )
            if result.success and result.results:
                deduped = [u for u in result.results if u.strip().startswith("http")]
                if deduped:
                    return deduped
        finally:
            tmp_path.unlink(missing_ok=True)

    # Fallback: dedupe by (host, path, sorted param names)
    seen: set[str] = set()
    deduped: list[str] = []
    for url in urls:
        try:
            parsed = urlparse(url)
            # Key: host + path + sorted param names (ignore values)
            params = sorted(parsed.query.split("&")) if parsed.query else []
            param_names = tuple(p.split("=")[0] for p in params if "=" in p)
            key = f"{parsed.netloc}{parsed.path}:{param_names}"
            if key not in seen:
                seen.add(key)
                deduped.append(url)
        except Exception:
            deduped.append(url)

    return deduped


def _deduplicate_nuclei_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate nuclei findings by template_id + host + parameter.

    When scanning URL lists, nuclei can find the same vuln via multiple URL
    variants (e.g., same SQLi on /search?q=1 and /search?q=2). Keep the
    finding with the most specific URL (longest path).
    """
    # Group by (template_id, host_root)
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        template_id = f.get("template_id", "")
        host = f.get("host", "")
        # Extract host root (strip path)
        try:
            parsed = urlparse(host if host.startswith("http") else f"https://{host}")
            host_root = parsed.netloc or host
        except Exception:
            host_root = host

        # Extract param from endpoint
        endpoint = f.get("endpoint", "")
        try:
            parsed_ep = urlparse(endpoint)
            param_key = parsed_ep.path
        except Exception:
            param_key = endpoint

        key = f"{template_id}:{host_root}:{param_key}"
        groups.setdefault(key, []).append(f)

    # Keep the finding with the longest/most specific endpoint
    deduped: list[dict[str, Any]] = []
    for group in groups.values():
        if len(group) == 1:
            deduped.append(group[0])
        else:
            # Pick the one with the most specific (longest) endpoint
            best = max(group, key=lambda f: len(f.get("endpoint", "")))
            deduped.append(best)

    return deduped


async def _group_hosts_by_technology(
    workspace_id: str,
    host_url_map: dict[str, str],
) -> dict[str, list[str]]:
    """Group hosts by detected technology for tech-specific nuclei scans.

    Returns: {comma-separated tags: [host_urls]}
    Only includes groups where at least one host was detected.
    """
    live_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    if not live_hosts:
        return {}

    items = live_hosts.get("data", []) if isinstance(live_hosts, dict) else live_hosts

    # Map: tag_group -> set of host URLs
    tag_groups: dict[str, set[str]] = {}

    for host_data in items:
        if not isinstance(host_data, dict):
            continue
        techs = host_data.get("technologies") or []
        host_url = host_data.get("url", "")
        if not host_url:
            hostname = host_data.get("host", "")
            host_url = host_url_map.get(hostname, f"https://{hostname}" if hostname else "")
        if not host_url:
            continue

        techs_lower = " ".join(str(t) for t in techs).lower()
        server = (host_data.get("web_server") or "").lower()
        combined = f"{techs_lower} {server}"

        for keyword, nuclei_tags in _TECH_NUCLEI_TAGS.items():
            if keyword in combined:
                tag_key = ",".join(sorted(set(nuclei_tags)))
                tag_groups.setdefault(tag_key, set()).add(host_url)

    return {k: sorted(v) for k, v in tag_groups.items()}


async def _get_versioned_hosts(
    workspace_id: str,
    host_url_map: dict[str, str],
) -> list[str]:
    """Get hosts with version-detected software for CVE-specific scanning.

    Checks technologies list, web_server header, and flags for version strings.
    Falls back to all hosts with recognized technologies if no explicit versions found.
    """
    live_hosts = await workspace.read_data(workspace_id, "hosts/live_hosts.json")
    if not live_hosts:
        return []

    items = live_hosts.get("data", []) if isinstance(live_hosts, dict) else live_hosts

    import re
    version_re = re.compile(r"\d+\.\d+")

    versioned: set[str] = set()
    has_tech: set[str] = set()

    for host_data in items:
        if not isinstance(host_data, dict):
            continue

        host_url = host_data.get("url", "")
        if not host_url:
            hostname = host_data.get("host", "")
            host_url = host_url_map.get(hostname, f"https://{hostname}" if hostname else "")
        if not host_url:
            continue

        techs = host_data.get("technologies") or []
        server = host_data.get("web_server") or ""

        # Check technologies, web_server, and flags for version strings
        all_strings = [str(t) for t in techs] + [server]
        for flag in (host_data.get("flags") or []):
            all_strings.append(str(flag))

        for s in all_strings:
            if version_re.search(s):
                versioned.add(host_url)
                break

        # Track hosts with any recognized technology (for fallback)
        techs_lower = " ".join(str(t) for t in techs).lower() + " " + server.lower()
        for keyword in _TECH_NUCLEI_TAGS:
            if keyword in techs_lower:
                has_tech.add(host_url)
                break

    # If we found explicit versions, use those; otherwise fall back to
    # all hosts with recognized tech (CVE templates still find unversioned vulns)
    return sorted(versioned or has_tech)


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


async def _read_attack_surface(workspace_id: str) -> dict[str, Any] | None:
    """Read cached attack surface analysis."""
    fpath = WORKSPACE_BASE_DIR / workspace_id / "analysis" / "attack_surface.json"
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
