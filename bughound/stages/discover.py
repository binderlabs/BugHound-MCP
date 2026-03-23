"""Stage 2: Probe, crawl, dirfuzz, JS analysis, secrets, cloud assets.

Day 5 implements Phase 2A: probing + fingerprinting + intelligence flags.
Day 6 adds Phase 2B-2F: URL discovery, JS analysis, secrets, etc.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import structlog

from bughound.core import workspace
from bughound.core.job_manager import JobManager
from bughound.schemas.models import TargetType, WorkspaceState
from bughound.tools.discovery import (
    auth_analyzer, cors_checker, dir_scanner, form_extractor, js_analyzer,
    katana, openapi_parser, param_classifier, sensitive_paths, takeover_checker,
)
from bughound.core import tool_runner
from bughound.tools.recon import gau, gospider, httpx, wafw00f, waybackurls

logger = structlog.get_logger()

# Default page title patterns indicating uninteresting/default installs
_DEFAULT_TITLES = {
    "welcome to nginx",
    "apache2 default page",
    "apache2 debian default page",
    "apache2 ubuntu default page",
    "iis windows server",
    "microsoft internet information services",
    "test page for the apache",
    "it works!",
    "default web site page",
    "web server's default page",
    "congratulations",
    "404 not found",
    "403 forbidden",
    "page not found",
    "under construction",
    "coming soon",
    "parked domain",
    "domain for sale",
}

# Old tech patterns: (regex on tech string, flag message)
_OLD_TECH_PATTERNS = [
    (re.compile(r"wordpress[/: ]*[1-5]\.", re.I), "WordPress < 6.x"),
    (re.compile(r"jquery[/: ]*1\.", re.I), "jQuery 1.x (EOL, multiple XSS CVEs)"),
    (re.compile(r"jquery[/: ]*2\.", re.I), "jQuery 2.x (EOL)"),
    (re.compile(r"jquery[/: ]*3\.[0-4]\.", re.I), "jQuery < 3.5 (CVE-2020-11022, CVE-2020-11023)"),
    (re.compile(r"php[/: ]*5\.", re.I), "PHP 5.x (EOL)"),
    (re.compile(r"php[/: ]*7\.[0-3]\.", re.I), "PHP 7.0-7.3 (EOL)"),
    (re.compile(r"angular[/: ]*1\.", re.I), "AngularJS 1.x (EOL, sandbox escape)"),
    (re.compile(r"apache[/: ]*2\.2\.", re.I), "Apache 2.2 (EOL)"),
    (re.compile(r"nginx[/: ]*1\.(1[0-8]|[0-9])\.", re.I), "nginx < 1.19 (old branch)"),
    (re.compile(r"openssl[/: ]*1\.0\.", re.I), "OpenSSL 1.0 (EOL)"),
    (re.compile(r"asp\.net[/: ]*[12]\.", re.I), "ASP.NET 1.x/2.x (EOL since 2011)"),
    (re.compile(r"asp\.net[/: ]*3\.", re.I), "ASP.NET 3.x (EOL)"),
    (re.compile(r"microsoft asp\.net[/: ]*[12]\.", re.I), "Microsoft ASP.NET 1.x/2.x (EOL)"),
    (re.compile(r"microsoft asp\.net[/: ]*3\.", re.I), "Microsoft ASP.NET 3.x (EOL)"),
    (re.compile(r"react[/: ]*1[0-5]\.", re.I), "React < 16 (XSS in SSR)"),
    (re.compile(r"express[/: ]*[1-3]\.", re.I), "Express.js < 4.x (old)"),
    (re.compile(r"rails[/: ]*[1-5]\.", re.I), "Ruby on Rails < 6.x"),
    (re.compile(r"django[/: ]*[12]\.", re.I), "Django 1.x/2.x (EOL)"),
    (re.compile(r"spring[/: ]*[1-4]\.", re.I), "Spring Framework < 5.x"),
    (re.compile(r"tomcat[/: ]*[1-8]\.", re.I), "Apache Tomcat < 9.x"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover(
    workspace_id: str,
    job_manager: JobManager | None = None,
    target_override: list[str] | None = None,
    host_filter_cb: Any = None,
) -> dict[str, Any]:
    """Run Stage 2 discovery on a workspace.

    target_override: if provided, discover only these specific hosts
                     instead of all subdomains from Stage 1.
    host_filter_cb: optional async callable(live_hosts) -> filtered_hosts.
        Called after httpx probing. CLI uses this for interactive host selection.
    """
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    if target_override:
        targets = target_override
    else:
        targets = await _resolve_targets(meta)
    if not targets:
        return _error(
            "invalid_input",
            "No targets to discover. Run bughound_enumerate first for broad domains.",
        )

    # Always run as background job to avoid MCP client timeouts
    if job_manager is not None:
        return await _start_discover_job(
            workspace_id, targets, meta, job_manager, host_filter_cb,
        )

    return await _run_discover(workspace_id, targets, meta, host_filter_cb=host_filter_cb)


# ---------------------------------------------------------------------------
# Synchronous discovery (Phase 2A)
# ---------------------------------------------------------------------------


async def _run_discover(
    workspace_id: str,
    targets: list[str],
    meta: Any,
    progress_cb: Any = None,
    host_filter_cb: Any = None,
) -> dict[str, Any]:
    """Run Phases 2A-2D and return structured results.

    progress_cb: optional async callable(pct, msg, module) for job progress.
    host_filter_cb: optional async callable(live_hosts) -> filtered_hosts.
        Called after httpx probing with the full live hosts list.
        CLI uses this for interactive host selection.
        If None or returns None, all hosts are used.
    """
    await workspace.update_metadata(
        workspace_id, state=WorkspaceState.DISCOVERING, current_stage=2,
    )
    await workspace.add_stage_history(workspace_id, 2, "running")

    target_label = meta.target
    warnings: list[str] = []
    files_written: list[str] = []

    # ===================================================================
    # Phase 2A: Probe + Fingerprint
    # ===================================================================
    if progress_cb:
        await progress_cb(10, "Probing live hosts", "httpx")  # 2A

    if not httpx.is_available():
        await workspace.add_stage_history(workspace_id, 2, "failed")
        return _error(
            "tool_not_found",
            "httpx is required for discovery but not installed. "
            "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        )

    httpx_result = await httpx.execute(targets if len(targets) > 1 else targets[0])
    if not httpx_result.success:
        warnings.append(f"httpx: {httpx_result.error.message if httpx_result.error else 'failed'}")

    live_hosts: list[dict[str, Any]] = httpx_result.results if httpx_result.success else []

    if not live_hosts:
        await workspace.add_stage_history(workspace_id, 2, "completed")
        return {
            "status": "success",
            "message": f"No live hosts found for {target_label}.",
            "workspace_id": workspace_id,
            "data": {"live_hosts": 0},
            "warnings": warnings,
        }

    # WAF detection
    if progress_cb:
        await progress_cb(20, "Detecting WAF/CDN", "wafw00f")  # 2A

    waf_results: list[dict[str, Any]] = []
    if wafw00f.is_available():
        live_urls = [h["url"] for h in live_hosts if h.get("url")]
        waf_tasks = [wafw00f.execute(url) for url in live_urls[:20]]
        waf_raw = await asyncio.gather(*waf_tasks, return_exceptions=True)
        for r in waf_raw:
            if not isinstance(r, Exception) and r.success:
                waf_results.extend(r.results)
    else:
        warnings.append("wafw00f not installed — WAF detection skipped.")

    waf_by_url: dict[str, str | None] = {
        wr.get("url", ""): wr.get("waf") for wr in waf_results
    }

    # Generate intelligence flags
    if progress_cb:
        await progress_cb(28, "Generating intelligence flags", "flags")  # 2A

    cdn_counter: Counter[str] = Counter()
    for h in live_hosts:
        if h.get("cdn"):
            cdn_counter[h["cdn"]] += 1
    majority_cdn = cdn_counter.most_common(1)[0][0] if cdn_counter else None

    flagged_hosts: list[dict[str, Any]] = []
    tech_counter: Counter[str] = Counter()
    for host in live_hosts:
        flags = _generate_flags(host, waf_by_url, majority_cdn)
        flagged_hosts.append({**host, "flags": flags})
        for tech in host.get("technologies") or []:
            tech_counter[tech] += 1

    # Write 2A results
    await workspace.write_data(
        workspace_id, "hosts/live_hosts.json", flagged_hosts,
        generated_by="httpx", target=target_label,
    )
    files_written.append("hosts/live_hosts.json")

    tech_list = [{"technology": t, "host_count": c} for t, c in tech_counter.most_common(30)]
    await workspace.write_data(
        workspace_id, "hosts/technologies.json", tech_list,
        generated_by="httpx", target=target_label,
    )
    files_written.append("hosts/technologies.json")

    # Host filter callback — CLI uses this for interactive selection
    if host_filter_cb and len(live_hosts) > 1:
        try:
            filtered = await host_filter_cb(flagged_hosts)
            if filtered is not None and isinstance(filtered, list):
                flagged_hosts = filtered
                live_hosts = filtered
                # Rewrite live_hosts.json with filtered set
                await workspace.write_data(
                    workspace_id, "hosts/live_hosts.json", flagged_hosts,
                    generated_by="httpx_filtered", target=target_label,
                )
        except Exception:
            pass  # On error, continue with all hosts

    if waf_results:
        await workspace.write_data(
            workspace_id, "hosts/waf.json", waf_results,
            generated_by="wafw00f", target=target_label,
        )
        files_written.append("hosts/waf.json")

    hosts_with_flags = [h for h in flagged_hosts if h.get("flags")]
    if hosts_with_flags:
        flags_summary = [{"host": h["host"], "url": h["url"], "flags": h["flags"]} for h in hosts_with_flags]
        await workspace.write_data(
            workspace_id, "hosts/flags.json", flags_summary,
            generated_by="discover", target=target_label,
        )
        files_written.append("hosts/flags.json")

    # ===================================================================
    # Phase 2A-post: Auth Discovery
    # ===================================================================
    if progress_cb:
        await progress_cb(29, "Discovering authentication mechanisms", "auth_analyzer")

    auth_results: list[dict[str, Any]] = []
    live_host_urls_for_auth = [h["url"] for h in live_hosts if h.get("url")][:20]
    for host_url in live_host_urls_for_auth:
        try:
            auth = await auth_analyzer.discover_auth(host_url, target_domain=meta.target)
            auth["target_url"] = host_url
            auth_results.append(auth)

            # Add auth flags
            for fh in flagged_hosts:
                if fh.get("url") == host_url:
                    if auth.get("insecure_cookie_flags"):
                        fh["flags"].append(f"INSECURE_COOKIES: {len(auth['insecure_cookie_flags'])} issues")
                    if auth.get("jwts"):
                        fh["flags"].append(f"JWT_DETECTED: {auth['jwts'][0].get('algorithm', 'unknown')} algorithm")
                    if auth.get("injectable_cookies"):
                        fh["flags"].append(f"INJECTABLE_COOKIES: {len(auth['injectable_cookies'])} candidates")
        except Exception as exc:
            warnings.append(f"Auth discovery failed for {host_url}: {exc}")

    if auth_results:
        await workspace.write_data(
            workspace_id, "hosts/auth_discovery.json", auth_results,
            generated_by="auth_analyzer", target=target_label,
        )
        files_written.append("hosts/auth_discovery.json")

        # Re-write flags
        hosts_with_flags = [h for h in flagged_hosts if h.get("flags")]
        if hosts_with_flags:
            flags_summary = [{"host": h["host"], "url": h["url"], "flags": h["flags"]} for h in hosts_with_flags]
            await workspace.write_data(
                workspace_id, "hosts/flags.json", flags_summary,
                generated_by="discover", target=target_label,
            )

    # ===================================================================
    # Phase 2B: URL Discovery
    # ===================================================================
    if progress_cb:
        await progress_cb(30, "Discovering URLs and endpoints", "url_discovery")  # 2B

    # Extract the root domain for gau/waybackurls
    classification = meta.classification or {}
    root_targets = classification.get("normalized_targets", [meta.target])

    all_urls: list[dict[str, str]] = []  # [{url, source}]
    url_tool_counts: dict[str, int] = {}  # tool_name -> count of URLs found

    # Passive URL sources (gau + waybackurls) — run in parallel
    url_tasks: dict[str, asyncio.Task] = {}
    for root in root_targets[:3]:  # limit to first 3 roots
        if gau.is_available():
            url_tasks[f"gau:{root}"] = asyncio.create_task(gau.execute(root))
        else:
            url_tool_counts["gau"] = -1  # -1 = not installed
        if waybackurls.is_available():
            url_tasks[f"waybackurls:{root}"] = asyncio.create_task(waybackurls.execute(root))
        else:
            url_tool_counts["waybackurls"] = -1

    if not url_tasks and not any(v >= 0 for v in url_tool_counts.values()):
        warnings.append("No URL discovery tools (gau, waybackurls) installed.")

    for key, task in url_tasks.items():
        tool_name = key.split(":")[0]
        try:
            result = await task
            if result.success:
                count = 0
                for u in result.results:
                    all_urls.append({"url": u, "source": tool_name})
                    count += 1
                url_tool_counts[tool_name] = url_tool_counts.get(tool_name, 0) + count
            else:
                url_tool_counts.setdefault(tool_name, 0)
                warnings.append(f"{tool_name}: {result.error.message if result.error else 'failed'}")
        except Exception as exc:
            url_tool_counts.setdefault(tool_name, 0)
            warnings.append(f"{tool_name}: {exc}")

    # Passive endpoint sources (AlienVault OTX, URLScan, Common Crawl)
    try:
        from bughound.tools.recon.passive_sources import gather_endpoints
        target_domain = meta.target.replace("http://", "").replace("https://", "").strip("/")
        ep_results = await gather_endpoints(target_domain)
        passive_url_count = 0
        for source_name, urls in ep_results.items():
            for url_str in urls:
                if url_str and url_str.startswith("http"):
                    all_urls.append({"url": url_str, "source": source_name})
                    passive_url_count += 1
        if passive_url_count > 0:
            logger.info("discover.passive_endpoints", count=passive_url_count, sources=list(ep_results.keys()))
    except Exception as exc:
        warnings.append(f"Passive endpoint sources: {exc}")

    # Active crawler — katana light/deep by target type, fallback to gospider
    crawl_targets = [h["url"] for h in live_hosts if h.get("url")][:10]
    katana_forms: list[dict[str, Any]] = []
    use_deep_crawl = meta.target_type in (TargetType.SINGLE_HOST, TargetType.SINGLE_ENDPOINT)
    # Determine crawl depth based on target type
    crawl_depth = 1 if len(crawl_targets) > 3 else 3  # shallow for many hosts, deep for single

    if katana.is_available():
        katana_count = 0
        for ct in crawl_targets:
            try:
                if use_deep_crawl:
                    cr = await katana.execute_deep(ct, timeout=180)
                elif crawl_depth == 1:
                    cr = await katana.execute(ct, depth=1, timeout=60)
                else:
                    cr = await katana.execute_light(ct, timeout=60)
                if cr.success:
                    for entry in cr.results:
                        u = entry["url"] if isinstance(entry, dict) else str(entry)
                        all_urls.append({"url": u, "source": "katana"})
                        katana_count += 1
                    # Extract forms from katana deep mode output
                    for w in cr.warnings:
                        if w.startswith("__forms__:"):
                            import json as _json
                            try:
                                katana_forms.extend(_json.loads(w[10:]))
                            except _json.JSONDecodeError:
                                pass
            except Exception as exc:
                warnings.append(f"Crawl failed for {ct}: {exc}")
        url_tool_counts["katana"] = katana_count
    elif gospider.is_available():
        gospider_count = 0
        for ct in crawl_targets:
            try:
                cr = await gospider.execute(ct, depth=2, timeout=60)
                if cr.success:
                    for entry in cr.results:
                        u = entry["url"] if isinstance(entry, dict) else str(entry)
                        all_urls.append({"url": u, "source": "gospider"})
                        gospider_count += 1
            except Exception as exc:
                warnings.append(f"Crawl failed for {ct}: {exc}")
        url_tool_counts["gospider"] = gospider_count
    else:
        url_tool_counts["crawler"] = -1
        warnings.append("No crawler installed (katana or gospider) — active crawling skipped.")

    # Form extraction — pure Python crawler for forms
    extracted_forms: list[dict[str, Any]] = list(katana_forms)
    form_targets = crawl_targets[:5] if use_deep_crawl else crawl_targets[:3]
    if form_targets:
        if progress_cb:
            await progress_cb(35, "Extracting forms from pages", "form_extractor")
        try:
            py_forms = await form_extractor.extract_forms(
                form_targets,
                max_pages=30 if use_deep_crawl else 15,
                depth=2 if use_deep_crawl else 1,
                concurrency=5,
            )
            extracted_forms.extend(py_forms)
        except Exception as exc:
            warnings.append(f"Form extraction failed: {exc}")

    # Deduplicate forms by (page_url, action, method)
    seen_forms: set[str] = set()
    unique_forms: list[dict[str, Any]] = []
    for form in extracted_forms:
        key = f"{form.get('page_url', '')}:{form.get('action', '')}:{form.get('method', '')}"
        if key not in seen_forms:
            seen_forms.add(key)
            unique_forms.append(form)

    # Merge form params into all_urls (GET forms produce URLs with params)
    for form in unique_forms:
        testable = form.get("testable", {})
        if testable.get("method") == "GET" and testable.get("url"):
            all_urls.append({"url": testable["url"], "source": "form_extractor"})

    # Robots.txt + sitemap.xml fetching
    robots_sitemap_data: list[dict[str, Any]] = []
    for host_url in crawl_targets[:5]:
        rs = await _fetch_robots_sitemap(host_url)
        if rs:
            robots_sitemap_data.extend(rs)
            for entry in rs:
                if entry.get("type") == "sitemap_url":
                    all_urls.append({"url": entry["value"], "source": "sitemap"})
                elif entry.get("type") == "disallowed":
                    # Construct full URL from disallowed path for discovery
                    base = host_url.rstrip("/")
                    full = f"{base}{entry['value']}"
                    all_urls.append({"url": full, "source": "robots"})

    # Deduplicate URLs
    seen_urls: set[str] = set()
    unique_urls: list[dict[str, str]] = []
    for entry in all_urls:
        u = entry["url"].strip()
        if u and u not in seen_urls:
            seen_urls.add(u)
            unique_urls.append(entry)

    # Extract JS files
    js_urls = sorted(set(
        e["url"] for e in unique_urls
        if e["url"].lower().endswith((".js", ".mjs", ".jsx"))
        or "/js/" in e["url"].lower()
    ))

    # Extract parameters from URLs
    params_by_path = _extract_parameters(unique_urls)

    # Write 2B results
    if unique_urls:
        await workspace.write_data(
            workspace_id, "urls/crawled.json", unique_urls,
            generated_by="url_discovery", target=target_label,
        )
        files_written.append("urls/crawled.json")

    if js_urls:
        await workspace.write_data(
            workspace_id, "urls/js_files.json",
            [{"url": u} for u in js_urls],
            generated_by="url_discovery", target=target_label,
        )
        files_written.append("urls/js_files.json")

    if robots_sitemap_data:
        await workspace.write_data(
            workspace_id, "urls/robots_sitemap.json", robots_sitemap_data,
            generated_by="discover", target=target_label,
        )
        files_written.append("urls/robots_sitemap.json")

    # Write forms data
    if unique_forms:
        await workspace.write_data(
            workspace_id, "urls/forms.json", unique_forms,
            generated_by="form_extractor", target=target_label,
        )
        files_written.append("urls/forms.json")

    await workspace.update_stats(workspace_id, urls_discovered=len(unique_urls))

    # ===================================================================
    # Phase 2C: JS Analysis
    # ===================================================================
    js_secrets: list[dict[str, Any]] = []
    js_endpoints: list[dict[str, Any]] = []
    hidden_endpoints: list[dict[str, Any]] = []
    secrets_by_conf: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if js_urls:
        if progress_cb:
            await progress_cb(45, "Analyzing JavaScript for secrets and endpoints", "js_analyzer")  # 2B

        js_result = await js_analyzer.analyze_js_files(
            js_urls[:100],  # cap at 100 JS files
            target_domain=meta.target,
        )

        js_secrets = js_result.get("secrets", [])
        js_endpoints = js_result.get("endpoints", [])
        js_hidden_params = js_result.get("hidden_params", [])
        secrets_by_conf = js_result.get("secrets_by_confidence", {})

        # Cross-reference: endpoints in JS but not in crawled URLs = hidden
        crawled_paths = set()
        for e in unique_urls:
            try:
                crawled_paths.add(urlparse(e["url"]).path)
            except Exception:
                pass

        for ep in js_endpoints:
            if ep["path"] not in crawled_paths:
                hidden_endpoints.append({**ep, "reason": "Found in JS but not in crawl results"})

        # Write 2C results — separate HIGH/MEDIUM from LOW for easier AI triage
        if js_secrets:
            high_med = [s for s in js_secrets if s.get("confidence") in ("HIGH", "MEDIUM")]

            await workspace.write_data(
                workspace_id, "secrets/js_secrets.json", js_secrets,
                generated_by="js_analyzer", target=target_label,
            )
            files_written.append("secrets/js_secrets.json")

            if high_med:
                await workspace.write_data(
                    workspace_id, "secrets/js_secrets_confirmed.json", high_med,
                    generated_by="js_analyzer", target=target_label,
                )
                files_written.append("secrets/js_secrets_confirmed.json")

        if js_endpoints:
            await workspace.write_data(
                workspace_id, "endpoints/api_endpoints.json", js_endpoints,
                generated_by="js_analyzer", target=target_label,
            )
            files_written.append("endpoints/api_endpoints.json")

        if hidden_endpoints:
            await workspace.write_data(
                workspace_id, "endpoints/hidden_endpoints.json", hidden_endpoints,
                generated_by="js_analyzer", target=target_label,
            )
            files_written.append("endpoints/hidden_endpoints.json")

        if js_hidden_params:
            await workspace.write_data(
                workspace_id, "urls/js_hidden_params.json",
                [{"param": p, "source": "js_analysis"} for p in js_hidden_params],
                generated_by="js_analyzer", target=target_label,
            )
            files_written.append("urls/js_hidden_params.json")

    # ===================================================================
    # Phase 2C-map: Check for exposed source maps (.js.map)
    # ===================================================================
    source_maps_found: list[dict[str, Any]] = []
    if js_urls:
        import aiohttp as _aiohttp
        _map_sem = asyncio.Semaphore(5)

        async def _check_map(js_url: str, sess: _aiohttp.ClientSession) -> dict[str, Any] | None:
            map_url = js_url + ".map"
            async with _map_sem:
                try:
                    async with sess.get(
                        map_url, ssl=False,
                        timeout=_aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            if len(body) > 100 and (
                                "mappings" in body or "sources" in body
                            ):
                                return {
                                    "url": map_url,
                                    "size": len(body),
                                    "source_js": js_url,
                                }
                except Exception:
                    pass
            return None

        async with _aiohttp.ClientSession() as _map_session:
            map_tasks = [_check_map(u, _map_session) for u in js_urls[:20]]
            map_results = await asyncio.gather(*map_tasks, return_exceptions=True)
        source_maps_found = [r for r in map_results if isinstance(r, dict)]

        if source_maps_found:
            # Add as sensitive findings flagged on matching hosts
            for sm in source_maps_found:
                sm_host = urlparse(sm["url"]).hostname or ""
                sm_host = sm_host.lower()
                for fh in flagged_hosts:
                    fh_host = (fh.get("host") or "").lower()
                    if not fh_host:
                        fh_host = urlparse(fh.get("url", "")).hostname or ""
                        fh_host = fh_host.lower()
                    if fh_host == sm_host:
                        flag = f"SOURCE_MAP_EXPOSED: {sm['url']} ({sm['size']} bytes)"
                        if flag not in fh["flags"]:
                            fh["flags"].append(flag)

            logger.info(
                "discover.source_maps",
                count=len(source_maps_found),
                urls=[sm["url"] for sm in source_maps_found],
            )

    # ===================================================================
    # Phase 2C-param: Parameter Summary
    # ===================================================================
    if params_by_path:
        await workspace.write_data(
            workspace_id, "urls/parameters.json", params_by_path,
            generated_by="discover", target=target_label,
        )
        files_written.append("urls/parameters.json")

    total_params = sum(len(e.get("params", [])) for e in params_by_path) if params_by_path else 0

    # ===================================================================
    # Phase 2D: Sensitive Path Checks
    # ===================================================================
    if progress_cb:
        await progress_cb(55, "Checking sensitive paths", "sensitive_paths")  # 2C

    sensitive_findings: dict[str, list[dict[str, Any]]] = {}
    live_host_urls = [h["url"] for h in live_hosts if h.get("url")]
    try:
        sensitive_findings = await sensitive_paths.check_hosts(
            live_host_urls, max_hosts=30,
        )
    except Exception as exc:
        warnings.append(f"Sensitive path check failed: {exc}")

    # Generate flags from sensitive path findings
    sp_flag_count = 0
    if sensitive_findings:
        all_sp: list[dict[str, Any]] = []
        for host_url, findings in sensitive_findings.items():
            for f in findings:
                all_sp.append({**f, "host_url": host_url})
                # Add flag to the matching flagged_host
                for fh in flagged_hosts:
                    if fh.get("url") == host_url:
                        flag_str = f"{f['category']}: {f['path']} accessible"
                        if flag_str not in fh["flags"]:
                            fh["flags"].append(flag_str)
                            sp_flag_count += 1

        await workspace.write_data(
            workspace_id, "hosts/sensitive_paths.json", all_sp,
            generated_by="sensitive_paths", target=target_label,
        )
        files_written.append("hosts/sensitive_paths.json")

    # ===================================================================
    # Phase 2D: OpenAPI/Swagger spec parsing
    # ===================================================================
    # If sensitive paths found swagger/openapi endpoints, parse them for endpoints
    openapi_results: list[dict[str, Any]] = []
    _SWAGGER_CATS = {"SWAGGER_EXPOSED"}
    swagger_hosts: dict[str, list[str]] = {}  # host_url -> list of spec paths
    for host_url, findings in sensitive_findings.items():
        for f in findings:
            if f.get("category") in _SWAGGER_CATS and f.get("path"):
                swagger_hosts.setdefault(host_url, []).append(f["path"])

    for host_url, spec_paths in swagger_hosts.items():
        try:
            result = await openapi_parser.discover_and_parse(
                host_url, known_spec_paths=spec_paths,
            )
            if result and result.get("endpoints"):
                result["host_url"] = host_url
                openapi_results.append(result)

                # Add discovered endpoints to hidden_endpoints for param classification
                for ep in result["endpoints"]:
                    ep_url = ep.get("url", f"{host_url.rstrip('/')}{ep['path']}")
                    # Build query string from params for classification
                    query_params = [p for p in ep.get("parameters", []) if p.get("in") == "query"]
                    if query_params:
                        qs = "&".join(f"{p['name']}=test" for p in query_params)
                        ep_url = f"{ep_url}?{qs}"

                logger.info(
                    "discover.openapi_parsed",
                    host=host_url,
                    endpoints=result["stats"]["total_endpoints"],
                )
        except Exception as exc:
            warnings.append(f"OpenAPI parsing failed for {host_url}: {exc}")

    if openapi_results:
        await workspace.write_data(
            workspace_id, "endpoints/openapi_specs.json", openapi_results,
            generated_by="openapi_parser", target=target_label,
        )
        files_written.append("endpoints/openapi_specs.json")

    # Re-write flags.json with updated flags
    hosts_with_flags = [h for h in flagged_hosts if h.get("flags")]
    if hosts_with_flags:
        flags_summary = [{"host": h["host"], "url": h["url"], "flags": h["flags"]} for h in hosts_with_flags]
        await workspace.write_data(
            workspace_id, "hosts/flags.json", flags_summary,
            generated_by="discover", target=target_label,
        )
        if "hosts/flags.json" not in files_written:
            files_written.append("hosts/flags.json")

    # ===================================================================
    # Phase 2E: Subdomain Takeover (broad domain only)
    # ===================================================================
    takeover_results: list[dict[str, Any]] = []
    takeover_confirmed: list[dict[str, Any]] = []

    if meta.target_type == TargetType.BROAD_DOMAIN:
        if progress_cb:
            await progress_cb(65, "Checking subdomain takeover", "takeover")  # 2D

        # Dead subs = in subdomains/all.txt but not in live hosts
        live_hosts_set = {h.get("host", "").lower() for h in live_hosts}
        all_subs_data = await workspace.read_data(workspace_id, "subdomains/all.txt")
        all_subs = all_subs_data if isinstance(all_subs_data, list) else []
        dead_subs = [s for s in all_subs if s.lower() not in live_hosts_set]

        # Load DNS records for CNAME lookup
        dns_data = await workspace.read_data(workspace_id, "dns/records.json")
        dns_lookup: dict[str, dict[str, Any]] = {}
        if isinstance(dns_data, dict) and "data" in dns_data:
            for rec in dns_data["data"]:
                if isinstance(rec, dict) and "domain" in rec:
                    dns_lookup[rec["domain"]] = rec

        if dead_subs:
            try:
                takeover_results = await takeover_checker.check_takeovers(
                    dead_subs[:100], dns_records=dns_lookup,
                )
            except Exception as exc:
                warnings.append(f"Takeover check failed: {exc}")

            # Also try nuclei if available
            try:
                takeover_confirmed = await takeover_checker.check_takeovers_nuclei(dead_subs[:100])
            except Exception:
                pass

        if takeover_results:
            await workspace.write_data(
                workspace_id, "cloud/takeover_candidates.json", takeover_results,
                generated_by="takeover_checker", target=target_label,
            )
            files_written.append("cloud/takeover_candidates.json")

        if takeover_confirmed:
            await workspace.write_data(
                workspace_id, "cloud/takeover_confirmed.json", takeover_confirmed,
                generated_by="nuclei", target=target_label,
            )
            files_written.append("cloud/takeover_confirmed.json")

    # ===================================================================
    # Phase 2F: CORS Probing
    # ===================================================================
    if progress_cb:
        await progress_cb(68, "Testing CORS configuration", "cors")  # 2E

    cors_results: list[dict[str, Any]] = []
    try:
        cors_results = await cors_checker.check_cors(live_host_urls, max_hosts=50)
    except Exception as exc:
        warnings.append(f"CORS check failed: {exc}")

    if cors_results:
        await workspace.write_data(
            workspace_id, "hosts/cors_results.json", cors_results,
            generated_by="cors_checker", target=target_label,
        )
        files_written.append("hosts/cors_results.json")

        # Add CORS flags to hosts
        for cr in cors_results:
            for fh in flagged_hosts:
                if fh.get("url") == cr.get("url"):
                    flag_str = f"CORS_MISCONFIGURED: {cr['severity']} — origin {cr['origin_tested']} reflected"
                    if flag_str not in fh["flags"]:
                        fh["flags"].append(flag_str)

        # Re-write flags with CORS additions
        hosts_with_flags = [h for h in flagged_hosts if h.get("flags")]
        if hosts_with_flags:
            flags_summary = [{"host": h["host"], "url": h["url"], "flags": h["flags"]} for h in hosts_with_flags]
            await workspace.write_data(
                workspace_id, "hosts/flags.json", flags_summary,
                generated_by="discover", target=target_label,
            )

    # ===================================================================
    # Phase 2F: Light Directory Discovery
    # ===================================================================
    if progress_cb:
        await progress_cb(72, "Light directory discovery", "dir_scanner")  # 2F

    dir_results: dict[str, list[dict[str, Any]]] = {}
    try:
        # Build host list for scanner
        scan_hosts = live_hosts[:30]  # cap for broad targets
        tech_data = await workspace.read_data(workspace_id, "hosts/technologies.json")
        tech_items = tech_data.get("data", []) if isinstance(tech_data, dict) else (tech_data or [])

        dir_results = await dir_scanner.scan_directories(
            scan_hosts, technologies=tech_items, concurrency=10, timeout=10,
        )
    except Exception as exc:
        warnings.append(f"Directory scan failed: {exc}")

    if dir_results:
        # Flatten into list for workspace storage
        dir_findings: list[dict[str, Any]] = []
        for hostname, results_list in dir_results.items():
            for r in results_list:
                r["host"] = hostname
                dir_findings.append(r)

        await workspace.write_data(
            workspace_id, "dirfuzz/light_results.json", dir_findings,
            generated_by="dir_scanner", target=target_label,
        )
        files_written.append("dirfuzz/light_results.json")

        # Generate directory flags
        for hostname, results_list in dir_results.items():
            new_flags: list[str] = []
            for r in results_list:
                path_lower = r["path"].lower()
                sc = r["status_code"]

                if sc == 200 and any(k in path_lower for k in ("/admin", "/dashboard", "/panel", "/console", "/manager")):
                    new_flags.append(f"ADMIN_PANEL_FOUND: {r['path']} (200)")
                if sc == 200 and any(k in path_lower for k in ("/swagger", "/openapi", "/api-docs", "/redoc")):
                    new_flags.append(f"API_DOCS_FOUND: {r['path']} (200)")
                if sc in (401, 403) and path_lower not in ("/.env", "/.git/head", "/.htaccess"):
                    new_flags.append(f"RESTRICTED_PATH: {r['path']} ({sc})")
                if sc == 200 and "/actuator" in path_lower:
                    new_flags.append(f"ACTUATOR_FOUND: {r['path']} (200)")

            # Update flagged_hosts
            if new_flags:
                for fh in flagged_hosts:
                    if fh.get("host") == hostname:
                        fh["flags"].extend(new_flags)

        # Re-write flags
        hosts_with_flags = [h for h in flagged_hosts if h.get("flags")]
        if hosts_with_flags:
            flags_summary = [{"host": h["host"], "url": h["url"], "flags": h["flags"]} for h in hosts_with_flags]
            await workspace.write_data(
                workspace_id, "hosts/flags.json", flags_summary,
                generated_by="discover", target=target_label,
            )

    # ===================================================================
    # Phase 2F-deep: Deep Directory Fuzzing with ffuf
    # ===================================================================
    from bughound.tools.scanning import ffuf
    if ffuf.is_available():
        if progress_cb:
            await progress_cb(78, "Deep directory fuzzing with ffuf", "ffuf")
        try:
            for host_url in live_host_urls[:5]:  # limit to first 5 hosts
                ffuf_result = await ffuf.execute(
                    host_url,
                    wordlist_size="small",
                    timeout=120,
                )
                if ffuf_result.success and ffuf_result.results:
                    for entry in ffuf_result.results:
                        if isinstance(entry, dict):
                            found_url = entry.get("url", "")
                            if found_url:
                                all_urls.append({"url": found_url, "source": "ffuf"})
                                # Also add to dir_results for the workspace
                                dir_results.setdefault(host_url.split("//")[-1].split("/")[0], []).append(entry)
        except Exception as exc:
            warnings.append(f"ffuf dir fuzzing: {exc}")

    # ===================================================================
    # Phase 2F-param: Parameter Name Fuzzing with ffuf
    # ===================================================================
    if ffuf.is_available():
        try:
            # Find API-like endpoints to fuzz for hidden params
            api_endpoints = [u for u in live_host_urls if any(
                kw in u.lower() for kw in ("/api", "/v1", "/v2", "/graphql")
            )]
            if not api_endpoints:
                # Use root URLs as fallback
                api_endpoints = live_host_urls[:3]

            param_wordlist = None
            from pathlib import Path
            # Check for SecLists param names
            param_paths = [
                Path("/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
                Path("/usr/share/wordlists/dirb/common.txt"),
            ]
            for p in param_paths:
                if p.exists():
                    param_wordlist = str(p)
                    break

            if param_wordlist:
                if progress_cb:
                    await progress_cb(80, "Fuzzing parameter names", "ffuf")
                for api_url in api_endpoints[:3]:
                    param_fuzz_result = await ffuf.execute(
                        api_url.rstrip("/") + "/FUZZ",
                        wordlist=param_wordlist,
                        wordlist_size="small",
                        timeout=60,
                    )
                    if param_fuzz_result.success and param_fuzz_result.results:
                        for entry in param_fuzz_result.results:
                            if isinstance(entry, dict):
                                found_url = entry.get("url", "")
                                if found_url:
                                    all_urls.append({"url": found_url, "source": "ffuf_param"})
        except Exception as exc:
            warnings.append(f"Parameter fuzzing: {exc}")

    # ===================================================================
    # Phase 2G: Light Parameter Discovery (arjun)
    # ===================================================================
    if progress_cb:
        await progress_cb(85, "Light parameter discovery", "arjun")  # 2G

    hidden_params: list[dict[str, Any]] = []
    if tool_runner.is_available("arjun"):
        try:
            # Pick top 10 interesting endpoints
            interesting_eps = _pick_arjun_targets(unique_urls, hidden_endpoints, 10)
            if interesting_eps:
                for ep_url in interesting_eps:
                    try:
                        arjun_result = await tool_runner.run(
                            "arjun", ["-u", ep_url, "-q", "-oJ", "/dev/stdout"],
                            target=ep_url, timeout=60,
                        )
                        if arjun_result.success and arjun_result.results:
                            import json as _json
                            for line in arjun_result.results:
                                try:
                                    data = _json.loads(line)
                                    if isinstance(data, dict):
                                        for url_key, params in data.items():
                                            if isinstance(params, list):
                                                hidden_params.append({
                                                    "url": url_key,
                                                    "hidden_params": params,
                                                    "tool": "arjun",
                                                })
                                except _json.JSONDecodeError:
                                    continue
                    except Exception:
                        continue
        except Exception as exc:
            warnings.append(f"Arjun parameter discovery failed: {exc}")

        if hidden_params:
            await workspace.write_data(
                workspace_id, "urls/hidden_parameters.json", hidden_params,
                generated_by="arjun", target=target_label,
            )
            files_written.append("urls/hidden_parameters.json")
    else:
        warnings.append("arjun not installed — skipping hidden parameter discovery.")

    # ===================================================================
    # Phase 2H: Parameter Classification
    # ===================================================================
    if progress_cb:
        await progress_cb(92, "Classifying parameters by vulnerability type", "param_classifier")  # 2H

    try:
        # Read all parameter sources
        urls_data = await workspace.read_data(workspace_id, "urls/crawled.json")
        urls_items = urls_data.get("data", []) if isinstance(urls_data, dict) else (urls_data or [])
        params_data = await workspace.read_data(workspace_id, "urls/parameters.json")
        params_items = params_data.get("data", []) if isinstance(params_data, dict) else (params_data or [])
        hidden_ep_data = await workspace.read_data(workspace_id, "endpoints/hidden_endpoints.json")
        hidden_ep_items = hidden_ep_data.get("data", []) if isinstance(hidden_ep_data, dict) else (hidden_ep_data or [])

        # Read forms data
        forms_data = await workspace.read_data(workspace_id, "urls/forms.json")
        forms_items = forms_data.get("data", []) if isinstance(forms_data, dict) else (forms_data or [])

        # Inject OpenAPI-discovered endpoints into hidden_ep_items for classification
        for oa_result in openapi_results:
            host_url = oa_result.get("host_url", "")
            for ep in oa_result.get("endpoints", []):
                ep_url = ep.get("url", f"{host_url.rstrip('/')}{ep['path']}")
                query_params = [p for p in ep.get("parameters", []) if p.get("in") in ("query", "body")]
                if query_params:
                    qs = "&".join(f"{p['name']}=test" for p in query_params if p.get("in") == "query")
                    full_url = f"{ep_url}?{qs}" if qs else ep_url
                    hidden_ep_items.append({
                        "path": full_url,
                        "method": ep.get("method", "GET"),
                        "source": "openapi_spec",
                    })
                    # Also add body params as separate entries
                    for p in query_params:
                        if p.get("in") == "body":
                            hidden_ep_items.append({
                                "path": ep_url,
                                "method": ep.get("method", "POST"),
                                "source": "openapi_spec",
                                "params": [{"name": p["name"], "value": ""}],
                            })

        param_classification = param_classifier.classify_parameters(
            urls_items, params_items, hidden_ep_items, forms_items,
        )

        # Phase 2: Live reflection probes — detect XSS/SQLi/LFI by behavior
        if progress_cb:
            await progress_cb(94, "Probing params for reflection & SQL errors", "probe")
        try:
            # Scale probe limits for broad domain
            live_count = len([h for h in live_hosts if not h.get("failed")])
            probe_max = min(500, max(60, live_count * 10))
            param_classification = await param_classifier.probe_reflection(
                param_classification, concurrency=8, max_params=probe_max,
            )
        except Exception as exc:
            warnings.append(f"Reflection probe failed: {exc}")

        await workspace.write_data(
            workspace_id, "urls/parameter_classification.json",
            [param_classification],  # wrap in list for DataWrapper
            generated_by="param_classifier", target=target_label,
        )
        files_written.append("urls/parameter_classification.json")
    except Exception as exc:
        warnings.append(f"Parameter classification failed: {exc}")
        param_classification = {}

    # ===================================================================
    # Finalize
    # ===================================================================
    if progress_cb:
        await progress_cb(98, "Final analysis", "finalize")

    await workspace.update_stats(workspace_id, live_hosts=len(live_hosts))
    await workspace.add_stage_history(workspace_id, 2, "completed")

    if progress_cb:
        await progress_cb(100, "Discovery complete", "done")

    # Build flag distribution from all phases
    flag_dist: Counter[str] = Counter()
    for h in flagged_hosts:
        for f in h.get("flags", []):
            flag_dist[f.split(":")[0]] += 1

    secret_types: Counter[str] = Counter()
    for s in js_secrets:
        secret_types[s.get("type", "UNKNOWN")] += 1

    # Sensitive path category counts
    sp_categories: Counter[str] = Counter()
    for findings_list in sensitive_findings.values():
        for f in findings_list:
            sp_categories[f["category"]] += 1

    # CORS severity counts
    cors_severities: Counter[str] = Counter()
    for cr in cors_results:
        cors_severities[cr.get("severity", "INFO")] += 1

    # URL categorization
    dynamic_urls: list[str] = []
    api_urls: list[str] = []
    admin_urls: list[str] = []
    static_urls: list[str] = []

    for entry in unique_urls:
        url_str = entry.get("url", "") if isinstance(entry, dict) else str(entry)
        if not url_str:
            continue
        parsed = urlparse(url_str)
        path = parsed.path.lower()

        if parsed.query:
            dynamic_urls.append(url_str)
        elif any(seg in path for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
            api_urls.append(url_str)
        elif any(seg in path for seg in ("/admin", "/debug", "/internal", "/manage", "/console")):
            admin_urls.append(url_str)
        else:
            static_urls.append(url_str)

    if dynamic_urls:
        await workspace.write_data(
            workspace_id, "urls/dynamic_urls.json", dynamic_urls,
            generated_by="url_categorizer", target=target_label,
        )
        files_written.append("urls/dynamic_urls.json")

    if api_urls:
        await workspace.write_data(
            workspace_id, "urls/api_urls.json", api_urls,
            generated_by="url_categorizer", target=target_label,
        )
        files_written.append("urls/api_urls.json")

    if admin_urls:
        await workspace.write_data(
            workspace_id, "urls/admin_urls.json", admin_urls,
            generated_by="url_categorizer", target=target_label,
        )
        files_written.append("urls/admin_urls.json")

    url_categories = {
        "dynamic": len(dynamic_urls),
        "api": len(api_urls),
        "admin": len(admin_urls),
        "js": len(js_urls),
        "static": len(static_urls),
        "total": len(unique_urls),
    }

    # Generate HTML report
    try:
        from bughound.utils.html_report import generate_discovery_html, save_html_report
        html = generate_discovery_html(workspace_id, {
            "target": target_label,
            "live_hosts": len(live_hosts),
            "urls_discovered": len(unique_urls),
            "js_files": len(js_urls),
            "technologies": [h.get("technologies", []) for h in live_hosts],
            "flags": flagged_hosts,
            "probe_stats": param_classification.get("stats", {}),
            "cors_results": cors_results,
            "sensitive_paths": sensitive_findings,
            "auth_results": auth_results,
            "crawled_urls": all_urls,
            "parameters_harvested": len(hidden_params) if hidden_params else 0,
            "forms_discovered": len(unique_forms),
            "secrets_found": len(js_secrets),
        })
        await save_html_report(workspace_id, "discovery.html", html)
        files_written.append("reports/discovery.html")
    except Exception as exc:
        warnings.append(f"HTML report generation failed: {exc}")

    return {
        "status": "success",
        "message": (
            f"Full discovery complete for {target_label}. "
            f"{len(live_hosts)} live hosts, {len(unique_urls)} URLs "
            f"({len(dynamic_urls)} dynamic, {len(api_urls)} API, {len(admin_urls)} admin), "
            f"{len(js_secrets)} secrets, {len(hidden_endpoints)} hidden endpoints, "
            f"{sum(len(v) for v in sensitive_findings.values())} sensitive paths, "
            f"{len(takeover_results)} takeover candidates, "
            f"{len(cors_results)} CORS issues, "
            f"{sum(len(v) for v in dir_results.values())} directory findings, "
            f"{len(unique_forms)} forms, "
            f"{len(hidden_params)} hidden param sets, "
            f"{param_classification.get('stats', {}).get('unique_params_matched', 0)} classified params."
        ),
        "workspace_id": workspace_id,
        "files_written": files_written,
        "data": {
            "live_hosts": len(live_hosts),
            "hosts_with_flags": len(hosts_with_flags),
            "waf_detected": sum(1 for w in waf_results if w.get("detected")),
            "urls_discovered": len(unique_urls),
            "url_categories": url_categories,
            "url_sources": url_tool_counts,
            "js_files_found": len(js_urls),
            "js_files_analyzed": min(len(js_urls), 100),
            "secrets_found": len(js_secrets),
            "secrets_by_confidence": secrets_by_conf if js_urls else {},
            "secret_types": dict(secret_types.most_common(10)),
            "endpoints_from_js": len(js_endpoints),
            "hidden_endpoints": len(hidden_endpoints),
            "forms_discovered": len(unique_forms),
            "form_types": dict(Counter(f.get("classification", "unknown") for f in unique_forms).most_common()),
            "parameters_harvested": total_params,
            "sensitive_paths_found": sum(len(v) for v in sensitive_findings.values()),
            "sensitive_path_categories": dict(sp_categories.most_common(10)),
            "takeover_candidates": len(takeover_results),
            "takeover_confirmed": len(takeover_confirmed),
            "cors_vulnerable": len(cors_results),
            "cors_severities": dict(cors_severities.most_common()),
            "dir_findings": sum(len(v) for v in dir_results.values()),
            "hidden_params_discovered": len(hidden_params),
            "param_classification": param_classification.get("stats", {}),
            "top_technologies": tech_counter.most_common(10),
            "flag_distribution": dict(flag_dist.most_common(15)),
            "majority_cdn": majority_cdn,
            "httpx_time": f"{httpx_result.execution_time_seconds}s",
        },
        "warnings": warnings,
        "next_step": (
            "Discovery complete. Present results to user and await further instructions."
        ),
    }


# ---------------------------------------------------------------------------
# Async discovery job
# ---------------------------------------------------------------------------


async def _start_discover_job(
    workspace_id: str,
    targets: list[str],
    meta: Any,
    job_manager: JobManager,
    host_filter_cb: Any = None,
) -> dict[str, Any]:
    """Start discovery as a background job for broad targets."""
    try:
        job_id = await job_manager.create_job(workspace_id, "discover", meta.target)
    except RuntimeError as exc:
        return _error("execution_failed", str(exc))

    async def _run_job(jid: str) -> None:
        async def _progress(pct: int, msg: str, module: str) -> None:
            await job_manager.update_progress(jid, pct, msg, module)

        result = await _run_discover(
            workspace_id, targets, meta,
            progress_cb=_progress, host_filter_cb=host_filter_cb,
        )
        if result.get("status") == "success":
            await job_manager.complete_job(jid, result.get("data"))
        else:
            await job_manager.fail_job(jid, result.get("message", "Discovery failed"))

    await job_manager.start_job(job_id, _run_job(job_id))

    return {
        "status": "job_started",
        "job_id": job_id,
        "message": f"Discovery started for {len(targets)} targets.",
        "workspace_id": workspace_id,
        "estimated_time": "5-20 minutes",
    }


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


async def _resolve_targets(meta: Any) -> list[str]:
    """Determine which targets to probe based on workspace metadata."""
    target_type = meta.target_type
    classification = meta.classification or {}

    if target_type == TargetType.BROAD_DOMAIN:
        subs = await workspace.read_data(meta.workspace_id, "subdomains/all.txt")
        if isinstance(subs, list) and subs:
            return subs
        return classification.get("normalized_targets", [meta.target])

    if target_type in (TargetType.SINGLE_HOST, TargetType.SINGLE_ENDPOINT):
        return classification.get("normalized_targets", [meta.target])

    if target_type == TargetType.URL_LIST:
        return classification.get("normalized_targets", [])

    return [meta.target]


# ---------------------------------------------------------------------------
# Intelligence flags
# ---------------------------------------------------------------------------


def _generate_flags(
    host: dict[str, Any],
    waf_by_url: dict[str, str | None],
    majority_cdn: str | None,
) -> list[str]:
    """Generate intelligence flags for a single host."""
    flags: list[str] = []
    url = host.get("url", "")
    title = (host.get("title") or "").lower()
    techs = host.get("technologies") or []
    techs_lower = " ".join(techs).lower()
    cdn = host.get("cdn", "")
    server = (host.get("web_server") or "").lower()

    # NO_WAF: url was scanned by wafw00f and no WAF was found
    if url in waf_by_url and waf_by_url[url] is None:
        flags.append("NO_WAF: No WAF detected — direct exposure")

    # NON_CDN_IP: this host isn't behind the CDN that most siblings use
    if majority_cdn and not cdn:
        flags.append(f"NON_CDN_IP: Not behind {majority_cdn} while siblings are")

    # DEFAULT_PAGE
    if any(default in title for default in _DEFAULT_TITLES):
        flags.append(f"DEFAULT_PAGE: Default/placeholder page ({title[:60]})")

    # GRAPHQL
    graphql_indicators = ("graphql", "graphiql", "playground", "apollo")
    if any(g in title for g in graphql_indicators) or any(g in url.lower() for g in graphql_indicators):
        flags.append("GRAPHQL: GraphQL detected — check introspection")

    # OLD_TECH
    for pattern, label in _OLD_TECH_PATTERNS:
        if pattern.search(techs_lower) or pattern.search(server):
            flags.append(f"OLD_TECH: {label}")
            break

    # DEBUG_MODE
    status = host.get("status_code", 0)
    if status == 500 or "debug" in title or "stack trace" in title or "traceback" in title:
        flags.append("DEBUG_MODE: Error/debug information exposed")

    return flags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pick_arjun_targets(
    urls: list[dict[str, str]],
    hidden_endpoints: list[dict[str, Any]],
    limit: int = 10,
) -> list[str]:
    """Pick the most interesting endpoints for parameter discovery.

    Prioritizes: hidden endpoints > endpoints with existing params > API paths.
    """
    from urllib.parse import urlparse

    candidates: list[tuple[int, str]] = []  # (priority, url)

    # Hidden endpoints are top priority
    for ep in hidden_endpoints:
        path = ep.get("path", "")
        if path and "://" in path:
            candidates.append((0, path))

    # URLs with query params (likely accept more params)
    for entry in urls:
        u = entry.get("url", "")
        if not u:
            continue
        parsed = urlparse(u)
        if parsed.query:
            candidates.append((1, u.split("?")[0]))  # base URL without params
        elif any(k in parsed.path.lower() for k in ("/api/", "/v1/", "/v2/", "/graphql", "/search")):
            candidates.append((2, u))

    # Deduplicate, sort by priority, return top N
    seen: set[str] = set()
    result: list[str] = []
    for _, url in sorted(candidates):
        if url not in seen:
            seen.add(url)
            result.append(url)
            if len(result) >= limit:
                break

    return result


def _extract_parameters(urls: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Extract unique parameters grouped by endpoint path with frequency analysis."""
    from urllib.parse import parse_qs, urlparse

    params_by_path: dict[str, dict[str, set]] = {}  # path -> {param_name: {values}}
    param_global_count: Counter[str] = Counter()  # param_name -> how many paths use it

    for entry in urls:
        try:
            parsed = urlparse(entry["url"])
            if not parsed.query:
                continue
            path = parsed.path or "/"
            qs = parse_qs(parsed.query)
            if path not in params_by_path:
                params_by_path[path] = {}
            for param, values in qs.items():
                if param not in params_by_path[path]:
                    params_by_path[path][param] = set()
                    param_global_count[param] += 1
                params_by_path[path][param].update(values[:3])
        except Exception:
            continue

    # Identify high-frequency params (appear on 3+ endpoints = framework-level)
    high_freq = {p for p, c in param_global_count.items() if c >= 3}

    # Convert to serializable format
    result: list[dict[str, Any]] = []
    for path, params in sorted(params_by_path.items()):
        result.append({
            "path": path,
            "params": [
                {
                    "name": name,
                    "example_values": sorted(vals)[:3],
                    "frequency": param_global_count[name],
                    "high_frequency": name in high_freq,
                }
                for name, vals in sorted(params.items())
            ],
        })
    return result


async def _fetch_robots_sitemap(base_url: str) -> list[dict[str, Any]]:
    """Fetch and parse robots.txt + sitemap.xml from a host."""
    import aiohttp

    results: list[dict[str, Any]] = []
    base = base_url.rstrip("/")

    # robots.txt
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base}/robots.txt",
                timeout=aiohttp.ClientTimeout(total=8),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="replace")
                    for line in body.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                results.append({
                                    "host": base,
                                    "type": "disallowed",
                                    "value": path,
                                })
                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            # Handle "Sitemap: https://..." where split on : cuts the URL
                            if not sitemap_url.startswith("http"):
                                sitemap_url = line.split(" ", 1)[1].strip()
                            results.append({
                                "host": base,
                                "type": "sitemap_ref",
                                "value": sitemap_url,
                            })
    except Exception:
        pass

    # sitemap.xml
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base}/sitemap.xml",
                timeout=aiohttp.ClientTimeout(total=8),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="replace")
                    # Simple regex extraction of <loc> tags
                    import re
                    for match in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", body):
                        results.append({
                            "host": base,
                            "type": "sitemap_url",
                            "value": match.group(1).strip(),
                        })
    except Exception:
        pass

    return results


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
