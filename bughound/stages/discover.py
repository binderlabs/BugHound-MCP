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

import aiohttp
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

    # Filter passive URLs to live hosts only — gau/waybackurls return URLs
    # from dead subdomains (e.g. ecor.yueco.edu.mm) that waste scan time.
    if all_urls and live_hosts:
        from urllib.parse import urlparse as _urlparse_filter
        live_hostnames: set[str] = set()
        for lh in live_hosts:
            if isinstance(lh, dict):
                h = lh.get("host", "")
                u = lh.get("url", "")
                if h:
                    live_hostnames.add(h.lower())
                if u:
                    try:
                        live_hostnames.add(_urlparse_filter(u).hostname.lower())
                    except Exception:
                        pass

        pre_filter = len(all_urls)
        filtered_urls = []
        for item in all_urls:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            try:
                hostname = _urlparse_filter(url).hostname
                if hostname and hostname.lower() in live_hostnames:
                    filtered_urls.append(item)
            except Exception:
                filtered_urls.append(item)  # keep if can't parse

        dropped = pre_filter - len(filtered_urls)
        if dropped > 0:
            logger.info("discover.url_filter_dead_hosts", dropped=dropped, remaining=len(filtered_urls))
        all_urls = filtered_urls

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
    # Seed katana with both:
    #   1. live host roots (traditional websites)
    #   2. interesting URLs from gau/wayback (for backend-only targets where
    #      the root is empty, like ebs01.telekom.de — root returns 23 bytes)
    #
    # Without seeds, katana on backend domains finds 0 URLs because the root
    # is just a service identifier with no HTML to crawl.
    crawl_targets = [h["url"] for h in live_hosts if h.get("url")][:10]

    # Add seed URLs from gau/wayback: prefer URLs with paths and query params
    # (more likely to return HTML pages with links to crawl)
    seed_urls: list[str] = []
    seen_seed_paths: set[str] = set()
    for entry in all_urls:
        url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
        try:
            parsed = urlparse(url)
            # Skip empty paths and bare hostnames (no point seeding from /)
            if not parsed.path or parsed.path == "/":
                continue
            # Dedup by path (don't seed 100 variants of /products?id=N)
            path_key = parsed.path
            if path_key in seen_seed_paths:
                continue
            seen_seed_paths.add(path_key)
            seed_urls.append(url)
            if len(seed_urls) >= 15:  # cap seeds at 15 to keep crawl bounded
                break
        except Exception:
            continue
    # Combine: live host roots + gau/wayback seed URLs
    crawl_targets = crawl_targets + seed_urls
    if seed_urls:
        logger.info(
            "discover.katana_seeds_added",
            seeds=len(seed_urls),
            total_targets=len(crawl_targets),
        )

    katana_forms: list[dict[str, Any]] = []
    use_deep_crawl = meta.target_type in (TargetType.SINGLE_HOST, TargetType.SINGLE_ENDPOINT)
    # Determine crawl depth based on target type
    crawl_depth = 1 if len(crawl_targets) > 5 else 3

    if katana.is_available():
        katana_count = 0
        # Single batch invocation — katana handles internal parallelism.
        # Previously: N sequential invocations (16 URLs × 180s = 48 min worst case).
        # Now: 1 invocation, internal concurrency, ~1-3 min for typical batch.
        #
        # Tuning: depth 2, scope=fqdn (strict to target host), forms disabled.
        # form-extraction + auto-fill on 16 URLs at depth 3 explodes to
        # 1000s of requests and times out. We extract forms via separate
        # form_extractor module on live_hosts only.
        try:
            cr = await katana.execute_batch(
                crawl_targets,
                depth=2,
                concurrency=10,
                scope="fqdn",  # strict: ebs01.telekom.de only, not www.telekom.de
                enable_forms=False,  # too slow on batch
                timeout=300,  # 5 min cap
            )
            if cr.success:
                for entry in cr.results:
                    u = entry["url"] if isinstance(entry, dict) else str(entry)
                    all_urls.append({"url": u, "source": "katana"})
                    katana_count += 1
                # Extract forms from katana batch output
                for w in cr.warnings:
                    if w.startswith("__forms__:"):
                        import json as _json
                        try:
                            katana_forms.extend(_json.loads(w[10:]))
                        except _json.JSONDecodeError:
                            pass
        except Exception as exc:
            warnings.append(f"Katana batch crawl failed: {exc}")
        url_tool_counts["katana"] = katana_count
    elif gospider.is_available():
        # Same seeding strategy as katana — use gau/wayback URLs as seeds
        gospider_count = 0
        for ct in crawl_targets:  # already includes seed_urls from above
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

    # Wayback Machine URLs — only if waybackurls binary didn't already run
    wayback_urls_found: list[str] = []
    if url_tool_counts.get("waybackurls", 0) <= 0:
        # waybackurls binary not available or returned nothing — use CDX API
        if progress_cb:
            await progress_cb(33, "Fetching Wayback Machine URLs (CDX API)", "wayback_cdx")
        target_domain = meta.target.replace("http://", "").replace("https://", "").strip("/")
        try:
            async with aiohttp.ClientSession() as _wb_session:
                wayback_urls_found = await _fetch_wayback_urls(target_domain, _wb_session)
                for wb_url in wayback_urls_found:
                    all_urls.append({"url": wb_url, "source": "wayback_cdx"})
                url_tool_counts["wayback_cdx"] = len(wayback_urls_found)
        except Exception as exc:
            warnings.append(f"Wayback Machine CDX fetch failed: {exc}")

        if wayback_urls_found:
            await workspace.write_data(
                workspace_id, "urls/wayback.json",
                [{"url": u, "source": "wayback_cdx"} for u in wayback_urls_found],
                generated_by="wayback_cdx", target=target_label,
            )
            files_written.append("urls/wayback.json")

    # OpenAPI/Swagger spec extraction (pure Python)
    if progress_cb:
        await progress_cb(34, "Checking for OpenAPI/Swagger specs", "openapi_spec")
    openapi_spec_endpoints: list[dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession() as _oa_session:
            for ct in crawl_targets[:5]:
                spec_eps = await _fetch_openapi_spec(ct, _oa_session)
                openapi_spec_endpoints.extend(spec_eps)
                for ep in spec_eps:
                    all_urls.append({"url": ep["url"], "source": "openapi"})
            url_tool_counts["openapi_spec"] = len(openapi_spec_endpoints)
    except Exception as exc:
        warnings.append(f"OpenAPI spec extraction failed: {exc}")

    # Save OpenAPI-discovered endpoints to workspace
    if openapi_spec_endpoints:
        await workspace.write_data(
            workspace_id, "endpoints/openapi_specs.json", openapi_spec_endpoints,
            generated_by="openapi_spec_extractor", target=target_label,
        )
        files_written.append("endpoints/openapi_specs.json")

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

    # Static asset extensions to filter out (no value for injection testing).
    # Note: .js/.mjs/.jsx are NOT filtered here — they're kept because:
    #   1. JSONP endpoints (/api/data.js?callback=) are real injection targets
    #   2. Dynamic .js with query params (?v=x) may reflect user input
    #   3. Injection tester can skip them at its own discretion
    _STATIC_ASSET_EXTS = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp3", ".mp4", ".wav", ".ogg", ".ogv", ".webm", ".avi", ".mov",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".css", ".map",
    })

    import re as _re_sa
    # Junk characters that crawlers sometimes capture at the end of URLs
    # (trailing quotes, parens, smart quotes, commas, periods).
    _URL_JUNK_RE = _re_sa.compile(
        r'["\'\)\(\]\}>,;\.\\]+$|%22$|%27$|%28$|%29$|%5b$|%5d$|%7b$|%7d$|%3e$|%e2%80%99$',
        _re_sa.I,
    )

    def _clean_url(url: str) -> str:
        """Strip trailing junk captured from HTML/JS extraction."""
        if not url:
            return url
        url = url.strip()
        # Repeatedly strip trailing junk until no more changes
        while True:
            new = _URL_JUNK_RE.sub("", url)
            if new == url:
                break
            url = new
        return url

    # Pre-compile a single regex that matches any static extension followed by
    # a URL delimiter (end-of-string, ?, #, ;, ), %, /) — this catches
    # malformed URLs with trailing CSS garbage like .png%29%7D._container_x.
    _ext_pattern = "|".join(
        re.escape(ext.lstrip(".")) for ext in _STATIC_ASSET_EXTS
    )
    _STATIC_ASSET_RE = _re_sa.compile(
        rf'\.({_ext_pattern})(?:$|[?#;)/%])',
        _re_sa.I,
    )

    def _is_static_asset(url: str) -> bool:
        """Check if URL points to a static file that shouldn't be tested.

        Uses regex to catch malformed URLs where extraction captured CSS
        garbage after the extension (e.g. .png%29%7D._container_x).
        """
        try:
            from urllib.parse import urlparse
            # Check path + query — static refs can appear either way
            parsed = urlparse(url)
            path = parsed.path.lower().rstrip("/")
            # Strip jsessionid and similar path params (/.css;jsessionid=abc)
            path_clean = path.split(";")[0]
            # Fast path: endswith check for clean URLs
            for ext in _STATIC_ASSET_EXTS:
                if path_clean.endswith(ext):
                    return True
            # Slower path: regex for malformed URLs with trailing junk
            if _STATIC_ASSET_RE.search(path):
                return True
        except Exception:
            pass
        return False

    # Deduplicate + clean + filter static assets
    seen_urls: set[str] = set()
    unique_urls: list[dict[str, str]] = []
    static_filtered = 0
    for entry in all_urls:
        u = _clean_url(entry.get("url", ""))
        if not u or u in seen_urls:
            continue
        seen_urls.add(u)
        if _is_static_asset(u):
            static_filtered += 1
            continue
        # Write cleaned URL back
        entry = {**entry, "url": u} if isinstance(entry, dict) else {"url": u}
        unique_urls.append(entry)

    if static_filtered > 0:
        logger.info(
            "discover.static_filtered",
            dropped=static_filtered,
            remaining=len(unique_urls),
        )

    # ===================================================================
    # Phase 2B-liveness: Probe URLs in bulk to filter dead historical URLs
    # ===================================================================
    # gau/waybackurls return historical URLs — many are 404 now. Probing
    # them keeps only live endpoints (200/301/302/401/403). Without this
    # filter, downstream tools waste time on dead URLs:
    #   - js_analyzer: downloads dead .js files (404 HTML pages, no secrets)
    #   - arjun: param-fuzzes dead endpoints
    #   - param_classifier: classifies non-existent URLs
    #   - injection_tester (Stage 4): tests against dead URLs
    if progress_cb:
        await progress_cb(40, "Probing URLs for liveness", "url_probe")

    if unique_urls and len(unique_urls) > 5:
        live_url_set: set[str] = set()
        dead_url_count = 0
        # Use httpx in stdin batch mode for speed
        if tool_runner.is_available("httpx"):
            url_list = [e["url"] for e in unique_urls if isinstance(e, dict) and e.get("url")]
            try:
                # httpx -l reads from file. Write urls to temp file.
                import tempfile as _tf_url, os as _os_url
                _ufd, _utmp = _tf_url.mkstemp(suffix=".txt", prefix="bh_url_probe_")
                with _os_url.fdopen(_ufd, "w") as _f:
                    _f.write("\n".join(url_list))
                try:
                    # -mc 200,301,302,401,403: keep "alive-ish" URLs
                    # -t 50: 50 threads for speed
                    # -timeout 5: short per-URL timeout
                    # -nc: no color codes
                    # -silent: only print URLs, no banner
                    probe_result = await tool_runner.run(
                        "httpx",
                        [
                            "-l", _utmp,
                            "-mc", "200,301,302,401,403",
                            "-t", "50",
                            "-timeout", "5",
                            "-silent",
                            "-nc",
                        ],
                        target=target_label,
                        timeout=600,  # 10 min max for huge URL sets
                    )
                    if probe_result.success and probe_result.results:
                        for line in probe_result.results:
                            line = str(line).strip()
                            if line.startswith("http"):
                                live_url_set.add(line.split()[0])  # strip status code if present
                finally:
                    try:
                        _os_url.unlink(_utmp)
                    except OSError:
                        pass

                # Filter unique_urls to only live ones.
                # httpx normalizes URLs (http→https via redirect, spaces→+,
                # encoding). Match by (hostname, path) instead of exact string.
                if live_url_set:
                    def _url_key(u: str) -> tuple[str, str]:
                        """Normalize URL to (hostname, path) for loose matching."""
                        try:
                            from urllib.parse import urlparse as _up, unquote as _uq
                            p = _up(u)
                            host = (p.hostname or "").lower()
                            path = _uq(p.path.lower()).rstrip("/")
                            return (host, path)
                        except Exception:
                            return (u.lower(), "")

                    live_keys = {_url_key(lu) for lu in live_url_set}
                    pre_count = len(unique_urls)
                    unique_urls = [
                        e for e in unique_urls
                        if isinstance(e, dict) and _url_key(e.get("url", "")) in live_keys
                    ]
                    dead_url_count = pre_count - len(unique_urls)
                    logger.info(
                        "discover.liveness_probe",
                        total=pre_count,
                        live=len(unique_urls),
                        dead=dead_url_count,
                    )
                    if dead_url_count > 0:
                        warnings.append(
                            f"URL liveness: dropped {dead_url_count} dead URLs "
                            f"from gau/wayback history ({len(unique_urls)} live remain)"
                        )
                else:
                    logger.warning(
                        "discover.liveness_probe.empty",
                        msg="httpx returned no live URLs — possible probe failure, keeping all",
                    )
            except Exception as exc:
                warnings.append(f"URL liveness probe failed: {exc}")

    # Extract JS files from all_urls (before static filter removes them).
    # Cleaned + deduped. These go into js_files.json for js_analyzer.
    # Probe JS URLs for liveness too — wayback/gau return many dead .js files.
    _js_seen: set[str] = set()
    js_urls_raw: list[str] = []
    for e in all_urls:
        u = _clean_url(e.get("url", "") if isinstance(e, dict) else str(e))
        if not u or u in _js_seen:
            continue
        lower = u.lower()
        # Match cleaned .js/.mjs/.jsx extension or /js/ path segment
        from urllib.parse import urlparse as _up
        path_only = _up(u).path.lower().rstrip("/").split(";")[0]
        if (
            path_only.endswith(".js")
            or path_only.endswith(".mjs")
            or path_only.endswith(".jsx")
            or "/js/" in lower
        ):
            _js_seen.add(u)
            js_urls_raw.append(u)

    # Probe JS URLs for liveness — most wayback .js files are dead 404s
    js_urls: list[str] = []
    if js_urls_raw and len(js_urls_raw) > 5 and tool_runner.is_available("httpx"):
        try:
            import tempfile as _tf_js, os as _os_js
            _jfd, _jtmp = _tf_js.mkstemp(suffix=".txt", prefix="bh_js_probe_")
            with _os_js.fdopen(_jfd, "w") as _jf:
                _jf.write("\n".join(js_urls_raw))
            try:
                js_probe = await tool_runner.run(
                    "httpx",
                    [
                        "-l", _jtmp,
                        "-mc", "200",  # JS files must return 200 (no point if 301/redirect)
                        "-t", "50",
                        "-timeout", "5",
                        "-silent",
                        "-nc",
                    ],
                    target=target_label,
                    timeout=600,
                )
                if js_probe.success and js_probe.results:
                    live_js = set()
                    for line in js_probe.results:
                        line = str(line).strip()
                        if line.startswith("http"):
                            live_js.add(line.split()[0])

                    # Match by (host, path) — httpx normalizes URLs
                    def _js_key(u: str) -> tuple[str, str]:
                        try:
                            from urllib.parse import urlparse as _up, unquote as _uq
                            p = _up(u)
                            return ((p.hostname or "").lower(),
                                    _uq(p.path.lower()).rstrip("/"))
                        except Exception:
                            return (u.lower(), "")
                    live_js_keys = {_js_key(lu) for lu in live_js}
                    js_urls = sorted(
                        u for u in js_urls_raw if _js_key(u) in live_js_keys
                    )
                    js_dead = len(js_urls_raw) - len(js_urls)
                    if js_dead > 0:
                        logger.info(
                            "discover.js_liveness",
                            total=len(js_urls_raw),
                            live=len(js_urls),
                            dead=js_dead,
                        )
                else:
                    js_urls = sorted(js_urls_raw)  # fallback if probe fails
            finally:
                try:
                    _os_js.unlink(_jtmp)
                except OSError:
                    pass
        except Exception:
            js_urls = sorted(js_urls_raw)
    else:
        js_urls = sorted(js_urls_raw)

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
    # Phase 2B-urlsecrets: Scan URL list for embedded secrets
    # ===================================================================
    # gau/wayback/katana often return URLs with secrets in query params:
    #   /callback?token=eyJhbGc...
    #   /api?api_key=sk_live_abc123
    #   https://user:pass@host/
    # These historical URLs can contain leaked credentials still active.
    url_secrets: list[dict[str, Any]] = []
    if unique_urls:
        try:
            url_list_to_scan = [
                e.get("url", "") if isinstance(e, dict) else str(e)
                for e in unique_urls
            ]
            url_secrets = js_analyzer.scan_urls_for_secrets(url_list_to_scan)
            if url_secrets:
                await workspace.write_data(
                    workspace_id, "secrets/url_secrets.json", url_secrets,
                    generated_by="url_scanner", target=target_label,
                )
                files_written.append("secrets/url_secrets.json")
                logger.info(
                    "discover.url_secrets",
                    count=len(url_secrets),
                    types=list({s["type"] for s in url_secrets}),
                )
        except Exception as exc:
            warnings.append(f"URL secret scan failed: {exc}")

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
        # Track real download success (some URLs are dead 404s from wayback/gau)
        js_files_actually_analyzed = js_result.get("files_analyzed", 0)
        js_files_failed = js_result.get("files_failed", 0)
        if js_files_failed > js_files_actually_analyzed * 3 and js_files_actually_analyzed < 10:
            warnings.append(
                f"JS analyzer: {js_files_failed} of "
                f"{js_files_actually_analyzed + js_files_failed} JS URLs failed "
                f"(404/timeout) — most JS URLs from wayback/gau are dead. "
                f"Only {js_files_actually_analyzed} actually analyzed."
            )

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
        # Phase 2C-trufflehog: Verify secrets with trufflehog (optional)
        # ===================================================================
        # js_analyzer finds pattern matches but doesn't verify them.
        # trufflehog calls the actual API to confirm secrets are live.
        # Verified secrets → CRITICAL findings, unverified → MEDIUM.
        try:
            from bughound.tools.scanning import trufflehog as _trufflehog_tool
            if _trufflehog_tool.is_available():
                if progress_cb:
                    await progress_cb(46, "Verifying secrets with trufflehog", "trufflehog")

                import tempfile
                import aiohttp as _th_aiohttp
                from pathlib import Path as _ThPath

                verified_secrets: list[dict[str, Any]] = []
                # Save downloaded JS files inside the workspace for inspection
                # (was tempfile.TemporaryDirectory which auto-deleted them,
                # making it impossible to verify what was scanned)
                from bughound.config.settings import WORKSPACE_BASE_DIR
                tmp_path = _ThPath(WORKSPACE_BASE_DIR) / workspace_id / "js_downloads"
                tmp_path.mkdir(parents=True, exist_ok=True)
                # Clean any old files from previous run
                for _old in tmp_path.iterdir():
                    if _old.is_file():
                        try:
                            _old.unlink()
                        except OSError:
                            pass
                _tmp_dir = str(tmp_path)
                if True:  # keep block scope similar to old `with` block

                    # Download JS files for filesystem scan (cap at 50 files for speed)
                    async with _th_aiohttp.ClientSession(
                        timeout=_th_aiohttp.ClientTimeout(total=15),
                    ) as _th_session:
                        downloaded = 0
                        for js_url in js_urls[:50]:
                            try:
                                async with _th_session.get(js_url, ssl=False) as resp:
                                    if resp.status == 200:
                                        content = await resp.text(errors="replace")
                                        # Sanitize filename
                                        safe_name = (
                                            js_url.replace("://", "_")
                                            .replace("/", "_")
                                            .replace(":", "_")
                                            .replace("?", "_")[:200]
                                        )
                                        (tmp_path / safe_name).write_text(
                                            content[:500_000], errors="replace",
                                        )
                                        downloaded += 1
                            except Exception:
                                continue

                    if downloaded > 0:
                        # Scan downloaded files with trufflehog (verified only)
                        th_result = await _trufflehog_tool.scan_filesystem(
                            str(tmp_path), only_verified=True, timeout=180,
                        )
                        if th_result.success and th_result.results:
                            verified_secrets = th_result.results
                            logger.info(
                                "trufflehog.verified_secrets",
                                count=len(verified_secrets),
                                files_scanned=downloaded,
                            )

                # Save verified secrets separately and merge into main secrets
                if verified_secrets:
                    await workspace.write_data(
                        workspace_id, "secrets/verified_secrets.json",
                        verified_secrets,
                        generated_by="trufflehog", target=target_label,
                    )
                    files_written.append("secrets/verified_secrets.json")

                    # Boost js_secrets: mark any pattern match that trufflehog
                    # also found as "verified" with HIGH confidence + critical
                    for vs in verified_secrets:
                        js_secrets.append({
                            "name": vs.get("detector", "unknown"),
                            "value": vs.get("raw_snippet", ""),
                            "source_file": vs.get("source_file", ""),
                            "confidence": "HIGH",
                            "verified": True,
                            "severity": "critical",
                            "description": vs.get("description", "Verified secret"),
                        })
                    # Re-save merged secrets
                    await workspace.write_data(
                        workspace_id, "secrets/js_secrets.json", js_secrets,
                        generated_by="js_analyzer+trufflehog", target=target_label,
                    )
        except Exception as _th_exc:
            logger.debug("trufflehog.skipped", error=str(_th_exc))

    # ===================================================================
    # Phase 2C-map: Check for exposed source maps (.js.map)
    # Save .map content to workspace/sourcemaps/ — these contain original
    # unminified source code, often revealing internal logic, comments,
    # and hidden endpoints. Worth keeping for AI/manual review later.
    # ===================================================================
    source_maps_found: list[dict[str, Any]] = []
    _MAP_SAVE_DIR = None
    _MAP_MAX_BYTES = 5_000_000  # 5MB cap per map file
    if js_urls:
        import aiohttp as _aiohttp
        from bughound.config.settings import WORKSPACE_BASE_DIR as _WBD_MAP
        from pathlib import Path as _PMAP
        _MAP_SAVE_DIR = _PMAP(_WBD_MAP) / workspace_id / "sourcemaps"
        _MAP_SAVE_DIR.mkdir(parents=True, exist_ok=True)
        # Clean old maps
        for _old in _MAP_SAVE_DIR.iterdir():
            if _old.is_file():
                try:
                    _old.unlink()
                except OSError:
                    pass

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
                                # Save to workspace
                                try:
                                    safe_name = (
                                        map_url.replace("://", "_")
                                        .replace("/", "_")
                                        .replace(":", "_")
                                        .replace("?", "_")[:200]
                                    )
                                    (_MAP_SAVE_DIR / safe_name).write_text(
                                        body[:_MAP_MAX_BYTES], errors="replace",
                                    )
                                    saved_path = str(_MAP_SAVE_DIR / safe_name)
                                except Exception:
                                    saved_path = None
                                return {
                                    "url": map_url,
                                    "size": len(body),
                                    "source_js": js_url,
                                    "local_path": saved_path,
                                    "truncated": len(body) > _MAP_MAX_BYTES,
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
                saved_to=str(_MAP_SAVE_DIR) if _MAP_SAVE_DIR else None,
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
    # Skip arjun if WAF detected — it will just hang on every request
    waf_hosts_detected = {
        urlparse(w.get("url", "")).hostname
        for w in waf_results
        if w.get("detected")
    }

    if tool_runner.is_available("arjun"):
        try:
            # Pick top 10 interesting endpoints
            interesting_eps = _pick_arjun_targets(unique_urls, hidden_endpoints, 10)
            # Filter out WAF-protected URLs (arjun will hang on them)
            if waf_hosts_detected:
                skipped_waf = sum(
                    1 for ep in interesting_eps
                    if urlparse(ep).hostname in waf_hosts_detected
                )
                interesting_eps = [
                    ep for ep in interesting_eps
                    if urlparse(ep).hostname not in waf_hosts_detected
                ]
                if skipped_waf:
                    warnings.append(
                        f"arjun: skipped {skipped_waf} WAF-protected URL(s)"
                    )
            if interesting_eps:
                import tempfile as _arjun_tempfile
                import json as _json
                import os as _os_arjun
                for ep_url in interesting_eps:
                    try:
                        # Write to temp file instead of /dev/stdout — arjun
                        # opens its output with 'w+' mode which fails when
                        # stdout is a captured pipe (ValueError: can't open
                        # pipe as read-write).
                        _arjun_fd, _arjun_tmp = _arjun_tempfile.mkstemp(
                            suffix=".json", prefix="bughound_arjun_",
                        )
                        _os_arjun.close(_arjun_fd)
                        # arjun workflow: probe stability → analyze HTTP
                        # response → extract params → logicforce each param →
                        # test → report. On slow ASP.NET/Java servers this
                        # takes 90-120s per URL. 180s gives headroom while
                        # still bailing on fully hung WAF targets.
                        #
                        # -t 20: parallel threads (default 2 is too slow)
                        # --rate-limit 100: WAF-friendly
                        # -T 10: per-request HTTP timeout (default 15s)
                        arjun_result = await tool_runner.run(
                            "arjun",
                            [
                                "-u", ep_url,
                                "-q", "-oJ", _arjun_tmp,
                                "-t", "20",
                                "-T", "10",
                                "--rate-limit", "100",
                            ],
                            target=ep_url, timeout=180,
                        )
                        # Process results from temp file regardless of exit code
                        # (arjun may exit 1 but still write valid JSON output).
                        try:
                            with open(_arjun_tmp) as _arjun_f:
                                data = _json.load(_arjun_f)
                            if isinstance(data, dict):
                                for url_key, info in data.items():
                                    # arjun newer output: {url: {params: [...]}}
                                    if isinstance(info, dict):
                                        params = info.get("params", [])
                                    elif isinstance(info, list):
                                        params = info
                                    else:
                                        continue
                                    # Skip ASP.NET framework params (always
                                    # present, never vulnerable to injection)
                                    real_params = [
                                        p for p in params
                                        if not p.startswith("__")
                                    ]
                                    if real_params:
                                        hidden_params.append({
                                            "url": url_key,
                                            "hidden_params": real_params,
                                            "tool": "arjun",
                                        })
                        except (_json.JSONDecodeError, FileNotFoundError, OSError):
                            pass
                        finally:
                            try:
                                _os_arjun.unlink(_arjun_tmp)
                            except OSError:
                                pass
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
    # Phase 2I: CMS Detection
    # ===================================================================
    if progress_cb:
        await progress_cb(96, "Detecting CMS platforms", "cms_detection")

    cms_info = await _detect_cms(workspace_id, unique_urls, flagged_hosts, target_label)
    if cms_info:
        files_written.append("hosts/cms_detection.json")

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
            # Use filtered unique_urls, NOT raw all_urls (which contains
            # static assets like .jpg/.woff/.css that we dropped)
            "crawled_urls": unique_urls,
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
            # actual downloads (excludes 404/timeout from dead wayback URLs)
            "js_files_analyzed": js_files_actually_analyzed if js_urls else 0,
            "js_files_failed": js_files_failed if js_urls else 0,
            "secrets_found": len(js_secrets),
            "secrets_by_confidence": secrets_by_conf if js_urls else {},
            "secret_types": dict(secret_types.most_common(10)),
            "url_secrets_found": len(url_secrets),
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
            "cms_detected": cms_info if cms_info else None,
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


_ARJUN_SKIP_EXTENSIONS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
    ".pdf", ".zip", ".gz", ".tar", ".mp3", ".mp4", ".wav",
    ".xml", ".json", ".txt", ".csv", ".doc", ".docx", ".xls",
})


def _pick_arjun_targets(
    urls: list[dict[str, str]],
    hidden_endpoints: list[dict[str, Any]],
    limit: int = 10,
) -> list[str]:
    """Pick the most interesting endpoints for parameter discovery.

    Prioritizes: hidden endpoints > endpoints with existing params > API paths.
    Skips static files (.js, .css, .png, .pdf, etc.) — they don't accept params.
    """
    from urllib.parse import urlparse

    def _is_static(url: str) -> bool:
        try:
            path = urlparse(url).path.lower().rstrip("/")
            return any(path.endswith(ext) for ext in _ARJUN_SKIP_EXTENSIONS)
        except Exception:
            return False

    candidates: list[tuple[int, str]] = []  # (priority, url)

    # Hidden endpoints are top priority
    for ep in hidden_endpoints:
        path = ep.get("path", "")
        if path and "://" in path and not _is_static(path):
            candidates.append((0, path))

    # URLs with query params (likely accept more params)
    for entry in urls:
        u = entry.get("url", "")
        if not u or _is_static(u):
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


# ---------------------------------------------------------------------------
# CMS Detection
# ---------------------------------------------------------------------------

_CMS_URL_PATTERNS: dict[str, list[str]] = {
    "wordpress": ["/wp-content/", "/wp-includes/", "/wp-json/", "/wp-login.php", "/xmlrpc.php", "/wp-admin/"],
    "joomla": ["/administrator/", "/components/com_", "/modules/mod_", "/templates/"],
    "drupal": ["/sites/default/", "/core/misc/", "/modules/contrib/", "/profiles/"],
    "magento": ["/skin/frontend/", "/js/mage/", "/downloader/", "/app/etc/"],
    "prestashop": ["/modules/ps_", "/themes/classic/", "/admin_ps/"],
    "opencart": ["/catalog/view/", "/admin/view/", "/system/storage/"],
}

_CMS_TECH_KEYWORDS: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "magento": ["magento", "adobe commerce"],
    "prestashop": ["prestashop"],
    "opencart": ["opencart"],
    "shopify": ["shopify"],
    "wix": ["wix"],
    "squarespace": ["squarespace"],
    "ghost": ["ghost"],
}

_SAAS_CMS = {"shopify", "wix", "squarespace", "webflow", "blogger", "weebly", "hubspot"}


async def _detect_cms(
    workspace_id: str,
    urls: list[dict[str, str]],
    flagged_hosts: list[dict[str, Any]],
    target_label: str,
) -> dict[str, Any] | None:
    """Detect CMS from crawled URLs and httpx technologies.

    Saves result to hosts/cms_detection.json and returns the detection dict,
    or None if no CMS was detected.
    """
    # Count URL matches per CMS
    cms_url_counts: Counter[str] = Counter()
    for entry in urls:
        url_str = entry.get("url", "") if isinstance(entry, dict) else str(entry)
        url_lower = url_str.lower()
        for cms_name, patterns in _CMS_URL_PATTERNS.items():
            for pattern in patterns:
                if pattern in url_lower:
                    cms_url_counts[cms_name] += 1
                    break  # count each URL once per CMS

    # Check httpx technologies
    cms_tech_matches: dict[str, list[str]] = {}
    for host in flagged_hosts:
        techs = host.get("technologies") or []
        techs_lower = " ".join(techs).lower()
        for cms_name, keywords in _CMS_TECH_KEYWORDS.items():
            for kw in keywords:
                if kw in techs_lower:
                    cms_tech_matches.setdefault(cms_name, []).append(
                        host.get("host", host.get("url", ""))
                    )
                    break

    # Determine best CMS match
    best_cms: str | None = None
    best_score = 0
    evidence_parts: list[str] = []

    # URL-based detection
    for cms_name, count in cms_url_counts.most_common(3):
        score = count
        if cms_name in cms_tech_matches:
            score += 100  # tech detection is strong signal
        if score > best_score:
            best_score = score
            best_cms = cms_name

    # Tech-only detection (no URL matches needed for SaaS CMS)
    if not best_cms:
        for cms_name, hosts_list in cms_tech_matches.items():
            if len(hosts_list) > 0:
                best_cms = cms_name
                best_score = 100
                break

    if not best_cms:
        return None

    # Determine confidence
    url_count = cms_url_counts.get(best_cms, 0)
    has_tech_match = best_cms in cms_tech_matches
    if url_count >= 5 and has_tech_match:
        confidence = "high"
    elif url_count >= 5 or has_tech_match:
        confidence = "high"
    elif url_count >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    if url_count > 0:
        evidence_parts.append(f"{url_count} URLs matching {best_cms} patterns")
    if has_tech_match:
        tech_hosts = cms_tech_matches[best_cms]
        evidence_parts.append(
            f"Technology detected on {len(tech_hosts)} host(s): {', '.join(tech_hosts[:3])}"
        )

    # Extract version from technologies if available
    cms_version: str | None = None
    for host in flagged_hosts:
        techs = host.get("technologies") or []
        for tech in techs:
            tech_lower = tech.lower()
            if best_cms.lower() in tech_lower and any(c.isdigit() for c in tech):
                # Extract version string (e.g. "WordPress 6.4.2" -> "6.4.2")
                parts = tech.split()
                for p in parts:
                    if p and p[0].isdigit():
                        cms_version = p
                        break
                if cms_version:
                    break
        if cms_version:
            break

    is_saas = best_cms in _SAAS_CMS

    cms_info = {
        "cms_type": best_cms,
        "cms_version": cms_version,
        "confidence": confidence,
        "evidence": "; ".join(evidence_parts),
        "is_saas": is_saas,
        "url_match_count": url_count,
        "tech_match_hosts": len(cms_tech_matches.get(best_cms, [])),
        "all_cms_detected": {
            name: {"url_matches": cms_url_counts.get(name, 0), "tech_matches": len(cms_tech_matches.get(name, []))}
            for name in set(list(cms_url_counts.keys()) + list(cms_tech_matches.keys()))
        },
    }

    await workspace.write_data(
        workspace_id, "hosts/cms_detection.json", [cms_info],
        generated_by="cms_detector", target=target_label,
    )

    logger.info(
        "discover.cms_detected",
        cms=best_cms,
        version=cms_version,
        confidence=confidence,
        url_matches=url_count,
        is_saas=is_saas,
    )

    return cms_info


async def _fetch_sitemap(base_url: str, session: aiohttp.ClientSession) -> list[str]:
    """Extract URLs from sitemap.xml."""
    urls: list[str] = []
    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml"]:
        try:
            async with session.get(
                f"{base_url.rstrip('/')}{path}",
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    # Extract <loc>...</loc> tags
                    locs = re.findall(r'<loc>(.*?)</loc>', text, re.I)
                    urls.extend(locs)
        except Exception:
            pass
    return urls


async def _fetch_robots_txt(base_url: str, session: aiohttp.ClientSession) -> list[str]:
    """Extract disallowed paths from robots.txt."""
    paths: list[str] = []
    try:
        async with session.get(
            f"{base_url.rstrip('/')}/robots.txt",
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and not path.startswith("#"):
                            full_url = f"{base_url.rstrip('/')}{path}"
                            paths.append(full_url)
                    elif line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        if sitemap_url.startswith("http"):
                            paths.append(sitemap_url)
    except Exception:
        pass
    return paths


async def _fetch_robots_sitemap(base_url: str) -> list[dict[str, Any]]:
    """Fetch and parse robots.txt + sitemap.xml from a host.

    Uses the enhanced _fetch_sitemap and _fetch_robots_txt helpers to
    check multiple sitemap paths and extract Allow/Disallow/Sitemap directives.
    """
    import aiohttp as _aiohttp

    results: list[dict[str, Any]] = []
    base = base_url.rstrip("/")

    try:
        async with _aiohttp.ClientSession() as session:
            # Fetch robots.txt paths (Disallow, Allow, Sitemap refs)
            robots_urls = await _fetch_robots_txt(base, session)
            for url_or_path in robots_urls:
                if url_or_path.startswith("http"):
                    # Sitemap reference
                    results.append({
                        "host": base,
                        "type": "sitemap_ref",
                        "value": url_or_path,
                    })
                else:
                    # Full URL constructed from a Disallow/Allow path
                    # Extract path portion back out for the legacy format
                    path = url_or_path.replace(base, "", 1) or url_or_path
                    results.append({
                        "host": base,
                        "type": "disallowed",
                        "value": path,
                    })

            # Fetch sitemap URLs from multiple sitemap paths
            sitemap_urls = await _fetch_sitemap(base, session)
            for loc_url in sitemap_urls:
                results.append({
                    "host": base,
                    "type": "sitemap_url",
                    "value": loc_url.strip(),
                })
    except Exception:
        pass

    return results


async def _fetch_openapi_spec(
    base_url: str, session: aiohttp.ClientSession,
) -> list[dict[str, Any]]:
    """Try common OpenAPI/Swagger paths and extract endpoints."""
    import json as _json

    spec_paths = [
        "/swagger.json", "/swagger/v1/swagger.json",
        "/v2/api-docs", "/v3/api-docs",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/swagger.json",
        "/api/docs", "/docs/api",
    ]
    endpoints: list[dict[str, Any]] = []
    for path in spec_paths:
        try:
            url = f"{base_url.rstrip('/')}{path}"
            async with session.get(
                url, ssl=False, timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if '"paths"' in text or '"openapi"' in text or '"swagger"' in text:
                        try:
                            spec = _json.loads(text)
                            paths = spec.get("paths", {})
                            for api_path, methods in paths.items():
                                if isinstance(methods, dict):
                                    for method in methods:
                                        if method.lower() in (
                                            "get", "post", "put", "delete", "patch",
                                        ):
                                            full_url = f"{base_url.rstrip('/')}{api_path}"
                                            endpoints.append({
                                                "url": full_url,
                                                "method": method.upper(),
                                                "source": "openapi",
                                            })
                        except _json.JSONDecodeError:
                            pass
        except Exception:
            pass
    return endpoints


async def _fetch_wayback_urls(
    domain: str, session: aiohttp.ClientSession, limit: int = 5000,
) -> list[str]:
    """Fetch historical URLs from Wayback Machine CDX API. Pure Python fallback only.

    Note: waybackurls binary runs separately via the tool wrapper in the passive
    URL sources section. This function is ONLY called when waybackurls binary
    is not available or returned nothing.
    """

    # Fallback: pure-Python CDX API
    urls: list[str] = []
    try:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
        )
        async with session.get(
            cdx_url, timeout=aiohttp.ClientTimeout(total=60),
        ) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        urls.append(line)
    except Exception:
        pass
    return urls


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}
