"""Stage 3: Analyze — Exploitability scoring, attack chains, immediate wins, playbooks.

This is the intelligence brain of BugHound. It does NOT call any AI. It aggregates
all Stage 2 data, scores targets by real exploitability, detects attack chains, and
presents everything so the AI client can make smart decisions.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import aiofiles
import structlog

from bughound.core import tool_runner, workspace
from bughound.schemas.models import WorkspaceState

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_items(data: list | dict | None) -> list[Any]:
    """Unwrap DataWrapper envelope or plain list. Never returns None."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("data", [])
    return []


def _host_from_url(url: str) -> str:
    """Extract hostname from a URL (strip scheme, path, port)."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return (parsed.hostname or "").lower()
    except Exception:
        return url.strip().lower()


def _error(error_type: str, message: str) -> dict[str, Any]:
    return {"status": "error", "error_type": error_type, "message": message}


# ---------------------------------------------------------------------------
# Data loading — reads ALL workspace files from Stages 1-2
# ---------------------------------------------------------------------------


async def _load_all_data(workspace_id: str) -> dict[str, Any]:
    """Read all workspace data files. Missing files return empty lists."""
    files = {
        "subdomains": "subdomains/all.txt",
        "dns_records": "dns/records.json",
        "dns_wildcards": "dns/wildcards.json",
        "live_hosts": "hosts/live_hosts.json",
        "technologies": "hosts/technologies.json",
        "waf": "hosts/waf.json",
        "flags": "hosts/flags.json",
        "sensitive_paths": "hosts/sensitive_paths.json",
        "cors_results": "hosts/cors_results.json",
        "crawled_urls": "urls/crawled.json",
        "parameters": "urls/parameters.json",
        "js_files": "urls/js_files.json",
        "robots_sitemap": "urls/robots_sitemap.json",
        "js_secrets": "secrets/js_secrets.json",
        "api_endpoints": "endpoints/api_endpoints.json",
        "hidden_endpoints": "endpoints/hidden_endpoints.json",
        "takeover_candidates": "cloud/takeover_candidates.json",
        "takeover_confirmed": "cloud/takeover_confirmed.json",
    }
    result: dict[str, list[Any]] = {}
    for key, path in files.items():
        raw = await workspace.read_data(workspace_id, path)
        result[key] = _extract_items(raw)
    return result


# ---------------------------------------------------------------------------
# Exploitability scoring (Part 2)
# ---------------------------------------------------------------------------


# Weight constants
_W_CRITICAL = 50
_W_HIGH = 30
_W_MEDIUM = 15
_W_LOW = 5


def _build_host_index(data: dict[str, list]) -> dict[str, dict[str, Any]]:
    """Index all per-host data by hostname for fast lookup."""
    idx: dict[str, dict[str, Any]] = {}

    # Live hosts
    for h in data["live_hosts"]:
        host = (h.get("host") or _host_from_url(h.get("url", ""))).lower()
        if host:
            idx.setdefault(host, {
                "host_data": None, "flags": [], "secrets": [], "sensitive_paths": [],
                "cors": [], "hidden_endpoints": [], "parameters": [],
                "urls": [], "waf": None, "technologies": [],
                "api_endpoints": [], "takeover": None, "robots_disallowed": [],
            })
            idx[host]["host_data"] = h
            idx[host]["technologies"] = h.get("technologies", [])

    # Flags
    for f in data["flags"]:
        host = (f.get("host") or "").lower()
        if host in idx:
            idx[host]["flags"] = f.get("flags", [])

    # Secrets — match by source_file host
    for s in data["js_secrets"]:
        src = s.get("source_file", "")
        host = _host_from_url(src)
        if host in idx:
            idx[host]["secrets"].append(s)

    # Sensitive paths
    for sp in data["sensitive_paths"]:
        host = _host_from_url(sp.get("host_url", ""))
        if host in idx:
            idx[host]["sensitive_paths"].append(sp)

    # CORS
    for c in data["cors_results"]:
        host = _host_from_url(c.get("url", ""))
        if host in idx:
            idx[host]["cors"].append(c)

    # Hidden endpoints — match by source_file
    for ep in data["hidden_endpoints"]:
        src = ep.get("source_file", "")
        host = _host_from_url(src)
        if host in idx:
            idx[host]["hidden_endpoints"].append(ep)

    # API endpoints
    for ep in data["api_endpoints"]:
        src = ep.get("source_file", "")
        host = _host_from_url(src)
        if host in idx:
            idx[host]["api_endpoints"].append(ep)

    # Parameters — match by host in path URL
    for p in data["parameters"]:
        path = p.get("path", "")
        # Parameters might have full URL or just path
        host = _host_from_url(path) if "://" in path else ""
        if host and host in idx:
            idx[host]["parameters"].append(p)
        elif not host:
            # Assign to all hosts (URL-path params apply broadly)
            for h_key in idx:
                idx[h_key]["parameters"].append(p)

    # URLs
    for u in data["crawled_urls"]:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        host = _host_from_url(url)
        if host in idx:
            idx[host]["urls"].append(u)

    # WAF
    for w in data["waf"]:
        host = _host_from_url(w.get("url", ""))
        if host in idx:
            idx[host]["waf"] = w

    # Takeover
    for t in data["takeover_candidates"]:
        host = (t.get("subdomain") or t.get("host") or "").lower()
        if host in idx:
            idx[host]["takeover"] = t
    for t in data["takeover_confirmed"]:
        host = (t.get("subdomain") or t.get("host") or "").lower()
        if host in idx:
            idx[host]["takeover"] = {**t, "confirmed": True}

    # Robots disallowed paths
    for rs in data["robots_sitemap"]:
        if rs.get("type") == "disallowed":
            host = _host_from_url(rs.get("host", ""))
            if host in idx:
                idx[host]["robots_disallowed"].append(rs.get("value", ""))

    return idx


def _score_host(host: str, info: dict[str, Any]) -> dict[str, Any]:
    """Score a single host by exploitability. Returns scored target dict."""
    score = 0
    reasons: list[str] = []
    flags_list = info["flags"]
    flags_set = {f.split(":")[0] for f in flags_list}
    sp_paths = [sp.get("path", "") for sp in info["sensitive_paths"]]
    sp_cats = [sp.get("category", "") for sp in info["sensitive_paths"]]

    # --- CRITICAL (50 each) ---
    for s in info["secrets"]:
        if s.get("confidence") == "HIGH" and s.get("type", "").startswith(("AWS", "GCP", "AZURE")):
            score += _W_CRITICAL
            reasons.append(f"{s['type']} leaked in JS (HIGH confidence) — verify if key is active")
            break  # count once per host

    if info.get("takeover", {}).get("confirmed"):
        score += _W_CRITICAL
        reasons.append("Confirmed subdomain takeover — immediate report")

    if any("GIT_EXPOSED" in f for f in flags_list) or any(p.endswith(".git/HEAD") or p == "/.git/HEAD" for p in sp_paths):
        score += _W_CRITICAL
        reasons.append("Exposed .git/HEAD — full source code recovery possible")

    if any("ENV_LEAKED" in f for f in flags_list) or any(".env" in p for p in sp_paths):
        score += _W_CRITICAL
        reasons.append("Exposed .env file — may contain DB creds, API keys, JWT secrets")

    # --- HIGH (30 each) ---
    critical_cors = [c for c in info["cors"] if c.get("severity") == "CRITICAL" and c.get("credentials_allowed")]
    if critical_cors:
        score += _W_HIGH
        reasons.append("CORS reflects origin with credentials — account takeover risk")

    if any("SWAGGER_EXPOSED" in f for f in flags_list) or any("swagger" in p.lower() or "openapi" in p.lower() for p in sp_paths):
        score += _W_HIGH
        reasons.append("API documentation publicly exposed — reveals all endpoints")

    if "GRAPHQL" in flags_set:
        score += _W_HIGH
        reasons.append("GraphQL endpoint — likely introspection enabled")

    if info["hidden_endpoints"]:
        score += _W_HIGH
        reasons.append(f"{len(info['hidden_endpoints'])} hidden API endpoints found in JS (not in crawl)")

    if any("SPRING_ACTUATOR" in f for f in flags_list):
        score += _W_HIGH
        reasons.append("Spring Boot actuator exposed — /actuator/env may leak secrets")

    if "DEBUG_MODE" in flags_set or any("DEBUG" in f for f in flags_list):
        score += _W_HIGH
        reasons.append("Debug mode enabled — stack traces/environment info exposed")

    if any("ADMIN_PANEL" in f for f in flags_list):
        score += _W_HIGH
        reasons.append("Admin panel accessible — test for default creds, auth bypass")

    # --- MEDIUM (15 each) ---
    if "NO_WAF" in flags_set:
        score += _W_MEDIUM
        reasons.append("No WAF protection — direct exploitation possible")

    if "OLD_TECH" in flags_set:
        score += _W_MEDIUM
        old_detail = next((f for f in flags_list if "OLD_TECH" in f), "")
        reasons.append(f"Outdated technology with known CVEs: {old_detail.split(':', 1)[-1].strip()}")

    non_crit_cors = [c for c in info["cors"] if c.get("severity") in ("HIGH", "MEDIUM") and not c.get("credentials_allowed")]
    if non_crit_cors:
        score += _W_MEDIUM
        reasons.append("CORS misconfiguration (no credentials)")

    total_params = sum(len(p.get("params", [])) for p in info["parameters"])
    if total_params >= 10:
        score += _W_MEDIUM
        reasons.append(f"{total_params} parameters — large injection surface")

    if any("BACKUP_FOUND" in f for f in flags_list):
        score += _W_MEDIUM
        reasons.append("Backup files exposed (.sql, .zip, .tar.gz)")

    # Missing security headers from host data
    hd = info.get("host_data") or {}
    if hd.get("security_headers", {}).get("score") == "F":
        score += _W_MEDIUM
        reasons.append("Missing critical security headers")

    # --- LOW (5 each) ---
    if "DEFAULT_PAGE" in flags_set:
        score += _W_LOW
        reasons.append("Default/placeholder page")

    if "NON_CDN_IP" in flags_set:
        score += _W_LOW
        reasons.append("Not behind CDN while siblings are — direct exposure")

    if 0 < total_params < 10:
        score += _W_LOW
        reasons.append(f"{total_params} parameters found")

    # robots.txt interesting disallowed paths
    if info.get("robots_disallowed"):
        score += _W_LOW
        reasons.append(f"robots.txt has {len(info['robots_disallowed'])} interesting disallowed paths")

    # Risk level
    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Build cors issue summary
    cors_issue = None
    if info["cors"]:
        worst = sorted(info["cors"], key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(c.get("severity", "INFO"), 5))
        c = worst[0]
        cors_issue = {"severity": c.get("severity"), "detail": f"origin {c.get('origin_tested', '?')} reflected" + (" with credentials" if c.get("credentials_allowed") else "")}

    # Secrets summary
    secrets_on_host = [
        {"type": s.get("type", "?"), "confidence": s.get("confidence", "?"), "file": s.get("source_file", "?").split("/")[-1]}
        for s in info["secrets"]
    ]

    # Sensitive paths found
    sp_found = [sp.get("path", "") for sp in info["sensitive_paths"]]

    url = (info.get("host_data") or {}).get("url", f"https://{host}")

    return {
        "host": host,
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "flags": sorted(flags_set),
        "technologies": info["technologies"][:10],
        "sensitive_paths_found": sp_found[:10],
        "cors_issue": cors_issue,
        "hidden_endpoints_count": len(info["hidden_endpoints"]),
        "api_endpoints_count": len(info["api_endpoints"]),
        "secrets_on_host": secrets_on_host,
        "parameters_count": total_params,
        "urls_count": len(info["urls"]),
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Attack chain detection (Part 3)
# ---------------------------------------------------------------------------


def _detect_attack_chains(
    host_idx: dict[str, dict[str, Any]],
    data: dict[str, list],
) -> list[dict[str, Any]]:
    """Check for exploitable multi-finding chains. Returns matched chains."""
    chains: list[dict[str, Any]] = []

    for host, info in host_idx.items():
        flags_str = " ".join(info["flags"])
        sp_paths = {sp.get("path", "") for sp in info["sensitive_paths"]}
        sp_cats = {sp.get("category", "") for sp in info["sensitive_paths"]}
        secret_types = {s.get("type", "") for s in info["secrets"]}
        secret_confs = {s.get("confidence", "") for s in info["secrets"]}
        has_no_waf = "NO_WAF" in {f.split(":")[0] for f in info["flags"]}
        hidden_eps = info["hidden_endpoints"]
        cors_list = info["cors"]

        # CHAIN 1 — Source Code Theft
        if any(".git" in p for p in sp_paths) or "GIT_EXPOSED" in flags_str:
            chains.append({
                "chain_id": "SOURCE_CODE_THEFT",
                "name": "Source Code Theft",
                "severity": "CRITICAL",
                "bounty_estimate": "$1000-5000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f".git/HEAD accessible on {host}",
                    "supporting": "Exposed git repository allows full source code recovery",
                },
                "exploitation_steps": [
                    f"curl -s https://{host}/.git/HEAD",
                    "Use git-dumper to download the full .git directory",
                    "Review source for hardcoded credentials, internal endpoints",
                    "Check commit history for removed secrets",
                ],
                "report_ready": True,
            })

        # CHAIN 2 — Cloud Credential Abuse
        cloud_keys = {s.get("type") for s in info["secrets"]
                      if s.get("confidence") == "HIGH"
                      and any(k in s.get("type", "") for k in ("AWS", "GCP", "AZURE", "S3"))}
        if cloud_keys and (data["takeover_candidates"] or any("S3" in t for t in secret_types)):
            key_type = next(iter(cloud_keys))
            src_file = next((s.get("source_file", "?") for s in info["secrets"] if s.get("type") == key_type), "?")
            chains.append({
                "chain_id": "CLOUD_CREDENTIAL_ABUSE",
                "name": "Cloud Credential Abuse",
                "severity": "CRITICAL",
                "bounty_estimate": "$2000-10000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"{key_type} found in {src_file.split('/')[-1]}",
                    "supporting": "Cloud resources detected in enumeration",
                },
                "exploitation_steps": [
                    f"Extract the {key_type} from the JS file",
                    "Test key validity: aws sts get-caller-identity",
                    "Enumerate S3 access: aws s3 ls",
                    "Check for sensitive data in accessible buckets",
                ],
                "report_ready": True,
            })

        # CHAIN 3 — Account Takeover via CORS
        crit_cors = [c for c in cors_list if c.get("severity") == "CRITICAL" and c.get("credentials_allowed")]
        if crit_cors:
            # Check for auth endpoints
            all_paths = {ep.get("path", "") for ep in hidden_eps + info["api_endpoints"]}
            all_paths |= {u.get("url", "") if isinstance(u, dict) else str(u) for u in info["urls"]}
            auth_patterns = re.compile(r"/(login|auth|oauth|api/session|signin|token)", re.I)
            has_auth = any(auth_patterns.search(p) for p in all_paths)
            if has_auth:
                chains.append({
                    "chain_id": "ACCOUNT_TAKEOVER_CORS",
                    "name": "Account Takeover via CORS",
                    "severity": "CRITICAL",
                    "bounty_estimate": "$1000-5000",
                    "affected_hosts": [host],
                    "evidence": {
                        "trigger": f"CORS reflects origin with credentials on {host}",
                        "supporting": "Authentication endpoints detected on same host",
                    },
                    "exploitation_steps": [
                        "Create attacker page that makes XHR to target with credentials",
                        "Victim visits attacker page → browser sends cookies",
                        "Response readable by attacker due to CORS misconfiguration",
                        "Extract session tokens, CSRF tokens, or user data",
                    ],
                    "report_ready": True,
                })

        # CHAIN 4 — API Abuse via Documentation
        has_swagger = any("SWAGGER" in f or "swagger" in f.lower() for f in info["flags"]) or \
                      any("swagger" in p.lower() or "openapi" in p.lower() for p in sp_paths)
        if has_swagger and hidden_eps:
            chains.append({
                "chain_id": "API_ABUSE_VIA_DOCS",
                "name": "API Abuse via Documentation",
                "severity": "HIGH",
                "bounty_estimate": "$500-3000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": "Swagger/OpenAPI docs publicly accessible",
                    "supporting": f"{len(hidden_eps)} hidden endpoints found in JS analysis",
                },
                "exploitation_steps": [
                    "Download Swagger/OpenAPI spec for complete endpoint map",
                    "Cross-reference with hidden endpoints from JS",
                    "Test each endpoint for IDOR, auth bypass, rate limiting",
                    "Check for undocumented admin/internal endpoints",
                ],
                "report_ready": False,
            })

        # CHAIN 5 — Environment Variable Leak
        if any(".env" in p for p in sp_paths) or "ENV_LEAKED" in flags_str:
            chains.append({
                "chain_id": "ENV_VARIABLE_LEAK",
                "name": "Environment Variable Leak",
                "severity": "CRITICAL",
                "bounty_estimate": "$1000-5000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f".env file accessible on {host}",
                    "supporting": "Environment files typically contain DB creds, API keys, JWT secrets",
                },
                "exploitation_steps": [
                    f"curl -s https://{host}/.env",
                    "Extract database credentials — test direct DB access",
                    "Extract API keys — test for cloud resource access",
                    "Extract JWT secret — forge authentication tokens",
                ],
                "report_ready": True,
            })

        # CHAIN 7 — Unauthenticated API + Injection
        eps_with_params = [ep for ep in hidden_eps if ep.get("path") and "?" in ep.get("path", "")]
        host_has_params = bool(info["parameters"]) or bool(eps_with_params)
        if hidden_eps and host_has_params and has_no_waf:
            chains.append({
                "chain_id": "UNAUTH_API_INJECTION",
                "name": "Unauthenticated API + Injection",
                "severity": "HIGH",
                "bounty_estimate": "$500-3000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"{len(hidden_eps)} hidden endpoints with no WAF protection",
                    "supporting": "Endpoints found in JS but not in public crawl results",
                },
                "exploitation_steps": [
                    "Enumerate hidden endpoints with parameters",
                    "Test SQLi: add ' OR 1=1-- to each parameter",
                    "Test XSS: inject <script>alert(1)</script>",
                    "Test SSRF: inject http://169.254.169.254/ in URL params",
                ],
                "report_ready": False,
            })

        # CHAIN 8 — Debug Information Disclosure
        is_debug = "DEBUG_MODE" in {f.split(":")[0] for f in info["flags"]}
        has_actuator = any("SPRING_ACTUATOR" in f for f in info["flags"])
        has_phpinfo = any("phpinfo" in p.lower() for p in sp_paths)
        if is_debug and (has_actuator or has_phpinfo or "DEBUG" in flags_str):
            chains.append({
                "chain_id": "DEBUG_INFO_DISCLOSURE",
                "name": "Debug Information Disclosure",
                "severity": "MEDIUM-HIGH",
                "bounty_estimate": "$300-1500",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"Debug mode active on {host}",
                    "supporting": "Stack traces, actuator, or phpinfo accessible",
                },
                "exploitation_steps": [
                    "Extract internal paths, framework versions from error pages",
                    "Check /actuator/env or phpinfo for environment variables",
                    "Use leaked info to target specific components",
                    "Check for database credentials in debug output",
                ],
                "report_ready": False,
            })

        # CHAIN 9 — WordPress Full Compromise
        techs_lower = " ".join(info["technologies"]).lower()
        has_wp = "wordpress" in techs_lower
        has_old_wp = "OLD_TECH" in {f.split(":")[0] for f in info["flags"]} and "wordpress" in flags_str.lower()
        has_wp_admin = any("wp-admin" in p or "wp-login" in p for p in sp_paths)
        if has_wp and (has_old_wp or has_wp_admin) and has_no_waf:
            chains.append({
                "chain_id": "WORDPRESS_COMPROMISE",
                "name": "WordPress Full Compromise",
                "severity": "HIGH",
                "bounty_estimate": "$500-2000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"WordPress detected on {host}" + (" (outdated)" if has_old_wp else ""),
                    "supporting": "No WAF protection" + (", wp-admin accessible" if has_wp_admin else ""),
                },
                "exploitation_steps": [
                    "Enumerate users: /wp-json/wp/v2/users",
                    "Test xmlrpc.php for brute force and SSRF",
                    "Check /wp-content/debug.log for exposed logs",
                    "Enumerate plugins via directory listing",
                    "Run nuclei -tags wordpress",
                ],
                "report_ready": False,
            })

        # CHAIN 10 — GraphQL Exploitation
        has_graphql = "GRAPHQL" in {f.split(":")[0] for f in info["flags"]}
        graphql_hidden = any("graphql" in ep.get("path", "").lower() for ep in hidden_eps)
        if has_graphql and (has_no_waf or graphql_hidden):
            chains.append({
                "chain_id": "GRAPHQL_EXPLOITATION",
                "name": "GraphQL Exploitation",
                "severity": "HIGH",
                "bounty_estimate": "$500-3000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"GraphQL endpoint detected on {host}",
                    "supporting": ("No WAF" if has_no_waf else "") + (", hidden GraphQL endpoints in JS" if graphql_hidden else ""),
                },
                "exploitation_steps": [
                    "Test introspection: query { __schema { types { name fields { name } } } }",
                    "Test query depth limit with nested query",
                    "Test batch queries for rate limit bypass",
                    "Check for IDOR via node/relay global IDs",
                    "Test unauthorized mutations",
                ],
                "report_ready": False,
            })

        # CHAIN 11 — Internal IP + Admin Bypass
        internal_ips = [s for s in info["secrets"] if s.get("type") == "INTERNAL_IP"]
        has_403_admin = any("ADMIN_PANEL" in f and "403" in f for f in info["flags"])
        if internal_ips and has_403_admin:
            chains.append({
                "chain_id": "INTERNAL_IP_ADMIN_BYPASS",
                "name": "Internal IP + Admin Bypass",
                "severity": "HIGH",
                "bounty_estimate": "$500-2000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"Internal IP found: {internal_ips[0].get('value', '?')}",
                    "supporting": "Admin panel returns 403 — IP-based bypass possible",
                },
                "exploitation_steps": [
                    f"curl -H 'X-Forwarded-For: {internal_ips[0].get('value', '10.0.0.1')}' https://{host}/admin",
                    f"curl -H 'X-Real-IP: {internal_ips[0].get('value', '10.0.0.1')}' https://{host}/admin",
                    "Try X-Original-URL, X-Rewrite-URL header bypass",
                    "Test with different internal IP ranges (10.x, 172.16.x, 192.168.x)",
                ],
                "report_ready": False,
            })

    # CHAIN 6 — Subdomain Takeover (global, not per-host)
    for t in data["takeover_candidates"]:
        host = (t.get("subdomain") or t.get("host") or "").lower()
        if t.get("confirmed") or t.get("vulnerable"):
            chains.append({
                "chain_id": "SUBDOMAIN_TAKEOVER",
                "name": "Subdomain Takeover",
                "severity": "HIGH",
                "bounty_estimate": "$500-2000",
                "affected_hosts": [host],
                "evidence": {
                    "trigger": f"Dangling DNS for {host}",
                    "supporting": f"CNAME → {t.get('cname', '?')} ({t.get('service', t.get('provider', '?'))})",
                },
                "exploitation_steps": [
                    f"Claim the resource at {t.get('service', t.get('provider', '?'))}",
                    "Serve controlled content on the subdomain",
                    "Test for cookie scope issues on parent domain",
                    "Check for OAuth callback interception",
                ],
                "report_ready": True,
            })

    # CHAIN 12 — Shared Infrastructure Pivot (global)
    ip_to_hosts: dict[str, list[str]] = {}
    for host, info in host_idx.items():
        hd = info.get("host_data") or {}
        ip = hd.get("ip") or hd.get("a_record") or ""
        if ip:
            ip_to_hosts.setdefault(ip, []).append(host)

    for ip, hosts in ip_to_hosts.items():
        if len(hosts) < 2:
            continue
        # Check if any host has findings while another is higher value
        high_value = [h for h in hosts if any(kw in h for kw in ("admin", "api", "internal", "staging"))]
        has_vulns = [h for h in hosts if host_idx[h]["sensitive_paths"] or host_idx[h]["secrets"]]
        if high_value and has_vulns and set(high_value) != set(has_vulns):
            chains.append({
                "chain_id": "SHARED_INFRA_PIVOT",
                "name": "Shared Infrastructure Pivot",
                "severity": "MEDIUM",
                "bounty_estimate": "$500-2000",
                "affected_hosts": hosts,
                "evidence": {
                    "trigger": f"{len(hosts)} hosts share IP {ip}",
                    "supporting": f"High-value: {', '.join(high_value)}; Findings on: {', '.join(has_vulns)}",
                },
                "exploitation_steps": [
                    "Exploit vulnerability on lower-value service",
                    "Test for localhost/127.0.0.1 access to co-hosted services",
                    "Check for shared filesystem or session storage",
                    "Test SSRF to internal ports on same server",
                ],
                "report_ready": False,
            })

    # Deduplicate chains by chain_id + host
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in chains:
        key = f"{c['chain_id']}:{','.join(sorted(c['affected_hosts']))}"
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


# ---------------------------------------------------------------------------
# Immediate wins (Part 4)
# ---------------------------------------------------------------------------


def _find_immediate_wins(
    host_idx: dict[str, dict[str, Any]],
    data: dict[str, list],
) -> list[dict[str, Any]]:
    """Findings reportable NOW without Stage 4 scanning."""
    wins: list[dict[str, Any]] = []

    for host, info in host_idx.items():
        sp_paths = {sp.get("path", ""): sp for sp in info["sensitive_paths"]}

        # 1. Confirmed subdomain takeovers
        if info.get("takeover", {}).get("confirmed"):
            t = info["takeover"]
            wins.append({
                "type": "SUBDOMAIN_TAKEOVER",
                "host": host,
                "path": t.get("cname", ""),
                "severity": "HIGH",
                "bounty_estimate": "$500-2000",
                "evidence": f"CNAME → {t.get('cname', '?')} ({t.get('service', '?')})",
                "reproduction": f"dig {host} CNAME && curl -s https://{host}",
                "impact": "Attacker can serve content on this subdomain. Cookie theft, phishing, OAuth interception.",
                "remediation": "Remove dangling DNS record or reclaim the service.",
                "report_ready": True,
            })

        # 2. Exposed .git repos
        for path, sp in sp_paths.items():
            if ".git" in path.lower():
                wins.append({
                    "type": "EXPOSED_GIT_REPO",
                    "host": host,
                    "path": path,
                    "severity": "HIGH",
                    "bounty_estimate": "$500-1500",
                    "evidence": f"Accessible at https://{host}{path} (status {sp.get('status_code', '?')})",
                    "reproduction": f"curl -s https://{host}/.git/HEAD",
                    "impact": "Full source code recovery. May contain hardcoded credentials, internal endpoints, business logic.",
                    "remediation": "Block access to .git directory in web server configuration.",
                    "report_ready": True,
                })

        # 3. Exposed .env files
        for path, sp in sp_paths.items():
            if ".env" in path.lower() and "env" in sp.get("category", "").lower():
                wins.append({
                    "type": "EXPOSED_ENV_FILE",
                    "host": host,
                    "path": path,
                    "severity": "HIGH",
                    "bounty_estimate": "$500-1500",
                    "evidence": f"Accessible at https://{host}{path} (status {sp.get('status_code', '?')})",
                    "reproduction": f"curl -s https://{host}/.env",
                    "impact": "Database credentials, API keys, JWT secrets, encryption keys exposed.",
                    "remediation": "Block access to .env files. Rotate all exposed credentials immediately.",
                    "report_ready": True,
                })

        # 4. Leaked cloud credentials (HIGH confidence)
        for s in info["secrets"]:
            if s.get("confidence") == "HIGH" and any(k in s.get("type", "") for k in ("AWS", "GCP", "AZURE")):
                wins.append({
                    "type": "LEAKED_CLOUD_CREDENTIAL",
                    "host": host,
                    "path": s.get("source_file", "?"),
                    "severity": "CRITICAL",
                    "bounty_estimate": "$1000-5000",
                    "evidence": f"{s['type']} found in {s.get('source_file', '?').split('/')[-1]}",
                    "reproduction": f"curl -s {s.get('source_file', '')} | grep -i key",
                    "impact": "Cloud infrastructure access. S3 buckets, databases, compute instances may be compromised.",
                    "remediation": "Rotate the leaked credential immediately. Remove from client-side code.",
                    "report_ready": True,
                })

        # 5. Critical CORS with credentials
        for c in info["cors"]:
            if c.get("severity") == "CRITICAL" and c.get("credentials_allowed"):
                wins.append({
                    "type": "CRITICAL_CORS",
                    "host": host,
                    "path": c.get("url", ""),
                    "severity": "HIGH",
                    "bounty_estimate": "$500-2000",
                    "evidence": f"Origin {c.get('origin_tested', '?')} reflected with Access-Control-Allow-Credentials: true",
                    "reproduction": f"curl -H 'Origin: https://evil.com' -v {c.get('url', '')}",
                    "impact": "Attacker-controlled domain can make authenticated requests. Session token theft.",
                    "remediation": "Whitelist allowed origins. Never reflect arbitrary origins with credentials.",
                    "report_ready": True,
                })

        # 6. Exposed actuator/env
        for path, sp in sp_paths.items():
            if "actuator" in path.lower() and "env" in path.lower():
                wins.append({
                    "type": "EXPOSED_ACTUATOR",
                    "host": host,
                    "path": path,
                    "severity": "HIGH",
                    "bounty_estimate": "$500-1500",
                    "evidence": f"Spring Boot actuator at https://{host}{path} (status {sp.get('status_code', '?')})",
                    "reproduction": f"curl -s https://{host}/actuator/env",
                    "impact": "Environment variables, DB credentials, API keys exposed via actuator.",
                    "remediation": "Restrict actuator endpoints to internal network only.",
                    "report_ready": True,
                })

        # 7. Exposed phpinfo
        for path, sp in sp_paths.items():
            if "phpinfo" in path.lower():
                wins.append({
                    "type": "EXPOSED_PHPINFO",
                    "host": host,
                    "path": path,
                    "severity": "MEDIUM",
                    "bounty_estimate": "$200-500",
                    "evidence": f"phpinfo() at https://{host}{path} (status {sp.get('status_code', '?')})",
                    "reproduction": f"curl -s https://{host}{path}",
                    "impact": "PHP version, extensions, environment variables, server paths disclosed.",
                    "remediation": "Remove phpinfo files from production servers.",
                    "report_ready": True,
                })

        # 8. Backup files
        for path, sp in sp_paths.items():
            if any(ext in path.lower() for ext in (".sql", ".zip", ".tar.gz", ".bak")):
                wins.append({
                    "type": "EXPOSED_BACKUP",
                    "host": host,
                    "path": path,
                    "severity": "HIGH",
                    "bounty_estimate": "$500-1500",
                    "evidence": f"Backup file at https://{host}{path} (status {sp.get('status_code', '?')})",
                    "reproduction": f"curl -s -o backup https://{host}{path}",
                    "impact": "Database dumps, source code, or configuration backups may contain credentials.",
                    "remediation": "Remove backup files from web-accessible directories.",
                    "report_ready": True,
                })

    return wins


# ---------------------------------------------------------------------------
# Technology playbooks (Part 5)
# ---------------------------------------------------------------------------


_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "wordpress": {
        "name": "WordPress",
        "match_patterns": [re.compile(r"wordpress", re.I)],
        "checks": [
            {"path": "/wp-json/wp/v2/users", "purpose": "User enumeration"},
            {"path": "/xmlrpc.php", "purpose": "Brute force and SSRF via pingback"},
            {"path": "/wp-content/debug.log", "purpose": "Debug log with errors and paths"},
            {"path": "/wp-content/plugins/", "purpose": "Plugin directory listing for CVE matching"},
            {"tool": "nuclei", "args": "-tags wordpress", "purpose": "Known WordPress CVEs"},
            {"path": "/wp-config.php.bak", "purpose": "Backup config with DB credentials"},
        ],
    },
    "graphql": {
        "name": "GraphQL",
        "match_patterns": [re.compile(r"graphql", re.I)],
        "checks": [
            {"query": 'query { __schema { types { name fields { name } } } }', "purpose": "Introspection — map entire schema"},
            {"test": "Nested query depth limit", "purpose": "DoS via deep queries"},
            {"test": "Batch queries in single request", "purpose": "Rate limit bypass"},
            {"test": "IDOR via node/relay global IDs", "purpose": "Access control bypass"},
            {"test": "Unauthorized mutations", "purpose": "Write access without auth"},
            {"test": "Query cost analysis bypass", "purpose": "Resource exhaustion"},
        ],
    },
    "spring_boot": {
        "name": "Spring Boot Actuator",
        "match_patterns": [re.compile(r"spring|actuator", re.I)],
        "checks": [
            {"path": "/actuator/health", "purpose": "Confirm actuator is enabled"},
            {"path": "/actuator/env", "purpose": "Environment variables and secrets"},
            {"path": "/actuator/heapdump", "purpose": "Memory dump — may contain secrets"},
            {"path": "/actuator/mappings", "purpose": "Complete URL mapping"},
            {"path": "/actuator/beans", "purpose": "Application component listing"},
            {"path": "/actuator/trace", "purpose": "Recent HTTP requests with headers"},
        ],
    },
    "nodejs_express": {
        "name": "Node.js / Express",
        "match_patterns": [re.compile(r"node\.?js|express", re.I)],
        "checks": [
            {"test": "Prototype pollution via __proto__ in JSON", "purpose": "RCE or privilege escalation"},
            {"test": "constructor.prototype in body params", "purpose": "Prototype pollution variant"},
            {"test": "Path traversal with ../ encoding variants", "purpose": "File read"},
            {"test": "SSRF via URL-accepting parameters", "purpose": "Internal service access"},
        ],
    },
    "react_angular_spa": {
        "name": "React / Angular SPA",
        "match_patterns": [re.compile(r"react|angular|vue\.?js", re.I)],
        "checks": [
            {"test": "JS bundle analysis for API keys and endpoints", "purpose": "All API logic is client-side"},
            {"test": "Check .js.map source map files", "purpose": "Original source code recovery"},
            {"test": "Hidden routes from JS router config", "purpose": "Admin panels, debug pages"},
            {"test": "Environment variables in JS bundles", "purpose": "Leaked build-time secrets"},
        ],
    },
}


def _get_playbooks(data: dict[str, list]) -> list[dict[str, Any]]:
    """Return playbooks for technologies detected in workspace."""
    # Collect all technology strings
    all_techs: set[str] = set()
    for t in data["technologies"]:
        tech = t.get("technology", "") if isinstance(t, dict) else str(t)
        all_techs.add(tech)
    for h in data["live_hosts"]:
        for t in h.get("technologies", []):
            all_techs.add(t)
    # Also check flags for GraphQL, actuator, etc.
    for f in data["flags"]:
        for flag in f.get("flags", []):
            if "GRAPHQL" in flag:
                all_techs.add("GraphQL")
            if "SPRING_ACTUATOR" in flag:
                all_techs.add("Spring Boot Actuator")

    tech_str = " ".join(all_techs)
    matched: list[dict[str, Any]] = []
    for key, playbook in _PLAYBOOKS.items():
        if any(p.search(tech_str) for p in playbook["match_patterns"]):
            matched.append({
                "technology": playbook["name"],
                "checks": playbook["checks"],
            })

    return matched


# ---------------------------------------------------------------------------
# Cross-stage correlations (Part 6)
# ---------------------------------------------------------------------------


def _detect_correlations(
    host_idx: dict[str, dict[str, Any]],
    data: dict[str, list],
) -> list[dict[str, Any]]:
    """Detect cross-stage intelligence patterns."""
    correlations: list[dict[str, Any]] = []

    # HIDDEN_ENDPOINT
    for host, info in host_idx.items():
        if info["hidden_endpoints"]:
            eps = [ep.get("path", "?") for ep in info["hidden_endpoints"][:10]]
            correlations.append({
                "type": "HIDDEN_ENDPOINT",
                "description": f"{len(info['hidden_endpoints'])} endpoints in JS but not in crawl results on {host}",
                "significance": "Endpoints exist but are not linked publicly — likely admin/internal",
                "affected_hosts": [host],
                "priority": "HIGH",
                "data": {"endpoints": eps},
            })

    # SHARED_INFRASTRUCTURE
    ip_to_hosts: dict[str, list[str]] = {}
    for host, info in host_idx.items():
        hd = info.get("host_data") or {}
        ip = hd.get("ip") or hd.get("a_record") or ""
        if ip:
            ip_to_hosts.setdefault(ip, []).append(host)
    for ip, hosts in ip_to_hosts.items():
        if len(hosts) >= 2:
            correlations.append({
                "type": "SHARED_INFRASTRUCTURE",
                "description": f"{len(hosts)} hosts share IP {ip}",
                "significance": "Shared server — vulnerability on one may affect others",
                "affected_hosts": hosts,
                "priority": "MEDIUM",
                "data": {"ip": ip, "host_count": len(hosts)},
            })

    # LEAKED_CREDENTIAL
    cred_by_type: dict[str, list[dict]] = {}
    for host, info in host_idx.items():
        for s in info["secrets"]:
            if s.get("confidence") in ("HIGH", "MEDIUM"):
                stype = s.get("type", "UNKNOWN")
                cred_by_type.setdefault(stype, []).append({
                    "host": host, "file": s.get("source_file", "?").split("/")[-1],
                    "confidence": s.get("confidence"),
                })
    for stype, entries in cred_by_type.items():
        hosts = list({e["host"] for e in entries})
        correlations.append({
            "type": "LEAKED_CREDENTIAL",
            "description": f"{stype}: {len(entries)} instance(s) across {len(hosts)} host(s)",
            "significance": "Credential leak — verify validity and scope of access",
            "affected_hosts": hosts,
            "priority": "CRITICAL" if any(e["confidence"] == "HIGH" for e in entries) else "HIGH",
            "data": {"credential_type": stype, "instances": entries},
        })

    # TECH_MISMATCH
    tech_counter: Counter[str] = Counter()
    host_techs: dict[str, list[str]] = {}
    for host, info in host_idx.items():
        techs = info["technologies"]
        host_techs[host] = techs
        for t in techs:
            tech_counter[t] += 1
    if tech_counter:
        majority = {t for t, c in tech_counter.most_common(3)}
        for host, techs in host_techs.items():
            if techs and not any(t in majority for t in techs):
                correlations.append({
                    "type": "TECH_MISMATCH",
                    "description": f"{host} runs {', '.join(techs[:3])} while majority use {', '.join(majority)}",
                    "significance": "Different tech stack = different team = potentially different security posture",
                    "affected_hosts": [host],
                    "priority": "LOW",
                    "data": {"host_tech": techs[:5], "majority_tech": list(majority)},
                })

    # PARAMETER_HOTSPOT
    param_counter: Counter[str] = Counter()
    param_endpoints: dict[str, list[str]] = {}
    for p in data["parameters"]:
        for param in p.get("params", []):
            name = param.get("name", "")
            freq = param.get("frequency", 1)
            if freq >= 3 or param.get("high_frequency"):
                param_counter[name] += freq
                param_endpoints.setdefault(name, []).append(p.get("path", "?"))
    for name, count in param_counter.most_common(10):
        if count >= 3:
            eps = param_endpoints.get(name, [])[:5]
            correlations.append({
                "type": "PARAMETER_HOTSPOT",
                "description": f"'{name}' parameter appears on {count} endpoints",
                "significance": "Framework-level parameter — if injectable, affects all endpoints",
                "affected_hosts": list({_host_from_url(e) for e in eps if "://" in e} or {"(multiple)"}),
                "priority": "HIGH",
                "data": {"parameter": name, "endpoint_count": count, "sample_endpoints": eps},
            })

    # ROBOTS_HIDDEN
    crawled_paths: set[str] = set()
    for u in data["crawled_urls"]:
        url = u.get("url", "") if isinstance(u, dict) else str(u)
        try:
            crawled_paths.add(urlparse(url).path)
        except Exception:
            pass
    for rs in data["robots_sitemap"]:
        if rs.get("type") == "disallowed":
            path = rs.get("value", "")
            if path and path not in crawled_paths:
                host = _host_from_url(rs.get("host", ""))
                correlations.append({
                    "type": "ROBOTS_HIDDEN",
                    "description": f"robots.txt disallows '{path}' — not in crawl results",
                    "significance": "Explicitly hidden path — may contain sensitive content",
                    "affected_hosts": [host] if host else [],
                    "priority": "MEDIUM",
                    "data": {"path": path, "host": host},
                })

    return correlations


# ---------------------------------------------------------------------------
# Stats computation
# ---------------------------------------------------------------------------


def _compute_stats(data: dict[str, list]) -> dict[str, Any]:
    """Compute aggregate statistics."""
    all_techs: set[str] = set()
    for h in data["live_hosts"]:
        for t in h.get("technologies", []):
            all_techs.add(t)

    secrets_by_conf: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in data["js_secrets"]:
        conf = s.get("confidence", "LOW")
        secrets_by_conf[conf] = secrets_by_conf.get(conf, 0) + 1

    cors_by_sev: dict[str, int] = {}
    for c in data["cors_results"]:
        sev = c.get("severity", "INFO")
        cors_by_sev[sev] = cors_by_sev.get(sev, 0) + 1

    total_params = sum(
        len(p.get("params", [])) for p in data["parameters"]
    )

    return {
        "total_subdomains": len(data["subdomains"]),
        "live_hosts": len(data["live_hosts"]),
        "unique_technologies": sorted(all_techs),
        "total_urls": len(data["crawled_urls"]),
        "total_parameters": total_params,
        "js_files": len(data["js_files"]),
        "secrets_found": len(data["js_secrets"]),
        "secrets_by_confidence": secrets_by_conf,
        "sensitive_paths": len(data["sensitive_paths"]),
        "takeover_candidates": len(data["takeover_candidates"]),
        "takeover_confirmed": len(data["takeover_confirmed"]),
        "cors_issues": len(data["cors_results"]),
        "cors_by_severity": cors_by_sev,
        "hidden_endpoints": len(data["hidden_endpoints"]),
        "api_endpoints": len(data["api_endpoints"]),
        "dns_records": len(data["dns_records"]),
    }


# ---------------------------------------------------------------------------
# Suggested test classes (derived from chains + playbooks)
# ---------------------------------------------------------------------------


def _suggest_test_classes(
    chains: list[dict],
    playbooks: list[dict],
) -> list[str]:
    """Derive test classes from matched attack chains and playbooks."""
    classes: set[str] = set()

    chain_to_class = {
        "SOURCE_CODE_THEFT": "information_disclosure",
        "CLOUD_CREDENTIAL_ABUSE": "cloud_security",
        "ACCOUNT_TAKEOVER_CORS": "cors",
        "API_ABUSE_VIA_DOCS": "api_security",
        "ENV_VARIABLE_LEAK": "information_disclosure",
        "SUBDOMAIN_TAKEOVER": "subdomain_takeover",
        "UNAUTH_API_INJECTION": "injection",
        "DEBUG_INFO_DISCLOSURE": "information_disclosure",
        "WORDPRESS_COMPROMISE": "wordpress",
        "GRAPHQL_EXPLOITATION": "graphql",
        "INTERNAL_IP_ADMIN_BYPASS": "access_control",
        "SHARED_INFRA_PIVOT": "ssrf",
    }
    for chain in chains:
        cls = chain_to_class.get(chain.get("chain_id", ""))
        if cls:
            classes.add(cls)

    playbook_to_class = {
        "WordPress": "wordpress",
        "GraphQL": "graphql",
        "Spring Boot Actuator": "spring_actuator",
        "Node.js / Express": "prototype_pollution",
        "React / Angular SPA": "client_side",
    }
    for pb in playbooks:
        cls = playbook_to_class.get(pb.get("technology", ""))
        if cls:
            classes.add(cls)

    # Always include generic classes
    classes.add("nuclei_general")

    return sorted(classes)


# ---------------------------------------------------------------------------
# Technology distribution
# ---------------------------------------------------------------------------


def _tech_distribution(data: dict[str, list]) -> dict[str, int]:
    """Group technologies with host counts."""
    counter: Counter[str] = Counter()
    for h in data["live_hosts"]:
        for t in h.get("technologies", []):
            counter[t] += 1
    return dict(counter.most_common(30))


def _flags_summary(data: dict[str, list]) -> dict[str, int]:
    """Count per flag type."""
    counter: Counter[str] = Counter()
    for f in data["flags"]:
        for flag in f.get("flags", []):
            key = flag.split(":")[0]
            counter[key] += 1
    return dict(counter.most_common(20))


# ===================================================================
# PUBLIC API — Part 1 + 7: get_attack_surface
# ===================================================================


async def get_attack_surface(workspace_id: str) -> dict[str, Any]:
    """Aggregate all Stage 2 data, score targets, detect chains, surface wins."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    # Update state
    await workspace.update_metadata(
        workspace_id, state=WorkspaceState.ANALYZING, current_stage=3,
    )
    await workspace.add_stage_history(workspace_id, 3, "running")

    # Load everything
    data = await _load_all_data(workspace_id)

    # Check we have some data
    if not data["live_hosts"]:
        await workspace.add_stage_history(workspace_id, 3, "completed")
        return {
            "status": "success",
            "workspace_id": workspace_id,
            "target": meta.target,
            "target_type": meta.target_type.value if meta.target_type else "unknown",
            "message": "No live hosts found. Run bughound_discover first.",
            "stats": _compute_stats(data),
            "high_interest_targets": [],
            "attack_chains": [],
            "immediate_wins": [],
            "correlations": [],
            "technology_playbooks": [],
            "technology_distribution": {},
            "flags_summary": {},
            "suggested_test_classes": [],
            "next_step": "Run bughound_discover first to collect attack surface data.",
        }

    # Build per-host index
    host_idx = _build_host_index(data)

    # Score all hosts (Part 2)
    scored = [_score_host(h, info) for h, info in host_idx.items()]
    scored.sort(key=lambda x: x["score"], reverse=True)
    high_interest = scored[:20]

    # Attack chains (Part 3)
    chains = _detect_attack_chains(host_idx, data)

    # Immediate wins (Part 4)
    wins = _find_immediate_wins(host_idx, data)

    # Playbooks (Part 5)
    playbooks = _get_playbooks(data)

    # Correlations (Part 6)
    correlations = _detect_correlations(host_idx, data)

    # Stats + summaries
    stats = _compute_stats(data)
    tech_dist = _tech_distribution(data)
    flags_sum = _flags_summary(data)
    test_classes = _suggest_test_classes(chains, playbooks)

    # Mark complete
    await workspace.add_stage_history(workspace_id, 3, "completed")

    return {
        "status": "success",
        "workspace_id": workspace_id,
        "target": meta.target,
        "target_type": meta.target_type.value if meta.target_type else "unknown",
        "stats": stats,
        "high_interest_targets": high_interest,
        "attack_chains": chains,
        "immediate_wins": wins,
        "correlations": correlations,
        "technology_playbooks": playbooks,
        "technology_distribution": tech_dist,
        "flags_summary": flags_sum,
        "suggested_test_classes": test_classes,
        "next_step": (
            "Review this analysis. For immediate wins, use bughound_generate_report "
            "directly. For deeper testing, use bughound_submit_scan_plan to define "
            "your strategy."
        ),
    }


# ===================================================================
# PUBLIC API — Part 8: submit_scan_plan
# ===================================================================


async def submit_scan_plan(
    workspace_id: str,
    scan_plan: dict[str, Any],
) -> dict[str, Any]:
    """Validate and store scan plan for Stage 4."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    errors: list[str] = []

    # Structure validation
    targets = scan_plan.get("targets")
    if not targets or not isinstance(targets, list):
        return _error("invalid_input", "scan_plan must have a non-empty 'targets' array.")

    global_settings = scan_plan.get("global_settings", {})
    if not isinstance(global_settings, dict):
        global_settings = {}

    # Validate global settings
    max_conc = global_settings.get("max_concurrent", 3)
    if isinstance(max_conc, int) and max_conc > 10:
        errors.append(f"max_concurrent={max_conc} exceeds limit of 10")

    timeout_pt = global_settings.get("timeout_per_target", 300)
    if isinstance(timeout_pt, int) and timeout_pt > 600:
        errors.append(f"timeout_per_target={timeout_pt} exceeds limit of 600")

    valid_sev = {"info", "low", "medium", "high", "critical"}
    nuc_sev = global_settings.get("nuclei_severity")
    if nuc_sev and isinstance(nuc_sev, list):
        invalid = set(s.lower() for s in nuc_sev) - valid_sev
        if invalid:
            errors.append(f"Invalid nuclei_severity: {', '.join(invalid)}")

    # Per-target validation
    all_tools: set[str] = set()
    out_of_scope: list[str] = []

    for i, t in enumerate(targets):
        if not isinstance(t, dict):
            errors.append(f"targets[{i}] is not an object")
            continue

        host = t.get("host")
        if not host:
            errors.append(f"targets[{i}] missing required 'host' field")
            continue

        # Scope check
        in_scope = await workspace.is_in_scope(workspace_id, host)
        if not in_scope:
            out_of_scope.append(host)

        # Collect tools
        for tool_name in t.get("tools", []):
            all_tools.add(tool_name)

        # Priority check
        priority = t.get("priority")
        if priority is not None and (not isinstance(priority, int) or priority < 1):
            errors.append(f"targets[{i}] ({host}): priority must be int >= 1")

        # Test classes
        tc = t.get("test_classes")
        if tc is not None and (not isinstance(tc, list) or not tc):
            errors.append(f"targets[{i}] ({host}): test_classes must be a non-empty list")

    if out_of_scope:
        errors.append(f"Out of scope: {', '.join(out_of_scope)}")

    if errors:
        return {
            "status": "rejected",
            "message": "Scan plan validation failed.",
            "rejected_reasons": errors,
        }

    # Tool availability check (warn, don't reject)
    tools_available: list[str] = []
    tools_missing: list[str] = []
    for tool_name in sorted(all_tools):
        if tool_runner.is_available(tool_name):
            tools_available.append(tool_name)
        else:
            tools_missing.append(tool_name)

    # Write scan_plan.json directly (single object, not DataWrapper list)
    plan_path = workspace.workspace_dir(workspace_id) / "scan_plan.json"
    async with aiofiles.open(plan_path, "w") as f:
        await f.write(json.dumps(scan_plan, indent=2))

    # Update stage history
    await workspace.add_stage_history(workspace_id, 3, "completed")

    # Count test classes
    test_classes_total = sum(len(t.get("test_classes", [])) for t in targets)

    return {
        "status": "approved",
        "message": f"Scan plan approved. {len(targets)} targets, {test_classes_total} test classes.",
        "targets_count": len(targets),
        "test_classes_total": test_classes_total,
        "tools_required": sorted(all_tools),
        "tools_available": tools_available,
        "tools_missing": tools_missing,
        "next_step": "Call bughound_execute_tests to run the scan plan.",
    }


# ===================================================================
# PUBLIC API — Part 9: enrich_target
# ===================================================================


async def enrich_target(workspace_id: str, host: str) -> dict[str, Any]:
    """Complete intelligence dossier on a single host."""
    meta = await workspace.get_workspace(workspace_id)
    if meta is None:
        return _error("not_found", f"Workspace '{workspace_id}' not found.")

    data = await _load_all_data(workspace_id)
    host_idx = _build_host_index(data)

    host_lower = host.strip().lower()
    # Try exact match, then partial
    info = host_idx.get(host_lower)
    if info is None:
        # Try matching by URL
        for h, i in host_idx.items():
            if host_lower in h or h in host_lower:
                info = i
                host_lower = h
                break

    if info is None:
        return _error("not_found", f"Host '{host}' not found in workspace data.")

    # Score this host
    scored = _score_host(host_lower, info)

    # Get attack chains for this host
    chains = _detect_attack_chains(host_idx, data)
    host_chains = [c for c in chains if host_lower in c.get("affected_hosts", [])]

    # DNS records
    dns_for_host: list[dict] = []
    for rec in data["dns_records"]:
        if isinstance(rec, dict) and rec.get("domain", "").lower() == host_lower:
            dns_for_host.append(rec)

    hd = info.get("host_data") or {}

    return {
        "status": "success",
        "host": host_lower,
        "workspace_id": workspace_id,
        "fingerprint": {
            "url": hd.get("url"),
            "status_code": hd.get("status_code"),
            "title": hd.get("title"),
            "web_server": hd.get("web_server"),
            "ip": hd.get("ip") or hd.get("a_record"),
            "cdn": hd.get("cdn"),
        },
        "score": scored["score"],
        "risk_level": scored["risk_level"],
        "reasons": scored["reasons"],
        "flags": info["flags"],
        "technologies": info["technologies"],
        "waf": info["waf"],
        "dns_records": dns_for_host,
        "urls": [u.get("url", "") if isinstance(u, dict) else str(u) for u in info["urls"][:50]],
        "urls_total": len(info["urls"]),
        "parameters": info["parameters"],
        "secrets": info["secrets"],
        "sensitive_paths": info["sensitive_paths"],
        "cors_results": info["cors"],
        "hidden_endpoints": [{"method": ep.get("method", "GET"), "path": ep.get("path", "?")} for ep in info["hidden_endpoints"]],
        "api_endpoints": [{"method": ep.get("method", "GET"), "path": ep.get("path", "?")} for ep in info["api_endpoints"]],
        "attack_chains": host_chains,
        "takeover": info.get("takeover"),
    }
