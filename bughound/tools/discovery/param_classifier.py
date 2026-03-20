"""Parameter classification engine — pattern matching + live reflection probes.

Phase 1: gf-style pattern matching classifies params by name.
Phase 2: lightweight HTTP probes detect reflection (XSS), SQL errors (SQLi),
          and path traversal indicators (LFI) regardless of param names.
"""

from __future__ import annotations

import asyncio
import fnmatch
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Vulnerability parameter patterns
# ---------------------------------------------------------------------------

SQLI_PARAMS: dict[str, Any] = {
    "exact": {
        "id", "select", "report", "query", "table", "column", "where", "order",
        "sort", "group", "by", "having", "limit", "offset", "fetch", "row",
        "union", "insert", "update", "delete", "search", "filter", "results",
        "num", "count", "page", "field", "view", "process", "show", "col",
        "cat", "category", "item", "product", "article", "key", "idx",
    },
    "patterns": ["*_id", "*_no", "*_num", "*_number", "*_key", "*_pk", "*_fk",
                  "*id", "*num", "*no"],
}

XSS_PARAMS: dict[str, Any] = {
    "exact": {
        "q", "search", "query", "keyword", "name", "input", "text", "value",
        "comment", "message", "body", "content", "title", "subject",
        "description", "feedback", "review", "bio", "note", "label",
        "placeholder", "data", "payload", "html", "xml", "callback", "jsonp",
        "func", "function", "handler", "error", "err", "msg", "alert",
        "redirect_uri", "return_url", "next",
        "key", "term", "s", "w", "p", "txt", "val",
    },
    "patterns": [
        "*_name", "*_text", "*_value", "*_msg", "*_message", "*_content",
        "*_title", "*_desc", "*name", "*search*", "*key*",
    ],
}

SSRF_PARAMS: dict[str, Any] = {
    "exact": {
        "url", "uri", "path", "src", "href", "redirect", "proxy", "fetch",
        "load", "target", "dest", "destination", "domain", "host", "site",
        "link", "source", "feed", "to", "out", "img", "image", "avatar",
        "icon", "logo", "preview", "callback", "webhook", "ping", "request",
        "api_url", "endpoint", "resource", "download", "file_url", "pdf_url",
        "image_url",
    },
    "patterns": [
        "*_url", "*_uri", "*_link", "*_src", "*_path", "*_endpoint", "*_host",
    ],
}

REDIRECT_PARAMS: dict[str, Any] = {
    "exact": {
        "next", "redirect", "redirect_to", "redirect_url", "return",
        "return_to", "return_url", "redir", "rurl", "goto", "go", "url",
        "link", "target", "dest", "destination", "continue", "forward",
        "forward_to", "redir_url", "checkout_url", "success_url",
        "failure_url", "callback", "callback_url", "login_url", "logout_url",
        "back", "back_url", "ref", "referer", "referrer",
    },
    "patterns": ["*_redirect", "*_return", "*_url"],
}

LFI_PARAMS: dict[str, Any] = {
    "exact": {
        "file", "path", "include", "page", "template", "doc", "folder",
        "root", "dir", "document", "pg", "style", "pdf", "display", "read",
        "category", "open", "view", "content", "layout", "mod", "conf",
        "lang", "locale", "theme", "skin", "type",
    },
    "patterns": [
        "*_file", "*_path", "*_dir", "*_page", "*_template", "*_include",
    ],
}

IDOR_PARAMS: dict[str, Any] = {
    "exact": {
        "id", "uid", "user_id", "account", "account_id", "profile",
        "profile_id", "order_id", "invoice_id", "cart_id", "doc_id",
        "file_id", "report_id", "message_id", "thread_id", "comment_id",
        "post_id", "project_id", "team_id", "org_id", "workspace_id",
        "customer_id", "client_id", "member_id", "employee_id", "ticket_id",
        "transaction_id", "payment_id", "subscription_id", "api_key", "token",
        "session", "no", "number", "pid", "ref",
    },
    "patterns": ["*_id", "*_uuid", "*_ref", "*_no", "*_number", "*_key",
                  "*id", "*num"],
}

RCE_PARAMS: dict[str, Any] = {
    "exact": {
        "cmd", "exec", "command", "execute", "run", "ping", "query", "jump",
        "code", "reg", "do", "func", "function", "arg", "option", "load",
        "process", "step", "read", "feature", "exe", "module", "payload",
        "daemon", "upload", "log", "ip", "cli", "eval",
    },
    "patterns": ["*_cmd", "*_exec", "*_command"],
}

SSTI_PARAMS: dict[str, Any] = {
    "exact": {
        "template", "preview", "page", "id", "view", "activity", "name",
        "content", "redirect", "lang", "email", "subject", "body", "message",
        "render", "layout",
    },
    "patterns": ["*_template", "*_view", "*_render"],
}

DESERIALIZATION_PARAMS: dict[str, Any] = {
    "exact": {
        "data", "object", "payload", "serialized", "state", "viewstate",
        "__viewstate", "__viewstategenerator", "__eventvalidation",
        "session", "token", "cache", "config", "preferences", "settings",
        "profile", "userdata", "cart", "basket", "checkout",
    },
    "patterns": [
        "*_data", "*_object", "*_state", "*_cache", "*_serialized",
        "*_payload", "*_config",
    ],
}

MASS_ASSIGNMENT_PARAMS: dict[str, Any] = {
    "exact": {
        "role", "is_admin", "isadmin", "admin", "is_staff", "is_superuser",
        "privilege", "permissions", "user_type", "usertype", "access_level",
        "group", "groups", "verified", "email_verified", "active", "approved",
        "balance", "credits", "price", "discount", "status", "level",
        "plan", "subscription", "tier",
    },
    "patterns": [
        "*_role", "*_admin", "*_privilege", "*_permission", "*_level",
        "*_status", "*_type",
    ],
}

_ALL_VULN_TYPES = {
    "sqli": SQLI_PARAMS,
    "xss": XSS_PARAMS,
    "ssrf": SSRF_PARAMS,
    "redirect": REDIRECT_PARAMS,
    "lfi": LFI_PARAMS,
    "idor": IDOR_PARAMS,
    "rce": RCE_PARAMS,
    "ssti": SSTI_PARAMS,
    "deserialization": DESERIALIZATION_PARAMS,
    "mass_assignment": MASS_ASSIGNMENT_PARAMS,
}


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------


def _matches_vuln_type(param_name: str, vuln_def: dict[str, Any]) -> bool:
    """Check if a parameter name matches a vulnerability pattern set."""
    name_lower = param_name.strip().lower()
    if name_lower in vuln_def["exact"]:
        return True
    for pat in vuln_def["patterns"]:
        if fnmatch.fnmatch(name_lower, pat):
            return True
    return False


def _classify_one_param(param_name: str) -> list[str]:
    """Return all vulnerability types this parameter matches."""
    return [
        vtype for vtype, vdef in _ALL_VULN_TYPES.items()
        if _matches_vuln_type(param_name, vdef)
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_parameters(
    urls_data: list[Any],
    parameters_data: list[Any],
    hidden_endpoints: list[Any] | None = None,
    forms_data: list[Any] | None = None,
) -> dict[str, Any]:
    """Classify all discovered parameters by vulnerability type.

    urls_data: items from urls/crawled.json
    parameters_data: items from urls/parameters.json
    hidden_endpoints: items from endpoints/hidden_endpoints.json
    forms_data: items from urls/forms.json

    Returns dict with per-vuln-type candidate lists + stats.
    """
    # Collect all (url, param_name, sample_value, method) tuples
    param_entries: list[tuple[str, str, str, str]] = []

    # From crawled URLs — extract query params
    _paramless_injectable: set[str] = set()  # track parameterless URLs for inference
    for item in urls_data:
        url = item.get("url", item) if isinstance(item, dict) else str(item)
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if qs:
            for pname, pvals in qs.items():
                param_entries.append((url, pname, pvals[0] if pvals else "", "GET"))
        else:
            # No query params — check if URL path suggests injectable endpoint
            path_lower = parsed.path.lower()
            _INJECTABLE_PATH_KEYWORDS = (
                "/api/", "/debug", "/admin", "/search", "/query", "/filter",
                "/graphql", "/rest/", "/v1/", "/v2/", "/v3/",
                "/products", "/users", "/orders", "/items", "/blog",
            )
            if any(kw in path_lower for kw in _INJECTABLE_PATH_KEYWORDS):
                _paramless_injectable.add(url)

    # Infer common params for parameterless injectable endpoints
    _COMMON_TEST_PARAMS = [
        ("search", "test"), ("q", "test"), ("query", "test"),
        ("id", "1"), ("filter", "test"), ("key", "test"),
        ("page", "1"), ("limit", "10"), ("offset", "0"),
        ("sort", "id"), ("order", "asc"), ("category", "1"),
    ]
    for url in _paramless_injectable:
        for pname, sample in _COMMON_TEST_PARAMS:
            param_entries.append((url, pname, sample, "GET"))

    # From parameters.json — structured param data
    for item in parameters_data:
        if not isinstance(item, dict):
            continue
        base_url = item.get("url", item.get("path", ""))
        method = item.get("method", "GET")
        for p in item.get("params", []):
            if isinstance(p, dict):
                param_entries.append((
                    base_url,
                    p.get("name", ""),
                    p.get("value", ""),
                    method,
                ))
            elif isinstance(p, str):
                param_entries.append((base_url, p, "", method))

    # From hidden endpoints
    for ep in (hidden_endpoints or []):
        if not isinstance(ep, dict):
            continue
        ep_path = ep.get("path", "")
        ep_method = ep.get("method", "GET")
        parsed = urlparse(ep_path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for pname, pvals in qs.items():
            param_entries.append((
                ep_path, pname, pvals[0] if pvals else "",
                ep_method,
            ))
        # Also extract structured params (e.g. from OpenAPI spec body params)
        for p in ep.get("params", []):
            if isinstance(p, dict):
                param_entries.append((
                    ep_path, p.get("name", ""), p.get("value", ""),
                    ep_method,
                ))
            elif isinstance(p, str):
                param_entries.append((ep_path, p, "", ep_method))

    # From forms — extract input names with form context
    file_upload_candidates: list[dict[str, Any]] = []
    post_endpoints: list[dict[str, Any]] = []
    _seen_uploads: set[str] = set()
    _seen_posts: set[str] = set()

    for form in (forms_data or []):
        if not isinstance(form, dict):
            continue
        page_url = form.get("page_url", "")
        form_method = form.get("method", "GET")
        classification = form.get("classification", "")
        testable = form.get("testable", {})
        action_url = testable.get("url", page_url)

        # Track POST endpoints
        if form_method == "POST" and action_url not in _seen_posts:
            _seen_posts.add(action_url)
            post_endpoints.append({
                "url": action_url,
                "form_type": classification,
                "page_url": page_url,
                "params": [inp.get("name", "") for inp in form.get("inputs", []) if inp.get("name")],
            })

        for inp in form.get("inputs", []):
            inp_name = inp.get("name", "")
            inp_type = inp.get("type", "text")
            if not inp_name:
                continue

            # File upload detection
            if inp_type == "file":
                dedup = f"{action_url}:{inp_name}"
                if dedup not in _seen_uploads:
                    _seen_uploads.add(dedup)
                    file_upload_candidates.append({
                        "url": action_url,
                        "param": inp_name,
                        "form_type": classification,
                        "page_url": page_url,
                        "method": form_method,
                    })
                continue

            param_entries.append((action_url, inp_name, "", form_method))

            # Form-context-aware classification boost
            if classification == "login_form" and inp_name.lower() in (
                "username", "user", "email", "login", "password", "passwd",
            ):
                param_entries.append((action_url, inp_name, "", "POST"))

    # Classify
    candidates: dict[str, list[dict[str, Any]]] = {
        f"{vtype}_candidates": [] for vtype in _ALL_VULN_TYPES
    }
    seen: dict[str, set[str]] = {
        f"{vtype}_candidates": set() for vtype in _ALL_VULN_TYPES
    }

    # Track per-param vuln type count for high_value detection
    param_vuln_count: dict[str, set[str]] = {}  # param_name -> set of vuln types

    urls_with_params = set()
    unique_params = set()

    for url, param_name, sample_value, method in param_entries:
        if not param_name:
            continue
        param_lower = param_name.strip().lower()
        unique_params.add(param_lower)
        urls_with_params.add(url)

        matched_types = _classify_one_param(param_lower)

        # Skip framework/internal params that are never user-injectable
        _SKIP_PARAMS = {
            "__viewstate", "__viewstategenerator", "__eventvalidation",
            "__eventtarget", "__eventargument", "__lastfocus",
            "__requestverificationtoken", "__previouspage",
            "csrf_token", "csrfmiddlewaretoken", "_token", "_csrf",
            "authenticity_token",
        }
        if param_lower in _SKIP_PARAMS:
            # These are anti-CSRF/framework tokens — classify as deserialization
            # only if they match, otherwise skip entirely
            if matched_types:
                param_vuln_count.setdefault(param_lower, set()).update(matched_types)
            continue

        # Ensure ALL user-input params get tested for core injection classes.
        core_types = {"xss", "sqli", "lfi", "ssti", "idor"}
        if matched_types:
            for ct in core_types:
                if ct not in matched_types:
                    matched_types.append(ct)
        else:
            matched_types = list(core_types)

        param_vuln_count.setdefault(param_lower, set()).update(matched_types)

        for vtype in matched_types:
            key = f"{vtype}_candidates"
            dedup_key = f"{url}:{param_lower}"
            if dedup_key not in seen[key]:
                seen[key].add(dedup_key)
                candidates[key].append({
                    "url": url,
                    "param": param_name,
                    "sample_value": sample_value,
                    "method": method,
                })

    # High-value params: match 5+ vuln types (at least 1 beyond the 4 core types)
    high_value = sorted([
        {"param": p, "vuln_types": sorted(vtypes), "match_count": len(vtypes)}
        for p, vtypes in param_vuln_count.items()
        if len(vtypes) >= 5
    ], key=lambda x: x["match_count"], reverse=True)

    # Stats
    stats = {
        "total_urls_with_params": len(urls_with_params),
        "unique_params_matched": sum(
            1 for p in unique_params if _classify_one_param(p)
        ),
        "total_unique_params": len(unique_params),
        "forms_analyzed": len(forms_data or []),
        "file_upload_forms": len(file_upload_candidates),
        "post_endpoints": len(post_endpoints),
    }
    for vtype in _ALL_VULN_TYPES:
        stats[f"{vtype}_count"] = len(candidates[f"{vtype}_candidates"])

    # Path-based IDOR candidates: URLs with numeric or UUID-like path segments
    path_idor_candidates: list[dict[str, Any]] = []
    _uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I,
    )
    _hex_re = re.compile(r"^[0-9a-f]{8,}$", re.I)
    _seen_path_idors: set[str] = set()
    for item in urls_data:
        url = item.get("url", item) if isinstance(item, dict) else str(item)
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        for part in parts:
            is_numeric = part.isdigit()
            is_uuid = bool(_uuid_re.match(part))
            is_hex = bool(_hex_re.match(part)) and not is_uuid
            if is_numeric or is_uuid or is_hex:
                dedup_key = f"{url}:{part}"
                if dedup_key not in _seen_path_idors:
                    _seen_path_idors.add(dedup_key)
                    seg_type = "numeric" if is_numeric else ("uuid" if is_uuid else "hex")
                    path_idor_candidates.append({
                        "url": url,
                        "param": "path_segment",
                        "sample_value": part,
                        "method": "GET",
                        "segment": part,
                        "segment_type": seg_type,
                    })

    # Also generate path IDOR candidates for API-style RESTful endpoints
    # /api/orders/ → test /api/orders/1, /api/orders/2
    _REST_PATTERNS = re.compile(
        r"/api/(?:v\d+/)?(\w+)/?$",  # matches /api/orders/, /api/v1/users/
        re.I,
    )
    for item in urls_data:
        url = item.get("url", item) if isinstance(item, dict) else str(item)
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        match = _REST_PATTERNS.search(parsed.path)
        if match:
            resource = match.group(1)
            # Skip common non-resource paths
            if resource.lower() in ("auth", "login", "register", "config", "health", "docs", "graphql"):
                continue
            # Generate test URL with numeric ID
            test_url = url.rstrip("/") + "/1"
            dedup_key = f"{test_url}:path_segment"
            if dedup_key not in _seen_path_idors:
                _seen_path_idors.add(dedup_key)
                path_idor_candidates.append({
                    "url": test_url,
                    "param": "path_segment",
                    "sample_value": "1",
                    "method": "GET",
                    "segment": "1",
                    "segment_type": "inferred_rest",
                })

    stats["path_idor_urls"] = len(path_idor_candidates)
    stats["deserialization_count"] = len(candidates.get("deserialization_candidates", []))
    stats["mass_assignment_count"] = len(candidates.get("mass_assignment_candidates", []))

    # Path-based redirect candidates: URLs whose path segments contain redirect keywords
    # This catches endpoints like /api/redirect, /goto, /redir even without query params
    _REDIRECT_PATH_KEYWORDS = {
        "redirect", "redir", "goto", "forward", "return", "callback",
        "logout", "login", "sso", "oauth",
    }
    _seen_path_redirects: set[str] = set()
    redirect_key = "redirect_candidates"
    redirect_seen = seen[redirect_key]
    all_url_sources = list(urls_data)
    for ep in (hidden_endpoints or []):
        if isinstance(ep, dict) and ep.get("path"):
            all_url_sources.append(ep)
    for item in all_url_sources:
        url = item.get("url", item.get("path", item)) if isinstance(item, dict) else str(item)
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        path_parts = [p for p in path_lower.split("/") if p]
        for part in path_parts:
            if part in _REDIRECT_PATH_KEYWORDS and url not in _seen_path_redirects:
                _seen_path_redirects.add(url)
                # Infer likely param name from common redirect param patterns
                inferred_param = "url"
                if parsed.query:
                    # If already has query params, use the first redirect-matching one
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    for pname in qs:
                        if _matches_vuln_type(pname, REDIRECT_PARAMS):
                            inferred_param = pname
                            break
                dedup_key = f"{url}:{inferred_param}"
                if dedup_key not in redirect_seen:
                    redirect_seen.add(dedup_key)
                    candidates[redirect_key].append({
                        "url": url,
                        "param": inferred_param,
                        "sample_value": "",
                        "method": "GET",
                        "source": "path_keyword",
                    })
                break

    stats["redirect_count"] = len(candidates.get("redirect_candidates", []))

    return {
        **candidates,
        "file_upload_candidates": file_upload_candidates,
        "post_endpoints": post_endpoints[:50],
        "path_idor_candidates": path_idor_candidates[:50],
        "high_value_params": high_value[:30],
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Phase 2: Live reflection probes (async)
# ---------------------------------------------------------------------------

_PROBE_TIMEOUT = aiohttp.ClientTimeout(total=10)
_PROBE_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
_PROBE_MARKER = "bh7r3f"  # unique marker unlikely to appear naturally

# SQL error patterns across databases
_SQL_ERROR_RE = re.compile(
    r"SQL syntax|ORA-\d{5}|PG::SyntaxError|mysql_fetch|"
    r"sqlite3\.OperationalError|ODBC SQL Server|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"SQL command not properly ended|"
    r"Microsoft OLE DB|JET Database|"
    r"unterminated string|syntax error at or near|"
    r"You have an error in your SQL|"
    r"java\.sql\.SQLException|"
    r"PostgreSQL.*ERROR:\s*syntax|"
    r"Warning:\s*mysql_|"
    r"SQLite.*error",
    re.I,
)

# LFI indicators
_LFI_INDICATOR_RE = re.compile(
    r"root:x:0:0|/bin/bash|/bin/sh|daemon:x:|"
    r"\[boot loader\]|\\windows\\system32",
    re.I,
)


def _replace_param_value(url: str, param: str, new_value: str) -> str:
    """Replace a query parameter value in a URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [new_value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def probe_reflection(
    classification: dict[str, Any],
    concurrency: int = 8,
    max_params: int = 60,
) -> dict[str, Any]:
    """Live-probe params to detect reflection, SQL errors, and LFI indicators.

    Enriches classification with high-confidence candidates found through
    actual HTTP probing rather than name matching alone.

    Sends 2-3 lightweight requests per param:
      1. Marker probe: inject unique string, check if reflected in response
      2. SQLi probe: inject single quote, check for SQL error messages
      3. LFI probe (if not already LFI candidate): inject traversal path

    Returns the enriched classification dict.
    """
    # Collect all unique (url, param) pairs from crawled URLs
    all_params: list[tuple[str, str, str]] = []  # (url, param, sample_value)
    seen: set[str] = set()

    for key in ("xss_candidates", "sqli_candidates", "lfi_candidates",
                "ssrf_candidates", "ssti_candidates", "redirect_candidates",
                "idor_candidates", "rce_candidates"):
        for c in classification.get(key, []):
            url = c.get("url", "")
            param = c.get("param", "")
            if url and param:
                dk = f"{url}:{param}"
                if dk not in seen:
                    seen.add(dk)
                    all_params.append((url, param, c.get("sample_value", "")))

    # Prioritize: real crawled params with values > API/debug endpoints > inferred
    _HIGH_PRIORITY_PARAMS = {"search", "q", "query", "id", "key", "url", "file", "page", "cmd"}
    _HIGH_PRIORITY_PATHS = ("/api/", "/debug", "/admin", "/search", "/products", "/orders")
    all_params.sort(key=lambda p: (
        0 if p[1].lower() in _HIGH_PRIORITY_PARAMS and any(kw in p[0].lower() for kw in _HIGH_PRIORITY_PATHS) else
        1 if p[2] not in ("test", "1", "") else  # has real sample value
        2
    ))

    if not all_params:
        return classification

    # Limit to avoid excessive probing
    all_params = all_params[:max_params]

    sem = asyncio.Semaphore(concurrency)
    new_xss: list[dict[str, Any]] = []
    new_sqli: list[dict[str, Any]] = []
    new_lfi: list[dict[str, Any]] = []
    probed_count = 0

    # Index existing candidates by url:param for tagging with probe results
    def _build_index(candidates: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        idx: dict[str, dict[str, Any]] = {}
        for c in candidates:
            dk = f"{c.get('url', '')}:{c.get('param', '')}"
            if dk not in idx:
                idx[dk] = c
        return idx

    xss_index = _build_index(classification.get("xss_candidates", []))
    sqli_index = _build_index(classification.get("sqli_candidates", []))
    lfi_index = _build_index(classification.get("lfi_candidates", []))

    async def _probe_one(session: aiohttp.ClientSession, url: str, param: str, sample: str) -> None:
        nonlocal probed_count
        async with sem:
            try:
                # --- Probe 1: Reflection check ---
                marker_url = _replace_param_value(url, param, _PROBE_MARKER)
                try:
                    async with session.get(
                        marker_url, headers=_PROBE_HEADERS,
                        timeout=_PROBE_TIMEOUT, ssl=False,
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        ct = resp.headers.get("content-type", "")

                        # If marker reflected in HTML body → XSS confirmed
                        if _PROBE_MARKER in body and "text/html" in ct.lower():
                            dk = f"{url}:{param}"
                            if dk in xss_index:
                                xss_index[dk]["probe"] = "reflected"
                            else:
                                new_xss.append({
                                    "url": url, "param": param,
                                    "sample_value": sample, "method": "GET",
                                    "probe": "reflected",
                                })
                except Exception:
                    pass

                # --- Probe 2: SQLi error check ---
                sqli_url = _replace_param_value(url, param, "1'")
                baseline_status = 0
                try:
                    # Get baseline with the param present
                    baseline_url = _replace_param_value(url, param, sample or "test")
                    async with session.get(
                        baseline_url, headers=_PROBE_HEADERS,
                        timeout=_PROBE_TIMEOUT, ssl=False,
                        allow_redirects=True,
                    ) as base_resp:
                        baseline_status = base_resp.status
                except Exception:
                    pass

                try:
                    async with session.get(
                        sqli_url, headers=_PROBE_HEADERS,
                        timeout=_PROBE_TIMEOUT, ssl=False,
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")

                        # SQL error string in response OR HTTP 500 on quote injection
                        sqli_detected = (
                            _SQL_ERROR_RE.search(body)
                            or (resp.status == 500 and baseline_status != 500)
                        )
                        probe_type = "sql_error" if _SQL_ERROR_RE.search(body) else "http_500"

                        if sqli_detected:
                            dk = f"{url}:{param}"
                            if dk in sqli_index:
                                sqli_index[dk]["probe"] = probe_type
                            else:
                                new_sqli.append({
                                    "url": url, "param": param,
                                    "sample_value": sample, "method": "GET",
                                    "probe": "sql_error",
                                })
                except Exception:
                    pass

                # --- Probe 3: LFI check ---
                dk = f"{url}:{param}"
                lfi_url = _replace_param_value(
                    url, param, "../../../../etc/passwd",
                )
                try:
                    async with session.get(
                        lfi_url, headers=_PROBE_HEADERS,
                        timeout=_PROBE_TIMEOUT, ssl=False,
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        if _LFI_INDICATOR_RE.search(body):
                            if dk in lfi_index:
                                lfi_index[dk]["probe"] = "lfi_confirmed"
                            else:
                                new_lfi.append({
                                    "url": url, "param": param,
                                    "sample_value": sample, "method": "GET",
                                    "probe": "lfi_confirmed",
                                })
                except Exception:
                    pass

                probed_count += 1
            except Exception:
                pass

    async with aiohttp.ClientSession() as session:
        tasks = [_probe_one(session, url, param, sample) for url, param, sample in all_params]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Count probe-confirmed from existing candidates BEFORE merging new ones
    tagged_xss = sum(1 for c in classification.get("xss_candidates", []) if c.get("probe"))
    tagged_sqli = sum(1 for c in classification.get("sqli_candidates", []) if c.get("probe"))
    tagged_lfi = sum(1 for c in classification.get("lfi_candidates", []) if c.get("probe"))

    # Merge new findings into classification
    if new_xss:
        classification.setdefault("xss_candidates", []).extend(new_xss)
    if new_sqli:
        classification.setdefault("sqli_candidates", []).extend(new_sqli)
    if new_lfi:
        classification.setdefault("lfi_candidates", []).extend(new_lfi)

    # Update stats — tagged counts are from existing items, new counts are additive
    stats = classification.get("stats", {})
    stats["probe_total"] = probed_count
    stats["probe_xss_found"] = tagged_xss + len(new_xss)
    stats["probe_sqli_found"] = tagged_sqli + len(new_sqli)
    stats["probe_lfi_found"] = tagged_lfi + len(new_lfi)
    stats["xss_count"] = len(classification.get("xss_candidates", []))
    stats["sqli_count"] = len(classification.get("sqli_candidates", []))
    stats["lfi_count"] = len(classification.get("lfi_candidates", []))

    total_confirmed = stats["probe_xss_found"] + stats["probe_sqli_found"] + stats["probe_lfi_found"]
    if total_confirmed > 0:
        logger.info(
            "param_probe.results",
            probed=probed_count,
            xss_confirmed=stats["probe_xss_found"],
            sqli_confirmed=stats["probe_sqli_found"],
            lfi_confirmed=stats["probe_lfi_found"],
        )

    return classification
