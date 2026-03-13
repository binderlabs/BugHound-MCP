"""Parameter classification engine — gf-style pattern matching, pure Python.

Classifies discovered parameters by vulnerability type so Stage 3/4 can
prioritize testing. A single parameter can match multiple vuln types.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Vulnerability parameter patterns
# ---------------------------------------------------------------------------

SQLI_PARAMS: dict[str, Any] = {
    "exact": {
        "id", "select", "report", "query", "table", "column", "where", "order",
        "sort", "group", "by", "having", "limit", "offset", "fetch", "row",
        "union", "insert", "update", "delete", "search", "filter", "results",
        "num", "count", "page", "field", "view", "process", "show", "col",
    },
    "patterns": ["*_id", "*_no", "*_num", "*_number", "*_key", "*_pk", "*_fk"],
}

XSS_PARAMS: dict[str, Any] = {
    "exact": {
        "q", "search", "query", "keyword", "name", "input", "text", "value",
        "comment", "message", "body", "content", "title", "subject",
        "description", "feedback", "review", "bio", "note", "label",
        "placeholder", "data", "payload", "html", "xml", "callback", "jsonp",
        "func", "function", "handler", "error", "err", "msg", "alert",
        "redirect_uri", "return_url", "next",
    },
    "patterns": [
        "*_name", "*_text", "*_value", "*_msg", "*_message", "*_content",
        "*_title", "*_desc",
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
    "patterns": ["*_id", "*_uuid", "*_ref", "*_no", "*_number", "*_key"],
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
        "__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION",
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
        "role", "is_admin", "isAdmin", "admin", "is_staff", "is_superuser",
        "privilege", "permissions", "user_type", "userType", "access_level",
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
    for item in urls_data:
        url = item.get("url", item) if isinstance(item, dict) else str(item)
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for pname, pvals in qs.items():
            param_entries.append((url, pname, pvals[0] if pvals else "", "GET"))

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
        parsed = urlparse(ep_path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for pname, pvals in qs.items():
            param_entries.append((
                ep_path, pname, pvals[0] if pvals else "",
                ep.get("method", "GET"),
            ))

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

    # High-value params: match 2+ vuln types
    high_value = sorted([
        {"param": p, "vuln_types": sorted(vtypes), "match_count": len(vtypes)}
        for p, vtypes in param_vuln_count.items()
        if len(vtypes) >= 2
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
    _seen_path_idors: set[str] = set()
    for item in urls_data:
        url = item.get("url", item) if isinstance(item, dict) else str(item)
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        for part in parts:
            if part.isdigit() or _uuid_re.match(part):
                if url not in _seen_path_idors:
                    _seen_path_idors.add(url)
                    path_idor_candidates.append({
                        "url": url,
                        "segment": part,
                        "segment_type": "numeric" if part.isdigit() else "uuid",
                    })
                break

    stats["path_idor_urls"] = len(path_idor_candidates)
    stats["deserialization_count"] = len(candidates.get("deserialization_candidates", []))
    stats["mass_assignment_count"] = len(candidates.get("mass_assignment_candidates", []))

    return {
        **candidates,
        "file_upload_candidates": file_upload_candidates,
        "post_endpoints": post_endpoints[:50],
        "path_idor_candidates": path_idor_candidates[:50],
        "high_value_params": high_value[:30],
        "stats": stats,
    }
