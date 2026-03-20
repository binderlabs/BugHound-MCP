"""JavaScript file analyzer for secret and endpoint extraction.

Downloads JS files via aiohttp and applies regex patterns to find:
- API keys, tokens, passwords, private keys, Firebase, S3 buckets, internal IPs
- API endpoints and internal paths
No external binary needed — pure Python.

Secrets are confidence-scored: HIGH / MEDIUM / LOW.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Secret patterns: (name, compiled regex, description, confidence)
# HIGH  = structural pattern (AWS key format, Slack token prefix, etc.)
# MEDIUM = variable-length key/token with reasonable entropy heuristics
# LOW   = generic keyword match — noisy, needs human review
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    # ── HIGH confidence ──────────────────────────────────────────────────────
    ("AWS_ACCESS_KEY",  re.compile(r"AKIA[0-9A-Z]{16}"),                                                          "AWS Access Key ID",          "HIGH"),
    ("AWS_SECRET_KEY",  re.compile(r"""(?:aws_secret|secret_?access_?key)['":\s=]+([A-Za-z0-9/+=]{40})""", re.I), "AWS Secret Key",              "HIGH"),
    ("GOOGLE_API",      re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                                    "Google API Key",              "HIGH"),
    ("SLACK_TOKEN",     re.compile(r"xox[bpors]-[0-9a-zA-Z-]{10,}"),                                              "Slack Token",                 "HIGH"),
    ("GITHUB_TOKEN",    re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),                                               "GitHub Token",                "HIGH"),
    ("PRIVATE_KEY",     re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),                              "Private Key",                 "HIGH"),
    ("JWT",             re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),            "JSON Web Token",              "HIGH"),
    ("FIREBASE",        re.compile(r"[a-z0-9-]+\.firebaseio\.com"),                                                "Firebase Database URL",       "HIGH"),
    ("S3_BUCKET",       re.compile(r"[a-z0-9.-]+\.s3\.amazonaws\.com"),                                            "AWS S3 Bucket",               "HIGH"),
    # ── MEDIUM confidence ────────────────────────────────────────────────────
    ("API_KEY",         re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret)[\s:="']+([A-Za-z0-9_\-]{20,})""", re.I),           "API Key",      "MEDIUM"),
    ("BEARER_TOKEN",    re.compile(r"""(?:bearer|authorization|auth[_-]?token)[\s:="']+([A-Za-z0-9_\-\.]{30,})""", re.I),        "Bearer Token", "MEDIUM"),
    ("INTERNAL_IP",     re.compile(
        r"""(?:^|[\"'\s,;=])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
        r"""|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"""
        r"""|192\.168\.\d{1,3}\.\d{1,3})(?:[\"'\s,;:]|$)"""
    ),                                                                                                              "Internal IP",                 "MEDIUM"),
    # ── LOW confidence ───────────────────────────────────────────────────────
    ("GENERIC_SECRET",  re.compile(r"""(?:secret|password|passwd|pwd)[\s:="']+([^\s"']{12,64})""", re.I),          "Generic Secret/Password",     "LOW"),
]

# ---------------------------------------------------------------------------
# False-positive filters for LOW-confidence generic secrets
# ---------------------------------------------------------------------------

# Values that are obviously not real secrets
_FP_VALUES: frozenset[str] = frozenset({
    "null", "undefined", "true", "false", "none", "empty", "required",
    "your_password_here", "changeme", "placeholder", "enter_password",
    "your_secret", "xxxxxxxx", "password123", "12345678", "00000000",
})

# Looks like minified JS: contains JS punctuation or is a code fragment
_FP_CODE_RE = re.compile(
    r"[{}()\[\];,!]"           # JS syntax chars
    r"|^\!0$|^\!1$"            # minified booleans
    r"|^[a-z]\."               # method call like "n.foo"
    r"|placeholder"            # common placeholder word
    r"|\.\.\."                 # truncated value
    r"|required:!0"            # React/minified prop
    r"|onChange:"              # React event handler
    r"|className"              # JSX prop
    r"|value:b\."              # minified state access
    , re.I
)

# Source files inside known library paths → skip entirely for LOW patterns
_LIB_PATH_RE = re.compile(
    r"node_modules|vendor|webpack|chunks?/|runtime\.|polyfill\.|jquery",
    re.I,
)


def _is_fp_value(value: str, source_file: str, confidence: str) -> bool:
    """Return True if this match is likely a false positive."""
    if confidence != "LOW":
        return False  # Only filter LOW confidence

    v = value.strip().lower()

    # Too short (< 12 chars already enforced by regex, but double-check)
    if len(v) < 12:
        return True

    # Known placeholder strings
    if v in _FP_VALUES:
        return True

    # Looks like a code fragment, not a secret
    if _FP_CODE_RE.search(value):
        return True

    # Source file is a known library path
    if _LIB_PATH_RE.search(source_file):
        return True

    return False


# ---------------------------------------------------------------------------
# Endpoint patterns
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"](\/[^'"]{2,}?)['"]"""),
    re.compile(r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'](\/[^"']+)["']"""),
    re.compile(r"""["'](\/api\/[^"']+)["']"""),
    re.compile(r"""["'](\/v[0-9]+\/[a-zA-Z0-9/_\-\.]{2,}?)["']"""),
    re.compile(r"""["'](\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9/_\-\.]{2,}?)["']"""),
    re.compile(r"""(?:url|endpoint|path|href|action)\s*[:=]\s*["'](\/[^"']{2,}?)["']""", re.I),
]

_ENDPOINT_IGNORE = re.compile(
    r"^/(favicon|static|assets|css|img|images|fonts|vendor|node_modules|\.)",
    re.I,
)

# Patterns for classifying endpoint types
_API_ENDPOINT_RE = re.compile(
    r"/api/|/v\d+/|/graphql|/rest/|/rpc/|\?|&|=",
    re.I,
)

_CLIENT_ROUTE_RE = re.compile(
    r"^/(dashboard|settings|login|logout|signup|register|profile|account"
    r"|home|about|contact|help|faq|terms|privacy|admin|onboarding"
    r"|notifications|messages|preferences|billing|checkout|cart"
    r"|search|explore|discover|feed|timeline)(/|$)",
    re.I,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def analyze_js_files(
    js_urls: list[str],
    target_domain: str = "",
    concurrency: int = 20,
    timeout: int = 15,
) -> dict[str, Any]:
    """Download and analyze JS files for secrets and endpoints.

    Secrets include a 'confidence' field: HIGH / MEDIUM / LOW.
    LOW confidence secrets are filtered more aggressively for false positives.

    Returns:
        {
            "secrets": [...],        # all passing secrets
            "secrets_by_confidence": {"HIGH": N, "MEDIUM": N, "LOW": N},
            "endpoints": [...],
            "files_analyzed": N,
            "files_failed": N,
            "errors": [...]
        }
    """
    sem = asyncio.Semaphore(concurrency)
    all_secrets: list[dict[str, Any]] = []
    all_endpoints: list[dict[str, Any]] = []
    errors: list[str] = []
    analyzed = 0
    failed = 0

    async def _analyze_one(url: str) -> None:
        nonlocal analyzed, failed
        async with sem:
            content = await _download_js(url, timeout)
            if content is None:
                failed += 1
                return
            analyzed += 1
            secrets = _extract_secrets(content, url)
            endpoints = _extract_endpoints(content, url, target_domain)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)

    tasks = [_analyze_one(u) for u in js_urls]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate endpoints by path
    seen_paths: set[str] = set()
    unique_endpoints: list[dict[str, Any]] = []
    for ep in all_endpoints:
        if ep["path"] not in seen_paths:
            seen_paths.add(ep["path"])
            unique_endpoints.append(ep)

    # Count by confidence
    by_conf: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in all_secrets:
        by_conf[s["confidence"]] = by_conf.get(s["confidence"], 0) + 1

    return {
        "secrets": all_secrets,
        "secrets_by_confidence": by_conf,
        "endpoints": unique_endpoints,
        "files_analyzed": analyzed,
        "files_failed": failed,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


async def _download_js(url: str, timeout: int) -> str | None:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return None
                content = await resp.text(encoding="utf-8", errors="replace")
                if len(content) > 5_000_000:
                    content = content[:5_000_000]
                return content
    except Exception:
        return None


def _extract_secrets(content: str, source_file: str) -> list[dict[str, Any]]:
    secrets: list[dict[str, Any]] = []

    for name, pattern, description, confidence in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()

            # Skip values below minimum length (12 chars)
            if len(value) < 12:
                continue

            # Skip common JS literal values regardless of confidence
            if value.strip().lower() in _FP_VALUES:
                continue

            # Apply false-positive filter
            if _is_fp_value(value, source_file, confidence):
                continue

            display = value[:60] + ("..." if len(value) > 60 else "")
            secrets.append({
                "type": name,
                "value": display,
                "description": description,
                "confidence": confidence,
                "source_file": source_file,
                "match_position": match.start(),
            })

    return secrets


def _extract_endpoints(content: str, source_file: str, target_domain: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            path = match.group(1) if match.lastindex else match.group(0)
            _add_endpoint(path, match, content, source_file, endpoints, seen)

    if target_domain:
        domain_pattern = re.compile(
            r"""["'](https?://[^"']*""" + re.escape(target_domain) + r"""[^"']*)["']"""
        )
        for match in domain_pattern.finditer(content):
            full_url = match.group(1).strip()
            try:
                path = urlparse(full_url).path
                if path and path != "/":
                    _add_endpoint(path, match, content, source_file, endpoints, seen)
            except Exception:
                pass

    return endpoints


def _add_endpoint(
    path: str,
    match: re.Match,
    content: str,
    source_file: str,
    endpoints: list[dict[str, Any]],
    seen: set[str],
) -> None:
    path = path.strip()
    if not path or path in seen:
        return
    if _ENDPOINT_IGNORE.match(path):
        return
    if len(path) < 3 or len(path) > 200:
        return

    seen.add(path)

    method = "GET"
    ctx_start = max(0, match.start() - 60)
    context = content[ctx_start : match.start()].lower()
    if ".post" in context or '"post"' in context or "'post'" in context:
        method = "POST"
    elif ".put" in context or '"put"' in context:
        method = "PUT"
    elif ".delete" in context or '"delete"' in context:
        method = "DELETE"
    elif ".patch" in context:
        method = "PATCH"

    # Classify endpoint type
    if _API_ENDPOINT_RE.search(path) or method != "GET":
        endpoint_type = "api"
    elif _CLIENT_ROUTE_RE.match(path):
        endpoint_type = "client_route"
    else:
        endpoint_type = "api"  # default to api — safer for testing

    endpoints.append({"path": path, "method": method, "source_file": source_file, "endpoint_type": endpoint_type})
