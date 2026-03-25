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
    # Cloud provider tokens
    ("GOOGLE_OAUTH",     re.compile(r"ya29\.[0-9A-Za-z\-_]+"),                                                          "Google OAuth Token",          "HIGH"),
    ("GOOGLE_CAPTCHA",   re.compile(r"6L[0-9A-Za-z\-_]{38}"),                                                           "Google reCAPTCHA Key",        "HIGH"),
    ("STRIPE_LIVE",      re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),                                                       "Stripe Live API Key",         "HIGH"),
    ("STRIPE_RESTRICTED", re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),                                                      "Stripe Restricted Key",       "HIGH"),
    ("FACEBOOK_TOKEN",   re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),                                                     "Facebook Access Token",       "HIGH"),
    ("TWILIO_API",       re.compile(r"SK[0-9a-fA-F]{32}"),                                                              "Twilio API Key",              "HIGH"),
    ("TWILIO_SID",       re.compile(r"AC[a-zA-Z0-9_\-]{32}"),                                                           "Twilio Account SID",          "HIGH"),
    ("MAILGUN_KEY",      re.compile(r"key-[0-9a-zA-Z]{32}"),                                                            "Mailgun API Key",             "HIGH"),
    ("SQUARE_TOKEN",     re.compile(r"sq0atp-[0-9A-Za-z\-_]{22,}"),                                                     "Square Access Token",         "HIGH"),
    ("SQUARE_OAUTH",     re.compile(r"sq0csp-[0-9A-Za-z\-_]{43,}"),                                                     "Square OAuth Secret",         "HIGH"),
    ("PAYPAL_BRAINTREE", re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),                           "PayPal Braintree Token",      "HIGH"),
    ("PGP_KEY",          re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),                                           "PGP Private Key",             "HIGH"),
    ("HEROKU_API",       re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "Heroku API Key (UUID)",       "MEDIUM"),
    ("AMAZON_MWS",       re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),      "Amazon MWS Auth Token",       "HIGH"),
    ("SHOPIFY_TOKEN",    re.compile(r"shpat_[a-fA-F0-9]{32}"),                                                          "Shopify Admin Token",         "HIGH"),
    ("SHOPIFY_KEY",      re.compile(r"shpss_[a-fA-F0-9]{32}"),                                                          "Shopify Shared Secret",       "HIGH"),
    ("DYNATRACE",        re.compile(r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}"),                                             "Dynatrace Token",             "HIGH"),
    ("SENDGRID_KEY",     re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),                                    "SendGrid API Key",            "HIGH"),
    # ── MEDIUM confidence ────────────────────────────────────────────────────
    ("API_KEY",         re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret)[\s:="']+([A-Za-z0-9_\-]{20,})""", re.I),           "API Key",      "MEDIUM"),
    ("BEARER_TOKEN",    re.compile(r"""(?:bearer|authorization|auth[_-]?token)[\s:="']+([A-Za-z0-9_\-\.]{30,})""", re.I),        "Bearer Token", "MEDIUM"),
    ("INTERNAL_IP",     re.compile(
        r"""(?:^|[\"'\s,;=])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
        r"""|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"""
        r"""|192\.168\.\d{1,3}\.\d{1,3})(?:[\"'\s,;:]|$)"""
    ),                                                                                                              "Internal IP",                 "MEDIUM"),
    # Database connection strings
    ("MONGODB_URI",      re.compile(r"mongodb(?:\+srv)?://[^\s\"']{10,}"),                                               "MongoDB Connection URI",      "MEDIUM"),
    ("POSTGRES_URI",     re.compile(r"postgres(?:ql)?://[^\s\"']{10,}"),                                                 "PostgreSQL Connection URI",   "MEDIUM"),
    ("MYSQL_URI",        re.compile(r"mysql://[^\s\"']{10,}"),                                                           "MySQL Connection URI",        "MEDIUM"),
    ("REDIS_URI",        re.compile(r"redis://[^\s\"']{10,}"),                                                           "Redis Connection URI",        "MEDIUM"),
    # Auth patterns
    ("BASIC_AUTH",       re.compile(r"(?:Authorization|authorization)[:\s]+Basic\s+([A-Za-z0-9+/=]{20,})"),              "HTTP Basic Auth (base64)",    "MEDIUM"),
    ("CRED_URL",         re.compile(r"https?://[^:@\s]+:[^:@\s]+@[^\s\"']+"),                                           "URL with Credentials",        "MEDIUM"),
    # Cloud keys
    ("AZURE_KEY",        re.compile(r"AccountKey=[A-Za-z0-9+/=]{44,}"),                                                 "Azure Storage Key",           "HIGH"),
    ("AZURE_SAS",        re.compile(r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=[^&]*&sig=[A-Za-z0-9%+/=]+"),                          "Azure SAS Token",             "MEDIUM"),
    ("GCP_SERVICE",      re.compile(r'"type"\s*:\s*"service_account"'),                                                  "GCP Service Account JSON",    "HIGH"),
    # ── LOW confidence ───────────────────────────────────────────────────────
    ("GENERIC_SECRET",  re.compile(r"""(?:secret|password|passwd|pwd)[\s:="']+([^\s"']{12,64})""", re.I),          "Generic Secret/Password",     "LOW"),
    # Generic keyword-value patterns (JS Miner style)
    ("SESSION_SECRET",   re.compile(r"""(?:session|encrypt|decrypt|ssh|consumer|signing)[-_]?(?:key|secret|token)[\s:="']+([^\s"']{12,64})""", re.I), "Session/Encrypt Secret", "LOW"),
    ("EMAIL_IN_JS",      re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),                           "Email Address in JS",         "LOW"),
]

# Cloud service URL patterns (inspired by JS Miner)
_CLOUD_URL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS_S3",          re.compile(r"[a-z0-9.-]+\.s3[.-](?:us|eu|ap|sa|ca|me|af)?-?(?:east|west|north|south|central|southeast|northeast)?-?\d?\.?amazonaws\.com"),  "AWS S3 Bucket"),
    ("AWS_RDS",         re.compile(r"[a-z0-9.-]+\.rds\.amazonaws\.com"),                                                "AWS RDS Instance"),
    ("AWS_CACHE",       re.compile(r"[a-z0-9.-]+\.cache\.amazonaws\.com"),                                              "AWS ElastiCache"),
    ("AZURE_BLOB",      re.compile(r"[a-z0-9]+\.blob\.core\.windows\.net"),                                             "Azure Blob Storage"),
    ("AZURE_TABLE",     re.compile(r"[a-z0-9]+\.table\.core\.windows\.net"),                                            "Azure Table Storage"),
    ("GCP_STORAGE",     re.compile(r"storage\.googleapis\.com/[a-z0-9._-]+"),                                           "Google Cloud Storage"),
    ("CLOUDFRONT",      re.compile(r"[a-z0-9]+\.cloudfront\.net"),                                                      "AWS CloudFront"),
    ("DO_SPACES",       re.compile(r"[a-z0-9.-]+\.digitaloceanspaces\.com"),                                            "DigitalOcean Spaces"),
    ("ALIBABA_OSS",     re.compile(r"[a-z0-9.-]+\.aliyuncs\.com"),                                                     "Alibaba Cloud OSS"),
    ("ORACLE_CLOUD",    re.compile(r"[a-z0-9.-]+\.oraclecloud\.com"),                                                  "Oracle Cloud"),
    ("RACKSPACE_CDN",   re.compile(r"[a-z0-9.-]+\.rackcdn\.com"),                                                      "Rackspace CDN"),
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
# Hidden parameter extraction from JS source code
# ---------------------------------------------------------------------------

_JS_PARAM_PATTERNS = [
    re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', re.I),
    re.compile(r'\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']\)', re.I),
    re.compile(r'\.query\.([a-zA-Z_][a-zA-Z0-9_]{1,30})', re.I),
    re.compile(r'\.params\.([a-zA-Z_][a-zA-Z0-9_]{1,30})', re.I),
    re.compile(r'name=["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']', re.I),
    re.compile(r'searchParams\.get\(["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']\)', re.I),
]

_JS_KEYWORD_FILTER = frozenset({
    'function', 'return', 'var', 'let', 'const', 'class', 'this', 'true',
    'false', 'null', 'undefined', 'import', 'export', 'default', 'new',
    'delete', 'typeof', 'void', 'if', 'else', 'for', 'while', 'do',
    'switch', 'case', 'break', 'continue', 'try', 'catch', 'throw',
    'finally', 'with', 'debugger', 'instanceof', 'in', 'of', 'async',
    'await', 'yield', 'from', 'as', 'static', 'get', 'set', 'constructor',
    'prototype', 'length', 'type', 'value', 'name', 'index', 'key', 'data',
    'error', 'message', 'status', 'result', 'response', 'request', 'options',
    'config', 'module', 'require', 'exports', 'window', 'document', 'console',
    'navigator', 'location', 'history', 'event', 'target', 'src', 'href',
    'url', 'path', 'method',
})


def extract_params_from_js(js_content: str) -> list[str]:
    """Extract parameter names from JavaScript source code."""
    params = set()
    for pattern in _JS_PARAM_PATTERNS:
        for match in pattern.findall(js_content):
            param = match.strip()
            # Filter out common JS keywords
            if param.lower() not in _JS_KEYWORD_FILTER:
                if len(param) >= 2:
                    params.add(param)
    return sorted(params)


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
    all_hidden_params: list[str] = []
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
            # Extract hidden params from JS source
            js_params = extract_params_from_js(content)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)
            all_hidden_params.extend(js_params)

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

    # Deduplicate hidden params
    unique_hidden_params = sorted(set(all_hidden_params))

    return {
        "secrets": all_secrets,
        "secrets_by_confidence": by_conf,
        "endpoints": unique_endpoints,
        "hidden_params": unique_hidden_params,
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

    # Cloud URL detection
    for name, pattern, description in _CLOUD_URL_PATTERNS:
        for match in pattern.finditer(content):
            url = match.group(0)
            secrets.append({
                "type": name,
                "description": description,
                "value": url,
                "source_file": source_file,
                "confidence": "MEDIUM",
                "line": content[:match.start()].count("\n") + 1,
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
