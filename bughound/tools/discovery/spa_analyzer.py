"""SPA (Single Page Application) analyzer.

Modern webapps ship an empty HTML skeleton like:

    <body><div id="root"></div><script src="/assets/index-X.js"></script></body>

Traditional crawlers see nothing — no forms, no links, no real content. This
module:

  1. Detects SPA skeletons (Vite/CRA/Vue/Angular/Next) via HTML heuristics.
  2. Extracts route configs from the JS bundle (React Router, Vue Router,
     Angular Router) — the REAL list of client-side routes.
  3. Probes common SPA backend paths (/api/health, /api/me, /graphql, etc.).
  4. Optionally renders the SPA in Playwright and captures network traffic
     (the actual backend APIs called during load).

Complements js_analyzer.py — js_analyzer scans JS for secrets + loose
endpoint strings; this module specifically understands SPA structure.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp
import structlog

logger = structlog.get_logger()

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_TIMEOUT = aiohttp.ClientTimeout(total=10)


# ---------------------------------------------------------------------------
# SPA detection
# ---------------------------------------------------------------------------

# Common SPA root-div IDs
_SPA_ROOT_PATTERN = re.compile(
    r'<div\s+[^>]*id\s*=\s*["\'](?:root|app|__next|__nuxt|main-app|ng-app|react-root|vue-app)["\']',
    re.IGNORECASE,
)

# Signatures that reveal the framework
_FRAMEWORK_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("vite", re.compile(r"/assets/(?:index|main)-[A-Za-z0-9_-]{6,}\.(?:js|css)", re.I)),
    ("nextjs", re.compile(r"_next/static/(?:chunks|css|media)", re.I)),
    ("nuxtjs", re.compile(r"_nuxt/|__nuxt", re.I)),
    ("create-react-app", re.compile(r"/static/js/(?:main|runtime-main)\.[0-9a-f]+\.js", re.I)),
    ("angular", re.compile(r"(?:main|polyfills|runtime|vendor)\.[0-9a-f]+\.js", re.I)),
    ("vue-cli", re.compile(r"/js/(?:app|chunk-vendors)\.[0-9a-f]+\.js", re.I)),
    ("gatsby", re.compile(r"(?:webpack-runtime|app-[0-9a-f]+)\.js", re.I)),
    ("remix", re.compile(r"/build/(?:manifest|root)-[0-9a-zA-Z]+\.js", re.I)),
    ("svelte-kit", re.compile(r"/_app/immutable/(?:chunks|entry)-", re.I)),
]

# Keywords in body/script tags that suggest specific frameworks
_FRAMEWORK_KEYWORDS: list[tuple[str, re.Pattern]] = [
    ("react", re.compile(r"__REACT_DEVTOOLS|React\.createElement|data-reactroot", re.I)),
    ("vue", re.compile(r"__VUE__|v-cloak|Vue\.component|Vue\.createApp", re.I)),
    ("angular", re.compile(r"ng-version=|ng-controller|angular\.module", re.I)),
    ("ember", re.compile(r"ember-view|Ember\.Application|ember-cli", re.I)),
]


def detect_spa(html: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Detect whether HTML is an SPA skeleton, and identify framework(s).

    Returns dict:
      {"is_spa": bool, "framework": str|None, "builders": [str],
       "root_selector": str|None, "signals": [str], "confidence": "high"|"medium"|"low"}
    """
    if not html or len(html) > 500_000:
        return {"is_spa": False, "framework": None, "builders": [], "signals": []}

    signals: list[str] = []
    builders: set[str] = set()
    frameworks: set[str] = set()
    root_sel = None

    # Very short HTML + root div = very strong SPA signal
    body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.IGNORECASE | re.DOTALL)
    body_content = body_match.group(1) if body_match else html
    body_text_len = len(re.sub(r"<[^>]+>", "", body_content).strip())

    root_match = _SPA_ROOT_PATTERN.search(body_content)
    if root_match:
        root_sel = root_match.group(0)
        signals.append(f"root-div: {root_sel[:60]}")

    # Framework builder signatures (Vite, CRA, Next etc.)
    for name, pattern in _FRAMEWORK_SIGNATURES:
        if pattern.search(html):
            builders.add(name)
            signals.append(f"builder: {name}")

    # Framework keyword heuristics
    for name, pattern in _FRAMEWORK_KEYWORDS:
        if pattern.search(html):
            frameworks.add(name)
            signals.append(f"framework: {name}")

    # Crossorigin modules indicate Vite-style bundling
    if re.search(r'<script\s+[^>]*type\s*=\s*["\']module["\']', html, re.I):
        signals.append("type=module script (ES modules)")

    # Empty-body heuristic
    if body_text_len < 200 and root_match:
        signals.append(f"empty body (text content: {body_text_len}B)")

    # Decision
    confidence = "low"
    is_spa = False
    if root_match and body_text_len < 200:
        is_spa = True
        confidence = "high"
    elif root_match and (builders or frameworks):
        is_spa = True
        confidence = "high"
    elif builders:
        is_spa = True
        confidence = "medium"
    elif frameworks and body_text_len < 1500:
        is_spa = True
        confidence = "medium"

    primary = next(iter(frameworks), None) or next(iter(builders), None)

    return {
        "is_spa": is_spa,
        "framework": primary,
        "frameworks": sorted(frameworks),
        "builders": sorted(builders),
        "root_selector": root_sel,
        "signals": signals,
        "confidence": confidence,
        "body_text_length": body_text_len,
    }


# ---------------------------------------------------------------------------
# Route extraction from JS bundles
# ---------------------------------------------------------------------------

# Patterns for router config in minified or readable JS. Each captures a path.
_ROUTE_PATTERNS: list[re.Pattern] = [
    # React Router v6: { path: "/users/:id", ... } — with quotes variants
    re.compile(r'\bpath\s*:\s*["\'`](/[^"\'`]{0,200}?)["\'`]'),
    # JSX: <Route path="/users/:id" ...>
    re.compile(r'<Route\s+[^>]*path\s*=\s*["\']([/][^"\']{0,200}?)["\']'),
    # Vue Router: routes:[{path:"/"},...]
    re.compile(r'\{\s*path\s*:\s*["\'`](/[^"\'`]{0,200}?)["\'`]\s*,\s*(?:component|redirect|name|children)'),
    # Angular: {path: 'users/:id', component: ...}  (note: no leading /)
    re.compile(r'\{\s*path\s*:\s*["\']([a-zA-Z][^"\']{0,200}?)["\']\s*,\s*component\s*:'),
    # createBrowserRouter: [{ path: "/" ... }]
    re.compile(r'createBrowserRouter\s*\(\s*\[\s*\{[^}]*path\s*:\s*["\']([/][^"\']+?)["\']'),
    # Reach Router / Next.js getStaticPaths
    re.compile(r'\bto\s*=\s*["\']([/][a-zA-Z][^"\']{0,200}?)["\']'),
    # Links: <a href="/path"> still valid in SPAs
    re.compile(r'href\s*:\s*["\'`]([/][a-zA-Z][^"\'`]{0,200}?)["\'`]'),
]


_ROUTE_BLACKLIST = re.compile(
    r"^/(?:\*|:\w+$|\.\.|assets|static|_next|_nuxt|node_modules|fonts|img|images|css|js|media)(/|$)",
    re.I,
)


def extract_routes_from_js(js_content: str) -> list[dict[str, Any]]:
    """Extract SPA route definitions from a JS bundle.

    Returns list of {route, source_pattern, has_param}.
    """
    if not js_content:
        return []

    found: dict[str, dict[str, Any]] = {}

    for pattern in _ROUTE_PATTERNS:
        for m in pattern.finditer(js_content):
            route = m.group(1).strip()
            # Normalize: ensure leading slash
            if not route.startswith("/"):
                route = "/" + route
            # Filter obvious junk
            if len(route) < 2 or len(route) > 200:
                continue
            if _ROUTE_BLACKLIST.match(route):
                continue
            # Skip pure globs / wildcards
            if route in ("/*", "/**"):
                continue
            # Dedup
            if route not in found:
                found[route] = {
                    "route": route,
                    "has_param": ":" in route or "*" in route,
                    "pattern_source": pattern.pattern[:60],
                }

    return list(found.values())


# ---------------------------------------------------------------------------
# GraphQL operation extraction
# ---------------------------------------------------------------------------

_GRAPHQL_OPERATION_RE = re.compile(
    r"(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]{2,60})\s*(?:\([^)]*\))?\s*\{",
)
_GRAPHQL_INLINE_RE = re.compile(
    r"gql\s*`\s*(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]{2,60})",
)


def extract_graphql_operations(js_content: str) -> list[str]:
    """Extract GraphQL operation names from JS bundle."""
    ops: set[str] = set()
    for m in _GRAPHQL_OPERATION_RE.finditer(js_content):
        ops.add(m.group(1))
    for m in _GRAPHQL_INLINE_RE.finditer(js_content):
        ops.add(m.group(1))
    return sorted(ops)


# ---------------------------------------------------------------------------
# Common SPA backend paths probe
# ---------------------------------------------------------------------------

# Cheap probes that reveal backend presence / config / auth endpoints.
# Each probe = (path, what_a_200_means, indicator_in_body)
_SPA_BACKEND_PATHS: list[tuple[str, str, re.Pattern | None]] = [
    ("/api/health", "health endpoint", re.compile(r'"?status"?\s*:|"?ok"?|healthy', re.I)),
    ("/api/healthz", "healthz endpoint", re.compile(r'"?status"?\s*:|"?ok"?', re.I)),
    ("/api/ping", "ping endpoint", None),
    ("/api/version", "version info", re.compile(r'"?version"?\s*:', re.I)),
    ("/api/status", "status endpoint", None),
    ("/api/config", "exposed config", re.compile(r'"?\w+"?\s*:', re.I)),
    ("/api/settings", "exposed settings", None),
    ("/api/me", "auth check endpoint", None),
    ("/api/user", "user endpoint", None),
    ("/api/users", "users endpoint", None),
    ("/api/users/me", "self user endpoint", None),
    ("/api/v1", "v1 API root", None),
    ("/api/v2", "v2 API root", None),
    ("/api/v3", "v3 API root", None),
    ("/api", "API root", None),
    ("/graphql", "GraphQL endpoint", re.compile(r'errors|data|__schema|introspection|graphql', re.I)),
    ("/graphiql", "GraphiQL UI (debug)", re.compile(r'graphiql|graphql', re.I)),
    ("/playground", "GraphQL Playground", re.compile(r'graphql|playground', re.I)),
    ("/api/graphql", "GraphQL API", None),
    ("/query", "query endpoint", None),
    ("/api/docs", "API docs", None),
    ("/api/swagger", "Swagger UI", None),
    ("/docs", "docs page", None),
    ("/openapi.json", "OpenAPI spec", re.compile(r'"?openapi"?|"?swagger"?', re.I)),
    ("/swagger.json", "Swagger spec", re.compile(r'"?paths"?\s*:', re.I)),
    ("/.well-known/openid-configuration", "OIDC config", re.compile(r'"?issuer"?', re.I)),
    ("/auth/login", "auth login endpoint", None),
    ("/api/auth/login", "API login", None),
    ("/api/auth/me", "API auth check", None),
    ("/api/session", "session endpoint", None),
    ("/api/token", "token endpoint", None),
    ("/api/csrf", "CSRF token endpoint", re.compile(r"token|csrf", re.I)),
    ("/api/admin", "admin API", None),
    ("/api/feature-flags", "feature flags", None),
    ("/api/flags", "feature flags (short)", None),
    ("/metrics", "Prometheus metrics", re.compile(r"^# HELP|^# TYPE", re.I | re.MULTILINE)),
    ("/actuator", "Spring Actuator", re.compile(r'"?_links"?', re.I)),
    ("/actuator/health", "Actuator health", None),
]


async def probe_spa_backends(
    base_url: str, concurrency: int = 15, timeout: int = 8,
) -> list[dict[str, Any]]:
    """Hit common SPA backend paths and record what responds with signal.

    Returns list of {path, url, status, content_type, indicator_matched, body_preview}.
    """
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings: list[dict[str, Any]] = []
    sem = asyncio.Semaphore(concurrency)
    t = aiohttp.ClientTimeout(total=timeout)

    async def _probe(path: str, meaning: str, indicator: re.Pattern | None) -> None:
        async with sem:
            url = base + path
            try:
                async with aiohttp.ClientSession(
                    headers={"User-Agent": _UA}, timeout=t,
                ) as s:
                    async with s.get(url, ssl=False, allow_redirects=False) as r:
                        status = r.status
                        ct = r.headers.get("content-type", "")
                        body = (await r.text(errors="replace"))[:4000]
            except Exception:
                return

            # Only keep probes that look like real responses
            if status in (404, 0, 502, 503, 504):
                return

            indicator_matched = False
            if indicator and body:
                indicator_matched = bool(indicator.search(body))

            # 200 with API-shaped content type = strong signal
            is_api_ct = any(k in ct.lower() for k in ("json", "xml", "graphql"))

            # Keep if: 200 + (indicator matched OR API content type),
            #          or 401/403 (auth-gated, still exists),
            #          or 301/302/307/308 (redirect — might reveal backend)
            keep = False
            if status == 200 and (indicator_matched or is_api_ct):
                keep = True
            elif status in (401, 403):
                keep = True
            elif status in (301, 302, 307, 308):
                keep = True
            elif status in (405, 400) and is_api_ct:
                keep = True  # endpoint exists but wrong method
            elif status == 200 and status_signals_endpoint(body, ct):
                keep = True

            if keep:
                findings.append({
                    "path": path,
                    "url": url,
                    "status": status,
                    "content_type": ct[:80],
                    "meaning": meaning,
                    "indicator_matched": indicator_matched,
                    "body_preview": body[:200],
                })

    await asyncio.gather(*[
        _probe(p, m, ind) for p, m, ind in _SPA_BACKEND_PATHS
    ])
    return sorted(findings, key=lambda f: (f["status"], f["path"]))


def status_signals_endpoint(body: str, content_type: str) -> bool:
    """Return True if body/CT suggest this is a real API endpoint, not an SPA fallback."""
    if not body:
        return False
    # SPA fallback HTML will contain <div id="root"> or <html — skip those
    if re.search(r"<div\s+[^>]*id\s*=\s*[\"'](?:root|app|__next)[\"']", body, re.I):
        return False
    if re.match(r"^\s*<!doctype html", body, re.I):
        return False
    # JSON-shaped body
    b = body.strip()
    if b.startswith(("{", "[")):
        return True
    return False


# ---------------------------------------------------------------------------
# Optional: render SPA with Playwright and capture network calls
# ---------------------------------------------------------------------------

async def render_and_capture(
    start_url: str, wait_seconds: int = 5, max_routes: int = 10,
) -> dict[str, Any]:
    """Open the SPA in headless Chromium, record all network traffic during
    initial render. Optionally walks a few common SPA routes to surface more
    API calls.

    Returns {captured_api_calls: [...], rendered_html_length, console_errors}.
    Skipped silently if playwright isn't installed.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"status": "skipped", "reason": "playwright not installed"}

    captured: list[dict[str, Any]] = []
    console_errors: list[str] = []

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True, user_agent=_UA,
            )
            page = await context.new_page()

            async def _on_req(req):
                try:
                    rt = req.resource_type
                    if rt in ("xhr", "fetch"):
                        captured.append({
                            "method": req.method,
                            "url": req.url,
                            "resource_type": rt,
                        })
                except Exception:
                    pass

            page.on("request", lambda r: asyncio.ensure_future(_on_req(r)))
            page.on("console", lambda m: (
                console_errors.append(f"{m.type}: {m.text}"[:200])
                if m.type in ("error", "warning") else None
            ))

            try:
                await page.goto(start_url, wait_until="networkidle", timeout=15000)
                await page.wait_for_timeout(wait_seconds * 1000)
            except Exception as exc:
                logger.debug("spa_render.goto_error", url=start_url, error=str(exc))

            # Try navigating to common SPA routes to capture more APIs
            common_routes = ["/login", "/dashboard", "/settings", "/profile", "/admin", "/users"]
            for route in common_routes[:max_routes]:
                try:
                    target = urljoin(start_url, route)
                    await page.goto(target, wait_until="domcontentloaded", timeout=10000)
                    await page.wait_for_timeout(1500)
                except Exception:
                    continue

            rendered = ""
            try:
                rendered = await page.content()
            except Exception:
                pass

            await browser.close()
    except Exception as exc:
        return {"status": "error", "message": str(exc)[:200]}

    # Dedup captured by (method, url_without_query)
    seen: set[tuple[str, str]] = set()
    dedup: list[dict[str, Any]] = []
    for c in captured:
        url_key = c["url"].split("?")[0]
        k = (c["method"], url_key)
        if k not in seen:
            seen.add(k)
            dedup.append(c)

    return {
        "status": "success",
        "captured_api_calls": dedup[:100],
        "total_captured": len(captured),
        "unique_api_endpoints": len(dedup),
        "rendered_html_length": len(rendered),
        "console_errors": console_errors[:20],
    }
