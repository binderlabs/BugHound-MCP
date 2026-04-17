"""Sensitive path checker — pure aiohttp, no external binary.

Checks ~70 high-value paths on live hosts for exposed files,
admin panels, API docs, debug endpoints, backups, and git leaks.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Path definitions grouped by category
# ---------------------------------------------------------------------------

_PATHS: list[dict[str, Any]] = [
    # Git/SVN exposure
    {"path": "/.git/HEAD", "category": "GIT_EXPOSED", "validate": lambda b: b.startswith("ref: ")},
    {"path": "/.git/config", "category": "GIT_EXPOSED", "validate": lambda b: "[core]" in b},
    {"path": "/.svn/entries", "category": "SVN_EXPOSED"},
    {"path": "/.svn/wc.db", "category": "SVN_EXPOSED"},
    # Env / config leaks
    {"path": "/.env", "category": "ENV_LEAKED", "validate": lambda b: "=" in b and len(b) < 50000},
    {"path": "/.env.bak", "category": "ENV_LEAKED"},
    {"path": "/.env.local", "category": "ENV_LEAKED"},
    {"path": "/.env.production", "category": "ENV_LEAKED"},
    {"path": "/config.json", "category": "CONFIG_LEAKED", "validate": lambda b: b.strip().startswith("{")},
    {"path": "/config.yaml", "category": "CONFIG_LEAKED"},
    {"path": "/config.yml", "category": "CONFIG_LEAKED"},
    {"path": "/config.php", "category": "CONFIG_LEAKED"},
    {"path": "/wp-config.php", "category": "CONFIG_LEAKED"},
    {"path": "/wp-config.php.bak", "category": "CONFIG_LEAKED"},
    {"path": "/wp-config.php.old", "category": "CONFIG_LEAKED"},
    {"path": "/web.config", "category": "CONFIG_LEAKED"},
    {"path": "/.htaccess", "category": "CONFIG_LEAKED"},
    {"path": "/.htpasswd", "category": "CONFIG_LEAKED"},
    # API documentation
    {"path": "/swagger.json", "category": "SWAGGER_EXPOSED", "validate": lambda b: '"paths"' in b or '"openapi"' in b},
    {"path": "/swagger-ui.html", "category": "SWAGGER_EXPOSED"},
    {"path": "/swagger-ui/", "category": "SWAGGER_EXPOSED"},
    {"path": "/api-docs", "category": "SWAGGER_EXPOSED"},
    {"path": "/openapi.json", "category": "SWAGGER_EXPOSED", "validate": lambda b: '"paths"' in b},
    {"path": "/openapi.yaml", "category": "SWAGGER_EXPOSED"},
    {"path": "/v1/api-docs", "category": "SWAGGER_EXPOSED"},
    {"path": "/v2/api-docs", "category": "SWAGGER_EXPOSED"},
    {"path": "/v3/api-docs", "category": "SWAGGER_EXPOSED"},
    {"path": "/graphql", "category": "GRAPHQL_INTROSPECTION"},
    {"path": "/graphiql", "category": "GRAPHQL_INTROSPECTION"},
    {"path": "/altair", "category": "GRAPHQL_INTROSPECTION"},
    {"path": "/playground", "category": "GRAPHQL_INTROSPECTION"},
    {"path": "/api/swagger", "category": "SWAGGER_EXPOSED"},
    {"path": "/docs", "category": "SWAGGER_EXPOSED"},
    {"path": "/redoc", "category": "SWAGGER_EXPOSED"},
    # Debug / admin
    {"path": "/phpinfo.php", "category": "DEBUG_ENABLED", "validate": lambda b: "phpinfo()" in b or "PHP Version" in b},
    {"path": "/info.php", "category": "DEBUG_ENABLED"},
    {"path": "/server-status", "category": "DEBUG_ENABLED", "validate": lambda b: "Apache Server Status" in b},
    {"path": "/server-info", "category": "DEBUG_ENABLED"},
    {"path": "/.DS_Store", "category": "INFO_LEAK"},
    {"path": "/Thumbs.db", "category": "INFO_LEAK"},
    {"path": "/debug", "category": "DEBUG_ENABLED"},
    {"path": "/debug/default/view", "category": "DEBUG_ENABLED"},
    {"path": "/_debug_toolbar/", "category": "DEBUG_ENABLED"},
    {"path": "/trace", "category": "DEBUG_ENABLED"},
    {"path": "/elmah.axd", "category": "DEBUG_ENABLED"},
    {"path": "/telescope", "category": "DEBUG_ENABLED"},
    {"path": "/horizon", "category": "ADMIN_PANEL"},
    {"path": "/admin", "category": "ADMIN_PANEL"},
    {"path": "/admin/", "category": "ADMIN_PANEL"},
    {"path": "/administrator", "category": "ADMIN_PANEL"},
    {"path": "/wp-admin/", "category": "ADMIN_PANEL"},
    {"path": "/actuator", "category": "SPRING_ACTUATOR", "validate": lambda b: '"_links"' in b},
    {"path": "/actuator/health", "category": "SPRING_ACTUATOR"},
    {"path": "/actuator/env", "category": "SPRING_ACTUATOR"},
    {"path": "/console", "category": "DEBUG_ENABLED"},
    {"path": "/rails/info", "category": "DEBUG_ENABLED"},
    {"path": "/rails/info/properties", "category": "DEBUG_ENABLED"},
    # Backups
    {"path": "/backup.sql", "category": "BACKUP_FOUND"},
    {"path": "/backup.zip", "category": "BACKUP_FOUND"},
    {"path": "/db.sql", "category": "BACKUP_FOUND"},
    {"path": "/dump.sql", "category": "BACKUP_FOUND"},
    {"path": "/backup.tar.gz", "category": "BACKUP_FOUND"},
    {"path": "/site.tar.gz", "category": "BACKUP_FOUND"},
    # Robots (check for juicy disallowed paths)
    {"path": "/robots.txt", "category": "INFO_LEAK"},
    # Security files
    {"path": "/security.txt", "category": "INFO_LEAK"},
    {"path": "/.well-known/security.txt", "category": "INFO_LEAK"},
    {"path": "/crossdomain.xml", "category": "INFO_LEAK"},
    {"path": "/clientaccesspolicy.xml", "category": "INFO_LEAK"},
    # Interesting files
    {"path": "/package.json", "category": "INFO_LEAK", "validate": lambda b: '"name"' in b and '"version"' in b},
    {"path": "/package-lock.json", "category": "INFO_LEAK", "validate": lambda b: '"lockfileVersion"' in b},
    {"path": "/composer.json", "category": "INFO_LEAK"},
    {"path": "/composer.lock", "category": "INFO_LEAK"},
    {"path": "/Dockerfile", "category": "INFO_LEAK", "validate": lambda b: "FROM " in b},
    {"path": "/docker-compose.yml", "category": "INFO_LEAK"},
    {"path": "/docker-compose.yaml", "category": "INFO_LEAK"},
    {"path": "/.dockerenv", "category": "INFO_LEAK"},
    {"path": "/.dockerignore", "category": "INFO_LEAK"},
    # --- BB-grade additions ---------------------------------------------
    # Extended env / config variants
    {"path": "/.env.dev", "category": "ENV_LEAKED"},
    {"path": "/.env.development", "category": "ENV_LEAKED"},
    {"path": "/.env.staging", "category": "ENV_LEAKED"},
    {"path": "/.env.test", "category": "ENV_LEAKED"},
    {"path": "/.env.example", "category": "ENV_LEAKED"},
    {"path": "/.env.sample", "category": "ENV_LEAKED"},
    {"path": "/.env.old", "category": "ENV_LEAKED"},
    {"path": "/.env.save", "category": "ENV_LEAKED"},
    {"path": "/env.js", "category": "ENV_LEAKED"},
    {"path": "/config.js", "category": "CONFIG_LEAKED"},
    {"path": "/appsettings.json", "category": "CONFIG_LEAKED", "validate": lambda b: b.strip().startswith("{")},
    {"path": "/appsettings.Development.json", "category": "CONFIG_LEAKED"},
    {"path": "/appsettings.Production.json", "category": "CONFIG_LEAKED"},
    {"path": "/web.config.bak", "category": "CONFIG_LEAKED"},
    {"path": "/web.config.old", "category": "CONFIG_LEAKED"},
    {"path": "/config.inc.php", "category": "CONFIG_LEAKED"},
    {"path": "/config.inc.php.bak", "category": "CONFIG_LEAKED"},
    {"path": "/settings.py", "category": "CONFIG_LEAKED", "validate": lambda b: "SECRET_KEY" in b or "DATABASES" in b},
    {"path": "/local_settings.py", "category": "CONFIG_LEAKED"},
    {"path": "/application.yml", "category": "CONFIG_LEAKED"},
    {"path": "/application.yaml", "category": "CONFIG_LEAKED"},
    {"path": "/application.properties", "category": "CONFIG_LEAKED"},
    {"path": "/.yarnrc", "category": "CONFIG_LEAKED"},
    {"path": "/.npmrc", "category": "CONFIG_LEAKED"},
    {"path": "/.pypirc", "category": "CONFIG_LEAKED"},
    {"path": "/firebase.json", "category": "CONFIG_LEAKED"},
    {"path": "/.firebaserc", "category": "CONFIG_LEAKED"},
    # Credentials / cloud
    {"path": "/.aws/credentials", "category": "CRED_LEAK"},
    {"path": "/.aws/config", "category": "CRED_LEAK"},
    {"path": "/.ssh/id_rsa", "category": "CRED_LEAK"},
    {"path": "/.ssh/known_hosts", "category": "CRED_LEAK"},
    {"path": "/.gcp/credentials.json", "category": "CRED_LEAK"},
    {"path": "/credentials.json", "category": "CRED_LEAK"},
    {"path": "/secrets.json", "category": "CRED_LEAK"},
    {"path": "/secrets.yaml", "category": "CRED_LEAK"},
    {"path": "/secrets.yml", "category": "CRED_LEAK"},
    # Git extended + other VCS
    {"path": "/.git/logs/HEAD", "category": "GIT_EXPOSED"},
    {"path": "/.git/index", "category": "GIT_EXPOSED"},
    {"path": "/.git/packed-refs", "category": "GIT_EXPOSED"},
    {"path": "/.git/COMMIT_EDITMSG", "category": "GIT_EXPOSED"},
    {"path": "/.gitignore", "category": "INFO_LEAK"},
    {"path": "/.gitconfig", "category": "INFO_LEAK"},
    {"path": "/.gitattributes", "category": "INFO_LEAK"},
    {"path": "/.hg/store/00manifest.i", "category": "INFO_LEAK"},
    {"path": "/.bzr/branch/branch.conf", "category": "INFO_LEAK"},
    # Common backup patterns (whole-site dumps)
    {"path": "/backup.tar", "category": "BACKUP_FOUND"},
    {"path": "/backup.zip", "category": "BACKUP_FOUND"},
    {"path": "/backup.tgz", "category": "BACKUP_FOUND"},
    {"path": "/backup.7z", "category": "BACKUP_FOUND"},
    {"path": "/website.zip", "category": "BACKUP_FOUND"},
    {"path": "/www.zip", "category": "BACKUP_FOUND"},
    {"path": "/htdocs.zip", "category": "BACKUP_FOUND"},
    {"path": "/public_html.zip", "category": "BACKUP_FOUND"},
    {"path": "/site.zip", "category": "BACKUP_FOUND"},
    {"path": "/old.zip", "category": "BACKUP_FOUND"},
    {"path": "/archive.tar.gz", "category": "BACKUP_FOUND"},
    {"path": "/db_backup.sql", "category": "BACKUP_FOUND"},
    {"path": "/database.sql", "category": "BACKUP_FOUND"},
    {"path": "/mysql.sql", "category": "BACKUP_FOUND"},
    {"path": "/database.sql.gz", "category": "BACKUP_FOUND"},
    {"path": "/dump.sql.gz", "category": "BACKUP_FOUND"},
    # IDE / editor artifacts
    {"path": "/.idea/workspace.xml", "category": "INFO_LEAK"},
    {"path": "/.vscode/settings.json", "category": "INFO_LEAK"},
    {"path": "/.project", "category": "INFO_LEAK"},
    # PHP / language-specific sensitive
    {"path": "/index.php.bak", "category": "BACKUP_FOUND"},
    {"path": "/index.php~", "category": "BACKUP_FOUND"},
    {"path": "/index.php.save", "category": "BACKUP_FOUND"},
    {"path": "/index.php.swp", "category": "BACKUP_FOUND"},
    {"path": "/phpmyadmin/", "category": "ADMIN_PANEL"},
    {"path": "/pma/", "category": "ADMIN_PANEL"},
    {"path": "/adminer.php", "category": "ADMIN_PANEL"},
    # Java / Spring additional
    {"path": "/actuator/loggers", "category": "SPRING_ACTUATOR"},
    {"path": "/actuator/mappings", "category": "SPRING_ACTUATOR"},
    {"path": "/actuator/beans", "category": "SPRING_ACTUATOR"},
    {"path": "/actuator/heapdump", "category": "SPRING_ACTUATOR"},
    {"path": "/actuator/httptrace", "category": "SPRING_ACTUATOR"},
    {"path": "/actuator/threaddump", "category": "SPRING_ACTUATOR"},
    # Node / Next.js / React dev leaks
    {"path": "/_next/", "category": "INFO_LEAK"},
    {"path": "/_next/static/", "category": "INFO_LEAK"},
    {"path": "/.next/BUILD_ID", "category": "INFO_LEAK"},
    {"path": "/__webpack_hmr", "category": "DEBUG_ENABLED"},
    # Misc high-signal
    {"path": "/sitemap.xml", "category": "INFO_LEAK"},
    {"path": "/sitemap_index.xml", "category": "INFO_LEAK"},
    {"path": "/ads.txt", "category": "INFO_LEAK"},
    {"path": "/humans.txt", "category": "INFO_LEAK"},
    {"path": "/.well-known/openid-configuration", "category": "INFO_LEAK", "validate": lambda b: '"issuer"' in b},
    {"path": "/.well-known/oauth-authorization-server", "category": "INFO_LEAK"},
    {"path": "/.well-known/apple-app-site-association", "category": "INFO_LEAK"},
    {"path": "/.well-known/assetlinks.json", "category": "INFO_LEAK"},
    # CI/CD artifacts
    {"path": "/.travis.yml", "category": "INFO_LEAK"},
    {"path": "/.circleci/config.yml", "category": "INFO_LEAK"},
    {"path": "/.gitlab-ci.yml", "category": "INFO_LEAK"},
    {"path": "/.github/workflows/", "category": "INFO_LEAK"},
    {"path": "/Jenkinsfile", "category": "INFO_LEAK"},
    {"path": "/bitbucket-pipelines.yml", "category": "INFO_LEAK"},
]

# Common 404 body patterns to filter false positives
_FALSE_POSITIVE_RE = re.compile(
    r"(page not found|404 not found|not found|error 404|does not exist|"
    r"the page you|we couldn't find|nothing here|no such page)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_host(
    base_url: str,
    concurrency: int = 10,
    timeout: int = 8,
) -> list[dict[str, Any]]:
    """Check all sensitive paths on a single host.

    Uses baseline comparison: requests a random nonexistent path first,
    then filters out responses that match the baseline (catch-all routes).

    Returns list of found paths with metadata.
    """
    base = base_url.rstrip("/")
    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    # --- Baseline: request a random path to detect catch-all responses ---
    import hashlib, time
    random_slug = hashlib.md5(f"{base}{time.time()}".encode()).hexdigest()[:16]
    baseline_status = 0
    baseline_length = 0
    baseline_body_hash = ""

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base}/bughound_baseline_{random_slug}",
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                ssl=False,
                allow_redirects=False,
            ) as resp:
                baseline_status = resp.status
                body = await resp.text(errors="replace")
                baseline_length = len(body)
                baseline_body_hash = hashlib.md5(body[:5000].encode()).hexdigest()
    except Exception:
        pass

    # Build dynamic backup paths from hostname
    try:
        from urllib.parse import urlparse
        hostname = urlparse(base).hostname or ""
        name_underscore = hostname.replace(".", "_")
        name_short = hostname.rsplit(".", 1)[0].replace(".", "_") if "." in hostname else hostname
    except Exception:
        name_underscore = ""
        name_short = ""

    dynamic_paths = _PATHS.copy()
    if name_underscore:
        dynamic_paths.append({"path": f"/{name_underscore}.sql", "category": "BACKUP_FOUND"})
        dynamic_paths.append({"path": f"/{name_underscore}.zip", "category": "BACKUP_FOUND"})
    if name_short and name_short != name_underscore:
        dynamic_paths.append({"path": f"/{name_short}.sql", "category": "BACKUP_FOUND"})
        dynamic_paths.append({"path": f"/{name_short}.zip", "category": "BACKUP_FOUND"})

    async def _check_one(entry: dict[str, Any]) -> None:
        async with sem:
            url = f"{base}{entry['path']}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                        ssl=False,
                        allow_redirects=False,
                    ) as resp:
                        if resp.status != 200:
                            return

                        body = await resp.text(errors="replace")
                        clen = resp.content_length or len(body)

                        if clen < 10:
                            return

                        # Baseline comparison: if this response looks like the
                        # catch-all/404 response, skip it (unless it has a validator)
                        import hashlib as _hl
                        body_hash = _hl.md5(body[:5000].encode()).hexdigest()
                        if (
                            baseline_status == 200
                            and body_hash == baseline_body_hash
                            and not entry.get("validate")
                        ):
                            return

                        # Also filter by similar content length (within 5%)
                        if (
                            baseline_status == 200
                            and baseline_length > 0
                            and not entry.get("validate")
                            and abs(clen - baseline_length) / max(baseline_length, 1) < 0.05
                        ):
                            return

                        # Check for false positive (generic 404 page)
                        if _FALSE_POSITIVE_RE.search(body[:2000]):
                            return

                        # Custom validation if defined
                        validator = entry.get("validate")
                        if validator and not validator(body[:10000]):
                            return

                        findings.append({
                            "path": entry["path"],
                            "url": url,
                            "category": entry["category"],
                            "status_code": resp.status,
                            "content_length": clen,
                        })
            except Exception:
                pass

    tasks = [_check_one(e) for e in dynamic_paths]
    await asyncio.gather(*tasks)

    findings.sort(key=lambda f: f["path"])
    return findings


async def check_hosts(
    host_urls: list[str],
    concurrency_per_host: int = 10,
    max_hosts: int = 30,
) -> dict[str, list[dict[str, Any]]]:
    """Check sensitive paths on multiple hosts.

    Returns: {host_url: [findings]}
    """
    results: dict[str, list[dict[str, Any]]] = {}

    for url in host_urls[:max_hosts]:
        try:
            findings = await check_host(url, concurrency=concurrency_per_host)
            if findings:
                results[url] = findings
        except Exception:
            pass

    return results
