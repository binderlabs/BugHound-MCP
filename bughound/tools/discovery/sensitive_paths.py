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
    {"path": "/wp-config.php", "category": "CONFIG_LEAKED"},
    {"path": "/wp-config.php.bak", "category": "CONFIG_LEAKED"},
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
    # Security files
    {"path": "/security.txt", "category": "INFO_LEAK"},
    {"path": "/.well-known/security.txt", "category": "INFO_LEAK"},
    {"path": "/crossdomain.xml", "category": "INFO_LEAK"},
    {"path": "/clientaccesspolicy.xml", "category": "INFO_LEAK"},
    # Interesting files
    {"path": "/package.json", "category": "INFO_LEAK", "validate": lambda b: '"name"' in b and '"version"' in b},
    {"path": "/composer.json", "category": "INFO_LEAK"},
    {"path": "/Dockerfile", "category": "INFO_LEAK", "validate": lambda b: "FROM " in b},
    {"path": "/docker-compose.yml", "category": "INFO_LEAK"},
    {"path": "/.dockerenv", "category": "INFO_LEAK"},
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

    Returns list of found paths with metadata.
    """
    base = base_url.rstrip("/")
    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async def _check_one(entry: dict[str, Any]) -> None:
        async with sem:
            url = f"{base}{entry['path']}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        headers={"User-Agent": "Mozilla/5.0 BugHound/1.0"},
                        ssl=False,
                        allow_redirects=False,
                    ) as resp:
                        if resp.status != 200:
                            return

                        body = await resp.text(errors="replace")
                        clen = resp.content_length or len(body)

                        if clen < 10:
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

    tasks = [_check_one(e) for e in _PATHS]
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
