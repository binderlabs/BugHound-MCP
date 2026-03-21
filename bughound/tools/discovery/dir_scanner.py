"""Light directory discovery — technology-aware path checking via aiohttp.

NOT full ffuf fuzzing. Fast, focused, no external binary needed.
Checks ~200 common paths + tech-specific paths per host.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Path lists
# ---------------------------------------------------------------------------

COMMON_PATHS: list[str] = [
    # Admin / Auth
    "/admin", "/admin/", "/administrator", "/login", "/dashboard", "/console",
    "/panel", "/manager", "/cpanel", "/webmail",
    # API
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/internal",
    # GraphQL
    "/graphql", "/graphiql", "/playground", "/altair",
    # Documentation
    "/swagger", "/swagger-ui", "/swagger.json", "/api-docs", "/openapi.json",
    "/redoc", "/docs",
    # Debug / Dev
    "/debug", "/trace", "/test", "/testing", "/staging", "/dev",
    # Backup / Archive
    "/backup", "/backups", "/old", "/archive", "/temp", "/tmp",
    # Upload / Static
    "/upload", "/uploads", "/files", "/media", "/static", "/assets",
    # Config
    "/config", "/configuration", "/settings", "/setup",
    # Health / Status
    "/status", "/health", "/healthcheck", "/ping", "/info", "/version",
    # Monitoring
    "/metrics", "/monitoring", "/prometheus", "/grafana",
    # Database admin
    "/phpmyadmin", "/pma", "/adminer", "/dbadmin",
    # WordPress
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    # CGI
    "/cgi-bin", "/scripts", "/bin",
    # Well-known
    "/.well-known", "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    # Discovery files
    "/sitemap.xml", "/robots.txt", "/crossdomain.xml", "/security.txt",
    # Server status
    "/server-status", "/server-info", "/nginx_status",
    # Spring / Java
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    # ASP.NET
    "/elmah.axd", "/trace.axd", "/glimpse",
    # Laravel / PHP
    "/telescope", "/horizon", "/nova", "/pulse",
    # Rails
    "/rails/info", "/rails/info/properties", "/rails/info/routes",
    # Common files
    "/.env", "/.git/HEAD", "/.gitignore", "/.htaccess",
    "/package.json", "/composer.json", "/Gemfile",
    "/Dockerfile", "/docker-compose.yml",
    "/phpinfo.php", "/info.php",
    "/wp-config.php.bak", "/web.config",
    # Error pages
    "/404", "/500", "/error",
    # CMS discovery
    "/spip.php", "/spip/", "/joomla/", "/drupal/",
    "/typo3/", "/magento/", "/umbraco/",
    # Source control
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/", "/.bzr/",
    "/.git/config", "/.git/logs/HEAD",
    # CI/CD
    "/.github/", "/.gitlab-ci.yml", "/Jenkinsfile",
    "/.circleci/config.yml", "/.travis.yml",
    # Environment / secrets
    "/.env.bak", "/.env.old", "/.env.local", "/.env.production",
    "/.env.staging", "/.env.development",
    "/config.json", "/config.yml", "/config.yaml",
    "/secrets.json", "/credentials.json",
    "/application.yml", "/application.properties",
    # Backup files
    "/backup.sql", "/dump.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/site.zip",
    "/.bak", "/db.sqlite3", "/data.db",
    # Log files
    "/error.log", "/access.log", "/debug.log",
    "/application.log", "/app.log",
    # AWS / Cloud
    "/.aws/credentials", "/aws.yml",
    "/firebase.json", "/.firebase",
    # Editor backup / temp files
    "/index.php~", "/config.php~", "/settings.php~",
    "/wp-config.php~", "/configuration.php~",
    "/.htaccess~", "/web.config~",
    "/index.php.bak", "/config.php.bak", "/settings.php.bak",
    "/index.php.old", "/config.php.old",
    "/index.php.swp", "/.index.php.swp",
    "/index.php.orig", "/config.php.orig",
    "/index.php.save", "/config.php.save",
    # Source code backups
    "/app.py.bak", "/main.py.bak", "/server.js.bak",
    "/application.properties.bak",
    "/.env.bak.1", "/.env.backup",
    "/test.php~", "/admin.php~",
    # IDE / Editor files
    "/.idea/", "/.vscode/", "/.project",
    "/nbproject/", "/.settings/",
    # Docker
    "/docker-compose.yaml", "/.dockerignore",
    "/Dockerfile.bak",
    # Other sensitive
    "/id_rsa", "/.ssh/authorized_keys",
    "/server.key", "/server.crt", "/private.key",
    "/.npmrc", "/.yarnrc", "/yarn.lock",
    "/Makefile", "/Gruntfile.js", "/Gulpfile.js",
    "/Procfile", "/Vagrantfile",
]

WORDPRESS_PATHS: list[str] = [
    "/wp-json", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/xmlrpc.php", "/wp-cron.php",
    "/wp-content/debug.log", "/wp-content/plugins/", "/wp-content/themes/",
    "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.txt",
    "/readme.html", "/license.txt",
]

API_PATHS: list[str] = [
    "/api/swagger", "/api/docs", "/api/redoc",
    "/api/graphql", "/api/health", "/api/status", "/api/version",
    "/api/config", "/api/debug", "/api/test",
    "/api/admin", "/api/internal", "/api/private",
    "/v1", "/v2", "/v3", "/v1/docs", "/v2/docs",
]

SPRING_PATHS: list[str] = [
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/metrics",
    "/actuator/configprops", "/actuator/threaddump", "/actuator/heapdump",
    "/actuator/loggers", "/actuator/scheduledtasks",
    "/console", "/h2-console", "/swagger-resources",
]

NODE_PATHS: list[str] = [
    "/graphql", "/playground", "/altair",
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/package.json", "/package-lock.json",
    "/node_modules",
]

DOTNET_PATHS: list[str] = [
    "/elmah.axd", "/trace.axd", "/glimpse",
    "/web.config", "/web.config.bak", "/web.config.old",
    "/applicationhost.config",
    "/_blazor", "/_framework/blazor.boot.json",
    "/swagger/index.html", "/swagger/v1/swagger.json",
    "/hangfire", "/hangfire/dashboard",
    "/elmah", "/elmah.axd",
    "/error.aspx", "/errorlog.axd",
    "/bin/web.dll",
    # ASP.NET sitemap / help / discovery
    "/SiteMap.aspx", "/Sitemap.aspx", "/sitemap.aspx",
    "/Help.aspx", "/help.aspx",
    "/Default.aspx", "/default.aspx",
    "/LogIn.aspx", "/Login.aspx", "/login.aspx",
    "/Register.aspx", "/register.aspx",
    "/Admin.aspx", "/admin.aspx",
    # IIS-specific
    "/iisstart.htm", "/iishelp/",
    "/aspnet_client/", "/ScriptResource.axd",
    "/WebResource.axd",
    # SignalR / MVC
    "/signalr/hubs", "/signalr/negotiate",
    "/_vti_bin/", "/_vti_cnf/",
]

JAVA_PATHS: list[str] = [
    "/manager/html", "/manager/status",  # Tomcat
    "/host-manager/html",
    "/solr/admin", "/solr/#/",  # Solr
    "/jenkins", "/jenkins/login", "/jenkins/script",  # Jenkins
    "/jmx-console",  # JBoss
    "/web-console",  # JBoss
    "/invoker/JMXInvokerServlet",
    "/h2-console", "/h2-console/",  # H2
    "/jolokia", "/jolokia/list",  # Jolokia
    "/struts/webconsole.html",  # Struts
    "/axis2/axis2-admin/",  # Axis2
    "/activemq/", "/admin/queues.jsp",  # ActiveMQ
]

PYTHON_PATHS: list[str] = [
    "/__debug__/", "/__debug__/sql/",  # Django debug toolbar
    "/admin/", "/admin/login/",  # Django admin
    "/_debug_toolbar/",
    "/flask-admin/", "/flask-debugtoolbar/",
    "/jupyter/", "/notebooks/",
    "/flower/",  # Celery monitor
    "/sentry/",
]

PHP_PATHS: list[str] = [
    "/info.php", "/phpinfo.php", "/test.php",
    "/php-info.php", "/i.php",
    "/adminer.php", "/adminer/",
    "/phpmyadmin/", "/pma/",
    "/.htpasswd", "/.htaccess.bak",
    "/composer.lock",
    "/storage/logs/laravel.log",  # Laravel
    "/debug/default/view",  # Yii
    "/typo3/", "/typo3conf/",  # TYPO3
    "/wp-config.php~",  # Editor backup
    "/config.php.bak", "/config.inc.php.bak",
]

# Interesting status codes (not 404)
_INTERESTING_STATUSES = {200, 301, 302, 401, 403, 405}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def scan_directories(
    hosts: list[dict[str, Any]],
    technologies: list[dict[str, Any]] | None = None,
    concurrency: int = 10,
    timeout: int = 10,
) -> dict[str, list[dict[str, Any]]]:
    """Scan directories for each host. Returns {hostname: [results]}.

    hosts: list of dicts with at least 'host' and 'url' keys.
    technologies: list from hosts/technologies.json for tech-aware paths.
    concurrency: max concurrent requests per host.
    timeout: per-request timeout in seconds.
    """
    # Build tech lookup: hostname -> set of tech strings
    tech_map: dict[str, set[str]] = {}
    for t in (technologies or []):
        if isinstance(t, dict):
            h = t.get("host", "")
            techs = {tech.lower() for tech in t.get("technologies", [])}
            if h:
                tech_map[h] = techs

    results: dict[str, list[dict[str, Any]]] = {}

    for host_data in hosts:
        hostname = host_data.get("host", "")
        base_url = host_data.get("url", "")
        if not hostname or not base_url:
            continue

        # Strip trailing slash
        base_url = base_url.rstrip("/")

        # Build path list
        paths = list(COMMON_PATHS)
        host_techs = tech_map.get(hostname, set())
        tech_str = " ".join(host_techs)

        if "wordpress" in tech_str or "wp-" in tech_str:
            paths.extend(WORDPRESS_PATHS)
        if any(k in tech_str for k in ("api", "rest", "swagger", "fastapi", "flask")):
            paths.extend(API_PATHS)
        if any(k in tech_str for k in ("spring", "java", "tomcat")):
            paths.extend(SPRING_PATHS)
        if any(k in tech_str for k in ("node", "express", "next.js", "nuxt")):
            paths.extend(NODE_PATHS)
        if any(k in tech_str for k in ("asp.net", ".net", "iis", "blazor")):
            paths.extend(DOTNET_PATHS)
        if any(k in tech_str for k in ("tomcat", "jboss", "wildfly", "solr", "jenkins", "jolokia")):
            paths.extend(JAVA_PATHS)
        if any(k in tech_str for k in ("python", "django", "flask", "gunicorn", "uvicorn")):
            paths.extend(PYTHON_PATHS)
        if any(k in tech_str for k in ("php", "laravel", "wordpress", "drupal", "joomla", "apache")):
            paths.extend(PHP_PATHS)

        # Deduplicate
        paths = sorted(set(paths))

        host_results = await _scan_host(base_url, hostname, paths, concurrency, timeout)
        if host_results:
            results[hostname] = host_results

    return results


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


async def _scan_host(
    base_url: str,
    hostname: str,
    paths: list[str],
    concurrency: int,
    timeout: int,
) -> list[dict[str, Any]]:
    """Check all paths for a single host."""
    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = []

    conn = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(
        connector=conn,
        timeout=client_timeout,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
    ) as session:
        tasks = [
            _check_path(session, sem, base_url, path)
            for path in paths
        ]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

    for r in completed:
        if isinstance(r, dict):
            results.append(r)

    # Sort by status code
    results.sort(key=lambda x: (x["status_code"], x["path"]))
    return results


async def _check_path(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    base_url: str,
    path: str,
) -> dict[str, Any] | None:
    """Check a single path. Returns result dict or None if 404/error."""
    url = f"{base_url}{path}"
    async with sem:
        try:
            async with session.head(url, allow_redirects=False) as resp:
                status = resp.status
                if status not in _INTERESTING_STATUSES:
                    return None

                # For 200/401/403, get content length from HEAD
                content_length = resp.content_length or 0
                redirect_location = str(resp.headers.get("Location", "")) if status in (301, 302) else ""

                return {
                    "path": path,
                    "url": url,
                    "status_code": status,
                    "content_length": content_length,
                    "redirect_location": redirect_location,
                }

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        except Exception:
            return None
