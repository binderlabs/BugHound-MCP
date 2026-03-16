"""Gotator wrapper — subdomain permutation generator.

Generates permutations from known subdomains + a permutation wordlist.
Output is fed to puredns for resolution and wildcard filtering.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "gotator"
TIMEOUT = 120

# Built-in permutation words (common prefixes/suffixes for subdomain permutation)
_DEFAULT_PERMS = [
    "dev", "staging", "stage", "stg", "prod", "production", "pro",
    "test", "testing", "uat", "qa", "pre", "preprod",
    "api", "app", "admin", "internal", "int", "ext", "external",
    "v1", "v2", "v3", "new", "old", "beta", "alpha",
    "portal", "panel", "dashboard", "cms", "cdn", "static",
    "auth", "login", "sso", "oauth", "mail", "smtp", "mx",
    "db", "database", "sql", "mongo", "redis", "cache",
    "git", "svn", "ci", "cd", "jenkins", "gitlab", "jira",
    "vpn", "proxy", "lb", "ns", "dns", "ntp",
    "backup", "bak", "tmp", "temp", "log", "logs",
    "web", "www", "m", "mobile", "wap",
    "demo", "sandbox", "lab", "try", "trial", "poc",
    "shop", "store", "pay", "billing", "invoice",
    "docs", "doc", "wiki", "help", "support", "kb",
    "status", "monitor", "health", "metrics", "grafana",
]


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    subdomains: list[str],
    depth: int = 1,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Generate permutations from known subdomains.

    Returns permutated subdomain candidates (not yet resolved).
    """
    if not subdomains:
        return ToolResult(
            tool=BINARY, target="", success=True, results=[], result_count=0,
            execution_time_seconds=0,
        )

    # Write subdomains to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="gotator_subs_",
    ) as f:
        f.write("\n".join(subdomains))
        subs_file = f.name

    # Write permutation words to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="gotator_perms_",
    ) as f:
        f.write("\n".join(_DEFAULT_PERMS))
        perms_file = f.name

    args = [
        "-sub", subs_file,
        "-perm", perms_file,
        "-depth", str(min(depth, 2)),  # cap at 2 to avoid explosion
        "-silent",
        "-mindup",  # minimize duplicates
    ]

    try:
        result = await tool_runner.run(
            BINARY, args, target=f"{len(subdomains)} subdomains", timeout=timeout,
        )
    finally:
        Path(subs_file).unlink(missing_ok=True)
        Path(perms_file).unlink(missing_ok=True)

    if result.success and result.results:
        # Deduplicate and filter — remove already-known subdomains
        known = set(s.lower() for s in subdomains)
        perms = sorted({
            line.strip().lower()
            for line in result.results
            if line.strip() and line.strip().lower() not in known
        })
        result.results = perms
        result.result_count = len(perms)

    return result
