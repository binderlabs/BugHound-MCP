"""PureDNS wrapper — resolve and bruteforce subdomains with wildcard filtering.

Uses massdns under the hood for fast resolution. Filters wildcard domains
automatically using heuristic algorithm.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from bughound.core import tool_runner
from bughound.schemas.models import ToolError, ToolErrorType, ToolResult

BINARY = "puredns"
TIMEOUT = 600  # 10 minutes for large wordlists

# Wordlist search paths (first found wins)
_WORDLIST_PATHS = [
    Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
    Path("/usr/share/sniper/plugins/dnscan/subdomains-10000.txt"),
    Path.home() / ".recon-mcp/wordlists/best-dns-wordlist.txt",
    Path("/usr/share/wordlists/dns-subdomains.txt"),
]

_RESOLVER_PATHS = [
    Path.home() / ".config/puredns/resolvers.txt",
    Path("/usr/share/puredns/resolvers.txt"),
]


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


def _find_file(paths: list[Path]) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


async def resolve(
    domains: list[str], timeout: int = TIMEOUT,
) -> ToolResult:
    """Resolve a list of domains, filtering wildcards. Returns valid domains."""
    if not domains:
        return ToolResult(
            tool=BINARY, target="", success=True, results=[], result_count=0,
            execution_time_seconds=0,
        )

    resolvers = _find_file(_RESOLVER_PATHS)

    # Write domains to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="puredns_resolve_",
    ) as f:
        f.write("\n".join(domains))
        domains_file = f.name

    args = ["resolve", domains_file, "--quiet"]
    if resolvers:
        args.extend(["-r", str(resolvers)])

    try:
        result = await tool_runner.run(
            BINARY, args, target=f"{len(domains)} domains", timeout=timeout,
        )
    finally:
        Path(domains_file).unlink(missing_ok=True)

    if result.success and result.results:
        # puredns outputs resolved domains one per line
        resolved = sorted({
            line.strip().lower()
            for line in result.results
            if line.strip()
        })
        result.results = resolved
        result.result_count = len(resolved)

    return result


async def bruteforce(
    target: str,
    wordlist: str | None = None,
    timeout: int = TIMEOUT,
) -> ToolResult:
    """Bruteforce subdomains using a wordlist. Returns discovered subdomains."""
    # Find wordlist
    if wordlist:
        wl_path = Path(wordlist)
    else:
        wl_path = _find_file(_WORDLIST_PATHS)

    if not wl_path or not wl_path.exists():
        return ToolResult(
            tool=BINARY, target=target, success=False, results=[],
            result_count=0, execution_time_seconds=0,
            error=ToolError(
                error_type=ToolErrorType.VALIDATION,
                message="No DNS wordlist found",
            ),
        )

    resolvers = _find_file(_RESOLVER_PATHS)

    args = ["bruteforce", str(wl_path), target, "--quiet"]
    if resolvers:
        args.extend(["-r", str(resolvers)])

    result = await tool_runner.run(
        BINARY, args, target=target, timeout=timeout,
    )

    if result.success and result.results:
        subs = sorted({
            line.strip().lower()
            for line in result.results
            if line.strip()
        })
        result.results = subs
        result.result_count = len(subs)

    return result
