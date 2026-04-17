"""GitHub recon — search GitHub code/repos for target leaks.

Uses GitHub REST API (requires token). Finds:
  - Source files mentioning the target domain
  - Org repos (if `target_org` provided) to clone+scan with trufflehog
  - Common secret patterns in matched code

Auth: GITHUB_TOKEN env var OR ~/.gau.toml [github] apikey.
Free GitHub tokens get 30 req/min for code search.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_API = "https://api.github.com"
_TIMEOUT = aiohttp.ClientTimeout(total=30)

# High-signal code search queries. Each one is {domain_var} substituted.
# Goal: find secrets / endpoints / internal infra references.
_CODE_QUERIES = [
    '"{domain}" extension:env',
    '"{domain}" extension:yaml',
    '"{domain}" extension:json',
    '"{domain}" filename:config',
    '"{domain}" filename:credentials',
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" authorization',
    '"{domain}" token',
]


def _token() -> str | None:
    """Resolve GitHub token: env > ~/.gau.toml [github] apikey."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        v = os.environ.get(var, "").strip()
        if v:
            return v
    # Fallback to ~/.gau.toml
    try:
        from bughound.tools.recon.passive_sources import _load_api_keys
        keys = _load_api_keys()
        return keys.get("github") or None
    except Exception:
        return None


def _auth_headers(token: str | None) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "BugHound-recon",
    }
    if token:
        h["Authorization"] = f"token {token}"
    return h


# Patterns we grep in result snippets after search.
_SECRET_PATTERNS = [
    (re.compile(r"(?i)(?:api[_-]?key|apikey)[\"':= ]{1,4}([a-zA-Z0-9_\-]{20,})"), "api_key"),
    (re.compile(r"(?i)secret[_-]?key[\"':= ]{1,4}([a-zA-Z0-9_\-]{20,})"), "secret_key"),
    (re.compile(r"(?i)(?:access|auth)[_-]?token[\"':= ]{1,4}([a-zA-Z0-9_\-\.]{20,})"), "access_token"),
    (re.compile(r"(?i)aws[_-]?access[_-]?key[_-]?id[\"':= ]{1,4}(AKIA[0-9A-Z]{16})"), "aws_key"),
    (re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"), "bearer_token"),
    (re.compile(r"(?i)password[\"':= ]{1,4}([^\s\"']{8,})"), "password"),
]


def _grep_secrets(snippet: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for regex, label in _SECRET_PATTERNS:
        for m in regex.finditer(snippet):
            val = m.group(1)
            # Filter placeholder values
            low = val.lower()
            if low in ("your_api_key", "your_token", "example", "xxxxxxxx", "change_me"):
                continue
            if re.fullmatch(r"[x*]+", val, re.I):
                continue
            found.append({"type": label, "value": val[:80]})
    return found


async def search_code(
    query: str, token: str | None, max_items: int = 30,
) -> list[dict[str, Any]]:
    """One GitHub code search call. Returns hits with snippet and HTML URL."""
    headers = _auth_headers(token)
    params = {"q": query, "per_page": str(min(max_items, 100))}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{_API}/search/code", headers=headers, params=params,
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status == 403:
                    # Rate limited
                    reset = r.headers.get("X-RateLimit-Reset", "?")
                    logger.warning(
                        "github.rate_limit", query=query[:50], reset=reset,
                    )
                    return []
                if r.status == 422:
                    # Invalid search syntax — skip
                    return []
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
                hits = []
                for item in data.get("items", [])[:max_items]:
                    repo = item.get("repository", {})
                    hits.append({
                        "repo": repo.get("full_name", ""),
                        "repo_url": repo.get("html_url", ""),
                        "path": item.get("path", ""),
                        "html_url": item.get("html_url", ""),
                        "snippet": " | ".join(
                            tf.get("fragment", "")[:300]
                            for tf in item.get("text_matches", [])[:3]
                        ),
                    })
                return hits
    except Exception as exc:
        logger.debug("github.search_error", query=query[:50], error=str(exc))
        return []


async def list_org_repos(
    org: str, token: str | None, max_repos: int = 100,
) -> list[dict[str, Any]]:
    """List public repos for an org. Returns [{name, clone_url, html_url}]."""
    if not org:
        return []
    headers = _auth_headers(token)
    repos: list[dict[str, Any]] = []
    page = 1
    try:
        async with aiohttp.ClientSession() as s:
            while len(repos) < max_repos and page <= 10:
                async with s.get(
                    f"{_API}/orgs/{org}/repos",
                    headers=headers,
                    params={"per_page": "100", "page": str(page), "type": "public"},
                    timeout=_TIMEOUT, ssl=False,
                ) as r:
                    if r.status != 200:
                        break
                    data = await r.json(content_type=None)
                    if not data:
                        break
                    for repo in data:
                        repos.append({
                            "name": repo.get("name", ""),
                            "full_name": repo.get("full_name", ""),
                            "clone_url": repo.get("clone_url", ""),
                            "html_url": repo.get("html_url", ""),
                            "description": (repo.get("description") or "")[:200],
                            "stars": repo.get("stargazers_count", 0),
                            "pushed_at": repo.get("pushed_at", ""),
                        })
                page += 1
    except Exception as exc:
        logger.debug("github.list_org_error", org=org, error=str(exc))
    return repos[:max_repos]


async def run_recon(
    domain: str, org: str | None = None, max_items_per_query: int = 10,
) -> dict[str, Any]:
    """Run GitHub recon for a domain. Optional `org` lists the org's repos.

    Returns {
        "code_hits": [ {repo, path, html_url, snippet, secrets} ],
        "org_repos": [ {name, clone_url, ...} ],
        "summary": { queries_run, hits_total, secrets_total },
    }
    """
    token = _token()
    if not token:
        return {
            "code_hits": [],
            "org_repos": [],
            "summary": {
                "status": "no_token",
                "note": "Set GITHUB_TOKEN env or ~/.gau.toml [github] apikey",
            },
        }

    # Fire searches in parallel, but pace them — GitHub gives 30/min for code search
    queries = [q.format(domain=domain) for q in _CODE_QUERIES]
    results: list[list[dict[str, Any]]] = []

    # Sequential with small delay to stay under rate limit (30/min = 2s/query)
    # Parallel would burst and hit 403.
    for q in queries:
        hits = await search_code(q, token, max_items=max_items_per_query)
        results.append(hits)
        await asyncio.sleep(2.5)  # ~24 queries/min — safely under 30

    # Flatten + dedup by html_url
    seen_urls: set[str] = set()
    code_hits: list[dict[str, Any]] = []
    for hits_list, q in zip(results, queries):
        for hit in hits_list:
            url = hit.get("html_url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            hit["query"] = q
            hit["secrets"] = _grep_secrets(hit.get("snippet", ""))
            code_hits.append(hit)

    org_repos = await list_org_repos(org, token) if org else []

    total_secrets = sum(len(h.get("secrets", [])) for h in code_hits)
    return {
        "code_hits": code_hits,
        "org_repos": org_repos,
        "summary": {
            "status": "ok",
            "queries_run": len(queries),
            "hits_total": len(code_hits),
            "secrets_total": total_secrets,
            "org_repo_count": len(org_repos),
        },
    }


async def clone_and_scan_org(
    org: str, output_dir: Path, max_repos: int = 20,
) -> dict[str, Any]:
    """Clone public repos of an org, run trufflehog on them.

    This is heavier — only call when user explicitly wants deep GitHub recon.
    Returns {repos_cloned, verified_secrets}.
    """
    import shutil
    if not shutil.which("git"):
        return {"error": "git not installed"}

    token = _token()
    repos = await list_org_repos(org, token, max_repos=max_repos)
    if not repos:
        return {"error": f"No public repos found for org '{org}'"}

    output_dir.mkdir(parents=True, exist_ok=True)
    cloned: list[str] = []
    for repo in repos:
        clone_url = repo.get("clone_url", "")
        name = repo.get("name", "")
        if not clone_url or not name:
            continue
        target = output_dir / name
        if target.exists():
            cloned.append(str(target))
            continue
        try:
            # Shallow clone to save bandwidth/time
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", clone_url, str(target),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=120)
                if proc.returncode == 0:
                    cloned.append(str(target))
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        except Exception as exc:
            logger.debug("github.clone_error", repo=name, error=str(exc))

    # Run trufflehog on the whole output_dir (filesystem mode)
    verified_secrets: list[dict[str, Any]] = []
    if shutil.which("trufflehog") and cloned:
        try:
            proc = await asyncio.create_subprocess_exec(
                "trufflehog", "filesystem", str(output_dir),
                "--json", "--no-update", "--only-verified",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=600,
                )
                import json as _json
                for line in stdout.decode(errors="replace").splitlines():
                    try:
                        rec = _json.loads(line)
                        verified_secrets.append({
                            "detector": rec.get("DetectorName", ""),
                            "verified": rec.get("Verified", False),
                            "file": rec.get("SourceMetadata", {}).get("Data", {}).get(
                                "Filesystem", {}
                            ).get("file", ""),
                            "raw": rec.get("Raw", "")[:120],
                        })
                    except (_json.JSONDecodeError, AttributeError):
                        continue
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        except Exception as exc:
            logger.debug("github.trufflehog_error", error=str(exc))

    return {
        "org": org,
        "repos_cloned": len(cloned),
        "clone_paths": cloned,
        "verified_secrets": verified_secrets,
        "verified_count": len(verified_secrets),
    }
