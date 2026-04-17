"""Cloud bucket/asset discovery — S3, Azure Blob, GCS.

Generates bucket-name permutations from the target domain + known subdomains,
then probes each cloud's public endpoint for existence. Pure aiohttp, no SDK.

Public buckets are a classic bug-bounty P1 source.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_TIMEOUT = aiohttp.ClientTimeout(total=8)

# Common bucket suffixes used by ops teams
_SUFFIXES = [
    "",
    "-backup", "-backups", "-bak",
    "-prod", "-production", "-stg", "-staging", "-dev", "-development",
    "-test", "-tests", "-qa", "-demo",
    "-public", "-private", "-internal",
    "-assets", "-static", "-media", "-images", "-uploads", "-files",
    "-logs", "-log", "-archive", "-archives",
    "-data", "-db", "-dumps",
    "-cdn", "-www", "-web", "-api",
    "-dev2", "-stg2", "-v2",
]

_PREFIXES = [
    "",
    "backup-", "dev-", "staging-", "prod-", "test-",
    "old-", "legacy-", "archive-",
    "internal-", "secure-",
]


def _normalize_basename(s: str) -> str:
    """Strip scheme/TLD/subdomain junk, lowercase, keep alnum+dash."""
    s = s.lower().strip()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r":\d+.*$", "", s)
    # Collapse weird chars; buckets are alnum + dashes (+ dots for S3).
    s = re.sub(r"[^a-z0-9.\-]", "-", s)
    return s.strip("-.")


def generate_names(bases: list[str], max_per_base: int = 60) -> list[str]:
    """Generate candidate bucket names from a list of base strings.

    bases: list of domains / subdomains / org name fragments.
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in bases:
        b = _normalize_basename(raw)
        if not b:
            continue
        # Add full domain variants (org.com, org) — S3 accepts dots
        parts = b.split(".")
        # Just the root label (e.g., telekom from telekom.de)
        roots: set[str] = set()
        if parts:
            roots.add(parts[0])
        # Full domain without dots (e.g., telekomde)
        roots.add("".join(parts))
        # Full domain with dots (valid for S3 path-style)
        roots.add(b)

        base_variants: list[str] = []
        for root in roots:
            if not root:
                continue
            for pre in _PREFIXES:
                for suf in _SUFFIXES:
                    name = f"{pre}{root}{suf}"
                    # S3 bucket name constraints: 3-63 chars, lowercase
                    if 3 <= len(name) <= 63 and name not in seen:
                        seen.add(name)
                        base_variants.append(name)
                        if len(base_variants) >= max_per_base:
                            break
                if len(base_variants) >= max_per_base:
                    break
            if len(base_variants) >= max_per_base:
                break
        out.extend(base_variants)
    return out


# ---------------------------------------------------------------------------
# Per-cloud probers
# ---------------------------------------------------------------------------


async def _probe_s3(
    session: aiohttp.ClientSession, bucket: str,
) -> dict[str, Any] | None:
    """Probe an S3 bucket. Returns finding dict or None."""
    url = f"https://{bucket}.s3.amazonaws.com/"
    try:
        async with session.get(url, timeout=_TIMEOUT, ssl=False, allow_redirects=False) as r:
            if r.status == 404:
                return None
            body = await r.text(errors="replace")
            if r.status == 200:
                listable = "<ListBucketResult" in body or "<Contents>" in body
                return {
                    "cloud": "s3",
                    "bucket": bucket,
                    "url": url,
                    "status": r.status,
                    "exists": True,
                    "public_listable": listable,
                    "severity": "HIGH" if listable else "INFO",
                }
            if r.status == 403:
                return {
                    "cloud": "s3",
                    "bucket": bucket,
                    "url": url,
                    "status": 403,
                    "exists": True,
                    "public_listable": False,
                    "severity": "INFO",  # exists but not listable
                }
            # 301 usually = bucket in other region; still exists
            if r.status in (301, 307):
                return {
                    "cloud": "s3",
                    "bucket": bucket,
                    "url": url,
                    "status": r.status,
                    "exists": True,
                    "public_listable": False,
                    "severity": "INFO",
                    "note": "Redirect — likely different AWS region",
                }
    except Exception:
        pass
    return None


async def _probe_azure(
    session: aiohttp.ClientSession, account: str,
) -> dict[str, Any] | None:
    """Probe Azure Blob storage account."""
    # Azure storage names: 3-24 chars, lowercase alphanumeric
    name = re.sub(r"[^a-z0-9]", "", account)
    if not (3 <= len(name) <= 24):
        return None
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    try:
        async with session.get(url, timeout=_TIMEOUT, ssl=False) as r:
            if r.status == 400:
                # 400 often = account exists but query-string invalid (still probe hit)
                return {
                    "cloud": "azure",
                    "account": name,
                    "url": url,
                    "status": 400,
                    "exists": True,
                    "public_listable": False,
                    "severity": "INFO",
                }
            if r.status == 200:
                body = await r.text(errors="replace")
                listable = "<EnumerationResults" in body
                return {
                    "cloud": "azure",
                    "account": name,
                    "url": url,
                    "status": 200,
                    "exists": True,
                    "public_listable": listable,
                    "severity": "HIGH" if listable else "INFO",
                }
            if r.status == 403:
                return {
                    "cloud": "azure",
                    "account": name,
                    "url": url,
                    "status": 403,
                    "exists": True,
                    "public_listable": False,
                    "severity": "INFO",
                }
    except Exception:
        pass
    return None


async def _probe_gcs(
    session: aiohttp.ClientSession, bucket: str,
) -> dict[str, Any] | None:
    """Probe Google Cloud Storage bucket."""
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        async with session.get(url, timeout=_TIMEOUT, ssl=False) as r:
            if r.status == 404:
                return None
            body = await r.text(errors="replace")
            if r.status == 200:
                listable = "<ListBucketResult" in body
                return {
                    "cloud": "gcs",
                    "bucket": bucket,
                    "url": url,
                    "status": 200,
                    "exists": True,
                    "public_listable": listable,
                    "severity": "HIGH" if listable else "INFO",
                }
            if r.status in (401, 403):
                # Exists but requires auth
                return {
                    "cloud": "gcs",
                    "bucket": bucket,
                    "url": url,
                    "status": r.status,
                    "exists": True,
                    "public_listable": False,
                    "severity": "INFO",
                }
    except Exception:
        pass
    return None


async def _probe_do_spaces(
    session: aiohttp.ClientSession, bucket: str,
) -> dict[str, Any] | None:
    """Probe DigitalOcean Spaces (S3-compatible). Tries nyc3/sfo3/fra1 regions."""
    for region in ("nyc3", "fra1", "sfo3", "ams3", "sgp1"):
        url = f"https://{bucket}.{region}.digitaloceanspaces.com/"
        try:
            async with session.get(
                url, timeout=_TIMEOUT, ssl=False, allow_redirects=False,
            ) as r:
                if r.status == 200:
                    body = await r.text(errors="replace")
                    if "<ListBucketResult" in body:
                        return {
                            "cloud": "do_spaces",
                            "bucket": bucket,
                            "region": region,
                            "url": url,
                            "status": 200,
                            "exists": True,
                            "public_listable": True,
                            "severity": "HIGH",
                        }
                if r.status == 403:
                    return {
                        "cloud": "do_spaces",
                        "bucket": bucket,
                        "region": region,
                        "url": url,
                        "status": 403,
                        "exists": True,
                        "public_listable": False,
                        "severity": "INFO",
                    }
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover(
    domain: str,
    subdomains: list[str] | None = None,
    max_candidates: int = 200,
    concurrency: int = 30,
    clouds: tuple[str, ...] = ("s3", "azure", "gcs", "do_spaces"),
) -> dict[str, Any]:
    """Discover cloud buckets for a domain via name permutation.

    domain: root domain (e.g. 'telekom.de')
    subdomains: optional list of already-discovered subdomains, to mine for
                bucket-name stems (e.g. 'assets.telekom.de' → try 'assets-telekom')
    clouds: which cloud providers to probe
    """
    bases = [domain]
    if subdomains:
        # Extract leftmost labels from subdomains as bucket-name stems
        for sub in subdomains:
            s = sub.lower().strip()
            if s.endswith(f".{domain}"):
                label = s[: -(len(domain) + 1)].replace(".", "-")
                if label and label != "www":
                    bases.append(label)
                    bases.append(f"{label}-{domain.split('.')[0]}")
        # Dedup
        bases = list(dict.fromkeys(bases))[:20]  # cap base stems

    candidates = generate_names(bases)[:max_candidates]
    if not candidates:
        return {"findings": [], "candidates_tested": 0}

    logger.info(
        "cloud_assets.start",
        domain=domain, candidates=len(candidates), clouds=list(clouds),
    )

    sem = asyncio.Semaphore(concurrency)
    findings: list[dict[str, Any]] = []

    async with aiohttp.ClientSession(headers={"User-Agent": _UA}) as session:
        async def _probe_all(name: str) -> None:
            async with sem:
                probes = []
                if "s3" in clouds:
                    probes.append(_probe_s3(session, name))
                if "azure" in clouds:
                    probes.append(_probe_azure(session, name))
                if "gcs" in clouds:
                    probes.append(_probe_gcs(session, name))
                if "do_spaces" in clouds:
                    probes.append(_probe_do_spaces(session, name))
                for coro in asyncio.as_completed(probes):
                    try:
                        r = await coro
                        if r:
                            findings.append(r)
                    except Exception:
                        continue

        await asyncio.gather(*[_probe_all(n) for n in candidates])

    # Summary
    by_cloud: dict[str, int] = {}
    listable: list[dict[str, Any]] = []
    for f in findings:
        c = f.get("cloud", "?")
        by_cloud[c] = by_cloud.get(c, 0) + 1
        if f.get("public_listable"):
            listable.append(f)

    logger.info(
        "cloud_assets.done",
        candidates_tested=len(candidates),
        findings_total=len(findings),
        publicly_listable=len(listable),
        by_cloud=by_cloud,
    )

    return {
        "findings": findings,
        "publicly_listable": listable,
        "candidates_tested": len(candidates),
        "summary": {
            "total": len(findings),
            "listable": len(listable),
            "by_cloud": by_cloud,
        },
    }
