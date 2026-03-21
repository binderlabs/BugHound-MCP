"""Passive subdomain and endpoint sources — pure aiohttp, no external tools.

Free API sources for subdomain enumeration and historical endpoint discovery.
"""

import asyncio
from typing import Any
import aiohttp
import structlog

logger = structlog.get_logger()
_TIMEOUT = aiohttp.ClientTimeout(total=30)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


async def hackertarget(domain: str) -> list[str]:
    """HackerTarget free API — hostsearch."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                text = await r.text()
                if "error" in text.lower() or "API count" in text:
                    return []
                subs = []
                for line in text.strip().split("\n"):
                    parts = line.split(",")
                    if parts and parts[0].strip():
                        subs.append(parts[0].strip().lower())
                return subs
    except Exception as e:
        logger.debug("hackertarget.error", error=str(e))
        return []


async def certspotter(domain: str) -> list[str]:
    """CertSpotter free API — certificate transparency."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                headers={"User-Agent": _UA},
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
                subs = set()
                for cert in data:
                    for name in cert.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            subs.add(name)
                return list(subs)
    except Exception as e:
        logger.debug("certspotter.error", error=str(e))
        return []


async def rapiddns(domain: str) -> list[str]:
    """RapidDNS — scrape subdomain results."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                headers={"User-Agent": _UA},
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                text = await r.text()
                import re
                pattern = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(domain) + r')', re.I)
                matches = pattern.findall(text)
                return list(set(m.lower() for m in matches))
    except Exception as e:
        logger.debug("rapiddns.error", error=str(e))
        return []


async def urlscan_subdomains(domain: str) -> list[str]:
    """URLScan.io — search for subdomains."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
                headers={"User-Agent": _UA},
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
                subs = set()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    host = page.get("domain", "").lower()
                    if host and (host.endswith(f".{domain}") or host == domain):
                        subs.add(host)
                return list(subs)
    except Exception as e:
        logger.debug("urlscan.error", error=str(e))
        return []


async def alienvault_otx_endpoints(domain: str) -> list[str]:
    """AlienVault OTX — historical URLs/endpoints."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=200&page=1",
                headers={"User-Agent": _UA},
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
                urls = []
                for entry in data.get("url_list", []):
                    url = entry.get("url", "")
                    if url:
                        urls.append(url)
                return urls
    except Exception as e:
        logger.debug("alienvault.error", error=str(e))
        return []


async def urlscan_endpoints(domain: str) -> list[str]:
    """URLScan.io — historical endpoints."""
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
                headers={"User-Agent": _UA},
                timeout=_TIMEOUT, ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
                urls = set()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    url = page.get("url", "")
                    if url and domain in url:
                        urls.add(url)
                return list(urls)
    except Exception as e:
        logger.debug("urlscan_endpoints.error", error=str(e))
        return []


async def commoncrawl_endpoints(domain: str) -> list[str]:
    """Common Crawl index — historical endpoints."""
    try:
        async with aiohttp.ClientSession() as s:
            # Get latest index
            async with s.get(
                f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}&output=json&limit=200",
                headers={"User-Agent": _UA},
                timeout=aiohttp.ClientTimeout(total=60), ssl=False,
            ) as r:
                if r.status != 200:
                    return []
                text = await r.text()
                import json
                urls = set()
                for line in text.strip().split("\n"):
                    try:
                        entry = json.loads(line)
                        url = entry.get("url", "")
                        if url:
                            urls.add(url)
                    except Exception:
                        continue
                return list(urls)
    except Exception as e:
        logger.debug("commoncrawl.error", error=str(e))
        return []


async def gather_subdomains(domain: str) -> dict[str, list[str]]:
    """Run all passive subdomain sources in parallel."""
    sources = {
        "hackertarget": hackertarget(domain),
        "certspotter": certspotter(domain),
        "rapiddns": rapiddns(domain),
        "urlscan": urlscan_subdomains(domain),
    }
    results = {}
    tasks = {name: asyncio.create_task(coro) for name, coro in sources.items()}
    for name, task in tasks.items():
        try:
            results[name] = await asyncio.wait_for(task, timeout=30)
        except Exception:
            results[name] = []
    return results


async def gather_endpoints(domain: str) -> dict[str, list[str]]:
    """Run all passive endpoint sources in parallel."""
    sources = {
        "alienvault_otx": alienvault_otx_endpoints(domain),
        "urlscan": urlscan_endpoints(domain),
        "commoncrawl": commoncrawl_endpoints(domain),
    }
    results = {}
    tasks = {name: asyncio.create_task(coro) for name, coro in sources.items()}
    for name, task in tasks.items():
        try:
            results[name] = await asyncio.wait_for(task, timeout=60)
        except Exception:
            results[name] = []
    return results
