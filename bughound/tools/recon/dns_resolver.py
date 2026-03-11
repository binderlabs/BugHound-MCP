"""Async DNS resolver using dnspython.

Resolves A, AAAA, CNAME records for a list of domains.
Detects wildcard DNS by probing random subdomains.
"""

from __future__ import annotations

import asyncio
import random
import string
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import structlog

logger = structlog.get_logger()

_RECORD_TYPES = ["A", "AAAA", "CNAME"]


async def resolve_domains(
    domains: list[str],
    concurrency: int = 50,
) -> dict[str, dict[str, Any]]:
    """Resolve DNS records for a list of domains.

    Returns a dict keyed by domain:
    {
      "sub.example.com": {
        "A": ["1.2.3.4"],
        "AAAA": [],
        "CNAME": ["cdn.example.com"],
        "resolved": True
      }
    }
    """
    sem = asyncio.Semaphore(concurrency)
    results: dict[str, dict[str, Any]] = {}

    async def _resolve_one(domain: str) -> None:
        async with sem:
            records: dict[str, list[str]] = {rt: [] for rt in _RECORD_TYPES}
            resolved = False

            for rtype in _RECORD_TYPES:
                try:
                    answers = await dns.asyncresolver.resolve(domain, rtype)
                    for rdata in answers:
                        records[rtype].append(rdata.to_text())
                        resolved = True
                except (
                    dns.asyncresolver.NXDOMAIN,
                    dns.asyncresolver.NoAnswer,
                    dns.asyncresolver.NoNameservers,
                    dns.exception.Timeout,
                    dns.asyncresolver.LifetimeTimeout,
                    Exception,
                ):
                    continue

            results[domain] = {**records, "resolved": resolved}

    tasks = [_resolve_one(d) for d in domains]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def detect_wildcards(
    base_domains: list[str],
    num_probes: int = 3,
) -> list[dict[str, Any]]:
    """Detect wildcard DNS for a list of base domains.

    For each base domain, resolve N random subdomains.
    If they all resolve to the same IP(s), it's a wildcard.

    Returns list of wildcard records:
    [{"domain": "example.com", "wildcard_ips": ["1.2.3.4"]}]
    """
    wildcards: list[dict[str, Any]] = []

    for base in base_domains:
        random_subs = [
            f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{base}"
            for _ in range(num_probes)
        ]

        ips_per_probe: list[set[str]] = []
        for sub in random_subs:
            try:
                answers = await dns.asyncresolver.resolve(sub, "A")
                ips_per_probe.append({rdata.to_text() for rdata in answers})
            except Exception:
                ips_per_probe.append(set())

        # If all probes resolved and got the same IPs, it's a wildcard
        non_empty = [ips for ips in ips_per_probe if ips]
        if len(non_empty) >= 2 and all(ips == non_empty[0] for ips in non_empty):
            wildcards.append({
                "domain": base,
                "wildcard_ips": sorted(non_empty[0]),
            })
            logger.info("dns.wildcard_detected", domain=base, ips=sorted(non_empty[0]))

    return wildcards
