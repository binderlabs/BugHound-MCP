"""Subdomain takeover detection via CNAME fingerprint matching.

Checks dead subdomains for dangling CNAMEs pointing to deprovisioned services.
Uses nuclei takeover templates if available, falls back to CNAME + HTTP fingerprinting.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import aiohttp
import dns.asyncresolver
import dns.exception
import structlog

from bughound.core import tool_runner

logger = structlog.get_logger()

# CNAME suffix -> (service name, HTTP fingerprint in response body)
_TAKEOVER_FINGERPRINTS: dict[str, tuple[str, str]] = {
    ".herokuapp.com": ("Heroku", "No such app"),
    ".herokudns.com": ("Heroku", "No such app"),
    ".s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    ".s3-website": ("AWS S3", "NoSuchBucket"),
    ".ghost.io": ("Ghost", "Site not found"),
    ".github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    ".shopifycloud.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    ".myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    ".azurewebsites.net": ("Azure", "404 Web Site not found"),
    ".cloudapp.net": ("Azure", "404 Web Site not found"),
    ".trafficmanager.net": ("Azure", "404 Web Site not found"),
    ".cloudfront.net": ("CloudFront", "Bad Request"),
    ".fastly.net": ("Fastly", "Fastly error"),
    ".pantheonsite.io": ("Pantheon", "404 error unknown site"),
    ".zendesk.com": ("Zendesk", "Help Center Closed"),
    ".teamwork.com": ("Teamwork", "Oops"),
    ".unbounce.com": ("Unbounce", "The requested URL was not found"),
    ".surge.sh": ("Surge", "project not found"),
    ".bitbucket.io": ("Bitbucket", "Repository not found"),
    ".wordpress.com": ("WordPress.com", "doesn't exist"),
    ".tumblr.com": ("Tumblr", "There's nothing here"),
    ".fly.dev": ("Fly.io", "404 Not Found"),
    ".netlify.app": ("Netlify", "Not Found"),
    ".vercel.app": ("Vercel", "NOT_FOUND"),
    ".webflow.io": ("Webflow", "page not found"),
}


async def check_takeovers(
    dead_subdomains: list[str],
    dns_records: dict[str, dict[str, Any]] | None = None,
    max_checks: int = 100,
) -> list[dict[str, Any]]:
    """Check dead subdomains for takeover potential.

    Args:
        dead_subdomains: Subdomains that didn't return a live HTTP response.
        dns_records: Pre-resolved DNS data (optional, will resolve if missing).
        max_checks: Max subdomains to check.

    Returns list of takeover candidates.
    """
    candidates: list[dict[str, Any]] = []

    for sub in dead_subdomains[:max_checks]:
        # Get CNAME record
        cname = None
        if dns_records and sub in dns_records:
            cnames = dns_records[sub].get("CNAME", [])
            if cnames:
                cname = cnames[0].rstrip(".")
        else:
            cname = await _resolve_cname(sub)

        if not cname:
            continue

        # Check CNAME against fingerprints
        cname_lower = cname.lower()
        for suffix, (service, fingerprint) in _TAKEOVER_FINGERPRINTS.items():
            if cname_lower.endswith(suffix):
                # Verify with HTTP request
                confirmed = await _verify_fingerprint(sub, fingerprint)
                candidates.append({
                    "subdomain": sub,
                    "cname": cname,
                    "service": service,
                    "fingerprint_matched": confirmed,
                    "confidence": "high" if confirmed else "medium",
                })
                break

    return candidates


async def check_takeovers_nuclei(
    dead_subdomains: list[str],
) -> list[dict[str, Any]]:
    """Use nuclei takeover templates if available."""
    import json

    if not tool_runner.is_available("nuclei"):
        return []

    if not dead_subdomains:
        return []

    # Write targets to temp file
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="bughound_takeover_"
    )
    for sub in dead_subdomains[:200]:
        tmp.write(f"{sub}\n")
    tmp.close()
    cleanup = Path(tmp.name)

    try:
        result = await tool_runner.run(
            "nuclei",
            ["-l", tmp.name, "-t", "http/takeovers/", "-jsonl", "-silent"],
            target="takeover_check",
            timeout=300,
        )
    finally:
        cleanup.unlink(missing_ok=True)

    if not result.success:
        return []

    confirmed: list[dict[str, Any]] = []
    for line in result.results:
        try:
            obj = json.loads(line)
            confirmed.append({
                "subdomain": obj.get("host", ""),
                "template": obj.get("template-id", ""),
                "service": obj.get("info", {}).get("name", ""),
                "severity": obj.get("info", {}).get("severity", ""),
                "confidence": "confirmed",
            })
        except (json.JSONDecodeError, AttributeError):
            continue

    return confirmed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _resolve_cname(domain: str) -> str | None:
    """Resolve CNAME for a domain."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "CNAME")
        for rdata in answers:
            return rdata.to_text().rstrip(".")
    except Exception:
        return None


async def _verify_fingerprint(subdomain: str, fingerprint: str) -> bool:
    """HTTP request to verify the takeover fingerprint."""
    for scheme in ("https", "http"):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{scheme}://{subdomain}",
                    timeout=aiohttp.ClientTimeout(total=8),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text(errors="replace")
                    if fingerprint.lower() in body[:5000].lower():
                        return True
        except Exception:
            continue
    return False
