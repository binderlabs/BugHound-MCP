"""WPScan WordPress scanner wrapper."""
from __future__ import annotations

import json
from typing import Any

from bughound.core import tool_runner
from bughound.schemas.models import ToolResult

BINARY = "wpscan"


def is_available() -> bool:
    return tool_runner.is_available(BINARY)


async def execute(
    target_url: str,
    *,
    enumerate: str = "vp,vt,u",  # vulnerable plugins, themes, users
    api_token: str | None = None,
    timeout: int = 600,
) -> ToolResult:
    """Run wpscan against a WordPress site."""
    args = [
        "--url", target_url,
        "--enumerate", enumerate,
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
        "--disable-tls-checks",
    ]
    if api_token:
        args.extend(["--api-token", api_token])

    result = await tool_runner.run(BINARY, args, target=target_url, timeout=timeout)

    # Parse JSON output
    if result.success and result.results:
        output = "\n".join(str(r) for r in result.results)
        findings = _parse_wpscan_output(output, target_url)
        if findings:
            result.results = findings
            result.result_count = len(findings)

    return result


def _parse_wpscan_output(output: str, target_url: str) -> list[dict[str, Any]]:
    """Parse wpscan JSON output into BugHound finding format."""
    findings = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return findings

    # WordPress version
    wp_version = data.get("version", {})
    if wp_version and wp_version.get("status") == "insecure":
        findings.append({
            "vulnerability_class": "wordpress",
            "tool": "wpscan",
            "technique_id": "wpscan",
            "host": target_url,
            "endpoint": target_url,
            "severity": "medium",
            "description": f"Outdated WordPress version: {wp_version.get('number', '?')}",
            "evidence": f"WordPress {wp_version.get('number')} detected, status: insecure",
            "confidence": "high",
            "needs_validation": False,
        })

    # Vulnerable plugins
    plugins = data.get("plugins", {})
    for name, info in plugins.items():
        vulns = info.get("vulnerabilities", [])
        for vuln in vulns:
            sev = "critical" if "rce" in str(vuln.get("title", "")).lower() else "high"
            findings.append({
                "vulnerability_class": "wordpress",
                "tool": "wpscan",
                "technique_id": "wpscan",
                "host": target_url,
                "endpoint": f"{target_url.rstrip('/')}/wp-content/plugins/{name}/",
                "severity": sev,
                "description": f"Vulnerable plugin '{name}': {vuln.get('title', 'Unknown vulnerability')}",
                "evidence": f"CVE: {', '.join(vuln.get('references', {}).get('cve', ['N/A']))}. Fixed in: {vuln.get('fixed_in', 'N/A')}",
                "confidence": "high",
                "needs_validation": False,
            })

    # Vulnerable themes
    themes = data.get("themes", {}) if isinstance(data.get("themes"), dict) else {}
    for name, info in themes.items():
        vulns = info.get("vulnerabilities", [])
        for vuln in vulns:
            findings.append({
                "vulnerability_class": "wordpress",
                "tool": "wpscan",
                "technique_id": "wpscan",
                "host": target_url,
                "endpoint": f"{target_url.rstrip('/')}/wp-content/themes/{name}/",
                "severity": "high",
                "description": f"Vulnerable theme '{name}': {vuln.get('title', 'Unknown vulnerability')}",
                "evidence": f"CVE: {', '.join(vuln.get('references', {}).get('cve', ['N/A']))}",
                "confidence": "high",
                "needs_validation": False,
            })

    # Users found
    users = data.get("users", {})
    if users:
        usernames = list(users.keys())[:10]
        findings.append({
            "vulnerability_class": "wordpress",
            "tool": "wpscan",
            "technique_id": "wpscan",
            "host": target_url,
            "endpoint": f"{target_url.rstrip('/')}/wp-json/wp/v2/users",
            "severity": "low",
            "description": f"WordPress user enumeration: {', '.join(usernames)}",
            "evidence": f"Found {len(users)} users: {', '.join(usernames)}",
            "confidence": "high",
            "needs_validation": False,
        })

    return findings
