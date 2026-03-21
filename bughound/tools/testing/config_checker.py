"""Passive security configuration checks for BugHound.

Checks security headers, version disclosure, transport security, PII leakage,
vulnerable components, ViewState MAC validation, and default credentials.
All async functions return dicts with ``vulnerable``, ``evidence``, and
``confidence`` keys, matching the injection_tester.py contract.
"""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import urlparse, urljoin

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> tuple[int, str, dict[str, str]]:
    """Send a request and return (status, body, lowercased_headers).

    Never raises -- connection errors return ``(0, "", {})``.
    """
    hdrs = {**_HEADERS, **(headers or {})}
    try:
        async with session.request(
            method,
            url,
            headers=hdrs,
            data=data,
            allow_redirects=allow_redirects,
            ssl=False,
            timeout=_TIMEOUT,
        ) as resp:
            body = await resp.text(errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body[:50_000], resp_headers
    except Exception as exc:
        logger.debug("config_checker_fetch_error", url=url, error=str(exc))
        return 0, "", {}


# ---------------------------------------------------------------------------
# 1. Security Headers
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = [
    "x-frame-options",
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
]


async def check_security_headers(url: str) -> dict[str, Any]:
    """Check for missing security response headers.

    Only flags as vulnerable when 3 or more headers are absent -- a single
    missing header is too common to be actionable.
    """
    try:
        async with aiohttp.ClientSession() as session:
            status, _body, headers = await _fetch(session, url)

            if status == 0:
                return {"vulnerable": False, "url": url, "error": "Could not reach target"}

            missing: list[str] = []
            present: dict[str, str] = {}

            for hdr in _SECURITY_HEADERS:
                value = headers.get(hdr)
                if value:
                    present[hdr] = value
                else:
                    missing.append(hdr)

            vulnerable = len(missing) >= 3
            evidence = (
                f"Missing: {', '.join(missing)}"
                if missing
                else "All checked security headers are present"
            )

            return {
                "vulnerable": vulnerable,
                "url": url,
                "missing_headers": missing,
                "present_headers": present,
                "evidence": evidence,
                "confidence": "high" if vulnerable else "info",
            }

    except Exception as exc:
        logger.debug("check_security_headers_error", url=url, error=str(exc))
        return {"vulnerable": False, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# 2. Version Disclosure
# ---------------------------------------------------------------------------

_VERSION_HEADERS = [
    "x-aspnet-version",
    "x-powered-by",
    "server",
    "x-aspnetmvc-version",
    "x-generator",
]

# Pattern that distinguishes a *versioned* Server header from a generic one.
# "Apache/2.4.41" is informative, but bare "Apache" or "nginx" is not.
_VERSION_RE = re.compile(r"/[\d.]+|[\d]+\.[\d]+")


async def check_version_disclosure(url: str) -> dict[str, Any]:
    """Check response headers for software version information."""
    try:
        async with aiohttp.ClientSession() as session:
            status, _body, headers = await _fetch(session, url)

            if status == 0:
                return {"vulnerable": False, "url": url, "error": "Could not reach target"}

            disclosed: dict[str, str] = {}

            for hdr in _VERSION_HEADERS:
                value = headers.get(hdr)
                if not value:
                    continue

                # For the Server header, only flag if it includes a version number.
                if hdr == "server" and not _VERSION_RE.search(value):
                    continue

                disclosed[hdr] = value

            if disclosed:
                parts = [f"{k}: {v}" for k, v in disclosed.items()]
                return {
                    "vulnerable": True,
                    "url": url,
                    "disclosed_versions": disclosed,
                    "evidence": f"Version information disclosed in headers -- {'; '.join(parts)}",
                    "confidence": "high",
                }

            return {
                "vulnerable": False,
                "url": url,
                "disclosed_versions": {},
                "evidence": "No version information found in response headers",
                "confidence": "info",
            }

    except Exception as exc:
        logger.debug("check_version_disclosure_error", url=url, error=str(exc))
        return {"vulnerable": False, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# 3. Transport Security
# ---------------------------------------------------------------------------


async def check_transport_security(url: str) -> dict[str, Any]:
    """Verify HTTPS availability and HSTS header presence."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    try:
        async with aiohttp.ClientSession() as session:
            if scheme == "http":
                # Attempt to reach the HTTPS variant.
                https_url = url.replace("http://", "https://", 1)
                status, _body, _headers = await _fetch(session, https_url)

                if status == 0:
                    return {
                        "vulnerable": True,
                        "url": url,
                        "evidence": "No HTTPS available -- all traffic transmitted in plaintext",
                        "confidence": "high",
                    }

                # HTTPS reachable -- still worth checking HSTS on the HTTPS response.
                hsts = _headers.get("strict-transport-security")
                if not hsts:
                    return {
                        "vulnerable": True,
                        "url": url,
                        "evidence": (
                            "HTTPS is available but HTTP endpoint does not redirect "
                            "securely -- Strict-Transport-Security header missing on HTTPS response"
                        ),
                        "confidence": "medium",
                    }

                return {
                    "vulnerable": False,
                    "url": url,
                    "evidence": "HTTPS available and HSTS header present",
                    "confidence": "info",
                }

            # URL is already HTTPS -- just check for HSTS header.
            status, _body, headers = await _fetch(session, url)
            if status == 0:
                return {"vulnerable": False, "url": url, "error": "Could not reach target"}

            hsts = headers.get("strict-transport-security")
            if not hsts:
                return {
                    "vulnerable": True,
                    "url": url,
                    "evidence": "HTTPS endpoint missing Strict-Transport-Security header",
                    "confidence": "low",
                }

            return {
                "vulnerable": False,
                "url": url,
                "evidence": f"HSTS header present: {hsts}",
                "confidence": "info",
            }

    except Exception as exc:
        logger.debug("check_transport_security_error", url=url, error=str(exc))
        return {"vulnerable": False, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# 4. PII Leakage in HTML
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

_GENERIC_PREFIXES = frozenset({
    "noreply", "no-reply", "support", "contact", "info",
    "admin", "webmaster", "help", "sales", "marketing",
})


def _is_generic_email(email: str) -> bool:
    """Return True if the email matches a common non-personal address."""
    local = email.split("@")[0].lower()
    return local in _GENERIC_PREFIXES


async def check_pii_leakage_html(url: str) -> dict[str, Any]:
    """Scan the HTML body for non-generic email addresses."""
    try:
        async with aiohttp.ClientSession() as session:
            status, body, _headers = await _fetch(session, url)

            if status == 0:
                return {"vulnerable": False, "url": url, "error": "Could not reach target"}

            all_emails = _EMAIL_RE.findall(body)
            personal_emails = [e for e in all_emails if not _is_generic_email(e)]
            # Deduplicate while preserving order.
            seen: set[str] = set()
            unique_emails: list[str] = []
            for email in personal_emails:
                lower = email.lower()
                if lower not in seen:
                    seen.add(lower)
                    unique_emails.append(email)

            if unique_emails:
                sample = ", ".join(unique_emails[:5])
                suffix = f" (and {len(unique_emails) - 5} more)" if len(unique_emails) > 5 else ""
                return {
                    "vulnerable": True,
                    "url": url,
                    "emails_found": unique_emails[:20],
                    "evidence": f"PII leaked: {sample}{suffix} on page",
                    "confidence": "medium",
                }

            return {
                "vulnerable": False,
                "url": url,
                "emails_found": [],
                "evidence": "No non-generic email addresses found in page body",
                "confidence": "info",
            }

    except Exception as exc:
        logger.debug("check_pii_leakage_error", url=url, error=str(exc))
        return {"vulnerable": False, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# 5. Vulnerable Components (synchronous -- works on existing tech data)
# ---------------------------------------------------------------------------

_VULNERABLE_COMPONENTS: dict[str, dict[str, Any]] = {
    "jquery": {
        "rules": [
            {
                "version_prefix": "1.",
                "cves": [
                    "CVE-2011-4969",
                    "CVE-2012-6708",
                    "CVE-2015-9251",
                    "CVE-2019-11358",
                    "CVE-2020-11022",
                    "CVE-2020-11023",
                ],
                "severity": "high",
            },
            {
                "version_prefix": "2.",
                "cves": [
                    "CVE-2019-11358",
                    "CVE-2020-11022",
                    "CVE-2020-11023",
                ],
                "severity": "high",
            },
            {
                "version_prefix": "3.0",
                "cves": ["CVE-2020-11022", "CVE-2020-11023"],
                "severity": "medium",
            },
            {
                "version_prefix": "3.1",
                "cves": ["CVE-2020-11022", "CVE-2020-11023"],
                "severity": "medium",
            },
            {
                "version_prefix": "3.2",
                "cves": ["CVE-2020-11022", "CVE-2020-11023"],
                "severity": "medium",
            },
            {
                "version_prefix": "3.3",
                "cves": ["CVE-2020-11022", "CVE-2020-11023"],
                "severity": "medium",
            },
            {
                "version_prefix": "3.4",
                "cves": ["CVE-2020-11022", "CVE-2020-11023"],
                "severity": "medium",
            },
        ],
    },
    "asp.net": {
        "rules": [
            {
                "version_prefix": "2.0",
                "cves": [],
                "note": "End-of-life framework version",
                "severity": "high",
            },
            {
                "version_prefix": "3.5",
                "cves": [],
                "note": "End-of-life framework version",
                "severity": "high",
            },
            {
                "version_prefix": "4.0",
                "cves": [],
                "note": "End-of-life framework version",
                "severity": "medium",
            },
        ],
    },
    "angularjs": {
        "rules": [
            {
                "version_prefix": "1.",
                "cves": ["Multiple XSS CVEs in Angular 1.x"],
                "severity": "high",
            },
        ],
    },
    "angular": {
        "rules": [
            {
                "version_prefix": "1.",
                "cves": ["Multiple XSS CVEs in Angular 1.x"],
                "severity": "high",
            },
        ],
    },
    "php": {
        "rules": [
            {
                "version_match": lambda v: _version_lt(v, "8.0"),
                "cves": ["Multiple CVEs in PHP versions prior to 8.0"],
                "severity": "high",
            },
        ],
    },
    "spip": {
        "rules": [
            {
                "version_prefix": "",
                "cves": ["CVE-2023-27372"],
                "note": "SPIP CMS RCE vulnerability",
                "severity": "critical",
            },
        ],
    },
    "wordpress": {
        "rules": [
            {
                "version_match": lambda v: _version_lt(v, "6.0"),
                "cves": ["Multiple CVEs in WordPress versions prior to 6.0"],
                "severity": "high",
            },
        ],
    },
}


def _version_lt(version_str: str, threshold: str) -> bool:
    """Return True if *version_str* is numerically less than *threshold*."""
    try:
        v_parts = [int(x) for x in version_str.split(".")]
        t_parts = [int(x) for x in threshold.split(".")]
        return v_parts < t_parts
    except (ValueError, AttributeError):
        return False


def _extract_version(tech_name: str) -> str | None:
    """Extract a version string from a technology name like 'jQuery 1.12.4'."""
    match = re.search(r"[\d]+(?:\.[\d]+)+", tech_name)
    return match.group(0) if match else None


def check_vulnerable_components(
    technologies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Check technology detection data for known vulnerable versions.

    Parameters
    ----------
    technologies:
        List of dicts, each with ``host`` (str) and ``technologies`` (list of
        str or list of dict with ``name``/``version`` keys).

    Returns
    -------
    list[dict]
        One finding dict per vulnerable component discovered.
    """
    findings: list[dict[str, Any]] = []

    for entry in technologies:
        host = entry.get("host", "unknown")
        techs = entry.get("technologies", [])

        for tech in techs:
            # Normalise: tech can be a string ("jQuery 1.12.4") or a dict.
            if isinstance(tech, dict):
                name = tech.get("name", "")
                version = tech.get("version", "") or _extract_version(name) or ""
            else:
                name = str(tech)
                version = _extract_version(name) or ""

            name_lower = name.lower().strip()

            for component_key, component_info in _VULNERABLE_COMPONENTS.items():
                if component_key not in name_lower:
                    continue

                for rule in component_info["rules"]:
                    matched = False

                    # Lambda-based version comparison.
                    version_match_fn = rule.get("version_match")
                    if version_match_fn and version:
                        matched = version_match_fn(version)

                    # Prefix-based version comparison.
                    elif "version_prefix" in rule:
                        prefix = rule["version_prefix"]
                        if prefix == "":
                            # Any version matches (e.g. SPIP).
                            matched = True
                        elif version and version.startswith(prefix):
                            matched = True

                    if matched:
                        cves = rule.get("cves", [])
                        note = rule.get("note", "")
                        severity = rule.get("severity", "medium")
                        cve_text = ", ".join(cves) if cves else "known vulnerabilities"
                        evidence_parts = [
                            f"{name} (version {version})" if version else name,
                            f"-- {cve_text}",
                        ]
                        if note:
                            evidence_parts.append(f"({note})")

                        findings.append({
                            "vulnerable": True,
                            "host": host,
                            "component": name,
                            "version": version,
                            "cves": cves,
                            "evidence": " ".join(evidence_parts),
                            "confidence": "high" if version else "medium",
                            "severity": severity,
                        })
                        # Only report the first matching rule per technology.
                        break

    return findings


# ---------------------------------------------------------------------------
# 6. ViewState MAC Validation
# ---------------------------------------------------------------------------

_VIEWSTATE_RE = re.compile(
    r'name="__VIEWSTATE"\s+value="([^"]+)"', re.I,
)
_VIEWSTATE_GENERATOR_RE = re.compile(
    r'name="__VIEWSTATEGENERATOR"\s+value="([^"]+)"', re.I,
)
_EVENT_VALIDATION_RE = re.compile(
    r'name="__EVENTVALIDATION"\s+value="([^"]+)"', re.I,
)
_HIDDEN_INPUT_RE = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
    re.I,
)
_HIDDEN_INPUT_ALT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\'][^>]+type=["\']hidden["\']',
    re.I,
)

_MAC_ERROR_RE = re.compile(
    r"validation of viewstate mac failed|"
    r"the state information is invalid|"
    r"invalid viewstate|"
    r"viewstate mac|"
    r"system\.web\.httpexception.*viewstate",
    re.I,
)


async def check_viewstate_mac(url: str) -> dict[str, Any]:
    """Check if ASP.NET ViewState MAC validation is disabled.

    Fetches the page, extracts the ViewState, tampers with it, and POSTs it
    back. If the server accepts the tampered value without an error, MAC
    validation is likely disabled.
    """
    try:
        async with aiohttp.ClientSession() as session:
            status, body, _headers = await _fetch(session, url)

            if status == 0:
                return {"vulnerable": False, "url": url, "error": "Could not reach target"}

            vs_match = _VIEWSTATE_RE.search(body)
            if not vs_match:
                return {
                    "vulnerable": False,
                    "url": url,
                    "evidence": "No __VIEWSTATE field found on page",
                    "confidence": "info",
                }

            viewstate_value = vs_match.group(1)

            # Tamper: replace last 4 characters of the base64 value.
            if len(viewstate_value) > 4:
                tampered = viewstate_value[:-4] + "AAAA"
            else:
                tampered = "AAAA"

            # Collect additional hidden fields.
            form_data: dict[str, str] = {"__VIEWSTATE": tampered}

            gen_match = _VIEWSTATE_GENERATOR_RE.search(body)
            if gen_match:
                form_data["__VIEWSTATEGENERATOR"] = gen_match.group(1)

            ev_match = _EVENT_VALIDATION_RE.search(body)
            if ev_match:
                form_data["__EVENTVALIDATION"] = ev_match.group(1)

            # POST the tampered ViewState back.
            post_status, post_body, _post_headers = await _fetch(
                session, url, method="POST", data=form_data,
            )

            if post_status == 0:
                return {
                    "vulnerable": False,
                    "url": url,
                    "evidence": "POST request with tampered ViewState failed to connect",
                    "confidence": "info",
                }

            # If the response is 200 and does NOT mention ViewState/MAC validation errors,
            # MAC is likely disabled.
            if post_status == 200 and not _MAC_ERROR_RE.search(post_body):
                return {
                    "vulnerable": True,
                    "url": url,
                    "evidence": "ViewState MAC validation disabled -- tampered ViewState accepted",
                    "confidence": "medium",
                }

            # Server rejected the tampered ViewState -- MAC is enabled.
            return {
                "vulnerable": False,
                "url": url,
                "evidence": "ViewState MAC validation is enabled -- tampered ViewState rejected",
                "confidence": "info",
            }

    except Exception as exc:
        logger.debug("check_viewstate_mac_error", url=url, error=str(exc))
        return {"vulnerable": False, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# 7. Default Credentials
# ---------------------------------------------------------------------------

_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "Password1"),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("demo", "demo"),
    ("admin", "1234"),
    ("admin", "12345"),
]

_SUCCESS_INDICATORS = re.compile(
    r"welcome|dashboard|logout|logged\s*in",
    re.I,
)

_FAILURE_INDICATORS = re.compile(
    r"invalid|incorrect|failed|error|wrong|denied|unauthorized",
    re.I,
)


def _extract_hidden_fields(html: str) -> dict[str, str]:
    """Extract all hidden input fields from an HTML page."""
    fields: dict[str, str] = {}
    for match in _HIDDEN_INPUT_RE.finditer(html):
        fields[match.group(1)] = match.group(2)
    for match in _HIDDEN_INPUT_ALT_RE.finditer(html):
        fields[match.group(1)] = match.group(2)
    return fields


async def test_default_credentials(
    login_url: str,
    form_data: dict[str, Any],
) -> dict[str, Any]:
    """Test common default credential pairs against a login form.

    Parameters
    ----------
    login_url:
        URL of the login page.
    form_data:
        Dict with keys ``username_field``, ``password_field``,
        ``action_url`` (optional -- defaults to *login_url*),
        ``method`` (optional -- defaults to ``POST``),
        and ``extra_fields`` (optional dict of hidden fields like CSRF tokens).
    """
    username_field = form_data.get("username_field", "username")
    password_field = form_data.get("password_field", "password")
    action_url = form_data.get("action_url") or login_url
    method = (form_data.get("method") or "POST").upper()

    # Resolve relative action URLs.
    if action_url and not action_url.startswith("http"):
        action_url = urljoin(login_url, action_url)

    try:
        async with aiohttp.ClientSession() as session:
            # Fetch the login page once to capture baseline failure text.
            base_status, base_body, _base_headers = await _fetch(session, login_url)

            if base_status == 0:
                return {"vulnerable": False, "url": login_url, "error": "Could not reach login page"}

            # Determine which failure keywords appear on the default login page
            # so we can distinguish "normal page" from "login failed" responses.
            baseline_failures = set(_FAILURE_INDICATORS.findall(base_body.lower()))

            for username, password in _DEFAULT_CREDS:
                # Step 1: GET the login page fresh to extract CSRF / hidden tokens.
                get_status, get_body, _get_headers = await _fetch(session, login_url)
                if get_status == 0:
                    continue

                hidden_fields = _extract_hidden_fields(get_body)

                # Merge caller-provided extra_fields (if any) -- these override
                # auto-detected hidden fields.
                extra = form_data.get("extra_fields")
                if isinstance(extra, dict):
                    hidden_fields.update(extra)

                # Build the POST body.
                post_data = {
                    **hidden_fields,
                    username_field: username,
                    password_field: password,
                }

                # Step 2: Submit the login form.
                post_status, post_body, post_headers = await _fetch(
                    session,
                    action_url,
                    method=method,
                    data=post_data,
                    allow_redirects=False,
                )

                if post_status == 0:
                    continue

                # Step 3: Detect success.
                is_redirect = post_status in (301, 302, 303, 307, 308)
                has_success_text = bool(_SUCCESS_INDICATORS.search(post_body))

                # Check if new failure indicators appeared (not present on the
                # blank login page).
                current_failures = set(_FAILURE_INDICATORS.findall(post_body.lower()))
                new_failures = current_failures - baseline_failures
                has_new_failure = bool(new_failures)

                success = False
                evidence_detail = ""

                if is_redirect:
                    location = post_headers.get("location", "")
                    # A redirect to the same login page usually means failure.
                    if login_url not in location:
                        success = True
                        evidence_detail = f"HTTP {post_status} redirect to {location}"

                if not success and has_success_text and not has_new_failure:
                    success = True
                    evidence_detail = "Response contains success indicators (welcome/dashboard/logout)"

                if success:
                    return {
                        "vulnerable": True,
                        "url": login_url,
                        "credentials": [{"username": username, "password": password}],
                        "evidence": f"Default credentials accepted: {username}:{password} -- {evidence_detail}",
                        "confidence": "high",
                    }

            # No credentials worked.
            return {
                "vulnerable": False,
                "url": login_url,
                "credentials": [],
                "evidence": f"Tested {len(_DEFAULT_CREDS)} default credential pairs -- none accepted",
                "confidence": "info",
            }

    except Exception as exc:
        logger.debug("test_default_credentials_error", url=login_url, error=str(exc))
        return {"vulnerable": False, "url": login_url, "error": str(exc)}
