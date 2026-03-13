"""Auth mechanism discovery — cookie analysis, JWT extraction, auth endpoint detection.

Pure aiohttp, no external binary. Discovers authentication mechanisms,
classifies cookies, decodes JWTs, and optionally auto-registers for
authenticated testing.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
import re
import string
from typing import Any
from urllib.parse import urljoin

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (BugHound Scanner)"}

# ---------------------------------------------------------------------------
# Cookie classification patterns
# ---------------------------------------------------------------------------

_SESSION_NAMES = re.compile(
    r"(session|sess|^sid$|phpsessid|jsessionid|asp\.net_sessionid|"
    r"connect\.sid|laravel_session|rack\.session|_session_id|ci_session)",
    re.IGNORECASE,
)
_AUTH_TOKEN_NAMES = re.compile(
    r"(token|auth|jwt|access|bearer|api_key|x-csrf|csrf_token|"
    r"remember_me|remember_token|logged_in|authenticated)",
    re.IGNORECASE,
)
_TRACKING_NAMES = re.compile(
    r"(track|analytics|_ga$|_gid$|utm|_fbp|_fbc|hubspot|intercom|"
    r"ajs_anonymous|mp_|amplitude|segment)",
    re.IGNORECASE,
)
_PREFERENCE_NAMES = re.compile(
    r"(pref|settings|config|user_prefs|theme|lang|locale|timezone|"
    r"dark_mode|consent|cookie_consent|gdpr|notice)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# JWT / token patterns
# ---------------------------------------------------------------------------

# JWT in body: three base64url segments separated by dots
_JWT_BODY_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# ---------------------------------------------------------------------------
# Injectable cookie detection patterns
# ---------------------------------------------------------------------------

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]{8,}$")
_JSON_START_RE = re.compile(r"^[\[{]")
# PHP serialized: s:4:"test"; or a:1:{...} or O:5:"Class":...
_PHP_SERIAL_RE = re.compile(r"^(a|s|i|o|b|d|N):\d*:[\{\"NTF]")
# Java serialized: \xac\xed magic bytes (url-encoded or raw)
_JAVA_SERIAL_RE = re.compile(r"(rO0AB|%ac%ed|\\xac\\xed)", re.IGNORECASE)
# Python pickle magic bytes (url-encoded: %80\x04 etc) — check hex-like patterns
_PICKLE_RE = re.compile(r"(%80|\\x80|gASV)", re.IGNORECASE)
# .NET ViewState
_VIEWSTATE_RE = re.compile(r"^/wE[A-Za-z0-9+/]", re.IGNORECASE)
# URL-encoded data
_URLENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# ---------------------------------------------------------------------------
# Common auth endpoints to probe
# ---------------------------------------------------------------------------

_AUTH_PATHS = [
    "/login",
    "/signin",
    "/auth",
    "/api/auth/login",
    "/api/auth/register",
    "/api/login",
    "/api/signin",
    "/oauth",
    "/api/token",
    "/api/session",
    "/register",
    "/signup",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/api/v1/register",
    "/api/v2/auth/login",
    "/auth/login",
    "/auth/register",
    "/auth/signup",
    "/account/login",
    "/user/login",
    "/users/sign_in",
    "/sso/login",
    "/jwt/token",
    "/oauth/token",
    "/oauth/authorize",
    "/api/users/login",
    "/api/users/register",
    "/.well-known/openid-configuration",
    "/forgot-password",
    "/reset-password",
    "/api/auth/forgot-password",
]

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _random_string(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ---------------------------------------------------------------------------
# Cookie parsing helpers
# ---------------------------------------------------------------------------


def _parse_set_cookie(raw: str) -> dict[str, Any]:
    """Parse a raw Set-Cookie header string into a structured dict."""
    parts = [p.strip() for p in raw.split(";")]
    name = ""
    value = ""
    domain = ""
    path = "/"
    secure = False
    http_only = False
    same_site = ""

    if parts:
        # First part is name=value
        first = parts[0]
        if "=" in first:
            name, _, value = first.partition("=")
        else:
            name = first

        for attr in parts[1:]:
            lower = attr.lower()
            if lower == "secure":
                secure = True
            elif lower == "httponly":
                http_only = True
            elif lower.startswith("samesite="):
                same_site = attr.split("=", 1)[1].strip()
            elif lower.startswith("domain="):
                domain = attr.split("=", 1)[1].strip()
            elif lower.startswith("path="):
                path = attr.split("=", 1)[1].strip()

    return {
        "name": name.strip(),
        "value": value.strip(),
        "domain": domain,
        "path": path,
        "secure": secure,
        "httpOnly": http_only,
        "sameSite": same_site,
    }


def _classify_cookie(name: str) -> str:
    """Return cookie classification string."""
    if _SESSION_NAMES.search(name):
        return "session"
    if _AUTH_TOKEN_NAMES.search(name):
        return "auth_token"
    if _TRACKING_NAMES.search(name):
        return "tracking"
    if _PREFERENCE_NAMES.search(name):
        return "preference"
    return "other"


def _insecure_flags(cookie: dict[str, Any], is_https: bool) -> list[dict[str, Any]]:
    """Return list of insecure flag issues for a cookie."""
    issues: list[dict[str, Any]] = []
    name = cookie["name"]

    if is_https and not cookie["secure"]:
        issues.append({
            "cookie_name": name,
            "issue": "missing_secure",
            "severity": "MEDIUM",
        })

    if not cookie["httpOnly"]:
        issues.append({
            "cookie_name": name,
            "issue": "missing_httponly",
            "severity": "MEDIUM",
        })

    same_site = (cookie.get("sameSite") or "").strip().lower()
    if same_site in ("", "none"):
        issues.append({
            "cookie_name": name,
            "issue": "missing_samesite",
            "severity": "LOW" if same_site == "" else "MEDIUM",
        })

    return issues


def _injectable_check(name: str, value: str) -> dict[str, Any] | None:
    """Return injection metadata if the cookie value looks tamperable."""
    if not value:
        return None

    if _NUMERIC_RE.match(value):
        return {
            "name": name,
            "value": value,
            "injection_type": "numeric_id",
            "reason": "Cookie value is a plain numeric ID — likely directly used as a user/record identifier",
        }

    if _UUID_RE.match(value):
        return {
            "name": name,
            "value": value,
            "injection_type": "uuid",
            "reason": "Cookie value is a UUID — may reference a user/session object directly",
        }

    if _JSON_START_RE.match(value):
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "json_data",
            "reason": "Cookie value appears to be JSON-encoded data — may be parsed and trusted server-side",
        }

    if _PHP_SERIAL_RE.match(value):
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "php_serialized",
            "reason": "Cookie value matches PHP serialization format — potential deserialization vulnerability",
        }

    if _JAVA_SERIAL_RE.search(value):
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "java_serialized",
            "reason": "Cookie value contains Java serialization markers — potential deserialization vulnerability",
        }

    if _PICKLE_RE.search(value):
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "python_pickle",
            "reason": "Cookie value contains pickle-like markers — potential insecure deserialization",
        }

    if _VIEWSTATE_RE.match(value):
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "viewstate",
            "reason": "Cookie value looks like .NET ViewState — potential deserialization target",
        }

    # URL-encoded check before base64 (common overlap)
    if _URLENC_RE.search(value) and len(value) > 8:
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "url_encoded",
            "reason": "Cookie value is URL-encoded — decode and inspect for structured data",
        }

    # Hex string (long enough to be meaningful)
    if _HEX_RE.match(value) and len(value) >= 16:
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "hex_token",
            "reason": "Cookie value is a hex token — may be a predictable or brute-forceable session ID",
        }

    # Base64 (standard alphabet)
    if _BASE64_RE.match(value) and len(value) >= 12:
        try:
            decoded = base64.b64decode(value + "==").decode("utf-8", errors="strict")
            if any(c.isprintable() for c in decoded) and len(decoded) > 3:
                return {
                    "name": name,
                    "value": value[:120],
                    "injection_type": "base64_data",
                    "reason": f"Cookie value decodes to printable base64 data: {decoded[:60]!r}",
                }
        except Exception:
            pass

    # Long opaque strings (>10 chars, not caught above) — still interesting
    if len(value) > 10 and not value.startswith("eyJ"):
        return {
            "name": name,
            "value": value[:120],
            "injection_type": "opaque_token",
            "reason": "Cookie value is a long opaque string — may be tamperable or predictable",
        }

    return None


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def _decode_jwt(token: str, source: str) -> dict[str, Any] | None:
    """Decode a JWT token and return structured metadata. Never raises."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_raw = _b64url_decode(parts[0])
        payload_raw = _b64url_decode(parts[1])

        try:
            header = json.loads(header_raw)
        except Exception:
            header = {"raw": header_raw.decode("utf-8", errors="replace")}

        try:
            payload = json.loads(payload_raw)
        except Exception:
            payload = {"raw": payload_raw.decode("utf-8", errors="replace")}

        alg = header.get("alg", "unknown")

        # Flag interesting claims
        interesting_claims: list[str] = []
        for key in payload:
            lower_key = key.lower()
            if any(k in lower_key for k in ("admin", "role", "is_staff", "superuser", "privilege", "group", "permission")):
                interesting_claims.append(f"{key}={payload[key]!r}")

        return {
            "token": token[:80] + ("..." if len(token) > 80 else ""),
            "source": source,
            "header": header,
            "claims": payload,
            "algorithm": alg,
            "interesting_claims": interesting_claims,
            "brute_candidate": alg in ("HS256", "HS384", "HS512"),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover_auth(
    target_url: str, target_domain: str = "",
) -> dict[str, Any]:
    """Discover authentication mechanisms on a target URL.

    target_domain: used for generating target-specific registration data and
    scoping cookie analysis. Falls back to extracting from target_url.

    Returns a structured dict with cookies, jwts, auth_endpoints,
    auth_mechanism, registered_credentials, auth_token, insecure_cookie_flags,
    and injectable_cookies.
    """
    log = logger.bind(target=target_url)
    log.info("auth_analyzer.start")

    if not target_domain:
        try:
            from urllib.parse import urlparse as _urlparse
            target_domain = _urlparse(target_url).hostname or ""
        except Exception:
            target_domain = ""

    is_https = target_url.lower().startswith("https://")
    base_url = target_url.rstrip("/")

    cookies_found: list[dict[str, Any]] = []
    jwts_found: list[dict[str, Any]] = []
    insecure_flags: list[dict[str, Any]] = []
    injectable_cookies: list[dict[str, Any]] = []
    auth_endpoints: list[dict[str, Any]] = []
    auth_mechanism = "none"
    registered_credentials: dict[str, Any] | None = None
    auth_token: str | None = None

    # -----------------------------------------------------------------------
    # Step 1: GET target_url, collect cookies and probe for JWTs
    # -----------------------------------------------------------------------
    try:
        async with aiohttp.ClientSession(headers=_HEADERS) as session:
            async with session.get(
                target_url,
                timeout=_TIMEOUT,
                ssl=False,
                allow_redirects=True,
            ) as resp:
                # Collect raw Set-Cookie headers
                raw_set_cookies = resp.headers.getall("Set-Cookie", [])

                for raw in raw_set_cookies:
                    cookie_data = _parse_set_cookie(raw)
                    if not cookie_data["name"]:
                        continue

                    classification = _classify_cookie(cookie_data["name"])
                    cookie_entry = {
                        "name": cookie_data["name"],
                        "value": cookie_data["value"],
                        "domain": cookie_data["domain"],
                        "path": cookie_data["path"],
                        "secure": cookie_data["secure"],
                        "httpOnly": cookie_data["httpOnly"],
                        "sameSite": cookie_data["sameSite"],
                        "classification": classification,
                    }
                    cookies_found.append(cookie_entry)

                    # Check insecure flags
                    insecure_flags.extend(_insecure_flags(cookie_data, is_https))

                    # Check for JWT in cookie value
                    val = cookie_data["value"]
                    if val.startswith("eyJ"):
                        decoded = _decode_jwt(val, source=f"cookie:{cookie_data['name']}")
                        if decoded:
                            jwts_found.append(decoded)
                    else:
                        # Check injectable
                        inj = _injectable_check(cookie_data["name"], val)
                        if inj:
                            injectable_cookies.append(inj)

                # Check Authorization header in response
                auth_header = resp.headers.get("Authorization", "")
                if auth_header:
                    # Strip "Bearer " prefix if present
                    token_candidate = auth_header.removeprefix("Bearer ").strip()
                    if token_candidate.startswith("eyJ"):
                        decoded = _decode_jwt(token_candidate, source="response_header:Authorization")
                        if decoded:
                            jwts_found.append(decoded)

                # Check WWW-Authenticate for Basic auth
                www_auth = resp.headers.get("WWW-Authenticate", "")

                # Scan response body for JWT patterns
                try:
                    body_text = await resp.text(errors="replace")
                    body_jwts = _JWT_BODY_RE.findall(body_text)
                    seen_tokens: set[str] = {j["token"].split("...")[0] for j in jwts_found}
                    for raw_token in body_jwts[:10]:  # cap at 10 matches per page
                        prefix = raw_token[:80]
                        if prefix not in seen_tokens:
                            decoded = _decode_jwt(raw_token, source="response_body")
                            if decoded:
                                jwts_found.append(decoded)
                                seen_tokens.add(prefix)
                except Exception:
                    body_text = ""
                    www_auth = www_auth or ""

    except Exception as exc:
        log.warning("auth_analyzer.initial_get_failed", error=str(exc))
        body_text = ""
        www_auth = ""

    # -----------------------------------------------------------------------
    # Step 2: Check common auth endpoints
    # -----------------------------------------------------------------------
    register_path: str | None = None

    async def _probe_path(path: str) -> None:
        nonlocal register_path
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            async with aiohttp.ClientSession(headers=_HEADERS) as session:
                async with session.get(
                    url,
                    timeout=_TIMEOUT,
                    ssl=False,
                    allow_redirects=False,
                ) as resp:
                    if resp.status != 404:
                        auth_endpoints.append({
                            "path": path,
                            "url": url,
                            "status_code": resp.status,
                            "method": "GET",
                        })
                        # Track register/signup endpoints for auto-registration
                        if path in ("/register", "/signup", "/api/auth/register") and register_path is None:
                            register_path = url
        except Exception:
            pass

    await asyncio.gather(*[_probe_path(p) for p in _AUTH_PATHS], return_exceptions=True)

    # -----------------------------------------------------------------------
    # Step 3: Auto-registration if a register endpoint was found
    # -----------------------------------------------------------------------
    if register_path:
        suffix = _random_string(8)
        reg_username = f"bughound_test_{suffix}"
        # Use target_domain for more realistic email
        email_domain = target_domain if target_domain else "test.local"
        reg_email = f"bughound_test_{suffix}@{email_domain}"
        reg_password = "BugHound_Test_123!"

        reg_payload = {
            "username": reg_username,
            "email": reg_email,
            "password": reg_password,
            "password_confirmation": reg_password,
            "name": f"BugHound Test {suffix}",
        }

        async def _try_register(
            sess: aiohttp.ClientSession, url: str, use_json: bool,
        ) -> tuple[int, aiohttp.ClientResponse | None]:
            try:
                kwargs: dict[str, Any] = {
                    "timeout": _TIMEOUT, "ssl": False, "allow_redirects": False,
                }
                if use_json:
                    kwargs["json"] = reg_payload
                else:
                    kwargs["data"] = reg_payload
                async with sess.post(url, **kwargs) as resp:
                    return resp.status, resp
            except Exception:
                return 0, None

        async def _extract_token_from_response(resp: aiohttp.ClientResponse) -> None:
            nonlocal auth_token, registered_credentials
            registered_credentials = {
                "username": reg_username,
                "email": reg_email,
                "password": reg_password,
                "register_url": register_path,
            }
            # Try to extract auth token from response body
            try:
                reg_body = await resp.json(content_type=None)
                for key in ("token", "access_token", "jwt", "accessToken", "id_token"):
                    if key in reg_body and isinstance(reg_body[key], str):
                        auth_token = reg_body[key]
                        registered_credentials["token_field"] = key
                        break
            except Exception:
                try:
                    reg_text = await resp.text(errors="replace")
                    match = re.search(
                        r'"(?:token|access_token|jwt|accessToken|id_token)"\s*:\s*"([^"]{10,})"',
                        reg_text,
                    )
                    if match:
                        auth_token = match.group(1)
                except Exception:
                    pass

            # Fall back to Set-Cookie for token
            if not auth_token:
                for raw in resp.headers.getall("Set-Cookie", []):
                    c = _parse_set_cookie(raw)
                    if c["name"] and _classify_cookie(c["name"]) == "auth_token":
                        auth_token = c["value"]
                        registered_credentials["token_field"] = f"cookie:{c['name']}"
                        break

        try:
            async with aiohttp.ClientSession(headers=_HEADERS) as session:
                # Try JSON first, then form-encoded
                for use_json in (True, False):
                    try:
                        kwargs: dict[str, Any] = {
                            "timeout": _TIMEOUT, "ssl": False, "allow_redirects": False,
                        }
                        if use_json:
                            kwargs["json"] = reg_payload
                        else:
                            kwargs["data"] = reg_payload
                        async with session.post(register_path, **kwargs) as resp:
                            if resp.status in (200, 201):
                                await _extract_token_from_response(resp)
                                break
                    except Exception:
                        continue

        except Exception as exc:
            log.warning("auth_analyzer.registration_failed", error=str(exc))

    # -----------------------------------------------------------------------
    # Step 4: Determine auth_mechanism
    # -----------------------------------------------------------------------
    if jwts_found:
        auth_mechanism = "jwt"
    elif any(c["classification"] == "session" for c in cookies_found):
        auth_mechanism = "session"
    elif www_auth and "basic" in www_auth.lower():
        auth_mechanism = "basic"
    else:
        auth_mechanism = "none"

    log.info(
        "auth_analyzer.complete",
        cookies=len(cookies_found),
        jwts=len(jwts_found),
        auth_endpoints=len(auth_endpoints),
        auth_mechanism=auth_mechanism,
        registered=registered_credentials is not None,
    )

    return {
        "cookies": cookies_found,
        "jwts": jwts_found,
        "auth_endpoints": auth_endpoints,
        "auth_mechanism": auth_mechanism,
        "registered_credentials": registered_credentials,
        "auth_token": auth_token,
        "insecure_cookie_flags": insecure_flags,
        "injectable_cookies": injectable_cookies,
    }
