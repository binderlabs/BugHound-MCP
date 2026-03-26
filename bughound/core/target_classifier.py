"""Stage 0: Classifies target as BROAD_DOMAIN, SINGLE_HOST, SINGLE_ENDPOINT, or URL_LIST.

Pure input analysis — no network calls.  Takes the raw user string and returns
a TargetClassification that tells downstream stages what to do.
"""

from __future__ import annotations

import re
from pathlib import Path

from bughound.schemas.models import TargetClassification, TargetType

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/\d{1,2}$"
)

# Country-code second-level domains (ccSLDs) — these are effectively TLDs.
# example.gov.mm, example.co.uk, example.com.au are root domains, not subdomains.
_CC_SLDS = frozenset({
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "go.kr", "ac.kr",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
    "co.th", "or.th", "ac.th", "go.th", "in.th",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "gov.mm", "edu.mm", "net.mm", "org.mm", "com.mm",
    "co.id", "or.id", "ac.id", "go.id", "web.id",
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr",
    "co.il", "org.il", "ac.il", "gov.il",
    "com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd",
    "com.ng", "net.ng", "org.ng", "edu.ng", "gov.ng",
    "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg",
    "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa",
    "com.pe", "net.pe", "org.pe", "edu.pe", "gob.pe",
    "com.co", "net.co", "org.co", "edu.co", "gov.co",
    "or.ke", "co.ke", "ac.ke", "go.ke",
})


def _is_root_domain(hostname: str) -> bool:
    """Check if hostname is a root domain (not a subdomain).

    Handles ccSLDs: example.gov.mm → root domain, sub.example.gov.mm → subdomain.
    """
    hostname = hostname.removeprefix("*.")
    parts = hostname.lower().split(".")

    if len(parts) == 2:
        # example.com → root domain
        return True

    if len(parts) == 3:
        # Check if last 2 parts are a ccSLD
        suffix = f"{parts[-2]}.{parts[-1]}"
        if suffix in _CC_SLDS:
            # example.gov.mm → root domain (3 parts but ccSLD)
            return True
        # pro.odaha.io → subdomain (3 parts, not ccSLD)
        return False

    if len(parts) == 4:
        # Check if last 2 parts are a ccSLD
        suffix = f"{parts[-2]}.{parts[-1]}"
        if suffix in _CC_SLDS:
            # sub.example.gov.mm → subdomain
            return False
        return False

    return False


# Wildcard or bare domain pattern (just validates characters)
_DOMAIN_CHARS_RE = re.compile(
    r"^(\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", re.IGNORECASE
)

ALL_STAGES = [0, 1, 2, 3, 4, 5, 6]
SKIP_ENUM = [0, 2, 3, 4, 5, 6]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify(target: str, depth: str = "light") -> TargetClassification:
    """Classify a raw user-provided target string.

    Parameters
    ----------
    target : str
        The raw target input from the user.
    depth : str
        "light" or "deep" — user-specified scanning intensity.

    Returns
    -------
    TargetClassification

    Raises
    ------
    ValueError
        If the target is a CIDR range (not supported) or completely invalid.
    """
    raw = target.strip()
    if not raw:
        raise ValueError("Empty target provided.")

    if depth not in ("light", "deep"):
        raise ValueError(f"Invalid depth '{depth}'. Must be 'light' or 'deep'.")

    # --- CIDR range: reject ---
    if _CIDR_RE.match(raw):
        raise ValueError(
            f"CIDR ranges are not supported (got '{raw}'). "
            "BugHound is a web bug bounty tool — provide a domain, URL, or host."
        )

    # --- URL list: file path or multi-line input ---
    if _is_url_list(raw):
        targets = _parse_url_list(raw)
        return TargetClassification(
            target_type=TargetType.URL_LIST,
            original_input=raw,
            normalized_targets=targets,
            stages_to_run=SKIP_ENUM,
            depth=depth,
            skip_reasons={"1": "URL list provided, enumeration not needed"},
        )

    # --- Single endpoint: URL with a path beyond / ---
    if _is_endpoint(raw):
        normalized = _normalize_url(raw)
        return TargetClassification(
            target_type=TargetType.SINGLE_ENDPOINT,
            original_input=raw,
            normalized_targets=[normalized],
            stages_to_run=SKIP_ENUM,
            depth=depth,
            skip_reasons={
                "1": "Single endpoint target, enumeration not needed",
                "2_lite": "Only crawl from provided path",
            },
        )

    # --- IP address: treat as single host ---
    cleaned = _strip_protocol(raw)
    if _IP_RE.match(cleaned):
        return TargetClassification(
            target_type=TargetType.SINGLE_HOST,
            original_input=raw,
            normalized_targets=[cleaned],
            stages_to_run=SKIP_ENUM,
            depth=depth,
            skip_reasons={"1": "IP address target, enumeration not needed"},
        )

    # --- Broad domain: root domain or wildcard ---
    if _DOMAIN_CHARS_RE.match(cleaned) and _is_root_domain(cleaned):
        # Strip wildcard prefix for normalized form
        norm = cleaned.removeprefix("*.")
        return TargetClassification(
            target_type=TargetType.BROAD_DOMAIN,
            original_input=raw,
            normalized_targets=[norm],
            stages_to_run=ALL_STAGES,
            depth=depth,
        )

    # --- Single host: anything else that looks like a hostname ---
    if _looks_like_hostname(cleaned):
        return TargetClassification(
            target_type=TargetType.SINGLE_HOST,
            original_input=raw,
            normalized_targets=[cleaned],
            stages_to_run=SKIP_ENUM,
            depth=depth,
            skip_reasons={"1": "Single host target, enumeration not needed"},
        )

    raise ValueError(
        f"Cannot classify target '{raw}'. "
        "Provide a domain (example.com), hostname (dev.example.com), "
        "URL (https://example.com/api), or file path with URLs."
    )


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _strip_protocol(s: str) -> str:
    """Remove http(s):// and trailing slashes/paths."""
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]   # drop path
    s = s.split(":")[0]   # drop port
    return s.lower().strip()


def _normalize_url(s: str) -> str:
    """Ensure a URL has a scheme."""
    s = s.strip()
    if not s.startswith(("http://", "https://")):
        s = f"https://{s}"
    return s


def _is_url_list(raw: str) -> bool:
    """True if input is a file path to a URL list or multi-line URL input."""
    # Multi-line with at least 2 non-empty lines
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    if len(lines) >= 2:
        return True
    # Existing file path
    if len(lines) == 1 and Path(lines[0]).is_file():
        return True
    return False


def _parse_url_list(raw: str) -> list[str]:
    """Extract normalized URLs from multi-line input or file."""
    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    # If single line and it's a file path, read the file
    if len(lines) == 1 and Path(lines[0]).is_file():
        lines = Path(lines[0]).read_text().splitlines()

    targets: list[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(_normalize_url(line))

    return sorted(set(targets))


def _is_endpoint(raw: str) -> bool:
    """True if input is a URL with a meaningful path (not just /)."""
    if not raw.startswith(("http://", "https://")):
        return False
    # Extract path portion
    after_scheme = re.sub(r"^https?://", "", raw)
    parts = after_scheme.split("/", 1)
    if len(parts) < 2:
        return False
    path = parts[1].rstrip("/")
    return len(path) > 0


def _looks_like_hostname(s: str) -> bool:
    """True if s looks like a valid hostname (has dots, alphanumeric labels)."""
    if "." not in s:
        return False
    labels = s.split(".")
    if len(labels) < 2:
        return False
    return all(
        re.match(r"^[a-z0-9*-]+$", label, re.IGNORECASE)
        for label in labels
        if label
    )
