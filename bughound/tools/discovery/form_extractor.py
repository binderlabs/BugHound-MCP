"""Pure-Python form extraction and crawling via aiohttp + html.parser.

Discovers HTML forms, classifies them, generates testable URLs/bodies,
and optionally submits forms to discover second-level pages.
No external binary or BeautifulSoup dependency.
"""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import aiohttp
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Form classification patterns
# ---------------------------------------------------------------------------

_FORM_TYPES: dict[str, list[str]] = {
    "login_form": ["login", "signin", "sign-in", "auth", "password", "passwd", "credential"],
    "search_form": ["search", "query", "q=", "find", "lookup"],
    "upload_form": ["upload", "file", "attach", "import"],
    "contact_form": ["contact", "feedback", "message", "support", "ticket", "inquiry"],
    "api_form": ["api", "token", "key", "webhook", "endpoint"],
    "registration_form": ["register", "signup", "sign-up", "create-account", "join"],
    "data_form": ["data", "submit", "form", "entry", "record", "update", "edit", "profile"],
}

# Test values by input type/name
_TEST_VALUES: dict[str, str] = {
    "email": "test@example.com",
    "password": "TestP@ss123",
    "username": "testuser",
    "name": "Test User",
    "search": "test",
    "q": "test",
    "query": "test",
    "url": "https://example.com",
    "phone": "5551234567",
    "text": "test input",
    "number": "1",
    "date": "2026-01-01",
}


# ---------------------------------------------------------------------------
# HTML Parser for forms
# ---------------------------------------------------------------------------


class _FormParser(HTMLParser):
    """Extract <form>, <input>, <select>, <textarea>, <button> elements."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._in_select = False
        self._select_name = ""
        self._select_options: list[str] = []
        self._textarea_name = ""
        self._in_textarea = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k: (v or "") for k, v in attrs}

        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method") or "GET").upper(),
                "enctype": attr_dict.get("enctype", ""),
                "id": attr_dict.get("id", ""),
                "name": attr_dict.get("name", ""),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            input_type = (attr_dict.get("type") or "text").lower()
            if input_type in ("submit", "button", "image", "reset"):
                return
            self._current_form["inputs"].append({
                "name": attr_dict.get("name", ""),
                "type": input_type,
                "value": attr_dict.get("value", ""),
                "placeholder": attr_dict.get("placeholder", ""),
                "required": "required" in attr_dict,
            })

        elif tag == "select" and self._current_form is not None:
            self._in_select = True
            self._select_name = attr_dict.get("name", "")
            self._select_options = []

        elif tag == "option" and self._in_select:
            val = attr_dict.get("value", "")
            if val:
                self._select_options.append(val)

        elif tag == "textarea" and self._current_form is not None:
            self._in_textarea = True
            self._textarea_name = attr_dict.get("name", "")

        elif tag == "button" and self._current_form is not None:
            btn_type = (attr_dict.get("type") or "submit").lower()
            if btn_type == "submit":
                # Just note there's a submit button
                pass

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

        elif tag == "select" and self._in_select and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": self._select_name,
                "type": "select",
                "value": self._select_options[0] if self._select_options else "",
                "options": self._select_options,
            })
            self._in_select = False

        elif tag == "textarea" and self._in_textarea and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": self._textarea_name,
                "type": "textarea",
                "value": "",
            })
            self._in_textarea = False


# ---------------------------------------------------------------------------
# Form classification
# ---------------------------------------------------------------------------


def _classify_form(form: dict[str, Any], page_url: str) -> str:
    """Classify form into a category based on action, inputs, and context."""
    # Build a search string from form attributes and input names
    parts = [
        form.get("action", ""),
        form.get("id", ""),
        form.get("name", ""),
        page_url,
    ]
    parts.extend(inp.get("name", "") for inp in form.get("inputs", []))
    parts.extend(inp.get("type", "") for inp in form.get("inputs", []))
    search = " ".join(parts).lower()

    # Check for file upload first (enctype check)
    if form.get("enctype") == "multipart/form-data" or any(
        inp.get("type") == "file" for inp in form.get("inputs", [])
    ):
        return "upload_form"

    for form_type, keywords in _FORM_TYPES.items():
        if any(kw in search for kw in keywords):
            return form_type

    return "data_form"


# ---------------------------------------------------------------------------
# Test value generation
# ---------------------------------------------------------------------------


def _get_test_value(inp: dict[str, Any]) -> str:
    """Get an appropriate test value for a form input."""
    name = (inp.get("name") or "").lower()
    input_type = (inp.get("type") or "text").lower()

    # Use existing value if present
    if inp.get("value"):
        return inp["value"]

    # Select: use first option
    if input_type == "select" and inp.get("options"):
        return inp["options"][0]

    # Match by name
    for key, val in _TEST_VALUES.items():
        if key in name:
            return val

    # Match by type
    type_defaults = {
        "email": "test@example.com",
        "password": "TestP@ss123",
        "number": "1",
        "tel": "5551234567",
        "url": "https://example.com",
        "date": "2026-01-01",
        "hidden": "",
        "checkbox": "on",
        "radio": "1",
    }
    return type_defaults.get(input_type, "test")


def _build_testable_url(form: dict[str, Any], page_url: str) -> dict[str, Any]:
    """Build a testable URL or POST body from a form."""
    action = form.get("action", "")
    method = form.get("method", "GET")

    # Resolve action URL
    if not action or action == "#":
        target_url = page_url
    else:
        target_url = urljoin(page_url, action)

    # Build params
    params: dict[str, str] = {}
    for inp in form.get("inputs", []):
        name = inp.get("name", "")
        if not name:
            continue
        params[name] = _get_test_value(inp)

    if method == "GET":
        if params:
            sep = "&" if "?" in target_url else "?"
            full_url = f"{target_url}{sep}{urlencode(params)}"
        else:
            full_url = target_url
        return {"url": full_url, "method": "GET", "params": params}
    else:
        return {
            "url": target_url,
            "method": "POST",
            "params": params,
            "body": urlencode(params),
            "content_type": form.get("enctype") or "application/x-www-form-urlencoded",
        }


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------


async def extract_forms(
    targets: list[str],
    max_pages: int = 50,
    depth: int = 2,
    concurrency: int = 10,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """Extract forms from target URLs.

    Returns list of form dicts with classification and testable URLs.
    """
    all_forms: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    queue: list[tuple[str, int]] = [(url, 0) for url in targets]
    sem = asyncio.Semaphore(concurrency)

    conn = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    jar = aiohttp.CookieJar(unsafe=True)

    async with aiohttp.ClientSession(
        connector=conn,
        timeout=client_timeout,
        cookie_jar=jar,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
    ) as session:
        while queue and len(seen_urls) < max_pages:
            # Process batch
            batch = []
            while queue and len(batch) < concurrency:
                url, d = queue.pop(0)
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                batch.append((url, d))

            if not batch:
                break

            tasks = [
                _fetch_and_parse(session, sem, url, d)
                for url, d in batch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception) or result is None:
                    continue
                page_url, forms, links = result

                for form in forms:
                    # Only include forms with named inputs
                    named_inputs = [i for i in form.get("inputs", []) if i.get("name")]
                    if not named_inputs:
                        continue

                    classification = _classify_form(form, page_url)
                    testable = _build_testable_url(form, page_url)

                    all_forms.append({
                        "page_url": page_url,
                        "action": form.get("action", ""),
                        "method": form.get("method", "GET"),
                        "enctype": form.get("enctype", ""),
                        "form_id": form.get("id", ""),
                        "form_name": form.get("name", ""),
                        "classification": classification,
                        "inputs": named_inputs,
                        "testable": testable,
                        "source": "form_extractor",
                    })

                # Add links for next depth level
                current_depth = next(
                    (d for u, d in batch if u == page_url), 0
                )
                if current_depth < depth:
                    base_domain = urlparse(page_url).netloc
                    for link in links:
                        parsed = urlparse(link)
                        if parsed.netloc == base_domain and link not in seen_urls:
                            queue.append((link, current_depth + 1))

    logger.info(
        "form_extractor.done",
        forms_found=len(all_forms),
        pages_crawled=len(seen_urls),
    )
    return all_forms


async def _fetch_and_parse(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    url: str,
    depth: int,
) -> tuple[str, list[dict[str, Any]], list[str]] | None:
    """Fetch URL, parse HTML for forms and links."""
    async with sem:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return None
                ct = resp.headers.get("Content-Type", "")
                if "text/html" not in ct and "application/xhtml" not in ct:
                    return None

                body = await resp.text(errors="replace")
                if len(body) > 2_000_000:  # skip very large pages
                    body = body[:2_000_000]

                # Parse forms
                parser = _FormParser()
                try:
                    parser.feed(body)
                except Exception:
                    pass

                # Extract links for crawling
                links: list[str] = []
                for match in re.finditer(r'href=["\']([^"\']+)["\']', body):
                    href = match.group(1)
                    if href.startswith(("javascript:", "mailto:", "#", "data:")):
                        continue
                    abs_url = urljoin(url, href)
                    if abs_url.startswith("http"):
                        links.append(abs_url)

                return url, parser.forms, links

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        except Exception:
            return None
