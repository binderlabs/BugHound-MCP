"""OpenAPI/Swagger specification parser — extract endpoints and parameters.

Fetches and parses OpenAPI 2.0 (Swagger) and 3.x specs found during
sensitive path scanning. Extracts all endpoints with their parameters,
methods, and authentication requirements.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# Spec paths to try, in priority order
SPEC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.yaml",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/openapi.json",
]


async def fetch_spec(base_url: str, spec_path: str | None = None) -> dict[str, Any] | None:
    """Fetch an OpenAPI/Swagger spec from a URL.

    If spec_path is given, fetch that directly. Otherwise try common paths.
    Returns parsed JSON spec or None.
    """
    base = base_url.rstrip("/")
    paths_to_try = [spec_path] if spec_path else SPEC_PATHS

    for path in paths_to_try:
        url = path if path.startswith("http") else urljoin(base + "/", path.lstrip("/"))
        try:
            async with aiohttp.ClientSession(headers=_HEADERS) as session:
                async with session.get(
                    url, timeout=_TIMEOUT, ssl=False, allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text(errors="replace")
                    if not text.strip().startswith(("{", "[")):
                        continue
                    spec = json.loads(text)
                    # Validate it's actually a spec
                    if "paths" in spec or "openapi" in spec or "swagger" in spec:
                        logger.info("openapi_parser.found_spec", url=url)
                        return spec
        except Exception:
            continue

    return None


def parse_spec(spec: dict[str, Any], base_url: str = "") -> dict[str, Any]:
    """Parse an OpenAPI/Swagger spec into structured endpoint data.

    Returns dict with:
        endpoints: list of endpoint dicts
        auth_schemes: list of auth scheme names
        base_path: API base path
        spec_version: detected spec version
        stats: summary counts
    """
    # Detect version
    version = "unknown"
    if "openapi" in spec:
        version = spec["openapi"]
    elif "swagger" in spec:
        version = f"swagger_{spec['swagger']}"

    # Base path
    base_path = ""
    if "basePath" in spec:
        # Swagger 2.0
        base_path = spec["basePath"].rstrip("/")
    elif "servers" in spec:
        # OpenAPI 3.x
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            server_url = servers[0].get("url", "")
            if server_url and not server_url.startswith("http"):
                base_path = server_url.rstrip("/")

    # Auth schemes
    auth_schemes: list[str] = []
    security_defs = spec.get("securityDefinitions", {})  # Swagger 2.0
    if not security_defs:
        components = spec.get("components", {})
        security_defs = components.get("securitySchemes", {})  # OpenAPI 3.x
    for name, scheme in security_defs.items():
        scheme_type = scheme.get("type", "unknown")
        auth_schemes.append(f"{name} ({scheme_type})")

    # Parse endpoints
    endpoints: list[dict[str, Any]] = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        full_path = f"{base_path}{path}"

        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            params: list[dict[str, Any]] = []

            # Path-level parameters
            for p in path_item.get("parameters", []):
                if isinstance(p, dict):
                    params.append(_parse_param(p))

            # Operation-level parameters
            for p in operation.get("parameters", []):
                if isinstance(p, dict):
                    params.append(_parse_param(p))

            # Request body (OpenAPI 3.x)
            req_body = operation.get("requestBody", {})
            if isinstance(req_body, dict):
                content = req_body.get("content", {})
                for media_type, schema_info in content.items():
                    if isinstance(schema_info, dict):
                        schema = schema_info.get("schema", {})
                        body_params = _extract_schema_params(schema, spec)
                        params.extend(body_params)

            # Swagger 2.0 body parameter
            for p in operation.get("parameters", []):
                if isinstance(p, dict) and p.get("in") == "body":
                    schema = p.get("schema", {})
                    body_params = _extract_schema_params(schema, spec)
                    params.extend(body_params)

            # Security requirements
            security = operation.get("security", [])
            requires_auth = bool(security)

            endpoint = {
                "path": full_path,
                "method": method.upper(),
                "summary": operation.get("summary", ""),
                "parameters": params,
                "requires_auth": requires_auth,
                "tags": operation.get("tags", []),
            }

            # Build full URL if base_url provided
            if base_url:
                endpoint["url"] = f"{base_url.rstrip('/')}{full_path}"

            endpoints.append(endpoint)

    # Classify interesting endpoints
    redirect_endpoints = []
    injection_endpoints = []
    file_endpoints = []
    admin_endpoints = []

    _redirect_keywords = {"redirect", "callback", "return", "goto", "forward", "logout", "oauth"}
    _injection_keywords = {"search", "query", "filter", "sort", "id", "user"}
    _file_keywords = {"upload", "file", "download", "import", "export", "attachment"}
    _admin_keywords = {"admin", "manage", "internal", "system", "config", "settings"}

    for ep in endpoints:
        path_lower = ep["path"].lower()
        param_names = {p["name"].lower() for p in ep["parameters"]}

        if any(k in path_lower for k in _redirect_keywords) or param_names & _redirect_keywords:
            redirect_endpoints.append(ep)
        if any(k in path_lower for k in _injection_keywords) or param_names & _injection_keywords:
            injection_endpoints.append(ep)
        if any(k in path_lower for k in _file_keywords) or param_names & _file_keywords:
            file_endpoints.append(ep)
        if any(k in path_lower for k in _admin_keywords):
            admin_endpoints.append(ep)

    stats = {
        "total_endpoints": len(endpoints),
        "unique_paths": len(set(ep["path"] for ep in endpoints)),
        "methods": dict(sorted(
            {m: sum(1 for ep in endpoints if ep["method"] == m)
             for m in set(ep["method"] for ep in endpoints)}.items(),
        )),
        "endpoints_with_params": sum(1 for ep in endpoints if ep["parameters"]),
        "auth_required_endpoints": sum(1 for ep in endpoints if ep["requires_auth"]),
        "redirect_endpoints": len(redirect_endpoints),
        "injection_candidates": len(injection_endpoints),
        "file_endpoints": len(file_endpoints),
        "admin_endpoints": len(admin_endpoints),
    }

    return {
        "spec_version": version,
        "base_path": base_path,
        "auth_schemes": auth_schemes,
        "endpoints": endpoints,
        "redirect_endpoints": redirect_endpoints,
        "injection_endpoints": injection_endpoints,
        "file_endpoints": file_endpoints,
        "admin_endpoints": admin_endpoints,
        "stats": stats,
    }


def _parse_param(param: dict[str, Any]) -> dict[str, Any]:
    """Parse a single parameter definition."""
    return {
        "name": param.get("name", ""),
        "in": param.get("in", "query"),
        "required": param.get("required", False),
        "type": param.get("type", param.get("schema", {}).get("type", "string")),
    }


def _extract_schema_params(
    schema: dict[str, Any], spec: dict[str, Any], depth: int = 0,
) -> list[dict[str, Any]]:
    """Extract parameter names from a JSON schema (request body)."""
    if depth > 3:
        return []

    # Resolve $ref
    if "$ref" in schema:
        ref_path = schema["$ref"]
        schema = _resolve_ref(ref_path, spec)
        if not schema:
            return []

    params: list[dict[str, Any]] = []
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))

    for name, prop in properties.items():
        if isinstance(prop, dict):
            prop_type = prop.get("type", "string")
            if prop_type == "object":
                # Recurse into nested objects
                params.extend(_extract_schema_params(prop, spec, depth + 1))
            else:
                params.append({
                    "name": name,
                    "in": "body",
                    "required": name in required,
                    "type": prop_type,
                })

    return params


def _resolve_ref(ref: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Resolve a JSON $ref pointer within the spec."""
    if not ref.startswith("#/"):
        return {}
    parts = ref[2:].split("/")
    current: Any = spec
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part, {})
        else:
            return {}
    return current if isinstance(current, dict) else {}


async def discover_and_parse(
    host_url: str,
    known_spec_paths: list[str] | None = None,
) -> dict[str, Any] | None:
    """Convenience: fetch spec from host and parse it.

    known_spec_paths: paths already discovered by sensitive_paths scanner.
    """
    base = host_url.rstrip("/")
    spec = None

    # Try known paths first
    if known_spec_paths:
        for path in known_spec_paths:
            spec = await fetch_spec(base, spec_path=path)
            if spec:
                break

    # Fall back to probing common paths
    if not spec:
        spec = await fetch_spec(base)

    if not spec:
        return None

    return parse_spec(spec, base_url=base)
