"""GraphQL security tester — pure aiohttp, no external tool.

Tests introspection, query depth limits, batch queries, field suggestions,
and unauthorized mutations.
"""

from __future__ import annotations

import json
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger()

_TIMEOUT = aiohttp.ClientTimeout(total=20)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/json",
}

_INTROSPECTION_QUERY = """{
  __schema {
    types {
      name
      kind
      fields {
        name
        args { name }
      }
    }
    mutationType {
      fields {
        name
        args { name type { name } }
      }
    }
    queryType {
      fields { name }
    }
  }
}"""

# 10-level nested query for depth limit testing
_DEPTH_QUERY = """{
  __typename
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          fields {
            name
            type {
              name
              fields {
                name
                type {
                  name
                  fields {
                    name
                    type {
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}"""


async def _gql_request(
    session: aiohttp.ClientSession,
    url: str,
    query: str | None = None,
    payload: Any = None,
) -> tuple[int, dict[str, Any]]:
    """Send a GraphQL request. Returns (status, json_body)."""
    if payload is None:
        payload = {"query": query}
    try:
        async with session.post(
            url, json=payload, headers=_HEADERS, ssl=False, timeout=_TIMEOUT,
        ) as resp:
            body = await resp.text(errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {"raw": body[:2000]}
            return resp.status, data
    except Exception:
        return 0, {}


async def test_graphql_data_leaks(
    url: str,
    auth_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Test for unauthenticated data leaks via GraphQL queries.

    Sends the introspection query, extracts top-level Query fields, then
    auto-generates simple queries for each field WITHOUT auth headers to
    detect data exposed to unauthenticated users.
    """
    result: dict[str, Any] = {
        "vulnerable": False,
        "leaks": [],
        "evidence": "",
        "confidence": "high",
    }

    _SKIP_FIELDS = {"mutation", "subscription", "__schema", "__type"}
    _LEAK_TIMEOUT = aiohttp.ClientTimeout(total=15)
    _MAX_FIELDS = 10
    _MAX_SCALAR_FIELDS = 8
    _MAX_RECORDS = 5

    async with aiohttp.ClientSession() as session:
        # Step 1: Introspection query (with auth if provided, to discover schema)
        intro_headers = {**_HEADERS}
        if auth_headers:
            intro_headers.update(auth_headers)

        try:
            async with session.post(
                url,
                json={"query": _INTROSPECTION_QUERY},
                headers=intro_headers,
                ssl=False,
                timeout=_LEAK_TIMEOUT,
            ) as resp:
                if resp.status != 200:
                    return result
                body = await resp.text(errors="replace")
                try:
                    intro_data = json.loads(body)
                except json.JSONDecodeError:
                    return result
        except Exception:
            logger.debug("graphql_data_leaks.introspection_failed", url=url)
            return result

        schema = (intro_data.get("data") or {}).get("__schema")
        if not schema:
            return result

        # Step 2: Extract top-level query field names
        query_type = schema.get("queryType")
        if not query_type or not query_type.get("fields"):
            return result

        query_fields = [
            f["name"]
            for f in query_type["fields"]
            if f.get("name") and f["name"].lower() not in _SKIP_FIELDS
        ][:_MAX_FIELDS]

        if not query_fields:
            return result

        # Build a type lookup from the schema for resolving return types
        type_map: dict[str, dict[str, Any]] = {}
        for t in schema.get("types", []):
            if t.get("name"):
                type_map[t["name"]] = t

        leaks: list[dict[str, Any]] = []

        for field_name in query_fields:
            # Step 3a: Query __type to discover return type and scalar fields
            type_query = (
                '{ __type(name: "__Query_field_placeholder__") '
                "{ name kind fields { name type { name kind ofType { name kind } } } } }"
            )
            # First, find the return type from the full schema types
            scalar_fields: list[str] = []
            return_type_name: str | None = None

            # Look up the field in the schema to find its return type
            for t in schema.get("types", []):
                if t.get("name") == (query_type.get("name") or "Query"):
                    for fld in t.get("fields") or []:
                        if fld.get("name") == field_name:
                            # Resolve the return type (unwrap NON_NULL / LIST)
                            ftype = fld.get("type") or {}
                            return_type_name = _resolve_type_name(ftype)
                            break
                    break

            # If we couldn't resolve the type from queryType's fields list,
            # try a __type introspection query
            if not return_type_name:
                type_introspect = (
                    "{ __schema { queryType { fields { name type { "
                    "name kind ofType { name kind ofType { name kind } } "
                    "} } } } }"
                )
                try:
                    async with session.post(
                        url,
                        json={"query": type_introspect},
                        headers=intro_headers,
                        ssl=False,
                        timeout=_LEAK_TIMEOUT,
                    ) as resp:
                        if resp.status == 200:
                            tbody = await resp.text(errors="replace")
                            tdata = json.loads(tbody)
                            qt_fields = (
                                (tdata.get("data") or {})
                                .get("__schema", {})
                                .get("queryType", {})
                                .get("fields", [])
                            )
                            for qf in qt_fields:
                                if qf.get("name") == field_name:
                                    return_type_name = _resolve_type_name(
                                        qf.get("type") or {},
                                    )
                                    break
                except Exception:
                    pass

            # Discover scalar fields of the return type
            if return_type_name and return_type_name in type_map:
                resolved = type_map[return_type_name]
                for fld in (resolved.get("fields") or [])[:_MAX_SCALAR_FIELDS]:
                    fld_type = fld.get("type") or {}
                    fld_kind = fld_type.get("kind", "")
                    inner_kind = (fld_type.get("ofType") or {}).get("kind", "")
                    if fld_kind == "SCALAR" or inner_kind == "SCALAR":
                        scalar_fields.append(fld["name"])

            # Fallback: if no scalar fields detected, use common field names
            if not scalar_fields:
                scalar_fields = ["id", "name", "email"]

            scalar_selection = " ".join(scalar_fields[:_MAX_SCALAR_FIELDS])

            # Step 3b: Build and send the data query WITHOUT auth
            # Try with pagination arguments
            for args_str in [
                f"(first: {_MAX_RECORDS})",
                f"(limit: {_MAX_RECORDS})",
                "",
            ]:
                data_query = f"{{ {field_name}{args_str} {{ {scalar_selection} }} }}"

                try:
                    async with session.post(
                        url,
                        json={"query": data_query},
                        headers=_HEADERS,  # NO auth headers
                        ssl=False,
                        timeout=_LEAK_TIMEOUT,
                    ) as resp:
                        if resp.status != 200:
                            continue
                        qbody = await resp.text(errors="replace")
                        try:
                            qdata = json.loads(qbody)
                        except json.JSONDecodeError:
                            continue
                except Exception:
                    continue

                # Step 5: Check if data was actually returned
                field_data = (qdata.get("data") or {}).get(field_name)
                if field_data is None:
                    continue

                # Ignore if only errors and no real data
                if qdata.get("errors") and not field_data:
                    continue

                # Determine record count and sample
                if isinstance(field_data, list):
                    if not field_data:
                        continue
                    record_count = len(field_data)
                    sample = field_data[0]
                elif isinstance(field_data, dict):
                    if not field_data:
                        continue
                    record_count = 1
                    sample = field_data
                else:
                    # Scalar return — not a data leak of records
                    continue

                # Extract which fields were actually exposed
                if isinstance(sample, dict):
                    fields_exposed = [
                        k for k in sample.keys()
                        if sample[k] is not None
                    ]
                else:
                    fields_exposed = scalar_fields

                sample_str = json.dumps(sample, default=str)
                if len(sample_str) > 200:
                    sample_str = sample_str[:200] + "..."

                leaks.append({
                    "query_name": field_name,
                    "record_count": record_count,
                    "fields_exposed": fields_exposed,
                    "sample_data": sample_str,
                })
                logger.info(
                    "graphql_data_leak_found",
                    url=url,
                    query=field_name,
                    records=record_count,
                    fields=fields_exposed,
                )
                break  # Got data, no need to try other pagination args

        if leaks:
            result["vulnerable"] = True
            result["leaks"] = leaks
            leak_summary = ", ".join(
                f"{l['query_name']} ({l['record_count']} records)" for l in leaks
            )
            result["evidence"] = f"GraphQL data leaks: {leak_summary}"

    return result


def _resolve_type_name(type_info: dict[str, Any]) -> str | None:
    """Unwrap NON_NULL / LIST wrappers to find the underlying type name."""
    current = type_info
    for _ in range(5):  # Guard against infinite nesting
        kind = current.get("kind", "")
        if kind in ("NON_NULL", "LIST"):
            current = current.get("ofType") or {}
        else:
            return current.get("name")
    return current.get("name")


async def test_graphql(graphql_url: str) -> dict[str, Any]:
    """Run comprehensive GraphQL security tests."""
    results: dict[str, Any] = {
        "url": graphql_url,
        "introspection_enabled": False,
        "schema_types": [],
        "mutations": [],
        "depth_limited": True,
        "batch_limited": True,
        "field_suggestions": False,
        "unauthorized_mutations": [],
        "full_schema": None,
    }

    async with aiohttp.ClientSession() as session:
        # Test 1: Introspection
        status, data = await _gql_request(session, graphql_url, _INTROSPECTION_QUERY)
        if status == 200 and "data" in data:
            schema = data.get("data", {}).get("__schema")
            if schema:
                results["introspection_enabled"] = True

                # Extract types (filter out built-in __ types)
                types = schema.get("types", [])
                user_types = [
                    {
                        "name": t["name"],
                        "kind": t.get("kind", ""),
                        "field_count": len(t.get("fields") or []),
                        "fields": [f["name"] for f in (t.get("fields") or [])][:20],
                    }
                    for t in types
                    if t.get("name") and not t["name"].startswith("__")
                ]
                results["schema_types"] = user_types[:50]

                # Extract mutations
                mutation_type = schema.get("mutationType")
                if mutation_type and mutation_type.get("fields"):
                    results["mutations"] = [
                        {
                            "name": m["name"],
                            "args": [a["name"] for a in (m.get("args") or [])],
                        }
                        for m in mutation_type["fields"]
                    ][:30]

                results["full_schema"] = schema

        # Test 2: Query Depth
        status, data = await _gql_request(session, graphql_url, _DEPTH_QUERY)
        if status == 200 and "data" in data and "errors" not in data:
            results["depth_limited"] = False
        elif status == 200 and "errors" in data:
            errors = data.get("errors", [])
            depth_err = any(
                "depth" in str(e).lower() or "complexity" in str(e).lower()
                for e in errors
            )
            results["depth_limited"] = depth_err

        # Test 3: Batch Query
        batch_query = {"query": "{ __typename }"}
        batch_payload = [batch_query] * 10
        status, data = await _gql_request(
            session, graphql_url, payload=batch_payload,
        )
        if status == 200 and isinstance(data, list) and len(data) >= 10:
            results["batch_limited"] = False

        # Test 4: Field Suggestions
        status, data = await _gql_request(
            session, graphql_url, "{ __typenameXYZ }",
        )
        if status in (200, 400):
            errors = data.get("errors", [])
            for err in errors:
                msg = str(err.get("message", ""))
                if "did you mean" in msg.lower() or "suggest" in msg.lower():
                    results["field_suggestions"] = True
                    break

        # Test 5: Unauthorized Mutations
        if results["mutations"]:
            for mutation in results["mutations"][:5]:
                m_name = mutation["name"]
                # Try a simple mutation call without auth
                m_query = f"mutation {{ {m_name} }}"
                status, data = await _gql_request(session, graphql_url, m_query)
                if status == 200 and "data" in data and data["data"].get(m_name) is not None:
                    results["unauthorized_mutations"].append({
                        "mutation": m_name,
                        "status": status,
                    })

    return results
