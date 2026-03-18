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
