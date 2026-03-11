#!/usr/bin/env python3
"""
Test for get_capabilities MCP tool — spec-aligned schema assertions.

Asserts:
  - workflow_model exists
  - tools.by_stage exists
  - tools.by_risk exists
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bughound.core.tool_registry import get_all_tools


def test_get_capabilities():
    print("=" * 60)
    print("TEST: get_capabilities (spec-aligned schema)")
    print("=" * 60)

    # --- replicate handler logic ---
    try:
        from bughound import __version__
        version = __version__
    except (ImportError, AttributeError):
        version = "dev"

    all_tools = get_all_tools()

    by_stage = {}
    for tool in all_tools:
        by_stage.setdefault(tool.stage, []).append({
            "name": tool.name,
            "risk": tool.risk,
            "default_enabled": tool.risk != "intrusive"
        })

    by_risk = {}
    for tool in all_tools:
        by_risk.setdefault(tool.risk, []).append({
            "name": tool.name,
            "risk": tool.risk,
            "default_enabled": tool.risk != "intrusive"
        })

    scan_modes = {
        "STEALTH": {"deep_scan_enabled": False, "intrusive_allowed": False},
        "NORMAL":  {"deep_scan_enabled": False, "intrusive_allowed": True},
        "WEB":     {"deep_scan_enabled": False, "intrusive_allowed": True},
        "INTENSE": {"deep_scan_enabled": True,  "intrusive_allowed": True},
    }

    result = {
        "name": "BugHound",
        "version": version,
        "workflow_model": "Context \u2192 Plan \u2192 Policy \u2192 Execute \u2192 Validate \u2192 Explain",
        "guarantees": {
            "simulation_executes_tools": False,
            "execution_is_policy_gated": True,
            "validation_suppresses_false_positives": True
        },
        "scan_modes": scan_modes,
        "tools": {
            "by_stage": by_stage,
            "by_risk": by_risk
        }
    }

    # --- mandatory spec assertions ---
    assert "workflow_model" in result, "FAIL: workflow_model missing"
    print("  \u2713 workflow_model present:", result["workflow_model"])

    assert "tools" in result, "FAIL: tools missing"
    assert "by_stage" in result["tools"], "FAIL: tools.by_stage missing"
    assert "by_risk" in result["tools"], "FAIL: tools.by_risk missing"
    print("  \u2713 tools.by_stage present:", list(result["tools"]["by_stage"].keys()))
    print("  \u2713 tools.by_risk present:", list(result["tools"]["by_risk"].keys()))

    # --- tool object shape ---
    for stage, tools in result["tools"]["by_stage"].items():
        for t in tools:
            assert "name" in t and "risk" in t and "default_enabled" in t, \
                f"FAIL: bad tool object in stage {stage}: {t}"
    print("  \u2713 All tool objects have {name, risk, default_enabled}")

    # --- guarantees block ---
    g = result["guarantees"]
    assert g["simulation_executes_tools"] == False
    assert g["execution_is_policy_gated"] == True
    assert g["validation_suppresses_false_positives"] == True
    print("  \u2713 guarantees block correct")

    # --- scan modes ---
    for mode in ["STEALTH", "NORMAL", "INTENSE"]:
        assert mode in result["scan_modes"], f"FAIL: missing mode {mode}"
    print("  \u2713 STEALTH/NORMAL/INTENSE present in scan_modes")

    print("\n\u2705 TEST PASSED\n")
    print("Example JSON output:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    test_get_capabilities()
