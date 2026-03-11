"""
Regression test: NameError 'ai_analysis' is not defined in _handle_smart_recon.

Root cause: recon_server.py line ~1142 called _format_progress_summary(...)
with `ai_analysis` but only `pattern_analysis` was ever assigned in that function.

Fix: pass `pattern_analysis` (already applied).

This file verifies the fix in two ways:
  1. AST scan of _handle_smart_recon — asserts `ai_analysis` is never LOADED
     without a corresponding STORE (i.e., no undefined-name read).
  2. Source-level grep — asserts the fixed variable name is present at the
     call site, and the old broken name is absent from that line range.
"""

import ast
import re
import sys
import unittest
from pathlib import Path

RECON_PATH = Path(__file__).parent.parent / "bughound" / "mcp_servers" / "recon_server.py"


def _function_line_range(path: Path, func_name: str):
    """Return (start_lineno, end_lineno) for the named function (1-indexed)."""
    source = path.read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == func_name:
                return node.lineno, node.end_lineno
    raise LookupError(f"Function {func_name!r} not found in {path}")


class TestNoStaleAiAnalysisReference(unittest.TestCase):
    """
    Verify `ai_analysis` is never used as an undefined name inside
    _handle_smart_recon.

    Strategy: walk the full file AST, restrict analysis to nodes whose
    source line falls inside the function, then check that every LOAD of
    `ai_analysis` has a preceding STORE of the same name.
    """

    def test_ai_analysis_has_no_bare_load_without_store(self):
        source = RECON_PATH.read_text()
        tree = ast.parse(source)

        start, end = _function_line_range(RECON_PATH, "_handle_smart_recon")

        stores = set()
        bare_loads = []

        # Walk in source order (ast.walk is unordered; use NodeVisitor)
        class Visitor(ast.NodeVisitor):
            def visit_Name(self, node):
                if node.lineno < start or node.lineno > end:
                    return
                if node.id == "ai_analysis":
                    if isinstance(node.ctx, ast.Store):
                        stores.add(node.lineno)
                    elif isinstance(node.ctx, ast.Load):
                        bare_loads.append(node.lineno)

        Visitor().visit(tree)

        # Any LOAD that has no preceding STORE is a NameError waiting to happen
        unguarded = [ln for ln in bare_loads if not stores]

        self.assertEqual(
            unguarded, [],
            msg=(
                f"NameError regression detected: `ai_analysis` is loaded at line(s) "
                f"{unguarded} inside _handle_smart_recon but is never assigned. "
                f"Should be `pattern_analysis`."
            )
        )
        print(f"✅ AST CHECK PASSED — no stale `ai_analysis` bare-loads in "
              f"_handle_smart_recon (lines {start}–{end})")


class TestCallSiteUsesPatternAnalysis(unittest.TestCase):
    """
    Source-level check: the _format_progress_summary call inside
    _handle_smart_recon must use `pattern_analysis`, not `ai_analysis`.
    """

    def _get_function_lines(self, func_name: str):
        lines = RECON_PATH.read_text().splitlines()
        start, end = _function_line_range(RECON_PATH, func_name)
        return lines[start - 1: end]   # 0-indexed slice

    def test_progress_summary_call_uses_pattern_analysis(self):
        func_lines = self._get_function_lines("_handle_smart_recon")

        # Find the _format_progress_summary call
        call_lines = [
            (i, line) for i, line in enumerate(func_lines)
            if "_format_progress_summary" in line
        ]

        self.assertTrue(call_lines, "_format_progress_summary call not found in _handle_smart_recon")

        # Grab the call block (the line and the next 2 lines for multi-line calls)
        call_idx = call_lines[0][0]
        call_block = "\n".join(func_lines[call_idx: call_idx + 4])

        self.assertIn(
            "pattern_analysis", call_block,
            f"Expected `pattern_analysis` in call block:\n{call_block}"
        )
        self.assertNotIn(
            "ai_analysis", call_block,
            f"Stale `ai_analysis` still present in call block:\n{call_block}"
        )

        print("✅ SOURCE CHECK PASSED — _format_progress_summary call uses `pattern_analysis`")
        print(f"   Call block:\n{call_block}")


class TestFormatProgressSummaryNoneSafety(unittest.TestCase):
    """
    Functional test: verify _format_progress_summary works with
    ai_analysis=None by importing and calling it directly via the class.
    We import only the module-level pieces we need, avoiding MCP bootstrap.
    """

    def _get_method(self):
        """
        Import just the _format_progress_summary method by reading and
        exec-ing only its source text in an isolated namespace.
        """
        source = RECON_PATH.read_text()
        lines = source.splitlines()
        start, end = _function_line_range(RECON_PATH, "_format_progress_summary")

        # Extract raw lines and dedent by one level (4 spaces = inside class)
        raw = lines[start - 1: end]
        dedented = []
        for line in raw:
            dedented.append(line[4:] if line.startswith("    ") else line)

        func_src = "\n".join(dedented)

        # Provide Any so the annotation resolves
        from typing import Any
        ns = {"Any": Any}
        exec(compile(func_src, "<_format_progress_summary>", "exec"), ns)
        return ns["_format_progress_summary"]

    def _fake_stats(self):
        return type("S", (), {
            "duration": 1.2,
            "total_found": 5,
            "sources": ["subfinder", "crtsh"],
            "resolving": 4,
            "categories": ["api", "admin"],
        })()

    def test_none_ai_analysis_returns_string_with_skipped(self):
        fn = self._get_method()
        result = fn(self, "example.com", "quick", self._fake_stats(), 3, None)

        self.assertIsInstance(result, str)
        self.assertIn("example.com", result)
        self.assertIn("Skipped", result)
        print("✅ FUNCTIONAL TEST PASSED — _format_progress_summary(ai_analysis=None) is safe")

    def test_truthy_ai_analysis_returns_complete_message(self):
        fn = self._get_method()
        result = fn(self, "example.com", "standard", self._fake_stats(), 3, object())

        self.assertIsInstance(result, str)
        self.assertIn("AI Analysis Complete", result)
        print("✅ FUNCTIONAL TEST PASSED — _format_progress_summary shows 'Complete' for truthy ai_analysis")


if __name__ == "__main__":
    unittest.main(verbosity=2)
