"""
BugHound Policy Engine

This module serves as the central authority for enforcing scope, mode, budget,
and tool restrictions. It provides boolean approvals or denials with reasons,
ensuring that the agent operates strictly within its defined boundaries.
"""

from dataclasses import dataclass
from typing import List, Optional, Set
import fnmatch
import logging

try:
    from .scan_plan import ScanPlan
except ImportError:
    # Fallback for standalone testing or relative import issues
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from bughound.core.scan_plan import ScanPlan

logger = logging.getLogger(__name__)

@dataclass
class PolicyDecision:
    """Represents a policy compliance decision."""
    allowed: bool
    reason: str

class PolicyEngine:
    """
    Enforces security and operational policies for BugHound.
    """
    
    # Tools considered "Deep" or "Intrusive"
    DEEP_TOOLS = {"sqlmap", "ffuf", "nmap", "dalfox", "hydra", "subjack"}

    def __init__(
        self, 
        mode: str, 
        scan_plan: ScanPlan, 
        scope_allowlist: Optional[List[str]] = None, 
        scope_denylist: Optional[List[str]] = None
    ):
        """
        Initialize the Policy Engine.

        Args:
            mode: The current operation mode (e.g., 'STEALTH', 'NORMAL').
            scan_plan: The approved ScanPlan object containing execution constraints.
            scope_allowlist: Optional list of allowed target patterns (glob/fnmatch).
            scope_denylist: Optional list of denied target patterns (glob/fnmatch).
        """
        self.mode = mode.upper()
        self.scan_plan = scan_plan
        self.scope_allowlist = scope_allowlist or []
        self.scope_denylist = scope_denylist or []

    def approve_target(self, target: str) -> PolicyDecision:
        """
        Check if a target is allowed based on the plan and scope lists.
        """
        # 1. Check Scan Plan Restrictions
        if self.scan_plan:
            approved_urls = [t.url for t in self.scan_plan.approved_targets]
            # Strip prefixes if necessary or check exact match
            # To be safe, we check if target is a substring or exactly matches an approved URL
            matched_plan = any(target in url or url in target for url in approved_urls)
            if not matched_plan and approved_urls:
                return PolicyDecision(False, f"Target '{target}' not in approved scan plan targets.")
            
            for forbidden in self.scan_plan.forbidden_targets:
                if fnmatch.fnmatch(target, forbidden) or target in forbidden or forbidden in target:
                    return PolicyDecision(False, f"Target '{target}' is explicitly forbidden by the scan plan.")

        # 2. Check Denylist (highest priority scope constraint)
        for pattern in self.scope_denylist:
            if fnmatch.fnmatch(target, pattern):
                return PolicyDecision(False, f"Target '{target}' matches denylist pattern '{pattern}'.")

        # 3. Check Allowlist (if exists)
        if self.scope_allowlist:
            matched = False
            for pattern in self.scope_allowlist:
                if fnmatch.fnmatch(target, pattern):
                    matched = True
                    break
            if not matched:
                return PolicyDecision(False, f"Target '{target}' does not match any allowlist scope.")

        return PolicyDecision(True, "Target is allowed.")

    def approve_tool(self, tool_name: str, tool_risk: Optional[str] = None) -> PolicyDecision:
        """
        Check if a tool execution is allowed.
        """
        tool_name = tool_name.lower()

        # 1. Check Scan Plan Explicit Allowlist (from approved_targets)
        if self.scan_plan and self.scan_plan.approved_targets:
            all_approved_tools = set()
            for t in self.scan_plan.approved_targets:
                for tool in t.tools:
                    all_approved_tools.add(tool.lower())
            
            if tool_name not in all_approved_tools:
                return PolicyDecision(False, f"Tool '{tool_name}' not in any scan plan approved_targets' tools.")

        # 2. Check Deep/Intrusive Logic
        is_deep = False
        if tool_risk:
            if tool_risk in ["intrusive", "deep"]:
                is_deep = True
        elif tool_name in self.DEEP_TOOLS:
            is_deep = True

        if is_deep:
            if self.mode == "STEALTH":
                return PolicyDecision(False, f"Deep tool '{tool_name}' denied in STEALTH mode.")
            if self.mode != "INTENSE" and tool_name in ["sqlmap", "dalfox"]: # Example constraint
                return PolicyDecision(False, f"Highly intrusive tool '{tool_name}' denied unless mode is INTENSE.")

        return PolicyDecision(True, "Tool is allowed.")

    def approve_deep_scan(self) -> PolicyDecision:
        """
        Check if deep scanning generically is allowed.
        """
        if self.mode == "STEALTH":
            return PolicyDecision(False, "Deep scan denied in STEALTH mode.")
        if self.scan_plan and self.scan_plan.mode.upper() == "STEALTH":
            return PolicyDecision(False, "Deep scan denied by scan plan mode.")
            
        return PolicyDecision(True, "Deep scan allowed.")

# --- Test Block ---
if __name__ == "__main__":
    from bughound.core.scan_plan import ApprovedTarget
    
    # 1. Setup Mock Plan
    plan = ScanPlan(
        workspace_id="test_run",
        mode="NORMAL",
        budget_minutes=60,
        approved_targets=[
            ApprovedTarget(url="https://testphp.vulnweb.com", tools=["httpx", "ffuf"], justification="Test")
        ],
        forbidden_targets=["admin.vulnweb.com"]
    )

    # 2. Setup Engine with Scope
    engine = PolicyEngine(
        mode="NORMAL",
        scan_plan=plan,
        scope_allowlist=["*.vulnweb.com", "example.com"],
        scope_denylist=["admin.vulnweb.com"]
    )

    print("--- Policy Engine Test ---\n")

    # Test Targets
    targets = [
        "testphp.vulnweb.com", # In plan, In allowlist -> OK
        "admin.vulnweb.com",   # In denylist -> DENY
        "google.com"           # Not in plan -> DENY
    ]

    print("Target Checks:")
    for t in targets:
        decision = engine.approve_target(t)
        print(f"[{'AVAIL' if decision.allowed else 'DENY'}] {t}: {decision.reason}")

    # Test Tools
    # Case 1: Normal Mode
    print("\nTool Checks (Normal Mode):")
    tools = ["httpx", "ffuf", "nmap"]
    for t in tools:
        decision = engine.approve_tool(t)
        print(f"[{'AVAIL' if decision.allowed else 'DENY'}] {t}: {decision.reason}")

    # Case 2: Stealth Mode
    engine.mode = "STEALTH"
    print("\nTool Checks (Stealth Mode):")
    for t in tools:
        decision = engine.approve_tool(t)
        print(f"[{'AVAIL' if decision.allowed else 'DENY'}] {t}: {decision.reason}")
