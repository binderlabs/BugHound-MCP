"""
BugHound Scan Plan Module

This module defines the ScanPlan dataclass, which represents a fully approved
and structured plan for a security scan execution. It encapsulates all
constraints, targets, and configuration parameters required to run a scan.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import uuid
import json
from datetime import datetime

@dataclass
class ApprovedTarget:
    """Represents a specific target approved for scanning, with associated tools and justification."""
    url: str
    tools: List[str]
    justification: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ScanPlan:
    """
    Represents an approved plan for execution.
    
    Attributes:
        workspace_id: Unique identifier for the workspace this plan belongs to.
        mode: The scan mode ('STEALTH', 'NORMAL', 'INTENSE').
        budget_minutes: The maximum time allocated for this scan.
        approved_targets: List of targets explicitly allowed for scanning, with tool assignments.
        forbidden_targets: List of targets that are strictly forbidden from scanning.
    """
    workspace_id: str
    mode: str
    budget_minutes: int
    approved_targets: List[ApprovedTarget]
    forbidden_targets: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the plan to a dictionary exactly matching the JSON schema."""
        return {
            "workspace_id": self.workspace_id,
            "mode": self.mode,
            "budget_minutes": self.budget_minutes,
            "approved_targets": [t.to_dict() for t in self.approved_targets],
            "forbidden_targets": self.forbidden_targets
        }

    @classmethod
    def from_context(cls, context: Dict[str, Any]) -> 'ScanPlan':
        """
        Create a ScanPlan from a raw context dictionary.
        
        Args:
            context: Dictionary containing plan parameters.
        
        Returns:
            A new ScanPlan instance.
        """
        approved_targets_data = context.get("approved_targets", [])
        approved_targets = [
            ApprovedTarget(
                url=t.get("url", ""),
                tools=t.get("tools", []),
                justification=t.get("justification", "")
            ) for t in approved_targets_data
        ]

        return cls(
            workspace_id=context.get("workspace_id", f"run_{uuid.uuid4().hex[:8]}"),
            mode=context.get("mode", "NORMAL"),
            budget_minutes=context.get("budget_minutes", 120),
            approved_targets=approved_targets,
            forbidden_targets=context.get("forbidden_targets", [])
        )

# Example Usage
if __name__ == "__main__":
    plan = ScanPlan(
        workspace_id="example_com_12345",
        mode="NORMAL",
        budget_minutes=120,
        approved_targets=[
            ApprovedTarget(
                url="https://api.example.com/v1",
                tools=["nuclei", "ffuf"],
                justification="High value target revealing GraphQL"
            )
        ],
        forbidden_targets=[
            "https://auth.example.com/*",
            "cdn.example.com"
        ]
    )
    
    print("--- Manual Plan ---")
    print(json.dumps(plan.to_dict(), indent=2))
