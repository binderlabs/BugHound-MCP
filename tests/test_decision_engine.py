import pytest
from unittest.mock import Mock, patch
from bughound.core.decision_engine import DecisionEngine
from bughound.core.workspace_manager import WorkspaceManager
from bughound.core.scan_plan import ScanPlan, ApprovedTarget

@pytest.fixture
def workspace_manager():
    return Mock(spec=WorkspaceManager)

@pytest.fixture
def decision_engine(workspace_manager):
    return DecisionEngine(workspace_manager)

def test_decide_plan_stealth_mode(decision_engine):
    # Setup mock context
    context = {
        "subdomains": [
            "api.example.com",
            "static.example.com"
        ],
        "httpx_results": [
            {"url": "https://api.example.com", "status_code": 200},
            {"url": "http://static.example.com", "status_code": 200}
        ]
    }
    
    plan: ScanPlan = decision_engine.decide_plan(
        workspace_id="test_ws",
        mode="STEALTH",
        budget_minutes=120,
        context_summary=context
    )
    
    assert plan.workspace_id == "test_ws"
    assert plan.mode == "STEALTH"
    assert plan.budget_minutes == 120
    
    # In stealth mode, static/cdn domains should be forbidden
    assert any("static.example.com" in f for f in plan.forbidden_targets)
    
    # api.example.com should be approved
    assert len(plan.approved_targets) == 1
    assert "api.example.com" in plan.approved_targets[0].url
    assert "nuclei-stealth" in plan.approved_targets[0].tools

def test_decide_plan_budget_constraint(decision_engine):
    # Create 10 mock targets
    subdomains = [f"api{i}.example.com" for i in range(10)]
    httpx_results = [{"url": f"https://api{i}.example.com", "status_code": 200} for i in range(10)]
    
    context = {
        "subdomains": subdomains,
        "httpx_results": httpx_results
    }
    
    # Given budget is only 2 minutes, max_targets will be 1 
    plan: ScanPlan = decision_engine.decide_plan(
        workspace_id="test_ws",
        mode="NORMAL",
        budget_minutes=2,
        context_summary=context
    )
    
    # max_targets = max(1, budget_minutes // 2) -> max(1, 1) = 1
    assert len(plan.approved_targets) == 1
    # The rest should be discarded or forbidden
    assert len(plan.forbidden_targets) > 0


