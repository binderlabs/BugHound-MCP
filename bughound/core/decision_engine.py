"""
BugHound Decision Engine

This module transforms raw reconnaissance data into a structured ScanPlan.
It applies deterministic scoring algorithms (and optionally AI) to prioritize
targets and configure the scan execution strategy.
"""

from typing import List, Dict, Any, Optional
import logging
from dataclasses import asdict

try:
    from .scan_plan import ScanPlan, ApprovedTarget
except ImportError:
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from bughound.core.scan_plan import ScanPlan, ApprovedTarget

logger = logging.getLogger(__name__)

class DecisionEngine:
    """
    Analyzes context and produces a ScanPlan.
    """
    
    # Scoring Constants
    HIGH_SIGNAL_KEYWORDS = {
        "admin", "api", "auth", "login", "portal", "dashboard", 
        "dev", "stage", "stg", "uat", "internal", "manage", "vpn",
        "secure", "test", "beta"
    }
    LOW_SIGNAL_KEYWORDS = {
        "cdn", "static", "assets", "img", "images", "js", "css", 
        "fonts", "media", "email", "mail", "autodiscover", "help"
    }
    
    SCORE_KEYWORD_HIGH = 10
    SCORE_KEYWORD_LOW = -20
    SCORE_WAYBACK_HIGH = 5
    SCORE_HTTPX_LIVE = 5

    def __init__(self, ai_client=None):
        """
        Args:
            ai_client: Optional AI client for advanced prioritization (unused in V1).
        """
        self.ai_client = ai_client

    def decide_plan(
        self, 
        workspace_id: str, 
        mode: str, 
        budget_minutes: int, 
        context_summary: Dict[str, Any]
    ) -> ScanPlan:
        """
        Generate a ScanPlan based on the provided context and constraints.

        Args:
            workspace_id: Unique ID for the workspace.
            mode: Scan mode (STEALTH, NORMAL, INTENSE).
            budget_minutes: Resource constraints based on time.
            context_summary: Dictionary containing recon data.
                             - subdomains: list[str]
                             - httpx_results: list[dict] (optional)
                             - wayback_counts: dict[str, int] (optional)
        
        Returns:
            A fully populated ScanPlan.
        """
        subdomains = context_summary.get("subdomains", [])
        httpx_results = context_summary.get("httpx_results", [])
        wayback_counts = context_summary.get("wayback_counts", {})
        
        # Pre-process httpx for faster lookup: map domain -> info dict
        httpx_map = {}
        for res in httpx_results:
            url = res.get("url", "")
            if url:
                clean_host = url.replace("https://", "").replace("http://", "").split("/")[0]
                httpx_map[clean_host] = res
                if "input" in res:
                    httpx_map[res["input"]] = res

        scored_targets = []
        forbidden_targets = []

        mode_upper = mode.upper()

        for target in subdomains:
            score = 0
            reasons = []

            # A. Keyword Analysis
            target_lower = target.lower()
            found_high = [k for k in self.HIGH_SIGNAL_KEYWORDS if k in target_lower]
            if found_high:
                score += self.SCORE_KEYWORD_HIGH
                reasons.append(f"High signal keywords found: {', '.join(found_high)}")
            
            found_low = [k for k in self.LOW_SIGNAL_KEYWORDS if k in target_lower]
            if found_low:
                score += self.SCORE_KEYWORD_LOW
                reasons.append(f"Low signal keywords found: {', '.join(found_low)}")

            # B. Wayback History
            wb_count = wayback_counts.get(target, 0)
            if wb_count > 50:
                score += self.SCORE_WAYBACK_HIGH
                reasons.append(f"High historical activity ({wb_count} URLs)")

            # C. Live Status (HTTPx)
            h_res = httpx_map.get(target)
            if h_res:
                status = h_res.get("status_code", 0)
                if status in [200, 302, 301, 307, 401, 403]:
                    score += self.SCORE_HTTPX_LIVE
                    reasons.append(f"Live host detected (Status: {status})")

            if not reasons:
                reasons.append("Baseline discovery")

            # Strategy for forbidden vs approved
            if score < 0 and mode_upper in ["STEALTH", "NORMAL"]:
                forbidden_targets.append(f"https://{target}/*")
                forbidden_targets.append(f"http://{target}/*")
            else:
                justification = "; ".join(reasons)
                
                # Determine URL
                url = f"https://{target}"
                if h_res and h_res.get("url"):
                    url = h_res.get("url")

                # Determine Tools based on score and mode
                tools = []
                if mode_upper == "INTENSE":
                    tools = ["nuclei", "nmap", "trufflehog"]
                elif mode_upper == "STEALTH":
                    tools = ["nuclei-stealth", "jsluice"]
                else: # NORMAL
                    if score >= 10:
                        tools = ["nuclei", "nmap", "ffuf"]
                    elif h_res: # Live target but lower score
                        tools = ["nuclei", "nmap-top100"]
                    else:
                        tools = ["tsunami", "jsluice"]

                scored_targets.append({
                    "score": score,
                    "target": ApprovedTarget(
                        url=url,
                        tools=tools,
                        justification=justification
                    )
                })

        # Sort descending by score
        scored_targets.sort(key=lambda x: x["score"], reverse=True)
        
        # Budget dictates max targets (rough estimation for mapping minutes to targets)
        # e.g., 5 mins per high priority target logic
        max_targets = max(1, budget_minutes // 2) if budget_minutes > 0 else 100
        approved_targets = [t["target"] for t in scored_targets[:max_targets]]

        # The rest of targets that didn't make the budget cut might be considered forbidden or just not approved
        for t in scored_targets[max_targets:]:
            target_obj = t["target"]
            parsed_domain = target_obj.url.replace("https://", "").replace("http://", "").split("/")[0]
            forbidden_targets.append(f"{target_obj.url}/*")

        return ScanPlan(
            workspace_id=workspace_id,
            mode=mode_upper,
            budget_minutes=budget_minutes,
            approved_targets=approved_targets,
            forbidden_targets=list(set(forbidden_targets)) # Deduplicate
        )

# --- Test Block ---
if __name__ == "__main__":
    import json
    
    # 1. Setup Dummy Context
    subdomains = [
        "admin.example.com",
        "api.example.com",
        "dev.example.com",
        "static.example.com",
        "cdn.example.com",
        "portal.example.com",
        "test.example.com",
        "images.example.com",
        "www.example.com",
        "legacy.example.com"
    ]
    
    httpx_results = [
        {"url": "https://admin.example.com", "status_code": 200},
        {"url": "https://portal.example.com", "status_code": 302},
        {"url": "https://www.example.com", "status_code": 200}
    ]
    
    wayback_counts = {
        "api.example.com": 150,
        "www.example.com": 5000,
        "static.example.com": 20
    }
    
    context = {
        "subdomains": subdomains,
        "httpx_results": httpx_results,
        "wayback_counts": wayback_counts
    }
    
    # 2. Run Engine
    engine = DecisionEngine()
    budget_minutes = 20 # Restrict to roughly 10 targets
    
    plan = engine.decide_plan(
        workspace_id="decision_test_v1",
        mode="NORMAL",
        budget_minutes=budget_minutes,
        context_summary=context
    )
    
    print("--- Decision Engine Test Output ---")
    print(json.dumps(plan.to_dict(), indent=2))
