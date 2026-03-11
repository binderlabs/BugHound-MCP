#!/usr/bin/env python3
"""
BugHound Arsenal Demo Script
Simulates a scan run using the core Decision and Policy engines.
Generates output files in demo/out/ for review.
"""

import sys
import json
import os
from pathlib import Path
from datetime import datetime

# Ensure bughound is in path
sys.path.append(os.getcwd())

from bughound.core.decision_engine import DecisionEngine
from bughound.core.policy_engine import PolicyEngine
from bughound.core.scan_plan import ScanPlan, ScanBudget
from bughound.core.tool_registry import get_all_tools

def main():
    print("🦅 BugHound Arsenal Demo Starting...")
    
    # 1. Setup Paths
    base_dir = Path(os.getcwd())
    demo_dir = base_dir / "demo"
    out_dir = demo_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    context_file = demo_dir / "demo_context.json"
    if not context_file.exists():
        print(f"❌ Error: Context file not found at {context_file}")
        sys.exit(1)
        
    print(f"📖 Loading context from {context_file.name}...")
    with open(context_file, 'r') as f:
        context = json.load(f)
        
    # 2. Planning Phase
    print("🧠 initializing DecisionEngine...")
    decision_engine = DecisionEngine()
    budget = ScanBudget(max_targets=5) # Restrict to top 5 for demo
    
    print("📝 Generating ScanPlan (Mode: NORMAL)...")
    plan = decision_engine.decide_plan(
        run_id="demo_arsenal_001",
        mode="NORMAL",
        budget=budget,
        context_summary=context
    )
    
    print(f"✅ Plan Created: {plan.reasoning}")
    print(f"🎯 Selected Targets: {len(plan.allowed_targets)}")
    for t in plan.allowed_targets:
        print(f"   - {t} (Score: {plan.target_reasons.get(t, [])})")
        
    # 3. Policy Phase (Simulation)
    print("\n🛡️  Applying PolicyEngine across Tool Registry...")
    policy_engine = PolicyEngine(mode="NORMAL", scan_plan=plan)
    
    simulation_out = {
        "scan_plan": plan.to_dict(),
        "tool_policy": {"allowed": [], "denied": {}},
        "decision_log": []
    }
    
    # Log Plan
    simulation_out["decision_log"].append({
        "timestamp": datetime.now().isoformat(),
        "stage": "planning",
        "action": "plan_created",
        "reason": plan.reasoning,
        "related": {"allowed_targets": len(plan.allowed_targets)}
    })
    
    all_tools = get_all_tools()
    for tool in all_tools:
        decision = policy_engine.approve_tool(tool.name, tool_risk=tool.risk)
        
        if decision.allowed:
            simulation_out["tool_policy"]["allowed"].append(tool.name)
            simulation_out["decision_log"].append({
                "timestamp": datetime.now().isoformat(),
                "stage": "policy",
                "action": "allow",
                "reason": decision.reason,
                "related": {"tool": tool.name}
            })
        else:
            simulation_out["tool_policy"]["denied"][tool.name] = decision.reason
            simulation_out["decision_log"].append({
                "timestamp": datetime.now().isoformat(),
                "stage": "policy",
                "action": "deny",
                "reason": decision.reason,
                "related": {"tool": tool.name}
            })
            
    # 4. Save Outputs
    print(f"\n💾 Saving outputs to {out_dir}/")
    
    sim_file = out_dir / "demo_simulation_output.json"
    with open(sim_file, 'w') as f:
        json.dump(simulation_out, f, indent=2)
    print(f"   - {sim_file.name}")
        
    log_file = out_dir / "demo_decision_log.json"
    with open(log_file, 'w') as f:
        json.dump(simulation_out["decision_log"], f, indent=2)
    print(f"   - {log_file.name}")
    
    print("\n✨ Demo Run Complete! Ready for Arsenal presentation.")

if __name__ == "__main__":
    main()
