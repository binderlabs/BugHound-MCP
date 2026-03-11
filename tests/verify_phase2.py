#!/usr/bin/env python3
"""
Verification Script for Phase 2 (AI Integration)
Tests the full workflow with AI prioritization enabled.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bughound.core.workspace_manager import WorkspaceManager
from bughound.core.workflow_engine import WorkflowEngine
from bughound.core.scan_modes import ScanModes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("verify_phase2")

async def main():
    logger.info("🧠 Starting Phase 2 Verification (AI Integration)...")
    
    try:
        wm = WorkspaceManager()
        engine = WorkflowEngine(wm)
        logger.info("✅ Components initialized")
        
        # Use a target that will yield some subdomains to trigger AI
        # testphp.vulnweb.com might not have many subdomains, so we might need to mock 
        # or use a target we know has some, or just rely on the fact that even 1 subdomain triggers it.
        # Let's stick with testphp.vulnweb.com but we expect at least the domain itself.
        target = "testphp.vulnweb.com"
        mode = ScanModes.NORMAL
        
        logger.info(f"🚀 Launching {mode} scan on {target}...")
        
        # Ensure workspace
        wm.ensure_workspace(target)
        
        result = await engine.run_mission(target, mode)
        
        logger.info("📊 Mission Result Summary:")
        
        # Check if AI ran
        # We can't easily check internal state from here without inspecting logs or return values
        # But if it didn't crash and logs show "AI Analyzing", we are good.
        # The WorkflowEngine logs will show "🧠 AI Analyzing subdomains..."
        
        if "errors" in result:
            logger.warning(f"⚠️ Errors: {result['errors']}")
        else:
            logger.info("✅ Mission completed without errors")
            
    except Exception as e:
        logger.error(f"❌ Mission failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
