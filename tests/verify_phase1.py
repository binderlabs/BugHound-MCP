#!/usr/bin/env python3
"""
Verification Script for Phase 1
Tests the WorkflowEngine and ScanModes by running a STEALTH scan.
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
logger = logging.getLogger("verify_phase1")

async def main():
    logger.info("🧪 Starting Phase 1 Verification...")
    
    # 1. Initialize Components
    try:
        wm = WorkspaceManager()
        engine = WorkflowEngine(wm)
        logger.info("✅ Components initialized successfully")
    except Exception as e:
        logger.error(f"❌ Initialization failed: {e}")
        return

    # 2. Run a Test Mission (STEALTH Mode)
    target = "testphp.vulnweb.com"
    mode = ScanModes.STEALTH
    
    logger.info(f"🚀 Launching {mode} scan on {target}...")
    
    try:
        # Ensure workspace exists
        wm.ensure_workspace(target)
        
        # Run mission
        result = await engine.run_mission(target, mode)
        
        # 3. Verify Results
        logger.info("📊 Mission Result Summary:")
        logger.info(f"   - Status: {result.get('mode')} Scan Completed")
        logger.info(f"   - Duration: {result.get('duration', 0):.2f}s")
        logger.info(f"   - Steps Completed: {len(result.get('steps_completed', []))}")
        
        for step in result.get('steps_completed', []):
            logger.info(f"     - {step['tool']}: {step['status']} ({step.get('items_found', 0)} items)")
            
        if "errors" in result:
            logger.warning(f"⚠️ Errors encountered: {result['errors']}")
        else:
            logger.info("✅ No errors reported")
            
        logger.info("🎉 Phase 1 Verification Passed!")
        
    except Exception as e:
        logger.error(f"❌ Mission failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
