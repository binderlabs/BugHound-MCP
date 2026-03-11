#!/usr/bin/env python3
"""
Verification Script for Enhanced Recon Tools
Tests the CrtShTool and verifies other tools are loaded.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bughound.core.workspace_manager import WorkspaceManager
from bughound.core.workflow_engine import WorkflowEngine
from bughound.tools.recon.crtsh import CrtShTool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_recon")

async def main():
    logger.info("🧪 Verifying Enhanced Recon Tools...")
    
    # 1. Verify Tool Loading
    try:
        wm = WorkspaceManager()
        engine = WorkflowEngine(wm)
        
        expected_tools = ["amass", "crtsh", "knockpy"]
        for tool in expected_tools:
            if tool in engine.tools and engine.tools[tool] is not None:
                logger.info(f"✅ Tool loaded: {tool}")
            else:
                logger.error(f"❌ Tool failed to load: {tool}")
                
    except Exception as e:
        logger.error(f"❌ Initialization failed: {e}")
        return

    # 2. Test CrtShTool (Fast API test)
    target = "exantria.com"
    logger.info(f"🚀 Testing crt.sh on {target}...")
    
    tool = CrtShTool()
    result = await tool.execute(target, {})
    
    if result.success:
        count = result.data.get("count", 0)
        logger.info(f"✅ crt.sh success! Found {count} subdomains.")
        logger.info(f"   Sample: {result.data.get('subdomains', [])[:3]}")
    else:
        logger.error(f"❌ crt.sh failed: {result.error}")

if __name__ == "__main__":
    asyncio.run(main())
