#!/usr/bin/env python3
"""
Verification Script for Phase 3 (Deep Scanning)
Tests the full workflow with INTENSE mode on testphp.vulnweb.com.
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
logger = logging.getLogger("verify_deep_scan")

async def main():
    logger.info("🚀 Starting Phase 3 Verification (Deep Scan)...")
    
    try:
        wm = WorkspaceManager()
        engine = WorkflowEngine(wm)
        logger.info("✅ Components initialized")
        
        target = "testphp.vulnweb.com"
        mode = ScanModes.INTENSE
        
        logger.info(f"🎯 Launching {mode} scan on {target}...")
        
        # Ensure workspace
        await wm.ensure_workspace(target)
        
        # Run mission
        result = await engine.run_mission(target, mode)
        
        logger.info("📊 Mission Result Summary:")
        
        if "errors" in result and result["errors"]:
            logger.warning(f"⚠️ Errors: {result['errors']}")
        
        # Check for vulnerabilities
        vulns = result.get("vulnerabilities", [])
        logger.info(f"🔥 Total Vulnerabilities Found: {len(vulns)}")
        
        # Check specifically for XSS and SQLi
        xss_found = any(v.get("type") == "XSS" for v in vulns)
        sqli_found = any(v.get("type") == "SQLi" or "sql" in str(v).lower() for v in vulns)
        
        if xss_found:
            logger.info("✅ XSS Vulnerabilities Found (Dalfox/Nuclei)")
        else:
            logger.warning("⚠️ No XSS found (Check Dalfox)")
            
        if sqli_found:
            logger.info("✅ SQL Injection Found (SQLMap/Nuclei)")
        else:
            logger.warning("⚠️ No SQLi found (Check SQLMap)")
            
        logger.info("✅ Mission completed")
            
    except Exception as e:
        logger.error(f"❌ Mission failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
