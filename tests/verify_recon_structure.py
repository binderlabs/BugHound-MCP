import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from bughound.core.workflow_engine import WorkflowEngine
from bughound.core.workspace_manager import WorkspaceManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("verify_recon")

async def main():
    target = "testphp.vulnweb.com"
    
    # Initialize components
    wm = WorkspaceManager()
    engine = WorkflowEngine(wm)
    
    logger.info(f"🎯 Launching RECON scan on {target}...")
    
    # Ensure workspace
    _, ws_path = await wm.ensure_workspace(target)
    logger.info(f"📂 Workspace: {ws_path}")
    
    # Run mission (RECON mode)
    # We use RECON mode which should include subfinder, httpx, gau
    result = await engine.run_mission(target, "RECON")
    
    logger.info("✅ Scan completed")
    
    # Verify files
    expected_files = [
        ws_path / "domains" / "subdomains.txt",
        ws_path / "web" / "all_urls.txt",
        ws_path / "web" / "endpoints_params.txt"
    ]
    
    for f in expected_files:
        if f.exists():
            logger.info(f"✅ Found file: {f}")
            # Print first 3 lines
            with open(f, "r") as file:
                head = [next(file) for _ in range(3)]
            logger.info(f"   Content preview: {head}")
        else:
            logger.error(f"❌ Missing file: {f}")

if __name__ == "__main__":
    asyncio.run(main())
