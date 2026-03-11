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
logger = logging.getLogger("verify_nmap")

async def main():
    # Use scanme.nmap.org IP
    target = "45.33.32.156" 
    
    # Initialize components
    wm = WorkspaceManager()
    engine = WorkflowEngine(wm)
    
    logger.info(f"🎯 Launching RECON scan on IP {target}...")
    
    # Ensure workspace
    _, ws_path = await wm.ensure_workspace(target)
    logger.info(f"📂 Workspace: {ws_path}")
    
    # Run mission (RECON mode)
    # This should SKIP subfinder/crtsh and RUN nmap
    result = await engine.run_mission(target, "NORMAL")
    
    logger.info("✅ Scan completed")
    
    # Verify files
    expected_files = [
        ws_path / "ips" / f"nmap-{target}.xml",
        ws_path / "ips" / f"nmap-{target}.txt"
    ]
    
    # Verify subfinder was skipped (no domains folder or empty)
    subdomains_file = ws_path / "domains" / "subdomains.txt"
    if subdomains_file.exists():
        logger.warning(f"⚠️ subdomains.txt found! Subfinder might not have been skipped.")
    else:
        logger.info(f"✅ subdomains.txt NOT found (Expected for IP target)")

    for f in expected_files:
        if f.exists():
            logger.info(f"✅ Found file: {f}")
            # Read first few lines
            with open(f, "r") as file:
                content = file.read(200)
            logger.info(f"   Preview:\n{content}...")
        else:
            logger.error(f"❌ Missing file: {f}")

if __name__ == "__main__":
    asyncio.run(main())
