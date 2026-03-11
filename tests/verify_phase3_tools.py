#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bughound.tools.recon.gau import GauTool
from bughound.tools.discovery.arjun import ArjunTool
from bughound.tools.scanning.dalfox import DalfoxTool
from bughound.tools.scanning.sqlmap import SQLMapTool
from bughound.tools.scanning.subjack import SubjackTool
from bughound.tools.scanning.ffuf import FFuFTool

async def verify_tools():
    print("🔍 Verifying Phase 3 Tools...")
    
    tools = [
        GauTool(),
        ArjunTool(),
        DalfoxTool(),
        SQLMapTool(),
        SubjackTool(),
        FFuFTool()
    ]
    
    for tool in tools:
        print(f"Testing {tool.name}...", end=" ")
        try:
            # Just run help or version to check if it runs
            # We use _run_command directly to test the PATH fix
            # For Nuclei, tool_name holds the binary path, for others it's just the name
            # But BaseTool.name is the logical name.
            # We should try to run the command using the tool's name.
            cmd = [tool.name, "--help"]
            # Some tools might not support --help or exit with non-zero, so we catch
            try:
                await tool._run_command(cmd)
                print("✅ OK")
            except Exception as e:
                # If it's just a help command failure but executable found, it might be different error
                if "No such file" in str(e):
                    print(f"❌ FAILED (Not found): {e}")
                else:
                    print(f"✅ OK (Found, but help exited with error)")
                    
        except Exception as e:
            print(f"❌ FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(verify_tools())
