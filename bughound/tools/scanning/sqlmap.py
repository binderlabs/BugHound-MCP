from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class SQLMapTool(BaseTool):
    def __init__(self):
        super().__init__("sqlmap", timeout=1800)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            # SQLMap doesn't have a clean JSON output flag for results in the same way
            # But we can use --batch and parse output or use the API.
            # For CLI wrapper, we'll use --batch and capture stdout.
            
            cmd = self._build_command(target, options)
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output(raw_output)
            
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # sqlmap -u URL --batch --random-agent
        cmd = ["sqlmap", "-u", target, "--batch", "--random-agent"]
        
        # Safety: Do not actually dump data unless explicitly told
        if not options.get("dump_data", False):
            cmd.append("--dbs") # Just list DBs to prove vuln
        
        # Level/Risk
        level = str(options.get("level", 1))
        risk = str(options.get("risk", 1))
        cmd.extend(["--level", level, "--risk", risk])
        
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        vulnerable = False
        payloads = []
        
        for line in raw_output.splitlines():
            if "is vulnerable" in line or "appears to be" in line:
                vulnerable = True
            if "Payload:" in line:
                payloads.append(line.split("Payload:")[1].strip())
                
        return {
            "vulnerable": vulnerable,
            "payloads": payloads,
            "count": 1 if vulnerable else 0
        }
