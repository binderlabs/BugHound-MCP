from typing import Dict, Any, List
import json
import os
from ..base_tool import BaseTool, ToolResult

class KnockpyTool(BaseTool):
    def __init__(self):
        super().__init__("knockpy", timeout=600)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        # Knockpy writes to a file, we need to handle that
        # For this simple wrapper, we'll assume standard output parsing or JSON if available
        # Modern knockpy supports -o json
        try:
            cmd = self._build_command(target, options)
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output(raw_output)
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # knockpy domain.com --no-http
        cmd = ["knockpy", target, "--no-http", "--no-load"]
        
        # Note: Knockpy output is tricky to parse from stdout sometimes, 
        # but we'll try to capture the JSON output if it prints it.
        # If knockpy is not installed, this will fail gracefully in the runner.
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        subdomains = []
        # Knockpy output parsing logic (simplified)
        # We look for lines that look like subdomains
        for line in raw_output.splitlines():
            if "Domain Name" in line: continue # Header
            parts = line.split()
            if len(parts) >= 3: # ip, domain, type
                domain = parts[1]
                if "." in domain:
                    subdomains.append(domain)
                    
        return {
            "subdomains": subdomains,
            "count": len(subdomains)
        }
