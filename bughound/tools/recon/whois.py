from typing import Dict, Any, List
import os
from ..base_tool import BaseTool, ToolResult

class WhoisTool(BaseTool):
    """Wrapper for standard whois command line tool"""
    def __init__(self):
        super().__init__("whois", timeout=60)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            cmd = self._build_command(target, options)
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output(raw_output)
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        return ["whois", target]

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        result = {
            "raw": raw_output,
            "summary": {}
        }
        # Basic parsing using common whois output keys
        for line in raw_output.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip().lower()
                val = parts[1].strip()
                if key and val and key not in result["summary"]:
                    result["summary"][key] = val
        return result
