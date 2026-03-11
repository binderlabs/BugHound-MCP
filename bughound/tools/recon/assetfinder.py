from typing import Dict, Any, List
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class AssetfinderTool(BaseTool):
    """Wrapper for assetfinder"""
    def __init__(self):
        super().__init__("assetfinder", timeout=120)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            cmd = self._build_command(target, options)
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output(raw_output)
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        cmd = ["assetfinder", "--subs-only", target]
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        subdomains = []
        for line in raw_output.splitlines():
            line = line.strip()
            if line:
                subdomains.append({"domain": line, "source": "assetfinder"})
        return {
            "subdomains": subdomains,
            "count": len(subdomains)
        }
