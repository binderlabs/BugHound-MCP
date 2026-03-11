from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class Wafw00fTool(BaseTool):
    """Wrapper for wafw00f WAF detection"""
    def __init__(self):
        super().__init__("wafw00f", timeout=90)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            cmd = self._build_command(target, options)
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output(raw_output)
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # Support either a single target or a file of targets
        cmd = ["wafw00f", "-f", "json"]
        
        target_file = options.get("target_file")
        if target_file and os.path.exists(target_file):
            cmd.extend(["-i", target_file])
        else:
            # If target is a fast list we might pass it differently or just run individually
            cmd.append(target)
            
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        results = []
        try:
            # wafw00f outputs JSON when -f json is passed, but it might have surrounding text.
            # We try to extract the JSON array.
            start_idx = raw_output.find('[')
            end_idx = raw_output.rfind(']') + 1
            if start_idx != -1 and end_idx != -1:
                json_str = raw_output[start_idx:end_idx]
                results = json.loads(json_str)
        except Exception:
            pass
            
        return {"waf_results": results}
