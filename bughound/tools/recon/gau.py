from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class GauTool(BaseTool):
    def __init__(self):
        super().__init__("gau", timeout=600)
        self.tool_name = "gau"
        # Check if gau is in PATH, if not try ~/go/bin/gau
        import shutil
        import os
        if not shutil.which("gau"):
            expanded_path = os.path.expanduser("~/go/bin/gau")
            if os.path.exists(expanded_path):
                self.tool_name = expanded_path

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            cmd = self._build_command(target, options)
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Executing GAU command: {cmd}")
            raw_output = await self._run_command(cmd)
            logger.info(f"GAU raw output length: {len(raw_output)}")
            parsed_data = self._parse_output(raw_output)
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # gau example.com --subs
        cmd = [self.tool_name, target]
        
        if options.get("subs", False):
            cmd.append("--subs")
            
        if options.get("blacklist"):
            cmd.extend(["--blacklist", options["blacklist"]])
            
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in raw_output.splitlines() if line.strip()]
        return {
            "urls": urls,
            "count": len(urls)
        }
