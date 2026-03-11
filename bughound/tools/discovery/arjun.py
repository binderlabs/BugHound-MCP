from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class ArjunTool(BaseTool):
    def __init__(self):
        super().__init__("arjun", timeout=600)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            # Arjun writes JSON to a file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                output_file = tmp_file.name

            cmd = self._build_command(target, options, output_file)
            raw_output = await self._run_command(cmd)
            
            parsed_data = self._parse_output_file(output_file)
            
            # Cleanup
            if os.path.exists(output_file):
                os.remove(output_file)
                
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any], output_file: str) -> List[str]:
        # arjun -u https://target.com -oJ output.json
        cmd = ["arjun", "-u", target, "-oJ", output_file]
        
        # Rate limit
        if "rate_limit" in options:
            cmd.extend(["-t", str(options["rate_limit"])])
            
        # Passive mode (if supported or via other flags)
        # Arjun is mostly active.
        
        return cmd

    def _parse_output_file(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Arjun JSON format: { "url": ["param1", "param2"] }
            parameters = []
            for url, params in data.items():
                for param in params:
                    parameters.append({"url": url, "parameter": param})
                    
            return {
                "parameters": parameters,
                "count": len(parameters)
            }
        except Exception:
            return {"parameters": [], "count": 0}

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        # Not used as we parse file
        return {}
