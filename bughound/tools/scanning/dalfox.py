from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class DalfoxTool(BaseTool):
    def __init__(self):
        super().__init__("dalfox", timeout=1200)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        # Target for dalfox is usually a URL or a file of URLs
        # If target is a domain, we might need to pipe urls into it
        # For this wrapper, we assume target is a single URL or we use pipe mode
        
        try:
            # Dalfox supports -o for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                output_file = tmp_file.name

            cmd = self._build_command(target, options, output_file)
            
            # If target is a list of URLs (passed via options), we might need to pipe them
            # But BaseTool _run_command doesn't support stdin piping easily yet without modification
            # So we'll assume target is a single URL for now OR we write targets to a file
            
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output_file(output_file)
            
            if os.path.exists(output_file):
                os.remove(output_file)
                
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any], output_file: str) -> List[str]:
        # dalfox url http://testphp.vulnweb.com/listproducts.php?cat=1 -o output.json --format json
        cmd = ["dalfox", "url", target, "-o", output_file, "--format", "json"]
        
        # Blind XSS payload
        if "blind_url" in options:
            cmd.extend(["-b", options["blind_url"]])
            
        return cmd

    def _parse_output_file(self, file_path: str) -> Dict[str, Any]:
        vulnerabilities = []
        try:
            # Dalfox JSON output is a list of objects
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if isinstance(data, list):
                for item in data:
                    vulnerabilities.append({
                        "type": "XSS",
                        "severity": "High",
                        "url": item.get("url"),
                        "payload": item.get("payload"),
                        "param": item.get("param")
                    })
            
            return {
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities)
            }
        except Exception:
            return {"vulnerabilities": [], "count": 0}

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {}
