from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class FFuFTool(BaseTool):
    def __init__(self):
        super().__init__("ffuf", timeout=1800)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            # FFuF needs a wordlist. We assume one is provided or we use a default.
            # Target should contain FUZZ keyword or we append it.
            
            wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            if not os.path.exists(wordlist):
                # Fallback or error
                return ToolResult(success=False, error=f"Wordlist not found: {wordlist}")

            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
                output_file = tmp_file.name

            cmd = self._build_command(target, options, output_file, wordlist)
            raw_output = await self._run_command(cmd)
            
            parsed_data = self._parse_output_file(output_file)
            
            if os.path.exists(output_file):
                os.remove(output_file)
                
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any], output_file: str, wordlist: str) -> List[str]:
        # ffuf -u https://example.com/FUZZ -w wordlist.txt -o output.json -of json
        
        url = target
        if "FUZZ" not in url:
            if not url.endswith("/"):
                url += "/"
            url += "FUZZ"
            
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-o", output_file, "-of", "json"]
        
        # Extensions
        if "extensions" in options:
            cmd.extend(["-e", options["extensions"]])
            
        return cmd

    def _parse_output_file(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            results = data.get("results", [])
            return {
                "results": results,
                "count": len(results)
            }
        except Exception:
            return {"results": [], "count": 0}

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {}
