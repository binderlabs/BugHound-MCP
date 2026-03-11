from typing import Dict, Any, List
import aiohttp
import asyncio
import json
from ..base_tool import BaseTool, ToolResult

class CrtShTool(BaseTool):
    def __init__(self):
        super().__init__("crtsh", timeout=60)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            # crt.sh doesn't use _run_command, it uses aiohttp
            url = f"https://crt.sh/?q=%.{target}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as response:
                    if response.status != 200:
                        raise Exception(f"crt.sh returned status {response.status}")
                    
                    data = await response.json()
                    parsed_data = self._parse_output(data)
                    return ToolResult(success=True, data=parsed_data)
                    
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # Not used for this tool
        return []

    def _parse_output(self, data: Any) -> Dict[str, Any]:
        subdomains = set()
        
        if isinstance(data, list):
            for entry in data:
                # name_value can be multi-line string
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    # Remove wildcards and clean
                    clean_name = name.replace("*.", "").strip()
                    if clean_name:
                        subdomains.add(clean_name)
                        
        return {
            "subdomains": list(subdomains),
            "count": len(subdomains),
            "source": "crt.sh"
        }
