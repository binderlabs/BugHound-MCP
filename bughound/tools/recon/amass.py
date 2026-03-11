from typing import Dict, Any, List
import json
from ..base_tool import BaseTool, ToolResult

class AmassTool(BaseTool):
    def __init__(self):
        super().__init__("amass", timeout=1800)  # Amass can be slow

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        try:
            cmd = self._build_command(target, options)
            # Amass writes to stdout, but we might want to use a temp file for cleaner JSON
            # For now, we'll use the standard stdout capture
            raw_output = await self._run_command(cmd)
            parsed_data = self._parse_output(raw_output)
            return ToolResult(success=True, data=parsed_data, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        # amass enum -d example.com -json -
        cmd = ["amass", "enum", "-d", target, "-json", "-"]
        
        if options.get("active"):
            cmd.append("-active")
        if options.get("passive"):
            cmd.append("-passive")
        if options.get("brute"):
            cmd.append("-brute")
            
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        subdomains = set()
        addresses = set()
        
        # Amass JSON output is one JSON object per line
        for line in raw_output.splitlines():
            try:
                if not line.strip(): continue
                entry = json.loads(line)
                if "name" in entry:
                    subdomains.add(entry["name"])
                if "addresses" in entry:
                    for addr in entry["addresses"]:
                        if "ip" in addr:
                            addresses.add(addr["ip"])
            except json.JSONDecodeError:
                continue
                
        return {
            "subdomains": list(subdomains),
            "addresses": list(addresses),
            "count": len(subdomains)
        }
