from typing import Dict, Any, List
import json
import os
import tempfile
from ..base_tool import BaseTool, ToolResult

class SubjackTool(BaseTool):
    def __init__(self):
        super().__init__("subjack", timeout=600)

    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        # Subjack needs a list of subdomains. 
        # If target is a single domain, we assume it's a list file path OR we treat it as single
        # But subjack -d expects a domain. -w expects a wordlist.
        # We'll assume 'target' here is a file path to a list of subdomains if it exists,
        # otherwise we treat it as a single domain to check (which subjack doesn't really do well without a list).
        # Ideally, WorkflowEngine passes a file path.
        
        try:
            # For this wrapper, we'll assume target is the domain name, 
            # and we expect a 'subdomains_file' in options.
            # If not, we can't really run subjack effectively on just the root domain.
            
            subdomains_file = options.get("subdomains_file")
            if not subdomains_file:
                return ToolResult(success=False, error="Subjack requires 'subdomains_file' option")

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_out:
                output_file = tmp_out.name

            cmd = self._build_command(subdomains_file, options, output_file)
            raw_output = await self._run_command(cmd)
            
            # Subjack output is just text lines of vulnerable domains
            vulnerable_domains = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            vulnerable_domains.append(line.strip())
                os.remove(output_file)
                
            return ToolResult(success=True, data={"vulnerable": vulnerable_domains, "count": len(vulnerable_domains)}, raw_output=raw_output)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _build_command(self, subdomains_file: str, options: Dict[str, Any], output_file: str) -> List[str]:
        # subjack -w subdomains.txt -t 100 -timeout 30 -o output.txt -ssl
        cmd = ["subjack", "-w", subdomains_file, "-o", output_file, "-a", "-ssl"]
        
        if "threads" in options:
            cmd.extend(["-t", str(options["threads"])])
            
        return cmd

    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        return {}
