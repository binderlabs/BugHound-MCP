"""
Subfinder Tool Wrapper for BugHound

Integrates subfinder subdomain discovery tool with proper error handling,
timeout management, and structured output parsing.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class SubfinderTool(BaseTool):
    """Subfinder subdomain discovery tool wrapper"""
    
    def __init__(self, timeout: int = 300):
        super().__init__("subfinder", timeout)
        self.output_format = "json"
    
    async def execute(self, target: str, options: Dict[str, Any]) -> ToolResult:
        """
        Execute subfinder against a target domain
        
        Args:
            target: Target domain to scan
            options: Tool options (threads, recursive, etc.)
            
        Returns:
            ToolResult with structured subdomain data
        """
        try:
            # Validate target
            self._validate_target(target)
            
            # Build command
            cmd = self._build_command(target, options)
            logger.info(f"Executing subfinder: {' '.join(cmd)}")
            
            # Execute command
            raw_output = await self._run_command(cmd)
            
            # Parse output
            parsed_data = self._parse_output(raw_output)
            
            return ToolResult(
                success=True,
                data=parsed_data,
                raw_output=raw_output
            )
            
        except Exception as e:
            logger.error(f"Subfinder execution failed: {e}")
            return ToolResult(
                success=False,
                error=str(e)
            )
    
    def _validate_target(self, target: str) -> None:
        """Validate target domain format and safety"""
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string")
        
        # Remove protocol if present
        if "://" in target:
            target = target.split("://", 1)[1]
        
        # Remove path if present
        if "/" in target:
            target = target.split("/")[0]
        
        # Basic domain validation
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target.strip()):
            raise ValueError("Invalid domain format")
        
        # Check for blocked patterns
        blocked_patterns = [
            r'^localhost$',
            r'^127\.',
            r'^192\.168\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.'
        ]
        
        for pattern in blocked_patterns:
            if re.match(pattern, target, re.IGNORECASE):
                raise ValueError(f"Internal/private domains not allowed: {target}")
    
    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build subfinder command with options"""
        cmd = ["subfinder", "-d", target]
        
        # Output format
        cmd.extend(["-o", "-"])  # Output to stdout
        cmd.extend(["-json"])    # JSON format
        
        # Threading options
        threads = options.get("threads", 10)
        cmd.extend(["-t", str(threads)])
        
        # Recursive search
        if options.get("recursive", False):
            cmd.append("-recursive")
        
        # Timeout
        timeout = options.get("timeout", self.timeout)
        cmd.extend(["-timeout", str(timeout)])
        
        # Verbose output
        if options.get("verbose", False):
            cmd.append("-v")
        
        # Silent mode (reduce noise)
        if not options.get("verbose", False):
            cmd.append("-silent")
        
        # Sources (if specified)
        sources = options.get("sources")
        if sources:
            if isinstance(sources, list):
                sources = ",".join(sources)
            cmd.extend(["-sources", sources])
        
        return cmd
    
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse subfinder JSON output into structured data
        
        Args:
            raw_output: Raw JSON output from subfinder
            
        Returns:
            Structured data with subdomains and metadata
        """
        subdomains = []
        sources_used = set()
        errors = []
        
        if not raw_output.strip():
            return {
                "subdomains": [],
                "count": 0,
                "sources": [],
                "errors": ["No output received from subfinder"]
            }
        
        # Parse JSON lines
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                
                # Extract subdomain info
                subdomain_info = {
                    "domain": data.get("host", ""),
                    "source": data.get("source", "unknown"),
                    "ip": data.get("ip", ""),
                    "timestamp": data.get("timestamp", "")
                }
                
                subdomains.append(subdomain_info)
                sources_used.add(data.get("source", "unknown"))
                
            except json.JSONDecodeError as e:
                # Handle non-JSON lines (errors, warnings)
                if line and not line.startswith('['):
                    errors.append(f"Parse error: {line}")
                continue
        
        # Remove duplicates while preserving order
        unique_subdomains = []
        seen_domains = set()
        
        for sub in subdomains:
            domain = sub["domain"]
            if domain and domain not in seen_domains:
                unique_subdomains.append(sub)
                seen_domains.add(domain)
        
        # Sort subdomains alphabetically
        unique_subdomains.sort(key=lambda x: x["domain"])
        
        return {
            "subdomains": unique_subdomains,
            "count": len(unique_subdomains),
            "sources": sorted(list(sources_used)),
            "errors": errors if errors else []
        }
    
    async def test_availability(self) -> bool:
        """Test if subfinder is available on the system"""
        try:
            result = await asyncio.create_subprocess_exec(
                "subfinder", "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def get_help(self) -> str:
        """Get help information for the tool"""
        return """
Subfinder - Subdomain Discovery Tool

Usage options:
- threads: Number of concurrent threads (default: 10)
- recursive: Enable recursive subdomain discovery (default: false)
- timeout: Timeout in seconds (default: 300)
- verbose: Enable verbose output (default: false)
- sources: Comma-separated list of sources to use

Example:
{
    "threads": 20,
    "recursive": true,
    "timeout": 600,
    "sources": "crtsh,hackertarget,threatcrowd"
}
"""