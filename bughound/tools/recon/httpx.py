"""
HTTPx Tool Wrapper for BugHound

Integrates httpx for live host detection and technology fingerprinting.
Provides detailed HTTP analysis including status codes, titles, technologies,
server headers, and content types.

Perfect for validating discovered subdomains and gathering intelligence
for bug bounty research.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class HTTPxTool(BaseTool):
    """HTTPx live host detection and analysis tool wrapper"""
    
    def __init__(self, timeout: int = 300, evidence_collector=None):
        super().__init__("httpx", timeout)
        self.evidence_collector = evidence_collector
        
        # Use ProjectDiscovery HTTPx if available, fallback to system httpx
        import os
        go_bin_httpx = os.path.expanduser("~/go/bin/httpx")
        if os.path.exists(go_bin_httpx):
            self.tool_name = go_bin_httpx
        else:
            self.tool_name = "httpx"
        
        # Default httpx options for comprehensive analysis
        self.default_options = [
            "-sc",              # Get HTTP status codes (--status-code)
            "-title",           # Extract page titles
            "-td",              # Detect technologies (--tech-detect)
            "-server",          # Get server headers (--web-server)
            "-ct",              # Get content types (--content-type)
            "-cl",              # Get content length (--content-length)
            "-fr",              # Follow redirects (--follow-redirects)
            "-j",               # JSON output format (--json)
            "-silent",          # Reduce noise
            "-nc"               # No color output (--no-color)
        ]
    
    async def execute(self, target: Any, options: Dict[str, Any], workspace_id: str = None) -> ToolResult:
        """
        Execute httpx against target subdomains
        
        Args:
            target: List of subdomains or single domain
            options: Tool options
            
        Returns:
            ToolResult with live host data and analysis
        """
        try:
            # Prepare target list
            if isinstance(target, str):
                targets = [target]
            elif isinstance(target, list):
                targets = target
            else:
                raise ValueError("Target must be a string or list of strings")
            
            if not targets:
                raise ValueError("No targets provided")
            
            # Validate targets
            valid_targets = []
            for t in targets:
                if self._is_valid_target(t):
                    # Ensure we have proper format (add protocol if missing)
                    if not t.startswith(('http://', 'https://')):
                        # Add both protocols for testing
                        valid_targets.extend([f"http://{t}", f"https://{t}"])
                    else:
                        valid_targets.append(t)
            
            if not valid_targets:
                raise ValueError("No valid targets after validation")
            
            # Limit targets to avoid overwhelming httpx
            max_targets = options.get("max_targets", 500)
            if len(valid_targets) > max_targets:
                valid_targets = valid_targets[:max_targets]
                logger.warning(f"Limited targets to {max_targets} for performance")
            
            logger.info(f"Testing {len(valid_targets)} targets with httpx")
            
            # Build httpx command
            cmd = self._build_command(valid_targets, options)
            logger.debug(f"HTTPx command: {' '.join(cmd)}")
            
            # Execute httpx
            raw_output = await self._run_command(cmd)
            
            # Parse output and collect evidence
            parsed_data = await self._parse_output_with_evidence(raw_output, workspace_id)
            
            return ToolResult(
                success=True,
                data=parsed_data,
                raw_output=raw_output
            )
            
        except Exception as e:
            logger.error(f"HTTPx execution failed: {e}")
            return ToolResult(
                success=False,
                error=str(e)
            )
    
    def _build_command(self, targets: List[str], options: Dict[str, Any]) -> List[str]:
        """Build httpx command with options"""
        
        # Start with httpx and default options
        cmd = [self.tool_name] + self.default_options.copy()
        
        # Add custom options
        threads = options.get("threads", 50)
        cmd.extend(["-t", str(threads)])
        
        timeout_seconds = options.get("timeout", 10)
        cmd.extend(["-timeout", str(timeout_seconds)])
        
        # Rate limiting
        rate_limit = options.get("rate_limit", 100)
        cmd.extend(["-rl", str(rate_limit)])
        
        # Custom ports if specified
        ports = options.get("ports")
        if ports:
            if isinstance(ports, list):
                ports = ",".join(map(str, ports))
            cmd.extend(["-p", str(ports)])
        
        # Custom HTTP methods
        methods = options.get("methods", ["GET"])
        if isinstance(methods, list) and len(methods) > 1:
            methods = ",".join(methods)
            cmd.extend(["-x", str(methods)])
        # For single GET method, HTTPx uses GET by default, so we skip this
        
        # Additional probes
        if options.get("probe_all_ips", False):
            cmd.append("-pa")
        
        if options.get("follow_host_redirects", False):
            cmd.append("-fhr")
        
        # Custom headers
        headers = options.get("headers")
        if headers:
            for header in headers:
                cmd.extend(["-H", header])
        
        # Add targets via stdin (better for large lists)
        # We'll use a temp file for this
        return cmd
    
    async def _run_command(self, cmd: List[str]) -> str:
        """Execute httpx command with target list via stdin"""
        try:
            # Create process
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # We need to get targets from somewhere - let's modify this
            # For now, we'll handle targets in the command building
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=self.timeout
            )
            
            if proc.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                raise Exception(f"HTTPx failed: {error_msg}")
            
            return stdout.decode()
            
        except asyncio.TimeoutError:
            if proc:
                proc.terminate()
            raise Exception(f"HTTPx timed out after {self.timeout}s")
    
    async def _run_command_with_targets(self, cmd: List[str], targets: List[str]) -> str:
        """Execute httpx with targets via stdin"""
        try:
            # Create temporary file with targets
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for target in targets:
                    f.write(f"{target}\n")
                target_file = f.name
            
            # Add target file to command
            cmd.extend(["-l", target_file])
            
            try:
                # Execute command
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout
                )
                
                if proc.returncode != 0:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    # Don't fail for partial results
                    if "No targets found" not in error_msg:
                        logger.warning(f"HTTPx warning: {error_msg}")
                
                return stdout.decode()
                
            finally:
                # Clean up temp file
                try:
                    Path(target_file).unlink()
                except:
                    pass
                    
        except asyncio.TimeoutError:
            if proc:
                proc.terminate()
            raise Exception(f"HTTPx timed out after {self.timeout}s")
    
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse httpx JSON output into structured data
        
        Args:
            raw_output: Raw JSON output from httpx
            
        Returns:
            Structured data with live hosts and analysis
        """
        live_hosts = []
        technologies = set()
        status_codes = {}
        servers = set()
        errors = []
        
        if not raw_output.strip():
            return {
                "live_hosts": [],
                "total_live": 0,
                "technologies": [],
                "status_distribution": {},
                "servers": [],
                "errors": ["No output received from httpx"]
            }
        
        # Parse JSON lines
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                
                # Extract host information
                host_info = {
                    "url": data.get("url", ""),
                    "host": data.get("host", ""),
                    "port": data.get("port", ""),
                    "scheme": data.get("scheme", ""),
                    "status_code": data.get("status_code", 0),
                    "content_length": data.get("content_length", 0),
                    "content_type": data.get("content_type", ""),
                    "title": data.get("title", ""),
                    "server": data.get("server", ""),
                    "technologies": data.get("technologies", []),
                    "response_time": data.get("response_time", ""),
                    "chain": data.get("chain", []),
                    "failed": data.get("failed", False)
                }
                
                # Only include successful responses
                if not host_info["failed"] and host_info["status_code"] > 0:
                    live_hosts.append(host_info)
                    
                    # Collect technologies
                    if host_info["technologies"]:
                        technologies.update(host_info["technologies"])
                    
                    # Collect status codes
                    status = host_info["status_code"]
                    status_codes[status] = status_codes.get(status, 0) + 1
                    
                    # Collect servers
                    if host_info["server"]:
                        servers.add(host_info["server"])
                
            except json.JSONDecodeError as e:
                # Handle non-JSON lines (errors, warnings)
                if line and not any(skip in line.lower() for skip in ['info', 'warn', 'debug']):
                    errors.append(f"Parse error: {line}")
                continue
        
        # Sort hosts by status code and host
        live_hosts.sort(key=lambda x: (x["status_code"], x["host"]))
        
        return {
            "live_hosts": live_hosts,
            "total_live": len(live_hosts),
            "technologies": sorted(list(technologies)),
            "status_distribution": dict(sorted(status_codes.items())),
            "servers": sorted(list(servers)),
            "errors": errors if errors else []
        }
    
    async def _parse_output_with_evidence(self, raw_output: str, workspace_id: str = None) -> Dict[str, Any]:
        """Parse httpx output and collect evidence for live hosts"""
        
        # First, parse normally using existing method
        parsed_data = self._parse_output(raw_output)
        
        # Collect evidence for live hosts if workspace and evidence collector available
        if workspace_id and self.evidence_collector and parsed_data.get("live_hosts"):
            try:
                logger.info(f"Collecting evidence for {len(parsed_data['live_hosts'])} live hosts")
                
                # Collect evidence for all live hosts
                evidence_results = await self.evidence_collector.collect_live_host_evidence(
                    workspace_id=workspace_id,
                    live_hosts=parsed_data["live_hosts"]
                )
                
                # Add evidence information to each live host
                for host_info in parsed_data["live_hosts"]:
                    url = host_info.get("url", "")
                    if url in evidence_results:
                        evidence_items = evidence_results[url]
                        host_info["evidence"] = {
                            "collected": True,
                            "count": len(evidence_items),
                            "evidence_ids": [e.evidence_id for e in evidence_items],
                            "evidence_types": [e.evidence_type.value for e in evidence_items]
                        }
                    else:
                        host_info["evidence"] = {"collected": False, "count": 0}
                
                # Add summary evidence statistics
                total_evidence = sum(len(items) for items in evidence_results.values())
                parsed_data["evidence_summary"] = {
                    "total_evidence_collected": total_evidence,
                    "hosts_with_evidence": len(evidence_results),
                    "evidence_types_collected": list(set(
                        e.evidence_type.value for items in evidence_results.values() for e in items
                    ))
                }
                
                logger.info(f"Evidence collection complete: {total_evidence} items collected")
                
            except Exception as e:
                logger.warning(f"Evidence collection failed for HTTPx results: {e}")
                # Add error information but don't fail the whole operation
                parsed_data["evidence_summary"] = {
                    "total_evidence_collected": 0,
                    "hosts_with_evidence": 0,
                    "error": str(e)
                }
        
        return parsed_data
    
    def _is_valid_target(self, target: str) -> bool:
        """Validate target format"""
        if not target or not isinstance(target, str):
            return False
        
        # Remove protocol for validation
        clean_target = target
        if "://" in target:
            clean_target = target.split("://", 1)[1]
        
        # Remove path if present
        if "/" in clean_target:
            clean_target = clean_target.split("/")[0]
        
        # Basic domain validation
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, clean_target))
    
    async def test_availability(self) -> bool:
        """Test if ProjectDiscovery httpx is available on the system"""
        try:
            result = await asyncio.create_subprocess_exec(
                self.tool_name, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            # Check if this is ProjectDiscovery HTTPx (not Python httpx)
            output = stdout.decode() + stderr.decode()
            if "projectdiscovery" in output.lower() or result.returncode == 0:
                return True
            else:
                # Try alternative check with help
                help_result = await asyncio.create_subprocess_exec(
                    self.tool_name, "-h",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                help_stdout, help_stderr = await help_result.communicate()
                help_output = help_stdout.decode() + help_stderr.decode()
                
                if "status-code" in help_output and "tech-detect" in help_output:
                    return True
                else:
                    logger.warning("Found Python httpx instead of ProjectDiscovery httpx. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
                    return False
                    
        except FileNotFoundError:
            logger.warning("HTTPx not found. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            return False
    
    def get_help(self) -> str:
        """Get help information for the tool"""
        return """
HTTPx - Fast HTTP probe and analysis tool

Usage options:
- threads: Number of concurrent threads (default: 50)
- timeout: Request timeout in seconds (default: 10)
- rate_limit: Requests per second (default: 100)
- ports: Custom ports to probe (e.g., "80,443,8080")
- methods: HTTP methods to use (default: ["GET"])
- headers: Custom headers to send
- probe_all_ips: Probe all IPs for a domain (default: false)
- follow_host_redirects: Follow redirects to same host (default: false)
- max_targets: Maximum targets to process (default: 500)

Example:
{
    "threads": 100,
    "timeout": 15,
    "rate_limit": 200,
    "ports": "80,443,8080,8443",
    "methods": ["GET", "HEAD"],
    "headers": ["User-Agent: BugHound"]
}
"""
    
    # Override the base method to handle target list properly
    def _build_command(self, targets: List[str], options: Dict[str, Any]) -> List[str]:
        """Build httpx command - this version stores targets for later use"""
        self._targets = targets  # Store for use in execution
        
        cmd = [self.tool_name] + self.default_options.copy()
        
        # Add custom options
        threads = options.get("threads", 50)
        cmd.extend(["-t", str(threads)])
        
        timeout_seconds = options.get("timeout", 10)
        cmd.extend(["-timeout", str(timeout_seconds)])
        
        rate_limit = options.get("rate_limit", 150)
        cmd.extend(["-rl", str(rate_limit)])
        
        # Custom ports if specified
        ports = options.get("ports")
        if ports:
            if isinstance(ports, list):
                ports = ",".join(map(str, ports))
            cmd.extend(["-p", str(ports)])
        
        # Custom HTTP methods
        methods = options.get("methods", ["GET"])
        if isinstance(methods, list):
            methods = ",".join(methods)
        cmd.extend(["-x", str(methods)])
        
        # Additional probes
        if options.get("probe_all_ips", False):
            cmd.append("-pa")
        
        if options.get("follow_host_redirects", False):
            cmd.append("-fhr")
        
        # Custom headers
        headers = options.get("headers")
        if headers:
            for header in headers:
                cmd.extend(["-H", header])
        
        return cmd
    
    async def _run_command(self, cmd: List[str]) -> str:
        """Execute httpx with stored targets"""
        return await self._run_command_with_targets(cmd, getattr(self, '_targets', []))