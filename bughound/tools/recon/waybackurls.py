#!/usr/bin/env python3
"""
Wayback URLs Tool for Historical URL Discovery

This tool fetches historical URLs for a domain from the Wayback Machine
and other web archives to discover endpoints, parameters, and attack surface.
"""

import asyncio
import json
import logging
import re
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from urllib.parse import urlparse, parse_qs

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class WaybackURLsTool(BaseTool):
    """Tool for discovering historical URLs using waybackurls"""
    
    def __init__(self, timeout: int = 300):
        super().__init__("waybackurls", timeout)
        
        # Check if waybackurls is available, fallback to direct API calls
        import os
        go_bin_waybackurls = os.path.expanduser("~/go/bin/waybackurls")
        if os.path.exists(go_bin_waybackurls):
            self.tool_name = go_bin_waybackurls
            self.use_tool = True
        else:
            self.use_tool = False
            logger.warning("waybackurls tool not found, will use API fallback")
        
        # Common file extensions to filter
        self.static_extensions = {
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
            '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz',
            '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.swf'
        }
        
        # Interesting parameter names for vulnerability testing
        self.interesting_params = {
            'id', 'user', 'admin', 'page', 'file', 'path', 'dir', 'folder',
            'include', 'url', 'uri', 'redirect', 'next', 'return', 'callback',
            'jsonp', 'api_key', 'token', 'auth', 'session', 'login', 'debug',
            'test', 'dev', 'prod', 'env', 'config', 'settings', 'data', 'json',
            'xml', 'cmd', 'command', 'exec', 'query', 'search', 'filter'
        }
    
    async def execute(self, target: str, options: Dict[str, Any] = None) -> ToolResult:
        """
        Execute waybackurls to discover historical URLs
        
        Args:
            target: Domain to investigate
            options: Additional options like max_urls, filter_extensions, etc.
            
        Returns:
            ToolResult with discovered URLs, endpoints, and parameters
        """
        
        if options is None:
            options = {}
        
        try:
            logger.info(f"Starting historical URL discovery for {target}")
            
            # Validate target
            if not self._validate_target(target):
                return ToolResult(
                    success=False,
                    error=f"Invalid target domain: {target}"
                )
            
            # Execute waybackurls or fallback to API
            if self.use_tool:
                raw_urls = await self._execute_waybackurls_tool(target, options)
            else:
                raw_urls = await self._execute_api_fallback(target, options)
            
            if not raw_urls:
                return ToolResult(
                    success=True,
                    data={
                        "urls": [],
                        "endpoints": [],
                        "parameters": [],
                        "statistics": {
                            "total_urls": 0,
                            "unique_endpoints": 0,
                            "parameters_found": 0,
                            "interesting_parameters": 0
                        }
                    }
                )
            
            # Process and analyze URLs
            processed_data = await self._process_urls(raw_urls, target, options)
            
            logger.info(f"Historical URL discovery completed for {target}: "
                       f"{processed_data['statistics']['total_urls']} URLs found")
            
            return ToolResult(success=True, data=processed_data)
            
        except Exception as e:
            error_msg = f"Wayback URLs discovery failed: {str(e)}"
            logger.error(error_msg)
            return ToolResult(success=False, error=error_msg)
    
    async def _execute_waybackurls_tool(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Execute the waybackurls tool"""
        
        try:
            # Build command
            cmd = [self.tool_name, target]
            
            # Add options
            if options.get("no_subs", False):
                cmd.append("-no-subs")
            
            logger.info(f"Executing waybackurls: {' '.join(cmd)}")
            
            # Execute command
            raw_output = await self._run_command(cmd)
            
            # Parse URLs from output
            urls = []
            for line in raw_output.strip().split('\n'):
                line = line.strip()
                if line and line.startswith('http'):
                    urls.append(line)
            
            return urls
            
        except Exception as e:
            logger.error(f"waybackurls tool execution failed: {e}")
            raise
    
    async def _execute_api_fallback(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Fallback to direct API calls when waybackurls tool is not available"""
        
        import aiohttp
        
        try:
            urls = []
            
            # Wayback Machine CDX API
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
                try:
                    async with session.get(wayback_url) as response:
                        if response.status == 200:
                            data = await response.json()
                            # Skip header row and extract URLs
                            for row in data[1:]:  
                                if row and len(row) > 0:
                                    url = row[0]
                                    if url and url.startswith('http'):
                                        urls.append(url)
                        else:
                            logger.warning(f"Wayback API returned status {response.status}")
                            
                except Exception as e:
                    logger.warning(f"Wayback Machine API failed: {e}")
            
            # Limit results to prevent overwhelming analysis
            max_urls = options.get("max_urls", 5000)
            if len(urls) > max_urls:
                urls = urls[:max_urls]
                logger.info(f"Limited results to {max_urls} URLs")
            
            return urls
            
        except Exception as e:
            logger.error(f"API fallback failed: {e}")
            return []
    
    async def _process_urls(self, urls: List[str], target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process and analyze discovered URLs"""
        
        # Filter and deduplicate URLs
        filtered_urls = self._filter_urls(urls, options)
        
        # Extract endpoints and parameters
        endpoints = self._extract_endpoints(filtered_urls)
        parameters = self._extract_parameters(filtered_urls)
        
        # Generate statistics
        stats = {
            "total_urls": len(filtered_urls),
            "unique_endpoints": len(endpoints),
            "parameters_found": len(parameters),
            "interesting_parameters": len([p for p in parameters if p["name"].lower() in self.interesting_params])
        }
        
        # Sort by interest level
        endpoints.sort(key=lambda x: x.get("interest_score", 0), reverse=True)
        parameters.sort(key=lambda x: x.get("interest_score", 0), reverse=True)
        
        return {
            "urls": filtered_urls[:100],  # Limit URLs in output
            "endpoints": endpoints[:50],   # Top 50 endpoints
            "parameters": parameters[:30], # Top 30 parameters
            "statistics": stats,
            "target": target
        }
    
    def _filter_urls(self, urls: List[str], options: Dict[str, Any]) -> List[str]:
        """Filter and deduplicate URLs"""
        
        filtered = []
        seen_urls = set()
        
        filter_static = options.get("filter_static", True)
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Skip invalid URLs
                if not parsed.netloc or not parsed.scheme:
                    continue
                
                # Filter static files if requested
                if filter_static and any(parsed.path.lower().endswith(ext) for ext in self.static_extensions):
                    continue
                
                # Remove duplicates
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                
                if clean_url not in seen_urls:
                    seen_urls.add(clean_url)
                    filtered.append(url)
                    
            except Exception as e:
                logger.debug(f"Failed to parse URL {url}: {e}")
                continue
        
        return filtered
    
    def _extract_endpoints(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract unique endpoints with interest scoring"""
        
        endpoints = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path
                
                if not path or path == '/':
                    continue
                
                # Calculate interest score
                interest_score = self._score_endpoint(path)
                
                # Group by path pattern
                path_key = self._normalize_path(path)
                
                if path_key not in endpoints or endpoints[path_key]["interest_score"] < interest_score:
                    endpoints[path_key] = {
                        "path": path,
                        "example_url": url,
                        "interest_score": interest_score,
                        "reasons": self._explain_endpoint_interest(path)
                    }
                    
            except Exception as e:
                logger.debug(f"Failed to process endpoint {url}: {e}")
                continue
        
        return list(endpoints.values())
    
    def _extract_parameters(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract unique parameters with interest scoring"""
        
        parameters = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if not parsed.query:
                    continue
                
                params = parse_qs(parsed.query)
                
                for param_name, values in params.items():
                    if param_name not in parameters:
                        interest_score = self._score_parameter(param_name)
                        
                        parameters[param_name] = {
                            "name": param_name,
                            "example_values": list(set(values))[:5],  # Limit examples
                            "example_url": url,
                            "interest_score": interest_score,
                            "reasons": self._explain_parameter_interest(param_name)
                        }
                        
            except Exception as e:
                logger.debug(f"Failed to process parameters in {url}: {e}")
                continue
        
        return list(parameters.values())
    
    def _score_endpoint(self, path: str) -> int:
        """Score endpoint by potential security interest"""
        
        score = 1  # Base score
        path_lower = path.lower()
        
        # Admin/management interfaces
        if any(term in path_lower for term in ['admin', 'manage', 'control', 'dashboard']):
            score += 5
        
        # API endpoints
        if any(term in path_lower for term in ['api', 'rest', 'graphql', 'json']):
            score += 4
        
        # File operations
        if any(term in path_lower for term in ['upload', 'download', 'file', 'document']):
            score += 3
        
        # Authentication
        if any(term in path_lower for term in ['login', 'auth', 'session', 'password']):
            score += 3
        
        # Development/test
        if any(term in path_lower for term in ['test', 'dev', 'debug', 'staging']):
            score += 2
        
        return score
    
    def _score_parameter(self, param_name: str) -> int:
        """Score parameter by potential vulnerability interest"""
        
        score = 1  # Base score
        param_lower = param_name.lower()
        
        # High interest parameters
        if param_lower in self.interesting_params:
            score += 3
        
        # Common vulnerability parameters
        if any(term in param_lower for term in ['id', 'user', 'admin', 'file', 'path']):
            score += 2
        
        # Potential injection points
        if any(term in param_lower for term in ['cmd', 'exec', 'query', 'search']):
            score += 2
        
        return score
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path for grouping similar endpoints"""
        
        # Replace numeric IDs with placeholder
        normalized = re.sub(r'/\d+(/|$)', '/[ID]$1', path)
        
        # Replace UUIDs with placeholder  
        normalized = re.sub(r'/[a-f0-9-]{32,}/|/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/', '/[UUID]/', normalized)
        
        return normalized
    
    def _explain_endpoint_interest(self, path: str) -> List[str]:
        """Explain why an endpoint is interesting"""
        
        reasons = []
        path_lower = path.lower()
        
        if any(term in path_lower for term in ['admin', 'manage', 'control']):
            reasons.append("Administrative interface")
        
        if any(term in path_lower for term in ['api', 'rest', 'json']):
            reasons.append("API endpoint")
        
        if any(term in path_lower for term in ['upload', 'file']):
            reasons.append("File operation")
        
        if any(term in path_lower for term in ['login', 'auth']):
            reasons.append("Authentication endpoint")
        
        if any(term in path_lower for term in ['test', 'dev', 'debug']):
            reasons.append("Development/test endpoint")
        
        return reasons if reasons else ["Standard endpoint"]
    
    def _explain_parameter_interest(self, param_name: str) -> List[str]:
        """Explain why a parameter is interesting"""
        
        reasons = []
        param_lower = param_name.lower()
        
        if param_lower in ['id', 'user_id', 'admin_id']:
            reasons.append("User/ID parameter - potential IDOR")
        
        if any(term in param_lower for term in ['file', 'path', 'dir']):
            reasons.append("File parameter - potential LFI/directory traversal")
        
        if any(term in param_lower for term in ['url', 'redirect', 'callback']):
            reasons.append("URL parameter - potential open redirect/SSRF")
        
        if any(term in param_lower for term in ['cmd', 'exec', 'query']):
            reasons.append("Command parameter - potential injection")
        
        if any(term in param_lower for term in ['admin', 'debug', 'test']):
            reasons.append("Sensitive parameter")
        
        return reasons if reasons else ["Standard parameter"]
    
    def _validate_target(self, target: str) -> bool:
        """Validate target domain"""
        
        if not target or len(target) < 3:
            return False
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', target):
            return False
        
        return True
    
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse waybackurls tool output (required by base class)"""
        
        if not raw_output:
            return {"urls": [], "statistics": {"total_urls": 0}}
        
        # Split output into lines and filter URLs
        urls = []
        for line in raw_output.strip().split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                urls.append(line)
        
        return {
            "urls": urls,
            "statistics": {
                "total_urls": len(urls)
            }
        }
    
    def format_results(self, result: ToolResult) -> str:
        """Format waybackurls results for display"""
        
        if not result.success:
            return f"❌ Wayback URLs discovery failed: {result.error}"
        
        data = result.data
        stats = data["statistics"]
        
        output = f"🕰️ **Historical URL Discovery - {data['target']}**\n\n"
        output += f"**Statistics:**\n"
        output += f"• Total URLs found: {stats['total_urls']}\n"
        output += f"• Unique endpoints: {stats['unique_endpoints']}\n"
        output += f"• Parameters discovered: {stats['parameters_found']}\n"
        output += f"• Interesting parameters: {stats['interesting_parameters']}\n\n"
        
        # Show top endpoints
        if data["endpoints"]:
            output += f"🎯 **Top Interesting Endpoints ({len(data['endpoints'])})**\n"
            for endpoint in data["endpoints"][:10]:
                score_emoji = "🔥" if endpoint["interest_score"] >= 5 else "⚡" if endpoint["interest_score"] >= 3 else "📍"
                output += f"{score_emoji} {endpoint['path']} (Score: {endpoint['interest_score']})\n"
                if endpoint["reasons"]:
                    output += f"   💡 {', '.join(endpoint['reasons'])}\n"
            output += "\n"
        
        # Show top parameters
        if data["parameters"]:
            output += f"🔍 **Interesting Parameters ({len(data['parameters'])})**\n"
            for param in data["parameters"][:10]:
                score_emoji = "🔥" if param["interest_score"] >= 4 else "⚡" if param["interest_score"] >= 2 else "📍"
                output += f"{score_emoji} {param['name']} (Score: {param['interest_score']})\n"
                if param["reasons"]:
                    output += f"   💡 {', '.join(param['reasons'])}\n"
                if param["example_values"]:
                    output += f"   📋 Examples: {', '.join(param['example_values'][:3])}\n"
            output += "\n"
        
        if not data["endpoints"] and not data["parameters"]:
            output += "ℹ️ No interesting endpoints or parameters found in historical data.\n"
        
        return output