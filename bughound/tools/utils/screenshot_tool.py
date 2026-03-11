#!/usr/bin/env python3
"""
Screenshot Tool for BugHound Evidence Collection

Captures screenshots of web services and vulnerabilities for evidence collection.
Supports multiple screenshot methods and fallbacks for reliability.
"""

import asyncio
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import tempfile
import shutil

logger = logging.getLogger(__name__)


class ScreenshotMethod:
    """Available screenshot capture methods"""
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WKHTMLTOIMAGE = "wkhtmltoimage"
    CUTYCAPT = "cutycapt"
    GOWITNESS = "gowitness"


class ScreenshotTool:
    """Tool for capturing screenshots of web services"""
    
    def __init__(self):
        """Initialize screenshot tool with available methods"""
        self.available_methods = []
        self._detect_available_methods()
        
        # Default screenshot settings
        self.default_options = {
            'width': 1920,
            'height': 1080,
            'timeout': 30,
            'format': 'png',
            'quality': 95,
            'wait_time': 3  # Seconds to wait for page load
        }
    
    def _detect_available_methods(self):
        """Detect which screenshot methods are available on the system"""
        
        # Check for common screenshot tools
        tools_to_check = [
            ('chromium-browser', ScreenshotMethod.CHROMIUM),
            ('chromium', ScreenshotMethod.CHROMIUM),
            ('google-chrome', ScreenshotMethod.CHROMIUM),
            ('firefox', ScreenshotMethod.FIREFOX),
            ('wkhtmltoimage', ScreenshotMethod.WKHTMLTOIMAGE),
            ('cutycapt', ScreenshotMethod.CUTYCAPT),
            ('gowitness', ScreenshotMethod.GOWITNESS)
        ]
        
        for tool_cmd, method in tools_to_check:
            if shutil.which(tool_cmd):
                self.available_methods.append(method)
                logger.debug(f"Found screenshot tool: {tool_cmd} ({method})")
        
        if not self.available_methods:
            logger.warning("No screenshot tools found. Screenshots will not be available.")
        else:
            logger.info(f"Available screenshot methods: {self.available_methods}")
    
    async def capture_url(
        self, 
        url: str, 
        workspace_id: str,
        finding_id: str = None,
        context: Dict[str, Any] = None,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Capture screenshot of a URL
        
        Args:
            url: URL to capture
            workspace_id: Workspace to save screenshot in
            finding_id: Optional finding ID for naming
            context: Additional context about the vulnerability/finding
            options: Screenshot options (width, height, timeout, etc.)
            
        Returns:
            Dictionary with success status, file path, and metadata
        """
        
        if not self.available_methods:
            return {
                'success': False,
                'error': 'No screenshot tools available',
                'method': 'none'
            }
        
        options = {**self.default_options, **(options or {})}
        
        try:
            logger.info(f"Capturing screenshot of {url}")
            
            # Try each available method until one succeeds
            for method in self.available_methods:
                try:
                    result = await self._capture_with_method(
                        url, workspace_id, finding_id, method, options, context
                    )
                    if result.get('success'):
                        logger.info(f"Screenshot captured successfully using {method}")
                        return result
                except Exception as e:
                    logger.warning(f"Screenshot method {method} failed: {e}")
                    continue
            
            return {
                'success': False,
                'error': 'All screenshot methods failed',
                'attempted_methods': self.available_methods
            }
            
        except Exception as e:
            logger.error(f"Error capturing screenshot: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _capture_with_method(
        self, 
        url: str, 
        workspace_id: str,
        finding_id: str,
        method: str, 
        options: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Capture screenshot using a specific method"""
        
        # Generate output filename
        output_path = self._generate_screenshot_path(
            workspace_id, url, finding_id, options.get('format', 'png')
        )
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Capture based on method
        if method == ScreenshotMethod.CHROMIUM:
            success = await self._capture_with_chromium(url, output_path, options)
        elif method == ScreenshotMethod.FIREFOX:
            success = await self._capture_with_firefox(url, output_path, options)
        elif method == ScreenshotMethod.WKHTMLTOIMAGE:
            success = await self._capture_with_wkhtmltoimage(url, output_path, options)
        elif method == ScreenshotMethod.CUTYCAPT:
            success = await self._capture_with_cutycapt(url, output_path, options)
        elif method == ScreenshotMethod.GOWITNESS:
            success = await self._capture_with_gowitness(url, output_path, options)
        else:
            success = False
        
        if success and output_path.exists():
            # Get additional metadata
            page_title = await self._extract_page_title(url)
            file_size = output_path.stat().st_size
            
            return {
                'success': True,
                'file_path': str(output_path),
                'file_size': file_size,
                'method': method,
                'viewport_size': f"{options['width']}x{options['height']}",
                'page_title': page_title,
                'final_url': url,  # Could be different if redirected
                'capture_options': options,
                'timestamp': datetime.now().isoformat()
            }
        
        return {'success': False, 'method': method}
    
    async def _capture_with_chromium(
        self, 
        url: str, 
        output_path: Path, 
        options: Dict[str, Any]
    ) -> bool:
        """Capture screenshot using Chromium/Chrome"""
        
        try:
            # Find chromium binary
            chromium_cmd = None
            for cmd in ['chromium-browser', 'chromium', 'google-chrome']:
                if shutil.which(cmd):
                    chromium_cmd = cmd
                    break
            
            if not chromium_cmd:
                return False
            
            # Build chromium command
            cmd = [
                chromium_cmd,
                '--headless',
                '--disable-gpu',
                '--disable-dev-shm-usage',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-background-timer-throttling',
                '--disable-renderer-backgrounding',
                '--disable-backgrounding-occluded-windows',
                '--no-sandbox',  # Needed for running as root (common in security tools)
                f'--window-size={options["width"]},{options["height"]}',
                f'--virtual-time-budget={options["timeout"] * 1000}',
                '--hide-scrollbars',
                '--disable-logging',
                '--disable-web-security',  # For testing purposes
                f'--screenshot={output_path}',
                url
            ]
            
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=options['timeout'] + 10
            )
            
            return process.returncode == 0 and output_path.exists()
            
        except Exception as e:
            logger.error(f"Chromium screenshot failed: {e}")
            return False
    
    async def _capture_with_firefox(
        self, 
        url: str, 
        output_path: Path, 
        options: Dict[str, Any]
    ) -> bool:
        """Capture screenshot using Firefox"""
        
        try:
            # Firefox headless screenshot command
            cmd = [
                'firefox',
                '--headless',
                '--screenshot', str(output_path),
                f'--window-size={options["width"]},{options["height"]}',
                url
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options['timeout'] + 10
            )
            
            return process.returncode == 0 and output_path.exists()
            
        except Exception as e:
            logger.error(f"Firefox screenshot failed: {e}")
            return False
    
    async def _capture_with_wkhtmltoimage(
        self, 
        url: str, 
        output_path: Path, 
        options: Dict[str, Any]
    ) -> bool:
        """Capture screenshot using wkhtmltoimage"""
        
        try:
            cmd = [
                'wkhtmltoimage',
                '--width', str(options['width']),
                '--height', str(options['height']),
                '--quality', str(options['quality']),
                f'--javascript-delay', str(options['wait_time'] * 1000),
                '--load-error-handling', 'ignore',
                '--load-media-error-handling', 'ignore',
                url,
                str(output_path)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options['timeout'] + 10
            )
            
            return process.returncode == 0 and output_path.exists()
            
        except Exception as e:
            logger.error(f"wkhtmltoimage screenshot failed: {e}")
            return False
    
    async def _capture_with_cutycapt(
        self, 
        url: str, 
        output_path: Path, 
        options: Dict[str, Any]
    ) -> bool:
        """Capture screenshot using CutyCapt"""
        
        try:
            cmd = [
                'cutycapt',
                f'--url={url}',
                f'--out={output_path}',
                f'--min-width={options["width"]}',
                f'--min-height={options["height"]}',
                f'--delay={options["wait_time"] * 1000}',
                '--max-wait=30000'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options['timeout'] + 10
            )
            
            return process.returncode == 0 and output_path.exists()
            
        except Exception as e:
            logger.error(f"CutyCapt screenshot failed: {e}")
            return False
    
    async def _capture_with_gowitness(
        self, 
        url: str, 
        output_path: Path, 
        options: Dict[str, Any]
    ) -> bool:
        """Capture screenshot using gowitness"""
        
        try:
            # gowitness saves to a directory, so we need to handle that
            temp_dir = output_path.parent / "temp_gowitness"
            temp_dir.mkdir(exist_ok=True)
            
            cmd = [
                'gowitness',
                'single',
                '--url', url,
                '--screenshot-path', str(temp_dir),
                '--timeout', str(options['timeout']),
                '--resolution', f"{options['width']}x{options['height']}"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options['timeout'] + 10
            )
            
            # Find the generated screenshot and move it
            if process.returncode == 0:
                screenshot_files = list(temp_dir.glob("*.png"))
                if screenshot_files:
                    shutil.move(str(screenshot_files[0]), str(output_path))
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return True
            
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
            
        except Exception as e:
            logger.error(f"gowitness screenshot failed: {e}")
            return False
    
    def _generate_screenshot_path(
        self, 
        workspace_id: str, 
        url: str, 
        finding_id: str = None,
        format: str = 'png'
    ) -> Path:
        """Generate output path for screenshot"""
        
        # Import workspace manager to get workspace path
        # Note: This creates a circular import issue, so we'll construct the path manually
        
        # Clean URL for filename
        clean_url = re.sub(r'[^\w\-_.]', '_', url.replace('https://', '').replace('http://', ''))
        clean_url = clean_url.strip('_')[:50]  # Limit length
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Build filename
        if finding_id:
            filename = f"{clean_url}_{finding_id}_{timestamp}.{format}"
        else:
            filename = f"{clean_url}_{timestamp}.{format}"
        
        # Construct workspace path (this is a bit of a hack)
        workspace_base = Path("workspaces")
        
        # Find workspace directory (should match workspace manager pattern)
        workspace_dirs = list(workspace_base.glob(f"*{workspace_id}*"))
        if workspace_dirs:
            workspace_path = workspace_dirs[0]
        else:
            # Fallback: create in current directory
            workspace_path = Path(f"workspace_{workspace_id}")
        
        screenshot_dir = workspace_path / "reports" / "evidence" / "screenshots"
        return screenshot_dir / filename
    
    async def _extract_page_title(self, url: str) -> Optional[str]:
        """Extract page title from URL (simple implementation)"""
        
        try:
            # Use curl to get page title quickly
            cmd = [
                'curl', '-s', '-L',
                '--max-time', '10',
                '--user-agent', 'BugHound-Screenshot/1.0',
                url
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=15
            )
            
            if process.returncode == 0:
                html_content = stdout.decode('utf-8', errors='ignore')
                
                # Extract title using regex
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                    # Clean up title
                    title = re.sub(r'\s+', ' ', title)
                    return title[:100]  # Limit length
            
        except Exception as e:
            logger.debug(f"Could not extract page title: {e}")
        
        return None
    
    async def capture_multiple_urls(
        self, 
        urls: List[str], 
        workspace_id: str,
        options: Dict[str, Any] = None,
        max_concurrent: int = 3
    ) -> Dict[str, Dict[str, Any]]:
        """
        Capture screenshots of multiple URLs concurrently
        
        Args:
            urls: List of URLs to capture
            workspace_id: Workspace to save screenshots in
            options: Screenshot options
            max_concurrent: Maximum concurrent screenshot operations
            
        Returns:
            Dictionary mapping URLs to capture results
        """
        
        if not urls:
            return {}
        
        logger.info(f"Capturing screenshots for {len(urls)} URLs (max concurrent: {max_concurrent})")
        
        # Create semaphore to limit concurrent operations
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def capture_single(url: str) -> tuple[str, Dict[str, Any]]:
            async with semaphore:
                result = await self.capture_url(url, workspace_id, options=options)
                return url, result
        
        # Execute captures concurrently
        try:
            tasks = [capture_single(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            capture_results = {}
            successful = 0
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Screenshot task failed: {result}")
                    continue
                
                url, capture_result = result
                capture_results[url] = capture_result
                
                if capture_result.get('success'):
                    successful += 1
            
            logger.info(f"Screenshot batch complete: {successful}/{len(urls)} successful")
            return capture_results
            
        except Exception as e:
            logger.error(f"Error in batch screenshot capture: {e}")
            return {}
    
    def get_available_methods(self) -> List[str]:
        """Get list of available screenshot methods"""
        return self.available_methods.copy()
    
    def is_available(self) -> bool:
        """Check if screenshot functionality is available"""
        return len(self.available_methods) > 0