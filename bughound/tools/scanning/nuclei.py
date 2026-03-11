#!/usr/bin/env python3
"""
Nuclei Tool for Basic Vulnerability Scanning

Simple implementation for Phase 1 - focuses on high and critical vulnerabilities
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

from ..base_tool import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class NucleiTool(BaseTool):
    """Simple nuclei vulnerability scanner for basic security testing with evidence collection"""
    
    def __init__(self, timeout: int = 900, evidence_collector=None):  # 15 minutes default
        super().__init__("nuclei", timeout)
        self.evidence_collector = evidence_collector
        
        # Check if nuclei is available
        import os
        go_bin_nuclei = os.path.expanduser("~/go/bin/nuclei")
        if os.path.exists(go_bin_nuclei):
            self.tool_name = go_bin_nuclei
        else:
            # Default to PATH
            self.tool_name = "nuclei"
        
        # Severity levels we care about for Phase 1
        self.target_severities = ["high", "critical"]
        
        # Basic template categories for quick scanning
        self.basic_templates = [
            "cves",           # Known CVEs
            "exposures",      # Information disclosure
            "misconfiguration", # Common misconfigs
            "vulnerabilities" # General vulns
        ]
    
    async def execute(self, targets: List[str], options: Dict[str, Any] = None, workspace_id: str = None) -> ToolResult:
        """
        Execute nuclei scan on targets
        
        Args:
            targets: List of URLs/hosts to scan
            options: Scan options (severity, templates, etc.)
            
        Returns:
            ToolResult with found vulnerabilities
        """
        
        if options is None:
            options = {}
        
        try:
            if not targets:
                return ToolResult(
                    success=False,
                    error="No targets provided for scanning"
                )
            
            # Validate and prepare targets
            valid_targets = self._prepare_targets(targets)
            if not valid_targets:
                return ToolResult(
                    success=False,
                    error="No valid targets after validation"
                )
            
            logger.info(f"Starting nuclei scan for {len(valid_targets)} targets")
            
            # Execute nuclei scan
            scan_results = await self._execute_nuclei_scan(valid_targets, options)
            
            if not scan_results:
                return ToolResult(
                    success=True,
                    data={
                        "vulnerabilities": [],
                        "statistics": {
                            "targets_scanned": len(valid_targets),
                            "vulnerabilities_found": 0,
                            "high_severity": 0,
                            "critical_severity": 0
                        }
                    }
                )
            
            # Process results and collect evidence
            processed_data = await self._process_scan_results(scan_results, valid_targets, workspace_id)
            
            vuln_count = len(processed_data["vulnerabilities"])
            logger.info(f"Nuclei scan completed: {vuln_count} vulnerabilities found")
            
            return ToolResult(success=True, data=processed_data)
            
        except Exception as e:
            error_msg = f"Nuclei scan failed: {str(e)}"
            logger.error(error_msg)
            return ToolResult(success=False, error=error_msg)
    
    def _prepare_targets(self, targets: List[str]) -> List[str]:
        """Prepare and validate targets for nuclei"""
        
        valid_targets = []
        
        for target in targets:
            try:
                # Clean up target
                target = target.strip()
                if not target:
                    continue
                
                # Add protocol if missing
                if not target.startswith(('http://', 'https://')):
                    # Add both HTTP and HTTPS for testing
                    valid_targets.append(f"https://{target}")
                    valid_targets.append(f"http://{target}")
                else:
                    valid_targets.append(target)
                    
            except Exception as e:
                logger.warning(f"Failed to prepare target {target}: {e}")
                continue
        
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for target in valid_targets:
            if target not in seen:
                seen.add(target)
                unique_targets.append(target)
        
        return unique_targets
    
    async def _execute_nuclei_scan(self, targets: List[str], options: Dict[str, Any]) -> Optional[List[Dict]]:
        """Execute nuclei and return parsed JSON results"""
        
        try:
            # Create temporary files for targets and output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as target_file:
                target_file_path = target_file.name
                for target in targets:
                    target_file.write(f"{target}\n")
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
                output_file_path = output_file.name
            
            # Build nuclei command
            cmd = self._build_nuclei_command(target_file_path, output_file_path, options)
            
            logger.info(f"Executing nuclei: {' '.join(cmd[:3])}... (truncated)")
            logger.debug(f"Full nuclei command: {' '.join(cmd)}")
            
            # Execute nuclei
            await self._run_command(cmd)
            
            # Read JSON output
            try:
                results = []
                with open(output_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                result = json.loads(line)
                                results.append(result)
                            except json.JSONDecodeError:
                                logger.debug(f"Failed to parse JSON line: {line}")
                                continue
                
                # Clean up temp files
                Path(target_file_path).unlink()
                Path(output_file_path).unlink()
                
                return results
                
            except Exception as e:
                logger.error(f"Failed to read nuclei output: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Nuclei execution failed: {e}")
            raise
    
    def _build_nuclei_command(self, target_file: str, output_file: str, options: Dict[str, Any]) -> List[str]:
        """Build nuclei command with appropriate options"""
        
        cmd = [self.tool_name]
        
        # Target file
        cmd.extend(["-l", target_file])
        
        # JSON output
        cmd.extend(["-o", output_file, "-json"])
        
        # Severity filter (default to high,critical)
        severities = options.get("severities", self.target_severities)
        if severities:
            cmd.extend(["-severity", ",".join(severities)])
        
        # Template selection
        templates = options.get("templates", self.basic_templates)
        if templates:
            for template in templates:
                cmd.extend(["-tags", template])
        
        # Rate limiting
        rate_limit = options.get("rate_limit", 150)
        cmd.extend(["-rate-limit", str(rate_limit)])
        
        # Timeout
        timeout = options.get("timeout", "10s")
        if isinstance(timeout, int) or isinstance(timeout, float):
            timeout = f"{int(timeout)}s"
        cmd.extend(["-timeout", str(timeout)])
        
        # Retries
        retries = options.get("retries", 1)
        cmd.extend(["-retries", str(retries)])
        
        # Concurrency
        concurrency = options.get("concurrency")
        if concurrency:
            cmd.extend(["-c", str(concurrency)])
        
        # Silent mode
        cmd.append("-silent")
        
        # No color output
        cmd.append("-no-color")
        
        # Disable update check
        cmd.append("-disable-update-check")
        
        return cmd
    
    async def _process_scan_results(self, results: List[Dict], targets: List[str], workspace_id: str = None) -> Dict[str, Any]:
        """Process nuclei JSON results into structured format"""
        
        vulnerabilities = []
        high_count = 0
        critical_count = 0
        
        for result in results:
            try:
                # Extract basic vulnerability information
                vuln = {
                    "template_id": result.get("template-id", "unknown"),
                    "template_name": result.get("info", {}).get("name", "Unknown"),
                    "severity": result.get("info", {}).get("severity", "unknown"),
                    "description": result.get("info", {}).get("description", ""),
                    "host": result.get("host", ""),
                    "matched_at": result.get("matched-at", ""),
                    "extracted_results": result.get("extracted-results", []),
                    "curl_command": result.get("curl-command", ""),
                    "type": result.get("type", "http")
                }
                
                # Count by severity
                severity = vuln["severity"].lower()
                if severity == "high":
                    high_count += 1
                elif severity == "critical":
                    critical_count += 1
                
                vulnerabilities.append(vuln)
                
                # Collect evidence for this vulnerability if workspace and evidence collector available
                if workspace_id and self.evidence_collector:
                    try:
                        target_url = vuln.get("matched_at") or vuln.get("host", "")
                        if target_url:
                            vulnerability_type = vuln.get("template_id", "unknown")
                            evidence_items = await self.evidence_collector.collect_evidence_for_finding(
                                workspace_id=workspace_id,
                                finding_data=result,  # Pass the full nuclei result
                                target_url=target_url,
                                vulnerability_type=vulnerability_type
                            )
                            
                            if evidence_items:
                                # Store evidence references in the vulnerability data
                                vuln["evidence"] = {
                                    "collected": True,
                                    "count": len(evidence_items),
                                    "evidence_ids": [e.evidence_id for e in evidence_items],
                                    "evidence_types": [e.evidence_type.value for e in evidence_items]
                                }
                                logger.info(f"Collected {len(evidence_items)} evidence items for {vulnerability_type}")
                            else:
                                vuln["evidence"] = {"collected": False, "count": 0}
                    except Exception as e:
                        logger.warning(f"Evidence collection failed for vulnerability {vuln.get('template_id')}: {e}")
                        vuln["evidence"] = {"collected": False, "error": str(e)}
                
            except Exception as e:
                logger.warning(f"Failed to process result: {e}")
                continue
        
        # Sort by severity (critical first, then high)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"].lower(), 5))
        
        return {
            "vulnerabilities": vulnerabilities,
            "statistics": {
                "targets_scanned": len(targets),
                "vulnerabilities_found": len(vulnerabilities),
                "high_severity": high_count,
                "critical_severity": critical_count
            }
        }
    
    def _parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse nuclei raw output (required by base class)"""
        
        if not raw_output:
            return {
                "vulnerabilities": [],
                "statistics": {
                    "targets_scanned": 0,
                    "vulnerabilities_found": 0,
                    "high_severity": 0,
                    "critical_severity": 0
                }
            }
        
        vulnerabilities = []
        lines = raw_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue
            
            # Simple parsing - look for vulnerability indicators
            if any(indicator in line.lower() for indicator in ['found', 'detected', 'vulnerable']):
                # Basic vulnerability extraction
                vulnerability = {
                    "template_id": "unknown",
                    "template_name": "Unknown Vulnerability",
                    "matched_at": line,
                    "severity": "medium",
                    "description": "Potential vulnerability detected",
                    "reference": [],
                    "classification": {},
                    "extracted_results": []
                }
                vulnerabilities.append(vulnerability)
        
        high_count = len([v for v in vulnerabilities if v["severity"].lower() == "high"])
        critical_count = len([v for v in vulnerabilities if v["severity"].lower() == "critical"])
        
        return {
            "vulnerabilities": vulnerabilities,
            "statistics": {
                "targets_scanned": 1,  # Simplified for raw output parsing
                "vulnerabilities_found": len(vulnerabilities),
                "high_severity": high_count,
                "critical_severity": critical_count
            }
        }
    
    def format_results(self, result: ToolResult) -> str:
        """Format nuclei results for display"""
        
        if not result.success:
            return f"❌ Nuclei scan failed: {result.error}"
        
        data = result.data
        stats = data["statistics"]
        vulns = data["vulnerabilities"]
        
        output = f"🔍 **Vulnerability Scan Results**\n\n"
        output += f"**Statistics:**\n"
        output += f"• Targets scanned: {stats['targets_scanned']}\n"
        output += f"• Vulnerabilities found: {stats['vulnerabilities_found']}\n"
        output += f"• Critical: {stats['critical_severity']}\n"
        output += f"• High: {stats['high_severity']}\n\n"
        
        if not vulns:
            output += "✅ No high or critical vulnerabilities found.\n"
            return output
        
        # Show critical vulnerabilities first
        critical_vulns = [v for v in vulns if v["severity"].lower() == "critical"]
        if critical_vulns:
            output += f"🚨 **Critical Vulnerabilities ({len(critical_vulns)})**\n"
            for vuln in critical_vulns[:5]:  # Show top 5
                output += f"🔥 {vuln['template_name']}\n"
                output += f"   🎯 {vuln['host']}\n"
                output += f"   📋 {vuln['template_id']}\n"
                if vuln['description']:
                    desc = vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
                    output += f"   💡 {desc}\n"
                output += "\n"
        
        # Show high severity vulnerabilities
        high_vulns = [v for v in vulns if v["severity"].lower() == "high"]
        if high_vulns:
            output += f"⚡ **High Severity Vulnerabilities ({len(high_vulns)})**\n"
            for vuln in high_vulns[:5]:  # Show top 5
                output += f"🔶 {vuln['template_name']}\n"
                output += f"   🎯 {vuln['host']}\n"
                output += f"   📋 {vuln['template_id']}\n"
                output += "\n"
        
        if len(vulns) > 10:
            output += f"... and {len(vulns) - 10} more vulnerabilities found.\n"
        
        return output